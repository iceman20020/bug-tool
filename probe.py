"""
probe.py — template engine.
Loads templates + fail_words, tests parameters, runs db discovery.
"""

import asyncio
import json
import os
import re
import time
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx

TEMPLATE_FILES = ["templates_xss.json", "templates_sqli.json", "templates_misc.json"]
FAIL_FILES = {
    "xss": "fail_words_xss.json",
    "sqli": "fail_words_sqli.json",
    "misc": "fail_words_misc.json",
}


def load_templates():
    index = {}
    base = os.path.dirname(os.path.abspath(__file__))
    for fname in TEMPLATE_FILES:
        path = os.path.join(base, fname)
        if not os.path.exists(path):
            print(f"[!] missing {fname}")
            continue
        with open(path) as f:
            data = json.load(f)
        for ttype, entries in data.items():
            for entry in entries:
                key = ttype
                index.setdefault(key, []).append(entry)
    total = sum(len(v) for v in index.values())
    print(f"[*] loaded {total} templates across {len(index)} types")
    return index


def load_fail_words():
    fw = {}
    base = os.path.dirname(os.path.abspath(__file__))
    for key, fname in FAIL_FILES.items():
        path = os.path.join(base, fname)
        if not os.path.exists(path):
            fw[key] = {"regex": [], "literal": [], "negative": []}
            continue
        with open(path) as f:
            fw[key] = json.load(f)
    return fw


def pick_fail_words(ttype):
    if ttype.startswith("xss"):
        return "xss"
    if ttype.startswith("sqli") or ttype == "nosqli":
        return "sqli"
    return "misc"


def is_negative(body_low, fail_words):
    for neg in fail_words.get("negative", []):
        if neg.lower() in body_low:
            return True
    return False


def find_match(body, fail_words):
    body_low = body.lower()
    for lit in fail_words.get("literal", []):
        if lit.lower() in body_low:
            return lit
    for rx in fail_words.get("regex", []):
        try:
            m = re.search(rx, body, re.I)
            if m:
                return m.group(0)[:200]
        except re.error:
            continue
    return None


def inject_param(url, param, value):
    parsed = urlparse(url)
    q = parse_qs(parsed.query)
    q[param] = [value]
    new_q = urlencode({k: v[0] for k, v in q.items()})
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, new_q, parsed.fragment))


def template_matches_body(entry, body, baseline_len, elapsed, baseline_time):
    mt = entry.get("match", {})
    mtype = mt.get("type")

    if mtype == "reflect":
        payload = entry["payload"]
        if payload in body:
            return True
        if payload.lower() in body.lower():
            return True
        return False

    if mtype == "length_delta":
        threshold = mt.get("threshold", 100)
        return abs(len(body) - baseline_len) > threshold

    if mtype == "timediff":
        threshold = mt.get("threshold", 3.0)
        return (elapsed - baseline_time) > threshold

    return False


async def test_param(client, url, param, entry, fail_words, cfg):
    payload = entry["payload"]
    method = "GET"
    if entry.get("methods"):
        method = entry["methods"][0]

    try:
        t0 = time.monotonic()
        if method == "GET":
            test_url = inject_param(url, param, payload)
            r = await client.get(test_url)
        else:
            parsed = urlparse(url)
            q = parse_qs(parsed.query)
            q[param] = [payload]
            r = await client.post(
                urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", "")),
                data={k: v[0] for k, v in q.items()})
        elapsed = time.monotonic() - t0
    except Exception:
        return None

    body = r.text or ""
    body_low = body.lower()

    if is_negative(body_low, fail_words):
        return None

    matched = find_match(body, fail_words)
    if matched:
        return {"evidence": matched, "status": r.status_code, "elapsed": elapsed}

    if template_matches_body(entry, body, 0, elapsed, 0):
        return {"evidence": f"template match: {entry.get('match', {}).get('type')}",
                "status": r.status_code, "elapsed": elapsed}

    return None


async def db_discovery(client, host_url, templates, cfg):
    findings = []
    entries = templates.get("db_discovery", [])
    base = f"{host_url.rstrip('/')}"

    sem = asyncio.Semaphore(cfg["concurrency"])

    async def check(entry):
        async with sem:
            path = entry.get("path", "")
            url = base + path
            try:
                r = await client.get(url)
            except Exception:
                return

            match = entry.get("match", {})
            ok = True

            if "status" in match and r.status_code not in match["status"]:
                ok = False
            if ok and "title_regex" in match:
                m = re.search(r"<title[^>]*>(.*?)</title>", r.text or "", re.I | re.S)
                title = m.group(1) if m else ""
                if not re.search(match["title_regex"], title, re.I):
                    ok = False
            if ok and "body_regex" in match:
                for rx in match["body_regex"]:
                    if not re.search(rx, r.text or "", re.I):
                        ok = False
                        break

            if ok:
                findings.append({
                    "type": "db_discovery",
                    "severity": entry.get("severity", "high"),
                    "url": url,
                    "param": None,
                    "method": "GET",
                    "payload": None,
                    "evidence": f"matched {entry.get('id', '')}",
                    "template": entry.get("id", ""),
                })

    await asyncio.gather(*[check(e) for e in entries])
    return findings


async def run(crawl_out, recon_out, scope, cfg, outdir):
    templates = load_templates()
    fail_words = load_fail_words()

    findings = []
    seen = set()

    hosts = [h["host"] for h in recon_out.get("hosts", []) if h.get("http")]
    if not hosts:
        print("[!] no live hosts to probe")
        return {"findings": []}

    headers = dict(cfg["headers"])
    headers["User-Agent"] = cfg["user_agent"]
    if cfg.get("cookie"):
        headers["Cookie"] = cfg["cookie"]

    async with httpx.AsyncClient(
            timeout=cfg["timeout"], verify=False, follow_redirects=True,
            headers=headers, proxy=cfg.get("proxy")) as client:

        # db discovery first
        print("[*] db discovery")
        for h in hosts[:50]:
            scheme = "https"
            for hh in recon_out["hosts"]:
                if hh["host"] == h and hh.get("http"):
                    scheme = urlparse(hh["http"][0]["url"]).scheme
                    break
            hits = await db_discovery(client, f"{scheme}://{h}", templates, cfg)
            for hit in hits:
                key = (hit["url"], hit["type"])
                if key not in seen:
                    seen.add(key)
                    findings.append(hit)

        # parameter tests
        param_urls = crawl_out.get("parameterized", [])
        print(f"[*] probing {len(param_urls)} parameterized urls")

        sem = asyncio.Semaphore(cfg["concurrency"])
        rate_sem = asyncio.Semaphore(cfg["rate"])

        async def rate_limited(coro):
            async with rate_sem:
                result = await coro
                await asyncio.sleep(1.0 / cfg["rate"])
                return result

        async def test_url(url):
            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys())
            if not params:
                return []
            local = []
            for p in params:
                # pick relevant templates by param name heuristic
                p_low = p.lower()
                candidates = []
                # xss always
                candidates.extend(templates.get("xss", [])[:200])
                # sqli if likely
                if any(k in p_low for k in ("id", "num", "page", "cat", "item",
                                             "user", "order", "sort", "q", "search")):
                    candidates.extend(templates.get("sqli", [])[:200])
                # misc all
                for t in ("ssrf", "lfi", "ssti", "cmd", "open_redirect",
                          "crlf", "path_traversal"):
                    candidates.extend(templates.get(t, [])[:50])

                for entry in candidates:
                    async with sem:
                        fw_key = pick_fail_words(entry["id"].split("-")[0])
                        fw = fail_words.get(fw_key, {})
                        res = await rate_limited(
                            test_param(client, url, p, entry, fw, cfg))
                        if res:
                            key = (url, p, entry["id"])
                            if key not in seen:
                                seen.add(key)
                                local.append({
                                    "type": entry["id"].split("-")[0],
                                    "severity": entry.get("severity", "medium"),
                                    "url": url,
                                    "param": p,
                                    "method": entry.get("methods", ["GET"])[0],
                                    "payload": entry["payload"][:200],
                                    "evidence": res["evidence"],
                                    "template": entry["id"],
                                })
            return local

        results = await asyncio.gather(
            *[test_url(u) for u in param_urls[:2000]], return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

    out = {
        "findings": findings,
        "count": len(findings),
    }
    path = os.path.join(outdir, "findings.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    return out
