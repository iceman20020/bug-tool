"""
crawl.py — async BFS crawler.
Extracts links, forms, JS endpoints, parameterized URLs, robots, sitemap.
"""

import asyncio
import json
import os
import re
from urllib.parse import urljoin, urlparse, parse_qs

import httpx
from bs4 import BeautifulSoup

JS_ENDPOINT_PATTERNS = [
    r'["\'](/[a-zA-Z0-9_\-/\.]+)["\']',
    r'fetch\(\s*["\']([^"\']+)["\']',
    r'axios\.(?:get|post|put|delete)\(\s*["\']([^"\']+)["\']',
    r'\.open\(\s*["\'](?:GET|POST)["\']\s*,\s*["\']([^"\']+)["\']',
    r'url\s*[:=]\s*["\']([^"\']+)["\']',
    r'path\s*[:=]\s*["\'](/[^"\']+)["\']',
]

DEFAULT_PARAMS = [
    "id", "q", "s", "search", "query", "page", "p", "file", "path", "url",
    "redirect", "next", "return", "view", "cat", "category", "product", "item",
    "user", "username", "email", "name", "lang", "locale", "sort", "order",
    "filter", "type", "action", "do", "cmd", "exec", "callback", "jsonp",
]


def in_scope(host, scope):
    h = host.lower()
    for ex in scope["exclude"]:
        if h.endswith(ex):
            return False
    for d in scope["domains"]:
        if h == d or h.endswith("." + d):
            return True
    for w in scope["wildcards"]:
        if h == w or h.endswith("." + w):
            return True
    return False


def extract_from_js(js_text):
    out = set()
    for pat in JS_ENDPOINT_PATTERNS:
        for m in re.finditer(pat, js_text):
            p = m.group(1)
            if p.startswith("/") and len(p) > 2:
                out.add(p)
    return out


def classify_url(url):
    parsed = urlparse(url)
    return {
        "url": url,
        "host": parsed.netloc,
        "path": parsed.path,
        "query": parsed.query,
        "has_params": bool(parse_qs(parsed.query)),
        "params": list(parse_qs(parsed.query).keys()),
    }


async def fetch(client, url):
    try:
        r = await client.get(url)
        return r
    except Exception:
        return None


async def crawl_host(host, cfg, scope, max_depth=3, max_urls=2000):
    base = f"https://{host}"
    headers = dict(cfg["headers"])
    headers["User-Agent"] = cfg["user_agent"]
    if cfg.get("cookie"):
        headers["Cookie"] = cfg["cookie"]

    urls = set()
    forms = []
    js_endpoints = set()
    params = {}

    async with httpx.AsyncClient(
            timeout=cfg["timeout"], verify=False, follow_redirects=True,
            headers=headers, proxy=cfg.get("proxy")) as client:

        # probe base
        base_r = await fetch(client, base)
        if not base_r:
            base = f"http://{host}"
            base_r = await fetch(client, base)
        if not base_r:
            return None

        # robots + sitemap
        for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
            r = await fetch(client, urljoin(base, path))
            if r and r.status_code == 200:
                if path == "/robots.txt":
                    for line in r.text.splitlines():
                        if line.lower().startswith("disallow:"):
                            p = line.split(":", 1)[1].strip()
                            if p and p != "/":
                                urls.add(urljoin(base, p))
                elif path == "/sitemap.xml":
                    for m in re.finditer(r"<loc>([^<]+)</loc>", r.text):
                        u = m.group(1).strip()
                        if in_scope(urlparse(u).netloc, scope):
                            urls.add(u)

        queue = [(base, 0)]
        seen = {base}

        sem = asyncio.Semaphore(cfg["concurrency"])

        async def process(url, depth):
            async with sem:
                r = await fetch(client, url)
                if not r:
                    return []
                if r.status_code >= 400:
                    return []
                ctype = r.headers.get("content-type", "").lower()
                if "html" not in ctype and "javascript" not in ctype:
                    return []

                if "javascript" in ctype:
                    for p in extract_from_js(r.text):
                        abs_url = urljoin(base, p)
                        if in_scope(urlparse(abs_url).netloc, scope):
                            js_endpoints.add(abs_url)
                    return []

                soup = BeautifulSoup(r.text, "html.parser")

                # forms
                for form in soup.find_all("form"):
                    action = form.get("action", "").strip()
                    method = (form.get("method") or "GET").upper()
                    inputs = []
                    for inp in form.find_all(["input", "textarea", "select"]):
                        n = inp.get("name")
                        if n:
                            inputs.append({"name": n, "type": inp.get("type", "text")})
                    forms.append({
                        "action": urljoin(url, action) if action else url,
                        "method": method,
                        "inputs": inputs,
                    })

                # links
                new_urls = []
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                        continue
                    abs_url = urljoin(url, href)
                    parsed = urlparse(abs_url)
                    if parsed.scheme not in ("http", "https"):
                        continue
                    if not in_scope(parsed.netloc, scope):
                        continue
                    clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    if parsed.query:
                        clean += "?" + parsed.query
                    if clean not in seen:
                        seen.add(clean)
                        new_urls.append(clean)
                        urls.add(clean)
                        if parsed.query:
                            for p in parse_qs(parsed.query).keys():
                                params.setdefault(p, []).append(clean)

                # scripts
                for s in soup.find_all("script", src=True):
                    src = urljoin(url, s["src"])
                    if in_scope(urlparse(src).netloc, scope):
                        js_endpoints.add(src)

                # inline js
                for s in soup.find_all("script"):
                    if s.string:
                        for p in extract_from_js(s.string):
                            abs_url = urljoin(base, p)
                            if in_scope(urlparse(abs_url).netloc, scope):
                                js_endpoints.add(abs_url)

                return [(u, depth + 1) for u in new_urls]

        while queue and len(urls) < max_urls:
            batch = []
            while queue and len(batch) < 20:
                u, d = queue.pop(0)
                if d > max_depth:
                    continue
                batch.append((u, d))
            results = await asyncio.gather(
                *[process(u, d) for u, d in batch], return_exceptions=True)
            for res in results:
                if isinstance(res, list):
                    for u, d in res:
                        if d <= max_depth and u not in seen:
                            seen.add(u)
                            queue.append((u, d))

    # also probe js endpoints
    if js_endpoints:
        async with httpx.AsyncClient(
                timeout=cfg["timeout"], verify=False,
                headers=headers, proxy=cfg.get("proxy")) as client:
            for ep in list(js_endpoints)[:200]:
                r = await fetch(client, ep)
                if r and r.status_code == 200 and "html" in r.headers.get("content-type", ""):
                    soup = BeautifulSoup(r.text, "html.parser")
                    for a in soup.find_all("a", href=True):
                        abs_url = urljoin(ep, a["href"])
                        if in_scope(urlparse(abs_url).netloc, scope):
                            urls.add(abs_url)
                            if "?" in abs_url:
                                for p in parse_qs(urlparse(abs_url).query).keys():
                                    params.setdefault(p, []).append(abs_url)

    return {
        "host": host,
        "urls": sorted(urls),
        "forms": forms,
        "js_endpoints": sorted(js_endpoints),
        "params": {k: v[:20] for k, v in params.items()},
    }


async def run(recon, scope, cfg, outdir):
    hosts = [h["host"] for h in recon.get("hosts", []) if h.get("http")]
    print(f"[*] crawling {len(hosts)} live hosts")

    all_urls = set()
    all_forms = []
    all_js = set()
    all_params = {}

    results = await asyncio.gather(
        *[crawl_host(h, cfg, scope) for h in hosts], return_exceptions=True)

    for r in results:
        if isinstance(r, dict) and r:
            all_urls.update(r["urls"])
            all_forms.extend(r["forms"])
            all_js.update(r["js_endpoints"])
            for k, v in r["params"].items():
                all_params.setdefault(k, []).extend(v)

    # seed with default params for parameterless urls
    param_urls = [u for u in all_urls if "?" in u]
    for u in all_urls:
        if "?" not in u and len(param_urls) < 5000:
            param_urls.append(u + "?id=1")

    out = {
        "urls": sorted(all_urls),
        "parameterized": sorted(param_urls),
        "forms": all_forms,
        "js_endpoints": sorted(all_js),
        "params": {k: list(set(v))[:20] for k, v in all_params.items()},
    }
    path = os.path.join(outdir, "crawl.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    return out
