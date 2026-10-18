"""
recon.py — hard recon stage.
Passive + active subdomain enum, DNS resolution, port scan,
HTTP liveness + tech fingerprint, WHOIS/ASN.
"""

import asyncio
import json
import os
import random
import re
import socket
import string

import dns.asyncresolver
import dns.resolver
import httpx
import whois

SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dev", "staging", "stage", "test", "beta", "alpha", "demo", "sandbox",
    "api", "api-dev", "api-staging", "api-v1", "api-v2", "rest", "graphql",
    "admin", "administrator", "panel", "cpanel", "whm", "dashboard", "manage",
    "portal", "intranet", "internal", "vpn", "remote", "ssh", "rdp",
    "cdn", "static", "assets", "media", "img", "images", "files", "download",
    "upload", "uploads", "backup", "backups", "db", "database", "mysql",
    "postgres", "mongo", "redis", "elastic", "kibana", "grafana",
    "jenkins", "gitlab", "github", "git", "ci", "cd", "build", "deploy",
    "jira", "confluence", "wiki", "docs", "doc", "help", "support",
    "blog", "news", "shop", "store", "cart", "checkout", "pay", "payments",
    "auth", "login", "sso", "oauth", "id", "accounts", "account",
    "m", "mobile", "app", "apps", "ios", "android", "wap",
    "status", "monitor", "monitoring", "metrics", "logs", "log",
    "s3", "bucket", "storage", "blob", "azure", "aws", "gcp",
    "v1", "v2", "v3", "old", "new", "legacy", "prod", "production",
    "preprod", "qa", "uat", "uat2", "preview", "review",
    "web", "web1", "web2", "node1", "node2", "lb", "proxy", "gateway",
    "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "imap", "pop3",
    "crm", "erp", "hr", "finance", "sales", "marketing", "analytics",
    "search", "chat", "meet", "conference", "video", "stream", "live",
    "forum", "community", "social", "profile", "user", "users", "member",
]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 631, 636, 993, 995, 1080, 1433, 1521, 1723, 2049, 2375,
    2376, 3000, 3128, 3260, 3306, 3389, 4443, 5000, 5432, 5601, 5672,
    5900, 5984, 6379, 7001, 7002, 8000, 8008, 8080, 8081, 8082, 8088,
    8443, 8888, 9000, 9042, 9090, 9200, 9300, 9443, 10000, 11211,
    27017, 27018, 50000,
]

TECH_SIGNATURES = [
    ("wordpress", r"wp-content|wp-includes|/wp-json"),
    ("drupal", r"drupal|sites/default/files"),
    ("joomla", r"joomla|/media/system/js"),
    ("magento", r"magento|/skin/frontend"),
    ("shopify", r"cdn\.shopify\.com|shopify"),
    ("nginx", r"^nginx"),
    ("apache", r"^apache"),
    ("iis", r"^microsoft-iis"),
    ("cloudflare", r"^cloudflare"),
    ("litespeed", r"^litespeed"),
    ("express", r"^express"),
    ("php", r"x-powered-by:\s*php"),
    ("aspnet", r"x-aspnet-version|x-powered-by:\s*asp\.net"),
    ("java", r"jsessionid|servlet"),
    ("tomcat", r"tomcat|jsessionid"),
    ("spring", r"spring"),
    ("react", r"react|__react"),
    ("vue", r"vue\.js|__vue__"),
    ("angular", r"ng-version|angular"),
    ("jquery", r"jquery"),
    ("bootstrap", r"bootstrap"),
    ("grafana", r"grafana"),
    ("kibana", r"kibana"),
    ("jenkins", r"jenkins"),
    ("gitlab", r"gitlab"),
]

resolver = dns.asyncresolver.Resolver()
resolver.timeout = 5
resolver.lifetime = 10


async def passive_crtsh(domain):
    out = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(url)
            if r.status_code == 200:
                for entry in r.json():
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(domain):
                            out.add(name)
    except Exception:
        pass
    return out


async def passive_hackertarget(domain):
    out = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(url)
            if r.status_code == 200 and "error" not in r.text.lower():
                for line in r.text.splitlines():
                    if "," in line:
                        out.add(line.split(",")[0].strip().lower())
    except Exception:
        pass
    return out


async def passive_otx(domain):
    out = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(url)
            if r.status_code == 200:
                for entry in r.json().get("passive_dns", []):
                    h = entry.get("hostname", "").lower()
                    if h.endswith(domain):
                        out.add(h)
    except Exception:
        pass
    return out


async def passive_urlscan(domain):
    out = set()
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(url)
            if r.status_code == 200:
                for entry in r.json().get("results", []):
                    h = entry.get("page", {}).get("domain", "").lower()
                    if h and h.endswith(domain):
                        out.add(h)
    except Exception:
        pass
    return out


def random_sub(domain):
    return "".join(random.choices(string.ascii_lowercase, k=12)) + "." + domain


async def detect_wildcard(domain):
    try:
        r = await resolver.resolve(random_sub(domain), "A")
        return {str(a) for a in r}
    except Exception:
        return set()


async def resolve_host(host):
    result = {"host": host, "a": [], "aaaa": [], "cname": [], "mx": [], "txt": []}
    for rtype, key in (("A", "a"), ("AAAA", "aaaa"), ("CNAME", "cname"),
                       ("MX", "mx"), ("TXT", "txt")):
        try:
            ans = await resolver.resolve(host, rtype)
            for r in ans:
                result[key].append(str(r))
        except Exception:
            pass
    return result


async def active_bruteforce(domain, wildcard_ips, concurrency=100):
    sem = asyncio.Semaphore(concurrency)
    found = set()

    async def try_host(sub):
        async with sem:
            host = f"{sub}.{domain}"
            try:
                ans = await resolver.resolve(host, "A")
                ips = {str(a) for a in ans}
                if wildcard_ips and ips.issubset(wildcard_ips):
                    return
                found.add(host)
            except Exception:
                pass

    await asyncio.gather(*[try_host(s) for s in SUBDOMAINS])
    return found


async def port_scan(host, ports=COMMON_PORTS, concurrency=200, timeout=3):
    open_ports = []
    sem = asyncio.Semaphore(concurrency)

    async def probe(port):
        async with sem:
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                open_ports.append(port)
            except Exception:
                pass

    await asyncio.gather(*[probe(p) for p in ports])
    return sorted(open_ports)


def fingerprint_tech(headers, body):
    blob = (str(headers).lower() + "\n" + (body or "").lower()[:50000])
    hits = set()
    for name, pattern in TECH_SIGNATURES:
        if re.search(pattern, blob, re.I | re.M):
            hits.add(name)
    return sorted(hits)


async def http_probe(host, cfg):
    out = []
    scheme_list = ["https", "http"]
    headers = dict(cfg["headers"])
    headers["User-Agent"] = cfg["user_agent"]
    if cfg.get("cookie"):
        headers["Cookie"] = cfg["cookie"]
    async with httpx.AsyncClient(
            timeout=cfg["timeout"], verify=False, follow_redirects=True,
            headers=headers, proxy=cfg.get("proxy")) as c:
        for scheme in scheme_list:
            url = f"{scheme}://{host}"
            try:
                r = await c.get(url)
                title = ""
                m = re.search(r"<title[^>]*>(.*?)</title>", r.text or "", re.I | re.S)
                if m:
                    title = m.group(1).strip()[:200]
                tech = fingerprint_tech(r.headers, r.text or "")
                out.append({
                    "url": str(r.url),
                    "status": r.status_code,
                    "title": title,
                    "server": r.headers.get("server", ""),
                    "tech": tech,
                    "length": len(r.content or b""),
                })
                break
            except Exception:
                continue
    return out


async def whois_lookup(domain):
    try:
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, whois.whois, domain)
        return {
            "registrar": str(w.registrar) if w.registrar else None,
            "org": str(w.org) if w.org else None,
            "creation": str(w.creation_date) if w.creation_date else None,
            "expiration": str(w.expiration_date) if w.expiration_date else None,
            "name_servers": w.name_servers if w.name_servers else [],
        }
    except Exception:
        return {}


async def run(scope, cfg, outdir):
    all_subs = set()
    for d in scope["domains"] + scope["wildcards"]:
        all_subs.add(d)

    passive = not cfg["passive"]
    if passive:
        for d in scope["domains"] + scope["wildcards"]:
            results = await asyncio.gather(
                passive_crtsh(d), passive_hackertarget(d),
                passive_otx(d), passive_urlscan(d),
                return_exceptions=True)
            for r in results:
                if isinstance(r, set):
                    all_subs |= r

    if not cfg["passive"]:
        for d in scope["domains"] + scope["wildcards"]:
            wc = await detect_wildcard(d)
            if wc:
                print(f"[*] wildcard dns on {d}: filtering {len(wc)} ips")
            found = await active_bruteforce(d, wc)
            all_subs |= found

    # exclusions
    for ex in scope["exclude"]:
        all_subs = {s for s in all_subs if not s.endswith(ex)}

    print(f"[*] resolving {len(all_subs)} candidate hosts")

    hosts = []
    sem = asyncio.Semaphore(50)

    async def resolve_and_probe(host):
        async with sem:
            r = await resolve_host(host)
            if not (r["a"] or r["aaaa"] or r["cname"]):
                return None
            http_info = await http_probe(host, cfg)
            if http_info:
                r["http"] = http_info
                ip = r["a"][0] if r["a"] else None
                if ip and not cfg["passive"]:
                    r["ports"] = await port_scan(ip)
                else:
                    r["ports"] = []
                return r
            return None

    results = await asyncio.gather(*[resolve_and_probe(h) for h in all_subs])
    hosts = [r for r in results if r]

    whois_data = {}
    for d in scope["domains"]:
        whois_data[d] = await whois_lookup(d)

    out = {
        "scope": scope,
        "hosts": hosts,
        "whois": whois_data,
        "passive": cfg["passive"],
    }
    path = os.path.join(outdir, "recon.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    return out
