#!/usr/bin/env python3
"""
Spider — orchestrator + CLI.
Drives recon -> crawl -> probe -> report. No scanning logic lives here.
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone

import recon
import crawl
import probe
import report


DEFAULTS = {
    "rate": 10,
    "concurrency": 4,
    "timeout": 15,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/122.0.0.0 Safari/537.36",
    "proxy": None,
    "cookie": None,
    "headers": {},
    "stages": ["recon", "crawl", "probe", "report"],
    "passive": False,
}


def parse_scope_file(path):
    scope = {"domains": [], "wildcards": [], "cidrs": [], "exclude": []}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("!"):
                scope["exclude"].append(line[1:].strip().lower())
            elif line.startswith("*."):
                scope["wildcards"].append(line[2:].strip().lower())
            elif "/" in line:
                scope["cidrs"].append(line)
            else:
                scope["domains"].append(line.lower())
    return scope


def normalize_scope(args):
    scope = {"domains": [], "wildcards": [], "cidrs": [], "exclude": []}
    if args.scope:
        scope = parse_scope_file(args.scope)
    if args.target:
        t = args.target.strip().lower()
        if "/" in t:
            scope["cidrs"].append(t)
        elif t.startswith("*."):
            scope["wildcards"].append(t[2:])
        else:
            scope["domains"].append(t)
    if not (scope["domains"] or scope["wildcards"] or scope["cidrs"]):
        sys.exit("[!] no scope provided. use -t or --scope")
    return scope


def make_outdir(target, override=None):
    if override:
        os.makedirs(override, exist_ok=True)
        return override
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe = target.replace("*", "wild").replace("/", "_").replace(":", "_")
    path = os.path.join("out", f"{safe}_{ts}")
    os.makedirs(path, exist_ok=True)
    return path


def load_prior(outdir):
    state = {}
    for stage in ("recon", "crawl", "findings"):
        p = os.path.join(outdir, f"{stage}.json")
        if os.path.exists(p):
            with open(p) as f:
                state[stage] = json.load(f)
    return state


def build_config(args):
    cfg = dict(DEFAULTS)
    cfg["rate"] = args.rate
    cfg["concurrency"] = args.concurrency
    cfg["proxy"] = args.proxy
    cfg["cookie"] = args.cookie
    cfg["passive"] = args.passive
    cfg["headers"] = dict(DEFAULTS["headers"])
    for h in args.header or []:
        if ":" in h:
            k, v = h.split(":", 1)
            cfg["headers"][k.strip()] = v.strip()
    if args.stages:
        cfg["stages"] = [s.strip() for s in args.stages.split(",") if s.strip()]
    return cfg


async def run(args):
    scope = normalize_scope(args)
    cfg = build_config(args)

    target_label = (args.target or (scope["domains"] or scope["wildcards"])[0] if
                    (scope["domains"] or scope["wildcards"]) else scope["cidrs"][0])
    outdir = make_outdir(target_label, args.out)
    print(f"[*] spider starting — target={target_label}")
    print(f"[*] outdir={outdir}")
    print(f"[*] scope: {len(scope['domains'])} domains, "
          f"{len(scope['wildcards'])} wildcards, "
          f"{len(scope['cidrs'])} cidrs, "
          f"{len(scope['exclude'])} exclusions")
    print(f"[*] stages: {cfg['stages']}")

    state = load_prior(outdir) if args.resume else {}
    if state:
        print(f"[*] resumed — loaded prior stages: {list(state.keys())}")

    if "recon" in cfg["stages"]:
        state["recon"] = await recon.run(scope, cfg, outdir)
        print(f"[+] recon: {len(state['recon'].get('hosts', []))} live hosts")

    if "crawl" in cfg["stages"]:
        if "recon" not in state:
            print("[!] crawl needs recon output. skipping.")
        else:
            state["crawl"] = await crawl.run(state["recon"], scope, cfg, outdir)
            print(f"[+] crawl: {len(state['crawl'].get('urls', []))} urls, "
                  f"{len(state['crawl'].get('params', {}))} params")

    if "probe" in cfg["stages"]:
        if "crawl" not in state:
            print("[!] probe needs crawl output. skipping.")
        else:
            state["findings"] = await probe.run(state["crawl"], state["recon"],
                                                scope, cfg, outdir)
            print(f"[+] probe: {len(state['findings'].get('findings', []))} findings")

    if "report" in cfg["stages"]:
        if "findings" not in state:
            print("[!] report needs probe output. skipping.")
        else:
            report.run(state["findings"], state["recon"], state["crawl"],
                       outdir, target_label)
            print(f"[+] report written to {outdir}/report.html")

    print("[*] done.")


def main():
    p = argparse.ArgumentParser(
        prog="spider",
        description="Automated web recon, crawling, and vulnerability probing.")
    p.add_argument("-t", "--target", help="single target: domain, *.wildcard, or CIDR")
    p.add_argument("--scope", help="path to scope file")
    p.add_argument("--passive", action="store_true",
                   help="passive recon only, no direct contact")
    p.add_argument("--stages", help="comma subset: recon,crawl,probe,report")
    p.add_argument("--rate", type=int, default=DEFAULTS["rate"])
    p.add_argument("--concurrency", type=int, default=DEFAULTS["concurrency"])
    p.add_argument("--proxy", help="http/socks proxy")
    p.add_argument("--cookie", help="cookie header")
    p.add_argument("--header", action="append", help="extra header K: V, repeatable")
    p.add_argument("--out", help="output dir override")
    p.add_argument("--resume", action="store_true",
                   help="resume from --out dir's prior stage files")
    args = p.parse_args()

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n[!] interrupted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
