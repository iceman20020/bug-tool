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
