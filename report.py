"""
report.py — dedupe, sort, write json + html.
"""

import json
import os
from datetime import datetime, timezone
from html import escape


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def dedupe(findings):
    seen = set()
    out = []
    for f in findings:
        key = (f.get("url"), f.get("param"), f.get("type"), f.get("template"))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def sort_findings(findings):
    return sorted(findings, key=lambda f: (
        SEV_ORDER.get(f.get("severity", "info"), 9),
        f.get("type", ""),
        f.get("url", ""),
    ))


def write_text_lists(crawl, outdir):
    urls = crawl.get("urls", []) + crawl.get("parameterized", [])
    with open(os.path.join(outdir, "urls.txt"), "w") as f:
        for u in sorted(set(urls)):
            f.write(u + "\n")
    with open(os.path.join(outdir, "params.txt"), "w") as f:
        for u in sorted(set(crawl.get("parameterized", []))):
            f.write(u + "\n")


def render_html(findings, recon, target, outdir):
    total = len(findings)
    by_sev = {}
    by_type = {}
    for f in findings:
        by_sev[f.get("severity", "info")] = by_sev.get(f.get("severity", "info"), 0) + 1
        by_type[f.get("type", "?")] = by_type.get(f.get("type", "?"), 0) + 1

    rows = []
    for f in findings:
        rows.append(f"""
        <tr class="sev-{escape(f.get('severity', 'info'))}" data-sev="{escape(f.get('severity', 'info'))}" data-type="{escape(f.get('type', ''))}">
          <td>{escape(f.get('severity', 'info'))}</td>
          <td>{escape(f.get('type', ''))}</td>
          <td><a href="{escape(f.get('url', ''))}" target="_blank">{escape(f.get('url', ''))}</a></td>
          <td>{escape(f.get('param') or '')}</td>
          <td>{escape(f.get('method') or '')}</td>
          <td><code>{escape((f.get('payload') or '')[:120])}</code></td>
          <td><code>{escape((f.get('evidence') or '')[:120])}</code></td>
          <td>{escape(f.get('template', ''))}</td>
        </tr>""")

    sev_opts = "".join(
        f'<option value="{k}">{k} ({v})</option>' for k, v in sorted(by_sev.items()))
    type_opts = "".join(
        f'<option value="{k}">{k} ({v})</option>' for k, v in sorted(by_type.items()))

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Spider — {escape(target)}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       background:#0e1116; color:#c9d1d9; margin:0; padding:20px; }}
h1 {{ color:#e6edf3; margin:0 0 4px 0; font-size:22px; }}
h2 {{ color:#8b949e; font-weight:normal; font-size:13px; margin:0 0 20px 0; }}
.controls {{ margin-bottom:16px; }}
.controls select {{ background:#161b22; color:#c9d1d9; border:1px solid #30363d;
                    border-radius:6px; padding:6px 10px; margin-right:8px; }}
.summary {{ display:flex; gap:8px; margin-bottom:20px; flex-wrap:wrap; }}
.chip {{ background:#161b22; border:1px solid #30363d; border-radius:20px;
         padding:4px 12px; font-size:12px; }}
table {{ width:100%; border-collapse:collapse; font-size:12px; }}
th {{ text-align:left; padding:8px; background:#161b22; color:#8b949e;
      border-bottom:1px solid #30363d; position:sticky; top:0; }}
td {{ padding:6px 8px; border-bottom:1px solid #21262d; vertical-align:top; }}
td a {{ color:#58a6ff; text-decoration:none; word-break:break-all; }}
code {{ background:#161b22; padding:1px 4px; border-radius:3px;
        font-size:11px; word-break:break-all; }}
tr.sev-critical td:first-child {{ color:#f85149; font-weight:bold; }}
tr.sev-high td:first-child {{ color:#ff7b72; font-weight:bold; }}
tr.sev-medium td:first-child {{ color:#d29922; }}
tr.sev-low td:first-child {{ color:#58a6ff; }}
tr.sev-info td:first-child {{ color:#8b949e; }}
</style></head><body>
<h1>Spider — {escape(target)}</h1>
<h2>{datetime.now(timezone.utc).isoformat()} — {total} findings</h2>
<div class="summary">
  {"".join(f'<div class="chip">{escape(k)}: {v}</div>' for k, v in sorted(by_sev.items(), key=lambda x: SEV_ORDER.get(x[0], 9)))}
</div>
<div class="controls">
  <select id="sevF"><option value="">all severities</option>{sev_opts}</select>
  <select id="typeF"><option value="">all types</option>{type_opts}</select>
</div>
<table><thead><tr>
<th>sev</th><th>type</th><th>url</th><th>param</th><th>method</th>
<th>payload</th><th>evidence</th><th>template</th>
</tr></thead><tbody id="rows">
{"".join(rows)}
</tbody></table>
<script>
const sevF = document.getElementById('sevF');
const typeF = document.getElementById('typeF');
function apply() {{
  const s = sevF.value, t = typeF.value;
  document.querySelectorAll('#rows tr').forEach(tr => {{
    const matchS = !s || tr.dataset.sev === s;
    const matchT = !t || tr.dataset.type === t;
    tr.style.display = (matchS && matchT) ? '' : 'none';
  }});
}}
sevF.onchange = apply; typeF.onchange = apply;
</script>
</body></html>"""

    with open(os.path.join(outdir, "report.html"), "w") as f:
        f.write(html)


def run(findings_out, recon, crawl, outdir, target):
    findings = dedupe(findings_out.get("findings", []))
    findings = sort_findings(findings)

    write_text_lists(crawl, outdir)

    canonical = {
        "target": target,
        "generated": datetime.now(timezone.utc).isoformat(),
        "count": len(findings),
        "findings": findings,
    }
    with open(os.path.join(outdir, "findings.json"), "w") as f:
        json.dump(canonical, f, indent=2)

    render_html(findings, recon, target, outdir)
    print(f"[+] {len(findings)} findings written")
