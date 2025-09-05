import os
import json
import re
from datetime import datetime
from html import escape

# ========================
# Severity Colors
# ========================
SEVERITY_COLOR = {
    "CRITICAL": "#e6ccff",  # light purple background
    "HIGH": "#f2dede",
    "MEDIUM": "#fcf8e3",
    "LOW": "#d9edf7"
}

# === Configure this to your React frontend public reports folder ===
FRONTEND_REPORTS_DIR = "secure-code-analyzer-frontend/public/reports"


def save_report_to_backend_and_frontend(content: str, backend_path: str, filename: str):
    os.makedirs(os.path.dirname(backend_path), exist_ok=True)
    with open(backend_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Report saved to backend: {backend_path}")

    frontend_path = os.path.join(FRONTEND_REPORTS_DIR, filename)
    os.makedirs(os.path.dirname(frontend_path), exist_ok=True)
    with open(frontend_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Report also saved to frontend: {frontend_path}")


def generate_json_report(issues, out_path):
    content = json.dumps(issues, indent=2)
    save_report_to_backend_and_frontend(content, out_path, "report.json")


def _sev_class(sev):
    s = (sev or "").upper()
    if s == "CRITICAL":
        return "row-critical"
    if s == "HIGH":
        return "row-high"
    if s == "MEDIUM":
        return "row-medium"
    if s == "LOW":
        return "row-low"
    return ""


def dedup_text(text):
    parts = [p.strip() for p in re.split(r"[.;\n]", text or "") if p.strip()]
    return "; ".join(dict.fromkeys(parts))


def generate_html_report(issues, out_path):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # --- Deduplicate issues ---
    unique_keys = set()
    deduped_issues = []
    for i in issues:
        key = (
            i.get("file", ""),
            i.get("line", 0),
            i.get("severity", "").upper(),
            dedup_text(i.get("message", "")),
            dedup_text(i.get("suggestion", "")),
        )
        if key not in unique_keys:
            unique_keys.add(key)
            deduped_issues.append(i)

    # --- OWASP normalization & dedup ---
    owasp_tags = set()
    for i in deduped_issues:
        tags = i.get("owasp", "").split(",")
        for t in tags:
            if t.strip():
                t = t.strip().replace(" ", "").replace("–", "-").replace("—", "-")
                m = re.match(r"A(\d+):?(\d{4})?-?(.*)", t, flags=re.I)
                if m:
                    num, year, rest = m.groups()
                    num = num.zfill(2)
                    year = year if year else "2021"
                    rest = (rest or "").lstrip("-")
                    norm = f"A{num}:{year}"
                    if rest:
                        norm += f"-{rest}"
                    owasp_tags.add(norm)
                else:
                    owasp_tags.add(t)

    def sort_owasp(tag):
        m = re.match(r"A(\d+):(\d{4})(?:-(.*))?", tag)
        if m:
            num, year, rest = m.groups()
            return (int(num), year, rest or "")
        return (999, "9999", tag)

    owasp_sorted = sorted(owasp_tags, key=sort_owasp)
    owasp_opts = "".join([f"<option value='{t}'>{t}</option>" for t in owasp_sorted])

    # --- CWE normalization & dedup ---
    cwe_tags = set()
    for i in deduped_issues:
        tags = i.get("cwe", "").split(",")
        for t in tags:
            if t.strip():
                t = t.strip().upper()
                m = re.match(r"CWE-?(\d+)", t)
                if m:
                    cwe_tags.add(f"CWE-{int(m.group(1))}")
                else:
                    cwe_tags.add(t)

    cwe_opts = "".join([f"<option value='{t}'>{t}</option>" for t in sorted(cwe_tags)])

    # --- Render issues into rows ---
    rows = []
    for i in deduped_issues:
        sev = escape(i.get("severity", ""))
        file = escape(i.get("file", ""))
        line = i.get("line", 0)
        category = escape(i.get("category", ""))
        message = escape(dedup_text(i.get("message", "")))
        suggestion = escape(dedup_text(i.get("suggestion", "")))
        snippet = escape(i.get("snippet", ""))
        detected_by = escape(i.get("detected_by", ""))
        rule_id = escape(i.get("id") or i.get("rule", "-"))
        owasp = escape(i.get("owasp", ""))
        cwe = escape(i.get("cwe", ""))

        extra_tags = []
        if owasp:
            for tag in sorted(set(owasp.split(","))):
                if tag.strip():
                    extra_tags.append(f"<span class='tag owasp'>{escape(tag)}</span>")
        if cwe:
            for tag in sorted(set(cwe.split(","))):
                if tag.strip():
                    extra_tags.append(f"<span class='tag cwe'>{escape(tag)}</span>")

        rule_cell = rule_id
        if extra_tags:
            rule_cell += "<br>" + " ".join(extra_tags)

        rows.append(f"""
          <tr class="{_sev_class(sev)}">
            <td>{file}</td>
            <td style="text-align:right">{line}</td>
            <td><span class="sev sev-{sev.lower()}">{sev}</span></td>
            <td>{category}</td>
            <td class="rule-cell">{rule_cell}</td>
            <td>{message}</td>
            <td><code>{snippet}</code></td>
            <td>{suggestion}</td>
            <td>{detected_by}</td>
          </tr>
        """)

    json_content = json.dumps(deduped_issues, indent=2)
    json_content_js = json_content.replace("\\", "\\\\").replace("`", "\\`")

    # --- Final HTML ---
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Secure Code Analyzer Report</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 16px; }}
.downloads button {{ background:#1976d2; color:white; border:none; padding:8px 12px; margin-right:8px; border-radius:4px; cursor:pointer; }}
.downloads button:hover {{ background:#1259a7; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
th, td {{ border: 1px solid #ddd; padding: 8px; font-size: 14px; }}
th {{ background: #f7f7f7; position: sticky; top: 0; }}
tr.row-critical {{ background: #e6ccff; }}
tr.row-high {{ background: #fdecea; }}
tr.row-medium {{ background: #fff8e1; }}
tr.row-low {{ background: #e8f4fd; }}
.sev-critical {{ background: #d1b3ff; color: #3d0066; }}
.sev-high {{ background: #f8d7da; color: #721c24; }}
.sev-medium {{ background: #fff3cd; color: #856404; }}
.sev-low {{ background: #d1ecf1; color: #0c5460; }}
.tag {{ display:inline-block; padding:2px 6px; border-radius: 3px; font-size: 12px; margin-top:2px; }}
.owasp {{ background:#ffe6e6; color:#900; }}
.cwe {{ background:#e6f0ff; color:#004080; }}
.controls {{ display:flex; gap:12px; align-items:center; margin:10px 0; flex-wrap: wrap; }}
</style>
<script>
function filterTable() {{
  const severity = document.getElementById('sevFilter').value;
  const owasp = document.getElementById('owaspFilter').value;
  const cwe = document.getElementById('cweFilter').value;
  const q = document.getElementById('searchBox').value.toLowerCase();

  const tbody = document.getElementById('tbody');
  Array.from(tbody.rows).forEach(r => {{
    const sev = r.querySelector('.sev').textContent.trim().toUpperCase();
    const text = r.textContent.toLowerCase();
    const ruleText = r.querySelector('.rule-cell').textContent;

    const okSev = (severity === 'ALL' || sev === severity);
    const okOwasp = (owasp === 'ALL' || ruleText.includes(owasp));
    const okCwe = (cwe === 'ALL' || ruleText.includes(cwe));
    const okSearch = text.includes(q);

    r.style.display = (okSev && okOwasp && okCwe && okSearch) ? '' : 'none';
  }});
}}

function downloadContent(filename, content, type) {{
  const blob = new Blob([content], {{type}});
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}}
function downloadJSON() {{
  const content = `{json_content_js}`;
  downloadContent("report.json", content, "application/json");
}}
function downloadHTML() {{
  const content = document.documentElement.outerHTML;
  downloadContent("report.html", content, "text/html");
}}
</script>
</head>
<body>
<h1>Secure Code Analyzer Report</h1>
<small>Generated at: {now}</small>

<div class="downloads">
  <button onclick="downloadJSON()">⬇ Download JSON</button>
  <button onclick="downloadHTML()">⬇ Download HTML</button>
</div>

<div class="controls">
  <label>Severity:
    <select id="sevFilter" onchange="filterTable()">
      <option value="ALL" selected>All</option>
      <option value="CRITICAL">Critical</option>
      <option value="HIGH">High</option>
      <option value="MEDIUM">Medium</option>
      <option value="LOW">Low</option>
    </select>
  </label>
  <label>OWASP:
    <select id="owaspFilter" onchange="filterTable()">
      <option value="ALL" selected>All</option>
      {owasp_opts}
    </select>
  </label>
  <label>CWE:
    <select id="cweFilter" onchange="filterTable()">
      <option value="ALL" selected>All</option>
      {cwe_opts}
    </select>
  </label>
  <label>Search:
    <input id="searchBox" type="text" placeholder="Search issues..." oninput="filterTable()"/>
  </label>
</div>

<table>
  <thead>
    <tr>
      <th>File</th><th>Line</th><th>Severity</th>
      <th>Category</th><th>Rule / Mapping</th>
      <th>Message</th><th>Snippet</th>
      <th>Suggestion</th><th>Detected By</th>
    </tr>
  </thead>
  <tbody id="tbody">
    {''.join(rows)}
  </tbody>
</table>
</body>
</html>
"""

    save_report_to_backend_and_frontend(html, out_path, "report.html")
