import re
import json
import os
import subprocess
import sys

# ========================
# Load rules from rules.json
# ========================
RULES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "rules",
    "rules.json"
)

with open(RULES_PATH, "r", encoding="utf-8") as f:
    RULES = json.load(f)

# ========================
# AST Runner Paths
# ========================
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)

JS_AST_RUNNER     = os.path.join(PROJECT_ROOT, "js_ast_runner.js")
PHP_AST_RUNNER    = os.path.join(PROJECT_ROOT, "php_ast_runner.js")
PY_AST_RUNNER     = os.path.join(PROJECT_ROOT, "python_ast_runner.py")
JAVA_AST_RUNNER   = os.path.join(PROJECT_ROOT, "java_ast_runner.py")

print("JS_AST_RUNNER:", JS_AST_RUNNER)
print("PHP_AST_RUNNER:", PHP_AST_RUNNER)
print("PY_AST_RUNNER:", PY_AST_RUNNER)
print("JAVA_AST_RUNNER:", JAVA_AST_RUNNER)

# ========================
# AST Runner Helper
# ========================
def run_ast_runner(runner, code, ast_rules, lang):
    """
    Run AST helper. 
    Node.js for JS/PHP, Python for Python/Java.
    """
    try:
        if lang in ["javascript", "php"]:
            cmd = ["node", runner]
        else:  # python, java
            cmd = [sys.executable, runner]

        proc = subprocess.run(
            cmd,
            input=json.dumps({"code": code, "rules": ast_rules}).encode("utf-8"),
            capture_output=True,
            check=True
        )
        return json.loads(proc.stdout.decode("utf-8"))
    except subprocess.CalledProcessError as e:
        return {"error": e.stderr.decode("utf-8")}
    except Exception as e:
        return {"error": str(e)}

# ========================
# Normalization Helpers
# ========================
def normalize_owasp(tag_str):
    tags = [t.strip() for t in tag_str.split(",") if t.strip()]
    norm_tags = set()
    for t in tags:
        t = t.replace(" ", "").replace("–", "-").replace("—", "-")
        if ":" in t:
            m = re.match(r"A(\d+):?(\d{4})?-?(.*)", t, flags=re.I)
            if m:
                num, year, rest = m.groups()
                num = num.zfill(2)
                year = year if year else "2021"
                rest = rest if rest else ""
                rest = rest.lstrip("-")
                norm = f"A{num}:{year}"
                if rest:
                    norm += f"-{rest}"
                norm_tags.add(norm)
            else:
                norm_tags.add(t)
        else:
            norm_tags.add(t)
    return norm_tags

def normalize_cwe(tag_str):
    tags = [t.strip().upper() for t in tag_str.split(",") if t.strip()]
    norm_tags = set()
    for t in tags:
        if t.startswith("CWE"):
            m = re.match(r"CWE-?(\d+)", t)
            if m:
                norm_tags.add(f"CWE-{int(m.group(1))}")
            else:
                norm_tags.add(t)
        else:
            norm_tags.add(t)
    return norm_tags

def normalize_category(cat):
    return cat.strip().title() if cat else cat

# ========================
# Rule-based detector
# ========================
def run_detectors(code, file_path):
    issues = []

    lang = (
        "javascript" if file_path.endswith(".js") else
        "php" if file_path.endswith(".php") else
        "python" if file_path.endswith(".py") else
        "java" if file_path.endswith(".java") else
        None
    )
    if not lang:
        return issues

    regex_rules       = [r for r in RULES if r["language"] == lang and r["type"] == "regex"]
    heuristic_rules   = [r for r in RULES if r["language"] == lang and r["type"] == "heuristic"]
    ast_rules         = [r for r in RULES if r["language"] == lang and r["type"] == "ast"]
    context_ast_rules = [r for r in RULES if r["language"] == lang and r["type"] == "context-ast"]
    taint_ast_rules   = [r for r in RULES if r["language"] == lang and r["type"] == "taint-ast"]

    runner_map = {
        "javascript": JS_AST_RUNNER,
        "php": PHP_AST_RUNNER,
        "python": PY_AST_RUNNER,
        "java": JAVA_AST_RUNNER
    }

    def make_issue(rule, line_no, snippet, detected_by):
        return {
            "id": rule["id"],
            "file": file_path,
            "line": line_no,
            "severity": rule["severity"].upper(),
            "category": normalize_category(rule["category"]),
            "message": rule["message"],
            "suggestion": rule["suggestion"],
            "owasp": ",".join(sorted(normalize_owasp(rule.get("owasp", "")))),
            "cwe": ",".join(sorted(normalize_cwe(rule.get("cwe", "")))),
            "snippet": snippet,
            "detected_by": detected_by
        }

    # --- Regex ---
    for rule in regex_rules:
        for match in re.finditer(rule["pattern"], code, flags=re.IGNORECASE):
            line_no = code[:match.start()].count("\n") + 1
            issues.append(make_issue(rule, line_no, code.splitlines()[line_no - 1].strip(), "Regex"))

    # --- Heuristic ---
    for rule in heuristic_rules:
        for match in re.finditer(rule["pattern"], code, flags=re.IGNORECASE):
            line_no = code[:match.start()].count("\n") + 1
            issues.append(make_issue(rule, line_no, code.splitlines()[line_no - 1].strip(), "Heuristic"))

    # --- AST ---
    if ast_rules:
        result = run_ast_runner(runner_map[lang], code, ast_rules, lang)
        if "error" not in result:
            for rule in ast_rules:
                for line_no in result.get(rule["id"], []):
                    issues.append(make_issue(rule, line_no, code.splitlines()[line_no - 1].strip(), "AST"))

    # --- Context-AST ---
    if context_ast_rules:
        result = run_ast_runner(runner_map[lang], code, context_ast_rules, lang)
        if "error" not in result:
            for rule in context_ast_rules:
                for line_no in result.get(rule["id"], []):
                    issues.append(make_issue(rule, line_no, code.splitlines()[line_no - 1].strip(), "Context-AST"))

    # --- Taint-AST ---
    if taint_ast_rules:
        result = run_ast_runner(runner_map[lang], code, taint_ast_rules, lang)
        if "error" not in result:
            for rule in taint_ast_rules:
                for line_no in result.get(rule["id"], []):
                    issues.append(make_issue(rule, line_no, code.splitlines()[line_no - 1].strip(), "AST(Taint)"))

    # --- Deduplication & Priority ---
    deduped = {}
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    for issue in issues:
        key = (issue["file"], issue["line"], issue["snippet"])
        existing = deduped.get(key)

        if not existing:
            deduped[key] = issue
        else:
            if sev_order[issue["severity"]] > sev_order[existing["severity"]]:
                merged = issue
            else:
                merged = existing

            merged["owasp"] = ",".join(sorted(normalize_owasp(existing.get("owasp", "")) |
                                              normalize_owasp(issue.get("owasp", ""))))
            merged["cwe"]   = ",".join(sorted(normalize_cwe(existing.get("cwe", "")) |
                                              normalize_cwe(issue.get("cwe", ""))))

            detected_set = set(existing["detected_by"].split("+")) | set(issue["detected_by"].split("+"))
            if "Context-AST" in detected_set:
                merged["detected_by"] = "Context-AST"
            elif "AST" in detected_set:
                merged["detected_by"] = "AST"
            elif "Heuristic" in detected_set:
                merged["detected_by"] = "Heuristic"
            else:
                merged["detected_by"] = "Regex"

            if "AST(Taint)" in detected_set and "AST(Taint)" not in merged["detected_by"]:
                merged["detected_by"] += "+AST(Taint)"

            deduped[key] = merged

    return list(deduped.values())

# ========================
# Main
# ========================
def detect_issues(file_path):
    try:
        # Read file in binary mode and decode as utf-8 ignoring errors to avoid decode errors on binary files
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
        code = raw_bytes.decode("utf-8", errors="ignore")
    except Exception as e:
        return [{
            "id": "FILE-ERROR",
            "file": file_path,
            "line": 0,
            "severity": "LOW",
            "category": "I/O",
            "message": f"Error reading file: {e}",
            "suggestion": "Check file path and permissions.",
            "detected_by": "System",
            "owasp": "",
            "cwe": "",
            "snippet": ""
        }]
    return run_detectors(code, file_path)