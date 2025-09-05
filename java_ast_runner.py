# java_ast_runner.py
# Java AST runner with Regex, Heuristic, Context-Aware AST (via javalang), and Taint Analysis

import sys
import json
import re

try:
    import javalang
except ImportError:
    javalang = None

input_data = sys.stdin.read()
payload = json.loads(input_data)
code = payload.get("code", "")
rules = payload.get("rules", [])

findings = {}
tainted_vars = set()

def mark(rule, node, line=0):
    findings.setdefault(rule["id"], []).append(line)

# --- Regex / Heuristic ---
for rule in rules:
    if rule["type"] in ("regex", "heuristic"):
        for m in re.finditer(rule["pattern"], code, re.IGNORECASE):
            line = code[:m.start()].count("\n") + 1
            findings.setdefault(rule["id"], []).append(line)

# --- AST + Context-aware + Taint (if javalang available) ---
if javalang:
    try:
        tree = javalang.parse.parse(code)

        for path, node in tree:
            for rule in rules:
                # AST / Context aware
                if rule["type"] in ("ast", "context-ast"):
                    if isinstance(node, javalang.tree.MethodInvocation):
                        if rule.get("calleeName") and node.member == rule["calleeName"]:
                            mark(rule, node, node.position.line if node.position else 0)
                        if rule.get("objectName") and node.qualifier == rule["objectName"]:
                            mark(rule, node, node.position.line if node.position else 0)

                # Taint analysis
                if rule["type"] == "taint-ast":
                    if isinstance(node, javalang.tree.VariableDeclarator):
                        rhs = str(node.initializer) if node.initializer else ""
                        if any(src in rhs for src in rule.get("sources", [])):
                            tainted_vars.add(node.name)
                    if isinstance(node, javalang.tree.MethodInvocation):
                        if node.member in rule.get("sinks", []):
                            for arg in node.arguments:
                                arg_str = str(arg)
                                if any(src in arg_str for src in rule.get("sources", [])):
                                    mark(rule, node, node.position.line if node.position else 0)
                                if arg_str in tainted_vars:
                                    mark(rule, node, node.position.line if node.position else 0)
    except Exception as e:
        findings["error"] = f"Java parse error: {e}"

print(json.dumps(findings))