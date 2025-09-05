# python_ast_runner.py
# Python AST runner with support for Regex, AST, Context-Aware AST, Heuristic, and Taint Analysis

import ast
import sys
import json
import re

input_data = sys.stdin.read()
payload = json.loads(input_data)
code = payload.get("code", "")
rules = payload.get("rules", [])

try:
    tree = ast.parse(code)
except Exception as e:
    print(json.dumps({"error": f"Python parse error: {e}"}))
    sys.exit(0)

findings = {}
tainted_vars = set()

def mark(rule, node):
    findings.setdefault(rule["id"], []).append(getattr(node, "lineno", 0))

def get_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return get_name(node.value) + "." + node.attr
    return None

class Visitor(ast.NodeVisitor):
    def visit_Assign(self, node):
        rhs_code = ast.unparse(node.value) if hasattr(ast, "unparse") else ""
        lhs_names = [get_name(t) for t in node.targets if get_name(t)]

        for rule in rules:
            if rule["type"] == "taint-ast":
                # direct taint
                if any(src in rhs_code for src in rule.get("sources", [])):
                    for lhs in lhs_names:
                        tainted_vars.add(lhs)

                rhs_name = get_name(node.value)
                if rhs_name in tainted_vars:
                    for lhs in lhs_names:
                        tainted_vars.add(lhs)
        self.generic_visit(node)

    def visit_Call(self, node):
        func_name = get_name(node.func) or ""
        arg_strs = [ast.unparse(a) if hasattr(ast, "unparse") else "" for a in node.args]

        for rule in rules:
            # --- AST & Context-Aware ---
            if rule["type"] in ("ast", "context-ast"):
                if rule.get("calleeName") and func_name == rule["calleeName"]:
                    mark(rule, node)
                if rule.get("objectName") and func_name.startswith(rule["objectName"]):
                    mark(rule, node)
                if rule.get("argIsString") and node.args:
                    if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        mark(rule, node)

            # --- Taint AST ---
            if rule["type"] == "taint-ast":
                if func_name in rule.get("sinks", []):
                    for arg in node.args:
                        arg_name = get_name(arg)
                        arg_code = ast.unparse(arg) if hasattr(ast, "unparse") else ""
                        if arg_name in tainted_vars:
                            mark(rule, node)
                        if any(src in arg_code for src in rule.get("sources", [])):
                            mark(rule, node)

        self.generic_visit(node)

visitor = Visitor()
visitor.visit(tree)

# --- Regex + Heuristic ---
for rule in rules:
    if rule["type"] in ("regex", "heuristic"):
        for m in re.finditer(rule["pattern"], code, re.IGNORECASE):
            line = code[:m.start()].count("\n") + 1
            findings.setdefault(rule["id"], []).append(line)

print(json.dumps(findings))