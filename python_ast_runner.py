# python_ast_runner.py
# Python AST runner with support for Regex, AST, Context-Aware AST, Heuristic, and Taint Analysis
# Fully updated for improved taint propagation, f-string, and subscript handling

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
        val = get_name(node.value)
        return val + "." + node.attr if val else node.attr
    if isinstance(node, ast.Subscript):
        return get_name(node.value)
    return None


def is_tainted_node(node):
    """Recursively check if a node contains a tainted variable"""
    if isinstance(node, ast.Name):
        return node.id in tainted_vars
    elif isinstance(node, ast.Attribute):
        return get_name(node) in tainted_vars
    elif isinstance(node, ast.Subscript):
        return is_tainted_node(node.value)
    elif isinstance(node, ast.JoinedStr):
        # f-string
        for v in node.values:
            if isinstance(v, ast.FormattedValue) and is_tainted_node(v.value):
                return True
            elif isinstance(v, ast.Str):
                continue
        return False
    elif isinstance(node, ast.BinOp):
        return is_tainted_node(node.left) or is_tainted_node(node.right)
    elif isinstance(node, ast.Call):
        # simple function propagation (if any argument is tainted, consider tainted)
        return any(is_tainted_node(a) for a in node.args)
    return False


class Visitor(ast.NodeVisitor):
    def visit_Assign(self, node):
        lhs_names = [get_name(t) for t in node.targets if get_name(t)]
        # Propagate taint if RHS is tainted
        if is_tainted_node(node.value):
            for lhs in lhs_names:
                tainted_vars.add(lhs)
        # Direct source match
        rhs_code = ast.unparse(node.value) if hasattr(ast, "unparse") else ""
        for rule in rules:
            if rule["type"] == "taint-ast":
                if any(src in rhs_code for src in rule.get("sources", [])):
                    for lhs in lhs_names:
                        tainted_vars.add(lhs)
        self.generic_visit(node)

    def visit_Call(self, node):
        func_name = get_name(node.func) or ""
        # Arguments code
        arg_codes = [ast.unparse(a) if hasattr(ast, "unparse") else "" for a in node.args]

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
                        if is_tainted_node(arg):
                            mark(rule, node)
                        # direct source match
                        arg_code = ast.unparse(arg) if hasattr(ast, "unparse") else ""
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