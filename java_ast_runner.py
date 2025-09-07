# java_ast_runner.py
# Java AST runner with Regex, Heuristic, Context-Aware AST (via javalang), and full Inter-Procedural Taint Analysis

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
method_returns = {}      # Tracks if a method is tainted
method_defs = {}         # Stores method definitions for inter-procedural analysis

def mark(rule, node, line=0):
    findings.setdefault(rule["id"], []).append(line)

def is_tainted_var(var_name):
    return var_name in tainted_vars

def propagate_taint_from_expression(expr):
    """Check if an expression contains tainted variables or tainted method calls"""
    if isinstance(expr, javalang.tree.Literal):
        return False
    if isinstance(expr, javalang.tree.MemberReference):
        return expr.member in tainted_vars
    if isinstance(expr, javalang.tree.MethodInvocation):
        # Check if any argument is tainted
        if any(propagate_taint_from_expression(arg) for arg in expr.arguments):
            return True
        # Inter-procedural: check if the called method is known to return tainted value
        key = f"{expr.qualifier}.{expr.member}" if expr.qualifier else expr.member
        return method_returns.get(key, False)
    if isinstance(expr, javalang.tree.BinaryOperation):
        return propagate_taint_from_expression(expr.operandl) or propagate_taint_from_expression(expr.operandr)
    return False

def analyze_method(node):
    """Analyze a method declaration for taint propagation"""
    method_name = node.name
    key = method_name
    if node.parameters:
        param_names = [p.name for p in node.parameters]
    else:
        param_names = []

    local_tainted = set()
    # Mark parameters as tainted if they match any taint source
    for rule in rules:
        if rule["type"] == "taint-ast" and rule.get("sources"):
            for param in param_names:
                if param in rule["sources"]:
                    local_tainted.add(param)

    # Walk through method body
    if node.body:
        for path, child in node:
            if isinstance(child, javalang.tree.VariableDeclarator):
                if child.initializer and propagate_taint_from_expression(child.initializer):
                    local_tainted.add(child.name)
                elif child.initializer:
                    rhs_str = str(child.initializer)
                    if any(src in rhs_str for rule in rules if rule["type"] == "taint-ast" for src in rule.get("sources", [])):
                        local_tainted.add(child.name)
            if isinstance(child, javalang.tree.MethodInvocation):
                # Check for sinks
                for rule in rules:
                    if rule["type"] == "taint-ast" and child.member in rule.get("sinks", []):
                        for arg in child.arguments:
                            if propagate_taint_from_expression(arg):
                                mark(rule, child, child.position.line if child.position else 0)
                # Track return taint
                key_call = f"{child.qualifier}.{child.member}" if child.qualifier else child.member
                if any(propagate_taint_from_expression(arg) for arg in child.arguments):
                    method_returns[key_call] = True

    # Method returns tainted if any local variable or call is tainted
    method_returns[key] = bool(local_tainted)
    return local_tainted

# --- Regex / Heuristic ---
for rule in rules:
    if rule["type"] in ("regex", "heuristic"):
        for m in re.finditer(rule["pattern"], code, re.IGNORECASE):
            line = code[:m.start()].count("\n") + 1
            findings.setdefault(rule["id"], []).append(line)

# --- AST + Context-aware + Inter-Procedural Taint ---
if javalang:
    try:
        tree = javalang.parse.parse(code)

        # Collect method declarations
        for path, node in tree.filter(javalang.tree.MethodDeclaration):
            method_defs[node.name] = node

        # Analyze methods recursively
        analyzed = set()
        def analyze_all_methods():
            progress = True
            while progress:
                progress = False
                for name, method in method_defs.items():
                    if name not in analyzed:
                        tainted_before = method_returns.get(name, False)
                        analyze_method(method)
                        if method_returns.get(name, False) != tainted_before:
                            progress = True
                        analyzed.add(name)
        analyze_all_methods()

        # Analyze top-level statements (like assignments and calls outside methods)
        for path, node in tree:
            for rule in rules:
                if rule["type"] in ("ast", "context-ast"):
                    if isinstance(node, javalang.tree.MethodInvocation):
                        if rule.get("calleeName") and node.member == rule["calleeName"]:
                            mark(rule, node, node.position.line if node.position else 0)
                        if rule.get("objectName") and node.qualifier == rule["objectName"]:
                            mark(rule, node, node.position.line if node.position else 0)

                if rule["type"] == "taint-ast":
                    if isinstance(node, javalang.tree.VariableDeclarator):
                        if node.initializer and propagate_taint_from_expression(node.initializer):
                            tainted_vars.add(node.name)
                    if isinstance(node, javalang.tree.MethodInvocation):
                        if node.member in rule.get("sinks", []):
                            for arg in node.arguments:
                                if propagate_taint_from_expression(arg):
                                    mark(rule, node, node.position.line if node.position else 0)

    except Exception as e:
        findings["error"] = f"Java parse error: {e}"

print(json.dumps(findings))