// php_ast_runner.js
// PHP AST runner with support for AST, Context-Aware AST, and Taint Analysis.

const parser = require("php-parser");

const engine = new parser.Engine({
  parser: { extractDoc: true, php7: true },
  ast: { withPositions: true, withLocations: true }
});

let input = "";
process.stdin.on("data", chunk => (input += chunk));
process.stdin.on("end", () => {
  try {
    const payload = JSON.parse(input.trim());
    const code = payload.code || "";
    const rules = payload.rules || [];

    let ast;
    try {
      ast = engine.parseCode(code);
    } catch (parseErr) {
      process.stdout.write(JSON.stringify({ error: "PHP parse error: " + parseErr.message }));
      return;
    }

    let findings = {};
    let taintedVars = new Set();

    function markFinding(rule, node) {
      findings[rule.id] = findings[rule.id] || [];
      findings[rule.id].push(node.loc?.start?.line || 0);
    }

    function getVarName(node) {
      if (!node) return null;
      if (node.kind === "variable") return node.name;
      if (node.kind === "offsetlookup" && node.what) return getVarName(node.what);
      return null;
    }

    function walk(node) {
      if (!node || typeof node !== "object") return;

      for (const rule of rules) {
        // --- Taint AST ---
        if (rule.type === "taint-ast") {
          if (node.kind === "assign") {
            const lhs = getVarName(node.left);
            const rhsDump = JSON.stringify(node.right);

            if (rule.sources.some(src => rhsDump.includes(src))) {
              taintedVars.add(lhs);
            }

            const rhsVar = getVarName(node.right);
            if (rhsVar && taintedVars.has(rhsVar)) {
              taintedVars.add(lhs);
            }
          }

          if (node.kind === "call" && node.what && node.what.name) {
            const fn = (node.what.name || "").toLowerCase();
            if (rule.sinks.map(s => s.toLowerCase()).includes(fn)) {
              if (node.arguments && node.arguments.length > 0) {
                node.arguments.forEach(arg => {
                  const argVar = getVarName(arg);
                  if (argVar && taintedVars.has(argVar)) {
                    markFinding(rule, node);
                  }
                  const argDump = JSON.stringify(arg);
                  if (rule.sources.some(src => argDump.includes(src))) {
                    markFinding(rule, node);
                  }
                });
              }
            }
          }

          if (["include", "includeonce", "require", "requireonce"].includes(node.kind)) {
            const argDump = JSON.stringify(node.target);
            if (rule.sources.some(src => argDump.includes(src))) {
              markFinding(rule, node);
            }
          }
        }

        // --- AST / Context ---
        if (rule.type === "ast" || rule.type === "context-ast") {
          if (node.kind === rule.nodeType) {
            let matched = false;

            if (node.kind === "call" && node.what && node.what.name) {
              const fn = (node.what.name || "").toLowerCase();
              if (rule.calleeName && fn === rule.calleeName.toLowerCase()) {
                matched = true;
              }
            }

            if (
              ["include", "includeonce", "require", "requireonce"].includes(node.kind) &&
              rule.nodeType === "include"
            ) {
              matched = true;
            }

            if (matched) markFinding(rule, node);
          }
        }
      }

      for (let key in node) {
        const val = node[key];
        if (Array.isArray(val)) val.forEach(walk);
        else if (val && typeof val === "object") walk(val);
      }
    }

    walk(ast);
    process.stdout.write(JSON.stringify(findings));
  } catch (err) {
    process.stdout.write(JSON.stringify({ error: err.message }));
  }
});
