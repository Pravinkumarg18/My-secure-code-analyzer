// php_ast_runner.js
// PHP AST runner with Regex, Context-Aware AST, and Inter-Procedural Taint Analysis

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
    let functionDefs = {}; // name -> function node
    let functionReturnsTainted = {}; // track if function return is tainted

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

    // Collect function definitions
    function collectFunctions(node) {
      if (!node || typeof node !== "object") return;
      if (node.kind === "function" && node.name && node.name.name) {
        functionDefs[node.name.name] = node;
      }
      for (let key in node) {
        const val = node[key];
        if (Array.isArray(val)) val.forEach(collectFunctions);
        else if (val && typeof val === "object") collectFunctions(val);
      }
    }

    collectFunctions(ast);

    function isTainted(node) {
      if (!node) return false;
      if (node.kind === "variable") return taintedVars.has(node.name);
      if (node.kind === "call") {
        const fnName = node.what?.name || "";
        return functionReturnsTainted[fnName] || (node.arguments || []).some(arg => isTainted(arg));
      }
      if (node.kind === "offsetlookup") return isTainted(node.what);
      if (node.kind === "bin") return isTainted(node.left) || isTainted(node.right);
      return false;
    }

    // Analyze function return taint
    function analyzeFunction(fnNode) {
      let localTainted = new Set();
      if (!fnNode.body || !fnNode.body.children) return false;

      fnNode.body.children.forEach(stmt => {
        if (stmt.kind === "assign") {
          const lhs = getVarName(stmt.left);
          if (isTainted(stmt.right)) localTainted.add(lhs);
        }
        if (stmt.kind === "return" && stmt.expr) {
          if (isTainted(stmt.expr)) localTainted.add("__return__");
        }
      });

      const fnName = fnNode.name.name;
      functionReturnsTainted[fnName] = localTainted.has("__return__");
    }

    // Iteratively analyze all functions for inter-procedural taint
    function analyzeAllFunctions() {
      let progress = true;
      let analyzed = new Set();
      while (progress) {
        progress = false;
        for (let fnName in functionDefs) {
          if (!analyzed.has(fnName)) {
            const before = functionReturnsTainted[fnName] || false;
            analyzeFunction(functionDefs[fnName]);
            if (functionReturnsTainted[fnName] !== before) progress = true;
            analyzed.add(fnName);
          }
        }
      }
    }

    analyzeAllFunctions();

    function walk(node) {
      if (!node || typeof node !== "object") return;

      for (const rule of rules) {
        // --- Taint Analysis ---
        if (rule.type === "taint-ast") {
          if (node.kind === "assign") {
            const lhs = getVarName(node.left);
            if (isTainted(node.right)) taintedVars.add(lhs);
            const rhsDump = JSON.stringify(node.right);
            if (rule.sources.some(src => rhsDump.includes(src))) taintedVars.add(lhs);
          }

          if (node.kind === "call" && node.what && node.what.name) {
            const fnName = node.what.name;
            if (rule.sinks.includes(fnName)) {
              (node.arguments || []).forEach(arg => {
                if (isTainted(arg)) markFinding(rule, node);
                const argDump = JSON.stringify(arg);
                if (rule.sources.some(src => argDump.includes(src))) markFinding(rule, node);
              });
            }
          }

          if (["include", "includeonce", "require", "requireonce"].includes(node.kind)) {
            const argDump = JSON.stringify(node.target);
            if (rule.sources.some(src => argDump.includes(src))) markFinding(rule, node);
          }
        }

        // --- AST / Context ---
        if (rule.type === "ast" || rule.type === "context-ast") {
          if (node.kind === rule.nodeType) {
            let matched = false;
            if (node.kind === "call" && node.what && node.what.name) {
              const fn = node.what.name;
              if (rule.calleeName && fn === rule.calleeName) matched = true;
            }
            if (["include", "includeonce", "require", "requireonce"].includes(node.kind) && rule.nodeType === "include") matched = true;
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