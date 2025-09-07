// js_ast_runner.js
// JavaScript AST runner with Regex, Context-Aware AST, and Inter-Procedural Taint Analysis

const esprima = require("esprima");

let input = "";
process.stdin.on("data", chunk => input += chunk);
process.stdin.on("end", () => {
  try {
    const payload = JSON.parse(input);
    const code = payload.code;
    const rules = payload.rules || [];
    const ast = esprima.parseScript(code, { loc: true, range: true });

    let findings = {};
    let taintedVars = new Set();
    let functionReturnsTainted = {}; // Track function return taint
    let functionDefs = {}; // Store function AST nodes for inter-procedural analysis

    function markFinding(rule, node) {
      findings[rule.id] = findings[rule.id] || [];
      findings[rule.id].push(node.loc.start.line);
    }

    function getIdentifierName(node) {
      if (!node) return null;
      if (node.type === "Identifier") return node.name;
      if (node.type === "MemberExpression") {
        return (
          (node.object && getIdentifierName(node.object)) +
          "." +
          (node.property && getIdentifierName(node.property))
        );
      }
      return null;
    }

    function isTainted(node) {
      if (!node) return false;
      if (node.type === "Identifier") return taintedVars.has(node.name);
      if (node.type === "MemberExpression") {
        return taintedVars.has(getIdentifierName(node));
      }
      if (node.type === "CallExpression") {
        const fnName = getIdentifierName(node.callee);
        return functionReturnsTainted[fnName] || node.arguments.some(arg => isTainted(arg));
      }
      if (node.type === "BinaryExpression") {
        return isTainted(node.left) || isTainted(node.right);
      }
      return false;
    }

    // Collect function definitions
    function collectFunctions(node) {
      if (!node || typeof node !== "object") return;
      if (node.type === "FunctionDeclaration" && node.id && node.id.name) {
        functionDefs[node.id.name] = node;
      }
      for (let key in node) {
        const val = node[key];
        if (Array.isArray(val)) val.forEach(collectFunctions);
        else if (val && typeof val === "object") collectFunctions(val);
      }
    }

    collectFunctions(ast);

    // Analyze function return values for taint
    function analyzeFunction(funcNode) {
      let localTainted = new Set();
      if (!funcNode.body || !funcNode.body.body) return false;

      funcNode.body.body.forEach(stmt => {
        if (stmt.type === "VariableDeclaration") {
          stmt.declarations.forEach(decl => {
            if (decl.init && isTainted(decl.init)) localTainted.add(decl.id.name);
          });
        }
        if (stmt.type === "ReturnStatement" && stmt.argument) {
          if (isTainted(stmt.argument)) localTainted.add("__return__");
        }
        if (stmt.type === "ExpressionStatement" && stmt.expression.type === "AssignmentExpression") {
          const left = stmt.expression.left;
          const right = stmt.expression.right;
          if (isTainted(right)) localTainted.add(getIdentifierName(left));
        }
      });

      const fnName = funcNode.id.name;
      functionReturnsTainted[fnName] = localTainted.has("__return__");
    }

    let analyzed = new Set();
    function analyzeAllFunctions() {
      let progress = true;
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

    function walk(node, parent) {
      if (!node || typeof node !== "object") return;

      // --- Taint Analysis ---
      rules.filter(r => r.type === "taint-ast").forEach(rule => {
        // Variable declaration
        if (node.type === "VariableDeclarator" && node.init) {
          const varName = getIdentifierName(node.id);
          const initCode = code.substring(node.init.range[0], node.init.range[1]);
          if (rule.sources.some(src => initCode.includes(src))) taintedVars.add(varName);
        }
        // Assignment
        if (node.type === "AssignmentExpression") {
          const leftName = getIdentifierName(node.left);
          if (isTainted(node.right)) taintedVars.add(leftName);
          const rightCode = code.substring(node.right.range[0], node.right.range[1]);
          if (rule.sources.some(src => rightCode.includes(src))) taintedVars.add(leftName);
        }
        // Function call sinks
        if (node.type === "CallExpression") {
          const calleeName = getIdentifierName(node.callee);
          if (rule.sinks.includes(calleeName)) {
            node.arguments.forEach(arg => {
              if (isTainted(arg)) markFinding(rule, node);
              const argCode = code.substring(arg.range[0], arg.range[1]);
              if (rule.sources.some(src => argCode.includes(src))) markFinding(rule, node);
            });
          }
        }
      });

      // --- AST / Context ---
      rules.filter(r => ["ast", "context-ast"].includes(r.type)).forEach(rule => {
        if (node.type === rule.nodeType) {
          let matched = false;
          if (node.type === "CallExpression" || node.type === "NewExpression") {
            const calleeName = node.callee.name || (node.callee.property && node.callee.property.name);
            const objName = node.callee.object && node.callee.object.name;
            if (rule.calleeName && calleeName === rule.calleeName) matched = true;
            if (rule.objectName && objName === rule.objectName) matched = true;
            if (rule.argIsString && node.arguments.length > 0 && node.arguments[0].type === "Literal" &&
                typeof node.arguments[0].value === "string") matched = true;
          }
          if (matched) markFinding(rule, node);
        }
      });

      for (let key in node) {
        const val = node[key];
        if (Array.isArray(val)) val.forEach(child => walk(child, node));
        else if (val && typeof val === "object") walk(val, node);
      }
    }

    walk(ast, null);

    process.stdout.write(JSON.stringify(findings));
  } catch (err) {
    process.stdout.write(JSON.stringify({ error: err.message }));
  }
});