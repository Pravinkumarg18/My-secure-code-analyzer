// js_ast_runner.js
// JavaScript AST runner with support for AST, Context-Aware AST, and Taint Analysis.

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
    let taintedVars = new Set(); // Track tainted identifiers

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

    function walk(node, parent) {
      if (!node || typeof node !== "object") return;

      // ======================
      // --- Taint Analysis ---
      // ======================
      for (const rule of rules) {
        if (rule.type === "taint-ast") {
          // Variable declarations: let x = req.query.foo;
          if (node.type === "VariableDeclarator" && node.init) {
            const varName = getIdentifierName(node.id);
            const initCode = code.substring(node.init.range[0], node.init.range[1]);
            if (rule.sources.some(src => initCode.includes(src))) {
              taintedVars.add(varName);
            }
          }

          // Assignments: x = userInput;
          if (node.type === "AssignmentExpression") {
            const leftName = getIdentifierName(node.left);
            const rightCode = code.substring(node.right.range[0], node.right.range[1]);

            if (rule.sources.some(src => rightCode.includes(src))) {
              taintedVars.add(leftName);
            }

            const rightName = getIdentifierName(node.right);
            if (rightName && taintedVars.has(rightName)) {
              taintedVars.add(leftName);
            }
          }

          // Function calls: eval(x);
          if (node.type === "CallExpression" && node.callee) {
            const calleeName = getIdentifierName(node.callee);
            if (rule.sinks.includes(calleeName)) {
              node.arguments.forEach(arg => {
                const argName = getIdentifierName(arg);
                if (argName && taintedVars.has(argName)) {
                  markFinding(rule, node);
                }
                if (arg.range) {
                  const argCode = code.substring(arg.range[0], arg.range[1]);
                  if (rule.sources.some(src => argCode.includes(src))) {
                    markFinding(rule, node);
                  }
                }
              });
            }
          }
        }
      }

      // ======================
      // --- AST / Context ---
      // ======================
      for (const rule of rules) {
        if (rule.type === "ast" || rule.type === "context-ast") {
          if (node.type === rule.nodeType) {
            let matched = false;

            if (node.type === "CallExpression" || node.type === "NewExpression") {
              if (node.callee) {
                const calleeName = node.callee.name || (node.callee.property && node.callee.property.name);
                const objName = node.callee.object && node.callee.object.name;

                if (rule.calleeName && calleeName === rule.calleeName) matched = true;
                if (rule.objectName && objName === rule.objectName) matched = true;

                if (rule.argIsString && node.arguments.length > 0 &&
                    node.arguments[0].type === "Literal" &&
                    typeof node.arguments[0].value === "string") {
                  matched = true;
                }

                if (rule.sources && node.arguments.length > 0) {
                  const argCode = code.substring(node.arguments[0].range ? node.arguments[0].range[0] : 0,
                                                 node.arguments[0].range ? node.arguments[0].range[1] : 0);
                  if (rule.sources.some(src => argCode.includes(src))) matched = true;
                }
              }
            }

            if (node.type === "AssignmentExpression") {
              const left = node.left;
              if (left && left.property && rule.calleeName && left.property.name === rule.calleeName) {
                matched = true;
              }
            }

            if (matched) {
              findings[rule.id] = findings[rule.id] || [];
              findings[rule.id].push(node.loc.start.line);
            }
          }
        }
      }

      // Recurse
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
