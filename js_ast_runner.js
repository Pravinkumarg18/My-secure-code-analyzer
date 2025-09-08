// js_ast_runner.js
// Enhanced JavaScript AST runner with Regex, AST, Context-Aware AST, and Inter-Procedural Taint Analysis
// - Produces findings as: { "<rule_id>": [line, line, ...], ... }
// - Uses Esprima for AST + ranges and attempts to avoid false positives by ignoring matches inside literals/comments.
// - Improvements: sanitizer-aware taint propagation, reduced setTimeout/setInterval false positives,
//   safer regex heuristics (ensures call-like contexts), and sanitizer-aware function return handling.

const esprima = require("esprima");

let input = "";
process.stdin.on("data", chunk => input += chunk);
process.stdin.on("end", () => {
  try {
    const payload = JSON.parse(input);
    const code = payload.code || "";
    const rules = (payload.rules || []).map(r => normalizeRule(r));

    // Parse AST with ranges & comments
    let ast;
    try {
      ast = esprima.parseScript(code, { range: true, loc: true, tolerant: true, comment: true, tokens: true });
    } catch (e) {
      process.stdout.write(JSON.stringify({ error: "JavaScript parse error: " + e.message }));
      return;
    }

    // Data structures
    const findings = {};           // ruleId -> Set(lines)
    const taintedVars = new Set(); // set of names like "x" or "obj.prop"
    const functionDefs = {};       // name -> function AST node
    const functionReturnsTainted = {}; // name -> boolean
    const literalRanges = collectLiteralRanges(ast); // ranges for string/template literals + regexps
    const commentRanges = collectCommentRanges(ast); // ranges for comments
    const sanitizerCandidates = buildSanitizerList(rules); // sanitizers listed in rules (best-effort)

    // --------------- Helpers ---------------
    function normalizeRule(rule) {
      const r = Object.assign({}, rule);
      if (r.calleeName && !Array.isArray(r.calleeName)) r.calleeName = [r.calleeName];
      if (r.sinks && !Array.isArray(r.sinks)) r.sinks = [r.sinks];
      if (r.sources && !Array.isArray(r.sources)) r.sources = [r.sources];
      if (r.requiresTaint === undefined) r.requiresTaint = false;
      if (r.argIndex === undefined) r.argIndex = null;
      if (r.sanitizers && !Array.isArray(r.sanitizers)) r.sanitizers = [r.sanitizers];
      if (r.propertyName && !Array.isArray(r.propertyName)) r.propertyName = [r.propertyName];
      return r;
    }

    function mark(rule, node) {
      if (!rule || !rule.id) return;
      let ln = 0;
      try {
        ln = (node && node.loc && node.loc.start && node.loc.start.line) ? node.loc.start.line : 0;
      } catch (e) { ln = 0; }
      findings[rule.id] = findings[rule.id] || new Set();
      findings[rule.id].add(ln);
    }

    function getNameFromIdentifierOrMember(node) {
      if (!node) return null;
      if (node.type === "Identifier") return node.name;
      if (node.type === "MemberExpression") {
        const objName = getNameFromIdentifierOrMember(node.object) || "?";
        let propName = "?";
        if (node.property) {
          if (node.property.type === "Identifier") propName = node.property.name;
          else if (node.property.type === "Literal") propName = String(node.property.value);
        }
        return objName + "." + propName;
      }
      return null;
    }

    function insideRanges(idx, ranges) {
      if (!Array.isArray(ranges)) return false;
      for (let i = 0; i < ranges.length; i++) {
        if (idx >= ranges[i][0] && idx < ranges[i][1]) return true;
      }
      return false;
    }

    function isPositionInLiteralOrComment(pos) {
      return insideRanges(pos, literalRanges) || insideRanges(pos, commentRanges);
    }

    function isStringLiteral(node) {
      return node && ((node.type === "Literal" && typeof node.value === "string") || node.type === "TemplateLiteral");
    }

    function snippetOf(node) {
      try {
        if (!node || !node.range) return "";
        return code.substring(node.range[0], node.range[1]);
      } catch (e) { return ""; }
    }

    // --------------- Collect functions & literal/comment ranges ---------------
    (function collectFunctions() {
      traverse(ast, node => {
        if (!node) return;
        if (node.type === "FunctionDeclaration" && node.id && node.id.name) {
          functionDefs[node.id.name] = node;
        } else if (node.type === "VariableDeclarator" && node.id && node.id.name && node.init &&
                   (node.init.type === "FunctionExpression" || node.init.type === "ArrowFunctionExpression")) {
          functionDefs[node.id.name] = node.init;
        }
      });
    })();

    // --------------- Inter-procedural & taint helpers ---------------
    function exprIsTainted(expr) {
      if (!expr) return false;
      if (expr.type === "Identifier") return taintedVars.has(expr.name);
      if (expr.type === "MemberExpression") {
        const n = getNameFromIdentifierOrMember(expr);
        if (!n) return false;
        if (taintedVars.has(n)) return true;
        // also check trimmed dotted forms like req.query
        if (taintedVars.has(n.split(".").slice(0,2).join("."))) return true;
        return false;
      }
      if (expr.type === "Literal") {
        return false;
      }
      if (expr.type === "CallExpression") {
        const cn = getNameFromIdentifierOrMember(expr.callee) || "";
        // If the call is a known sanitizer, we treat its return as NOT tainted (best-effort)
        if (sanitizerCandidates.some(s => s && cn.endsWith(s))) return false;
        if (cn && functionReturnsTainted[cn]) return true;
        for (let a of (expr.arguments || [])) if (exprIsTainted(a)) return true;
        // textual argument check against common sources
        const argsText = (expr.arguments || []).map(a => snippetOf(a)).join(" ");
        for (const r of rules.filter(rr => rr.type === "taint-ast")) {
          if (r.sources && r.sources.some(src => src && argsText.includes(src))) return true;
        }
        return false;
      }
      if (expr.type === "BinaryExpression" || expr.type === "LogicalExpression") {
        return exprIsTainted(expr.left) || exprIsTainted(expr.right);
      }
      if (expr.type === "TemplateLiteral") {
        for (const q of (expr.expressions || [])) if (exprIsTainted(q)) return true;
        return false;
      }
      return false;
    }

    function analyzeFunctionReturnTaint(fnNode, fnName) {
      let returnsTainted = functionReturnsTainted[fnName] || false;
      const localTainted = new Set();

      // If params already mapped to taintedVars, mark local
      if (fnNode.params && Array.isArray(fnNode.params)) {
        fnNode.params.forEach(p => {
          if (p.type === "Identifier" && taintedVars.has(p.name)) localTainted.add(p.name);
        });
      }

      traverse(fnNode.body, node => {
        if (!node) return;
        if (node.type === "VariableDeclarator" && node.init) {
          if (exprIsTainted(node.init)) {
            if (node.id.type === "Identifier") localTainted.add(node.id.name);
            else if (node.id.type === "MemberExpression") localTainted.add(getNameFromIdentifierOrMember(node.id));
          }
        }
        if (node.type === "AssignmentExpression") {
          if (exprIsTainted(node.right)) {
            const leftName = getNameFromIdentifierOrMember(node.left);
            if (leftName) localTainted.add(leftName);
          }
        }
        if (node.type === "ReturnStatement" && node.argument) {
          if (exprIsTainted(node.argument)) returnsTainted = true;
        }
      });

      functionReturnsTainted[fnName] = returnsTainted;
    }

    function runInterproceduralAnalysis() {
      let progress = true;
      let iter = 0;
      while (progress && iter < 8) {
        progress = false;
        iter++;
        for (const fnName in functionDefs) {
          const before = !!functionReturnsTainted[fnName];
          analyzeFunctionReturnTaint(functionDefs[fnName], fnName);
          if (!!functionReturnsTainted[fnName] !== before) progress = true;
        }
      }
    }

    // --------------- Regex / heuristic scanning (avoid literals/comments) ---------------
    (function runRegexHeuristics() {
      rules.filter(r => r.type === "regex" || r.type === "heuristic").forEach(rule => {
        try {
          const flags = rule.regexFlags || "i";
          const patt = (typeof rule.pattern === "string") ? new RegExp(rule.pattern, flags) : rule.pattern;
          let m;
          while ((m = patt.exec(code)) !== null) {
            const idx = m.index;
            if (isPositionInLiteralOrComment(idx)) {
              if (patt.lastIndex === m.index) patt.lastIndex++;
              continue;
            }

            // Basic sanity: ensure this looks like a function call or assignment context for certain patterns
            // (reduce false positives for patterns like "setTimeout" mentioned inside comments or non-call contexts)
            const tail = code.substring(idx, Math.min(code.length, idx + 60));
            const looksLikeCall = /\w+\s*\(/.test(tail); // e.g., setTimeout(
            if (!looksLikeCall && (rule.pattern && /setTimeout|setInterval|document\.write|innerHTML/.test(rule.pattern))) {
              if (patt.lastIndex === m.index) patt.lastIndex++;
              continue;
            }

            const line = code.substring(0, idx).split("\n").length;
            mark(rule, { loc: { start: { line } }});
            if (patt.lastIndex === m.index) patt.lastIndex++;
          }
        } catch (e) {
          // ignore invalid pattern
        }
      });
    })();

    // --------------- Taint source initialization based on rules ---------------
    rules.filter(r => r.type === "taint-ast").forEach(rule => {
      traverse(ast, node => {
        if (!node) return;
        if (node.type === "VariableDeclarator" && node.init) {
          const initText = snippetOf(node.init);
          const varName = (node.id && node.id.type === "Identifier") ? node.id.name : getNameFromIdentifierOrMember(node.id);
          if (!varName) return;
          if (rule.sources && rule.sources.some(src => src && initText.includes(src))) {
            taintedVars.add(varName);
          }
        }
        if (node.type === "AssignmentExpression" && node.right) {
          const rightText = snippetOf(node.right);
          const leftName = getNameFromIdentifierOrMember(node.left);
          if (!leftName) return;
          if (rule.sources && rule.sources.some(src => src && rightText.includes(src))) {
            taintedVars.add(leftName);
          }
        }
        // best-effort: arguments containing sources are seeds when used directly in sinks later
      });
    });

    // initial inter-procedural analysis
    runInterproceduralAnalysis();

    // --------------- Main AST walk to detect sinks / AST rules ---------------
    traverse(ast, node => {
      if (!node) return;

      // 1) AST / context-ast rules
      rules.filter(r => r.type === "ast" || r.type === "context-ast").forEach(rule => {
        try {
          const nodeTypeNormalized = String(node.type || "").toLowerCase();
          const ruleNodeType = String(rule.nodeType || "").toLowerCase();

          const typeMatches = nodeTypeNormalized === ruleNodeType ||
                              nodeTypeNormalized.includes(ruleNodeType) ||
                              ruleNodeType.includes(nodeTypeNormalized);

          if (!typeMatches) return;

          let matched = false;

          if (node.type === "CallExpression" || node.type === "NewExpression") {
            const calleeFull = getNameFromIdentifierOrMember(node.callee) || "";
            const calleeSimple = (node.callee && node.callee.name) ? node.callee.name : null;
            const objectSimple = (node.callee && node.callee.object && node.callee.object.name) ? node.callee.object.name : null;

            // calleeName match (support arrays)
            if (rule.calleeName && rule.calleeName.length) {
              for (const cn of rule.calleeName) {
                if (!cn) continue;
                const cnStr = String(cn);
                if (cnStr === calleeFull || cnStr === calleeSimple || calleeFull.endsWith("." + cnStr) || calleeSimple === cnStr) {
                  matched = true;
                  break;
                }
              }
            }

            // objectName / propertyName checks
            if (!matched && rule.objectName && objectSimple) {
              if (rule.objectName === objectSimple || (Array.isArray(rule.objectName) && rule.objectName.includes(objectSimple))) matched = true;
            }
            if (!matched && rule.propertyName && node.callee && node.callee.property) {
              const prop = (node.callee.property.type === "Identifier") ? node.callee.property.name : (node.callee.property.value || "");
              if (rule.propertyName === prop || (Array.isArray(rule.propertyName) && rule.propertyName.includes(prop))) matched = true;
            }

            // argIsString / argIndex checks
            if (!matched && rule.argIsString && node.arguments && node.arguments.length > 0) {
              if (isStringLiteral(node.arguments[0])) matched = true;
            }
            if (!matched && rule.argIndex !== null && node.arguments && node.arguments.length > 0) {
              const idx = rule.argIndex;
              if (node.arguments[idx] && isStringLiteral(node.arguments[idx])) matched = true;
            }

            // Special-case: setTimeout / setInterval — only flag if first arg is string literal OR is tainted
            if (!matched && (calleeSimple === "setTimeout" || calleeSimple === "setInterval")) {
              // Only consider rules that are targeted at setTimeout/setInterval (calleeName includes those)
              if (rule.calleeName && rule.calleeName.some(n => String(n) === "setTimeout" || String(n) === "setInterval")) {
                const firstArg = (node.arguments && node.arguments.length) ? node.arguments[0] : null;
                let unsafe = false;
                if (firstArg && isStringLiteral(firstArg)) unsafe = true;
                if (firstArg && exprIsTainted(firstArg)) unsafe = true;
                if (unsafe) matched = true;
              }
            }

            // requiresTaint: ensure at least one argument is tainted or contains textual source markers
            if (matched && rule.requiresTaint) {
              let argTainted = false;
              const sources = rule.sources || [];
              for (const a of (node.arguments || [])) {
                if (exprIsTainted(a)) { argTainted = true; break; }
                const atxt = snippetOf(a);
                for (const s of sources) {
                  if (s && atxt.includes(s)) { argTainted = true; break; }
                }
                if (argTainted) break;
              }
              if (!argTainted) matched = false;
            }

            // sanitizer detection: skip if callee is sanitizer
            if (matched && rule.sanitizers && rule.sanitizers.length) {
              const callee = getNameFromIdentifierOrMember(node.callee) || "";
              if (rule.sanitizers.some(s => callee.endsWith(s))) matched = false;
            }
          }

          // AssignmentExpression targeting innerHTML, etc.
          if (!matched && node.type === "AssignmentExpression") {
            if (rule.calleeName && rule.calleeName.length) {
              const leftName = getNameFromIdentifierOrMember(node.left) || "";
              for (const cn of rule.calleeName) {
                if (!cn) continue;
                if (leftName.endsWith("." + cn) || leftName === cn) {
                  matched = true;
                  break;
                }
              }
            }
            if (!matched && rule.propertyName) {
              const leftName = getNameFromIdentifierOrMember(node.left) || "";
              if (Array.isArray(rule.propertyName)) {
                for (const pn of rule.propertyName) {
                  if (leftName.endsWith("." + pn) || leftName.includes("." + pn + ".")) { matched = true; break; }
                }
              } else {
                if (leftName.endsWith("." + rule.propertyName) || leftName.includes("." + rule.propertyName + ".")) matched = true;
              }
            }

            // requiresTaint: ensure RHS tainted
            if (matched && rule.requiresTaint) {
              if (!exprIsTainted(node.right)) matched = false;
            }

            // sanitizer check on RHS (if RHS is sanitizer call, treat as safe)
            if (matched && rule.sanitizers && rule.sanitizers.length) {
              if (node.right && node.right.type === "CallExpression") {
                const callee = getNameFromIdentifierOrMember(node.right.callee) || "";
                if (rule.sanitizers.some(s => callee.endsWith(s))) matched = false;
              }
            }
          }

          if (matched) mark(rule, node);
        } catch (e) {
          // ignore to keep scanner robust
        }
      });

      // 2) taint-ast rules (sinks)
      rules.filter(r => r.type === "taint-ast").forEach(rule => {
        try {
          if (node.type === "CallExpression") {
            const calleeFull = getNameFromIdentifierOrMember(node.callee) || "";
            if (rule.sinks && rule.sinks.some(s => {
              if (!s) return false;
              const sStr = String(s);
              return calleeFull === sStr || calleeFull.endsWith("." + sStr) || calleeFull.includes(sStr);
            })) {
              let triggered = false;
              for (const arg of (node.arguments || [])) {
                if (exprIsTainted(arg)) { triggered = true; break; }
                const atxt = snippetOf(arg);
                if (rule.sources && rule.sources.some(src => src && atxt.includes(src))) { triggered = true; break; }
              }
              if (rule.requiresTaint && !triggered) return;
              if (triggered) {
                // If this sink is preceded by a sanitizer call on the argument, skip (best-effort)
                let sanitized = false;
                for (const arg of (node.arguments || [])) {
                  if (arg && arg.type === "CallExpression") {
                    const callee = getNameFromIdentifierOrMember(arg.callee) || "";
                    if (sanitizerCandidates.some(s => s && callee.endsWith(s))) {
                      sanitized = true;
                      break;
                    }
                  }
                }
                if (!sanitized) mark(rule, node);
              }
            }
          }
        } catch (e) {}
      });

      // 3) propagate taint: variable declarators and assignments & sanitize detection
      try {
        if (node.type === "VariableDeclarator" && node.init) {
          const varName = (node.id && node.id.type === "Identifier") ? node.id.name : getNameFromIdentifierOrMember(node.id);
          if (!varName) { /* skip */ }
          else if (exprIsTainted(node.init)) {
            taintedVars.add(varName);
          } else {
            // textual check for sources
            const initText = snippetOf(node.init);
            rules.filter(r => r.type === "taint-ast").forEach(rule => {
              if (rule.sources && rule.sources.some(src => src && initText.includes(src))) {
                taintedVars.add(varName);
              }
            });

            // sanitizer detection: if RHS is call to sanitizer, ensure varName is NOT tainted
            if (node.init.type === "CallExpression") {
              const callee = getNameFromIdentifierOrMember(node.init.callee) || "";
              if (sanitizerCandidates.some(s => s && callee.endsWith(s))) {
                // explicitly clear taint for varName (best-effort)
                if (taintedVars.has(varName)) taintedVars.delete(varName);
              }
            }
          }
        }

        if (node.type === "AssignmentExpression") {
          const leftName = getNameFromIdentifierOrMember(node.left);
          if (!leftName) { /* skip */ }
          else if (exprIsTainted(node.right)) {
            taintedVars.add(leftName);
          } else {
            const rightText = snippetOf(node.right);
            rules.filter(r => r.type === "taint-ast").forEach(rule => {
              if (rule.sources && rule.sources.some(src => src && rightText.includes(src))) {
                taintedVars.add(leftName);
              }
            });

            // sanitizer detection: RHS is call to sanitizer -> remove leftName taint
            if (node.right && node.right.type === "CallExpression") {
              const callee = getNameFromIdentifierOrMember(node.right.callee) || "";
              if (sanitizerCandidates.some(s => s && callee.endsWith(s))) {
                if (taintedVars.has(leftName)) taintedVars.delete(leftName);
              }
            }
          }
        }

        // If calling a known function with tainted args, propagate param names (best-effort)
        if (node.type === "CallExpression") {
          const calleeName = getNameFromIdentifierOrMember(node.callee);
          if (calleeName && functionDefs[calleeName]) {
            const fnNode = functionDefs[calleeName];
            (fnNode.params || []).forEach((p, idx) => {
              if (!p || p.type !== "Identifier") return;
              const arg = node.arguments && node.arguments[idx];
              if (!arg) return;
              if (exprIsTainted(arg)) taintedVars.add(p.name);
            });
          }
        }
      } catch (e) {}

    }); // end traverse

    // After walking AST, run interprocedural pass again to update functionReturnsTainted with newly discovered taints
    runInterproceduralAnalysis();

    // finalize findings: convert sets to sorted arrays of lines
    const out = {};
    for (const id in findings) {
      const arr = Array.from(findings[id]).filter(Boolean).sort((a,b) => a - b);
      out[id] = arr;
    }

    process.stdout.write(JSON.stringify(out));
  } catch (err) {
    process.stdout.write(JSON.stringify({ error: err.message }));
  }

  // ----------------- Utilities -----------------

  function traverse(node, fn) {
    if (!node || typeof node !== "object") return;
    fn(node);
    for (const k in node) {
      if (!node.hasOwnProperty(k)) continue;
      const child = node[k];
      if (Array.isArray(child)) {
        for (const c of child) traverse(c, fn);
      } else if (child && typeof child === "object" && child.type) {
        traverse(child, fn);
      }
    }
  }

  function collectLiteralRanges(astRoot) {
    const ranges = [];
    traverse(astRoot, node => {
      if (!node) return;
      if (node.type === "Literal" && typeof node.value === "string" && node.range) {
        ranges.push([node.range[0], node.range[1]]);
      }
      if (node.type === "Literal" && node.regex && node.range) {
        ranges.push([node.range[0], node.range[1]]);
      }
      if (node.type === "TemplateLiteral" && node.range) {
        ranges.push([node.range[0], node.range[1]]);
      }
    });
    return mergeRanges(ranges);
  }

  function collectCommentRanges(astRoot) {
    const ranges = [];
    (astRoot.comments || []).forEach(c => {
      if (c.range) ranges.push([c.range[0], c.range[1]]);
    });
    return mergeRanges(ranges);
  }

  function mergeRanges(ranges) {
    if (!ranges || ranges.length === 0) return [];
    ranges.sort((a,b) => a[0] - b[0]);
    const out = [ranges[0].slice()];
    for (let i = 1; i < ranges.length; i++) {
      const cur = ranges[i];
      const last = out[out.length - 1];
      if (cur[0] <= last[1]) {
        last[1] = Math.max(last[1], cur[1]);
      } else out.push(cur.slice());
    }
    return out;
  }

  function buildSanitizerList(rulesList) {
    const s = new Set();
    rulesList.forEach(r => {
      if (r.sanitizers && Array.isArray(r.sanitizers)) {
        r.sanitizers.forEach(x => x && s.add(String(x)));
      }
    });
    // Add some common sanitizer heuristics if none provided (best-effort)
    if (!s.size) {
      ["DOMPurify.sanitize", "sanitizeHtml", "xssFilter", "escapeHtml"].forEach(x => s.add(x));
    }
    return Array.from(s);
  }
});
