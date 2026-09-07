// Parse only; proposed source is never evaluated. Acorn 8.18.0, MIT (vendor/ACORN-LICENSE).
const fs = require('node:fs');
const acorn = require('./vendor/acorn.cjs');
try {
  const tree = acorn.parse(fs.readFileSync(0, 'utf8'), {ecmaVersion: 2022, sourceType: 'module'});
  const names = [];
  const visit = node => {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'CallExpression' && node.callee?.type === 'MemberExpression'
        && !node.callee.computed && node.callee.object?.name === 'customElements'
        && node.callee.property?.name === 'define' && node.arguments[0]?.type === 'Literal'
        && typeof node.arguments[0].value === 'string') names.push(node.arguments[0].value);
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) value.forEach(visit);
      else if (value && typeof value === 'object') visit(value);
    }
  };
  visit(tree);
  console.log(JSON.stringify({syntax_valid: true, registered_elements: [...new Set(names)].sort(), duplicate_registrations: names.length !== new Set(names).size}));
} catch (error) {
  // Never echo source or parser messages which can contain proposed secrets.
  console.log(JSON.stringify({syntax_valid: false, registered_elements: [], error: 'invalid_javascript', line: error.loc?.line ?? null, column: error.loc?.column ?? null}));
}
