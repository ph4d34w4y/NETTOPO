#!/usr/bin/env node
/* Parses every inline <script> block in nettopo.html to catch syntax errors
 * (e.g. a dropped function declaration from an edit). Exits non-zero on failure.
 */
const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const h = fs.readFileSync(path.resolve(__dirname, '..', 'nettopo.html'), 'utf8');
let n = 0, bad = 0;
for (const part of h.split('</script>')) {
  const oi = part.lastIndexOf('<script');
  if (oi < 0) continue;
  const te = part.indexOf('>', oi);
  if (/src=/.test(part.slice(oi, te + 1))) continue;
  const code = part.slice(te + 1);
  if (!code.trim()) continue;
  n++;
  try { acorn.parse(code, { ecmaVersion: 'latest' }); }
  catch (e) { console.error('Block ' + n + ' syntax error: ' + e.message); bad++; }
}
console.log(n + ' inline script block(s) checked, ' + bad + ' error(s)');
process.exit(bad ? 1 : 0);
