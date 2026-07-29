#!/usr/bin/env node
/* Rebuilds the reachability-engine <script> block inside nettopo.html from the
 * canonical source in src/reach-engine.js (+ src/pfsense-reach.js).
 *
 * The engine is the single source of truth so it can be unit-tested in Node.
 * ip2int/int2ip/mask2bits are provided by the app and stripped here to avoid
 * duplicate definitions; the engine's IPv6-aware netKey/cidrContains/isIPv4 win.
 *
 * Usage: node src/inject.js
 */
const fs = require('fs');
const path = require('path');
const ROOT = path.resolve(__dirname, '..');

let eng = fs.readFileSync(path.join(ROOT, 'src/reach-engine.js'), 'utf8').split('module.exports')[0].trimEnd();
for (const fn of ['ip2int', 'int2ip', 'mask2bits']) {
  eng = eng.replace(new RegExp('\\nfunction\\s+' + fn + '\\([^\\n]*\\n'), '\n');
}
const pf = fs.readFileSync(path.join(ROOT, 'src/pfsense-reach.js'), 'utf8');
const block = '/* ============================ reachability engine ============================ */\n'
  + eng + '\n\n' + pf + '\n';

const htmlPath = path.join(ROOT, 'nettopo.html');
let h = fs.readFileSync(htmlPath, 'utf8');
const START = '/* ============================ reachability engine ============================ */';
const END = '\n</script>\n<script>\n/* Security hardening';
const si = h.indexOf(START);
const ei = h.indexOf(END, si);
if (si < 0 || ei < 0) { console.error('Engine markers not found in nettopo.html'); process.exit(1); }
h = h.slice(0, si) + block + h.slice(ei);
fs.writeFileSync(htmlPath, h);
console.log('Injected reachability engine into nettopo.html');
