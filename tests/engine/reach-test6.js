const E = require('../../src/reach-engine.js');
let pass=0, fail=0;
const eq=(name,got,want)=>{ const ok=got===want; console.log((ok?'PASS':'FAIL')+'  '+name+(ok?'':`  got=${JSON.stringify(got)} want=${JSON.stringify(want)}`)); ok?pass++:fail++; };

/* ===== SEL security gateway ===== */
const sel = `access-rule 1 permit source 10.1.1.0/24 destination 10.2.2.5 service tcp/23
access-rule 2 deny source any destination any`;
const ms=E.rulesSel(sel);
eq('SEL permit engineering access 23', E.evalDevice(ms,{sip:'10.1.1.9',dip:'10.2.2.5',proto:'tcp',dport:23}).decision, 'permit');
eq('SEL deny other', E.evalDevice(ms,{sip:'10.1.1.9',dip:'10.2.2.5',proto:'tcp',dport:22}).decision, 'deny');
eq('SEL deny other source', E.evalDevice(ms,{sip:'192.168.1.1',dip:'10.2.2.5',proto:'tcp',dport:23}).decision, 'deny');

/* ===== Phoenix Contact mGuard ===== */
const mg = `firewall incoming 1 from 192.168.1.0/24 to 10.0.0.5 protocol tcp dport 502 action accept
firewall incoming 2 from any to any action drop`;
const mm=E.rulesMguard(mg);
console.log('  mGuard rules:', mm.rules.length);
eq('mGuard permit Modbus 502', E.evalDevice(mm,{sip:'192.168.1.9',dip:'10.0.0.5',proto:'tcp',dport:502}).decision, 'permit');
eq('mGuard drop other port', E.evalDevice(mm,{sip:'192.168.1.9',dip:'10.0.0.5',proto:'tcp',dport:22}).decision, 'deny');
eq('mGuard drop other source', E.evalDevice(mm,{sip:'10.9.9.9',dip:'10.0.0.5',proto:'tcp',dport:502}).decision, 'deny');

/* ===== Waterfall unidirectional gateway ===== */
const wf = `replication source-side plant destination-side corporate
replicate server 10.5.0.10 protocol tcp port 502
replicate server 10.5.0.11 protocol tcp port 44818`;
const mw=E.rulesWaterfall(wf);
console.log('  Waterfall rules:', mw.rules.length, 'unidir:', JSON.stringify(mw.unidirectional));
eq('Waterfall permit replicated plant->corp 502', E.evalDevice(mw,{sip:'10.4.0.5',dip:'10.5.0.10',proto:'tcp',dport:502,fromZone:'plant',toZone:'corporate'}).decision, 'permit');
eq('Waterfall permit EtherNet/IP replicated', E.evalDevice(mw,{sip:'10.4.0.5',dip:'10.5.0.11',proto:'tcp',dport:44818,fromZone:'plant',toZone:'corporate'}).decision, 'permit');
eq('Waterfall BLOCK reverse corp->plant (data diode)', E.evalDevice(mw,{sip:'10.5.0.10',dip:'10.4.0.5',proto:'tcp',dport:502,fromZone:'corporate',toZone:'plant'}).decision, 'deny');
eq('Waterfall deny non-replicated forward', E.evalDevice(mw,{sip:'10.4.0.5',dip:'10.5.0.10',proto:'tcp',dport:22,fromZone:'plant',toZone:'corporate'}).decision, 'deny');

/* ===== evalRuleList (port ACL) ===== */
const pacl=[{action:'permit',proto:'tcp',src:{any:true},dst:{cidr:'10.1.10.5/32'},dports:[[443,443]],seq:0}];
eq('evalRuleList permit match', E.evalRuleList(pacl,{sip:'10.1.10.9',dip:'10.1.10.5',proto:'tcp',dport:443},'deny').decision, 'permit');
eq('evalRuleList implicit deny', E.evalRuleList(pacl,{sip:'10.1.10.9',dip:'10.1.10.5',proto:'tcp',dport:22},'deny').decision, 'deny');

console.log(`\n${pass}/${pass+fail} SEL/mGuard/Waterfall/portACL checks passed`);
process.exit(fail?1:0);
