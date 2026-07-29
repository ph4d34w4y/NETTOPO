const E = require('../../src/reach-engine.js');
let pass=0, fail=0;
const eq=(name,got,want)=>{ const ok=got===want; console.log((ok?'PASS':'FAIL')+'  '+name+(ok?'':`  got=${JSON.stringify(got)} want=${JSON.stringify(want)}`)); ok?pass++:fail++; };

/* ===== Hirschmann (IOS-like) ===== */
const hir = `ip access-list extended PROCESS
   10 permit tcp 10.1.10.0/24 host 10.1.20.5 eq 502
   20 deny ip any any
interface 1/1
   ip access-group PROCESS in`;
const mh=E.rulesHirschmann(hir);
eq('Hirschmann permit Modbus 502', E.evalDevice(mh,{sip:'10.1.10.9',dip:'10.1.20.5',proto:'tcp',dport:502,fromZone:'1/1',toZone:null}).decision, 'permit');
eq('Hirschmann deny other port', E.evalDevice(mh,{sip:'10.1.10.9',dip:'10.1.20.5',proto:'tcp',dport:22,fromZone:'1/1',toZone:null}).decision, 'deny');

/* ===== Moxa ===== */
const moxa = `firewall default policy drop
firewall filter 1 accept src-ip 192.168.10.0/24 dst-ip 192.168.20.10 protocol tcp dst-port 502
firewall filter 2 accept src-ip 192.168.10.0/24 dst-ip 192.168.20.11 protocol tcp dst-port 44818`;
const mm=E.rulesMoxa(moxa);
console.log('  Moxa rules:', mm.rules.length, 'default:', mm.defaultAction);
eq('Moxa permit Modbus to PLC', E.evalDevice(mm,{sip:'192.168.10.5',dip:'192.168.20.10',proto:'tcp',dport:502}).decision, 'permit');
eq('Moxa permit EtherNet/IP 44818', E.evalDevice(mm,{sip:'192.168.10.5',dip:'192.168.20.11',proto:'tcp',dport:44818}).decision, 'permit');
eq('Moxa default drop for unlisted', E.evalDevice(mm,{sip:'192.168.10.5',dip:'192.168.20.10',proto:'tcp',dport:22}).decision, 'deny');
eq('Moxa drop from other src', E.evalDevice(mm,{sip:'10.0.0.9',dip:'192.168.20.10',proto:'tcp',dport:502}).decision, 'deny');

/* ===== Siemens SCALANCE ===== */
const sca = `rule 1 from cell1 to cell2 src 10.5.1.0/24 dst 10.5.2.20 service tcp/502 action allow
rule 2 from cell1 to cell2 src any dst any service any action drop`;
const ms=E.rulesScalance(sca);
console.log('  SCALANCE rules:', ms.rules.length, 'zoneScoped:', ms.zoneScoped);
eq('SCALANCE permit 502 cell1->cell2', E.evalDevice(ms,{sip:'10.5.1.9',dip:'10.5.2.20',proto:'tcp',dport:502,fromZone:'cell1',toZone:'cell2'}).decision, 'permit');
eq('SCALANCE drop other port', E.evalDevice(ms,{sip:'10.5.1.9',dip:'10.5.2.20',proto:'tcp',dport:22,fromZone:'cell1',toZone:'cell2'}).decision, 'deny');
eq('SCALANCE zone mismatch -> default deny', E.evalDevice(ms,{sip:'10.5.1.9',dip:'10.5.2.20',proto:'tcp',dport:502,fromZone:'cell2',toZone:'cell1'}).decision, 'deny');

console.log(`\n${pass}/${pass+fail} OT vendor checks passed`);
process.exit(fail?1:0);
