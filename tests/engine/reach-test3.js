const E = require('../../src/reach-engine.js');
let pass=0, fail=0;
const eq=(name,got,want)=>{ const ok=got===want; console.log((ok?'PASS':'FAIL')+'  '+name+(ok?'':`  got=${JSON.stringify(got)} want=${JSON.stringify(want)}`)); ok?pass++:fail++; };

/* ===== ASA security-level defaults (no ACL bound) ===== */
const asa = `hostname asa-sec
interface Gi0/0
 nameif outside
 security-level 0
 ip address 203.0.113.2 255.255.255.0
interface Gi0/1
 nameif inside
 security-level 100
 ip address 192.168.1.1 255.255.255.0
interface Gi0/2
 nameif dmz
 security-level 50
 ip address 10.10.0.1 255.255.255.0`;
const m = E.rulesCisco(asa);
console.log('  secLevels:', JSON.stringify(m.secLevels));
// inside(100) -> outside(0): high->low permit
eq('seclevel inside->outside permit (high->low)', E.evalDevice(m,{sip:'192.168.1.5',dip:'8.8.8.8',proto:'tcp',dport:443,fromZone:'inside',toZone:'outside'}).decision, 'permit');
// outside(0) -> inside(100): low->high deny
eq('seclevel outside->inside deny (low->high)', E.evalDevice(m,{sip:'8.8.8.8',dip:'192.168.1.5',proto:'tcp',dport:443,fromZone:'outside',toZone:'inside'}).decision, 'deny');
// dmz(50) -> outside(0): high->low permit
eq('seclevel dmz->outside permit', E.evalDevice(m,{sip:'10.10.0.5',dip:'8.8.8.8',proto:'tcp',dport:443,fromZone:'dmz',toZone:'outside'}).decision, 'permit');
// outside(0) -> dmz(50): low->high deny
eq('seclevel outside->dmz deny', E.evalDevice(m,{sip:'8.8.8.8',dip:'10.10.0.5',proto:'tcp',dport:443,fromZone:'outside',toZone:'dmz'}).decision, 'deny');
// same-level deny by default
const asaSame = asa + '\ninterface Gi0/3\n nameif dmz2\n security-level 50\n ip address 10.11.0.1 255.255.255.0';
const ms = E.rulesCisco(asaSame);
eq('same security-level deny by default', E.evalDevice(ms,{sip:'10.10.0.5',dip:'10.11.0.5',proto:'tcp',dport:443,fromZone:'dmz',toZone:'dmz2'}).decision, 'deny');
const asaSamePermit = asaSame + '\nsame-security-traffic permit inter-interface';
const msp = E.rulesCisco(asaSamePermit);
eq('same-security permit when configured', E.evalDevice(msp,{sip:'10.10.0.5',dip:'10.11.0.5',proto:'tcp',dport:443,fromZone:'dmz',toZone:'dmz2'}).decision, 'permit');

/* ===== ASA object NAT (static DNAT port-forward) ===== */
const nat = `hostname asa-nat
object network web-real
 host 10.10.0.80
 nat (dmz,outside) static 203.0.113.10 service tcp 443 443`;
const mn = E.rulesCisco(nat);
console.log('  ASA dnat:', JSON.stringify(mn.nat.dnat));
const tr = E.translateDest(mn, '203.0.113.10', 443, 'tcp');
eq('ASA DNAT translates mapped->real ip', tr && tr.ip, '10.10.0.80');
eq('ASA DNAT keeps port 443', tr && tr.port, 443);
eq('ASA DNAT no match on wrong port', E.translateDest(mn,'203.0.113.10',22,'tcp'), null);

/* ===== IOS static NAT ===== */
const ios = `ip nat inside source static tcp 10.20.0.90 3306 203.0.113.20 3306
ip nat inside source static 10.20.0.5 203.0.113.5`;
const mi = E.rulesCisco(ios);
eq('IOS static PAT translate', (E.translateDest(mi,'203.0.113.20',3306,'tcp')||{}).ip, '10.20.0.90');
eq('IOS static NAT (1-to-1) any port', (E.translateDest(mi,'203.0.113.5',80,'tcp')||{}).ip, '10.20.0.5');

/* ===== iptables DNAT ===== */
const ipt = `*nat
-A PREROUTING -d 198.51.100.10 -p tcp --dport 443 -j DNAT --to-destination 10.30.0.80:8443
COMMIT
*filter
:FORWARD DROP [0:0]
COMMIT`;
const mt = E.rulesIptables(ipt);
console.log('  iptables dnat:', JSON.stringify(mt.nat.dnat));
const trt=E.translateDest(mt,'198.51.100.10',443,'tcp');
eq('iptables DNAT translates ip', trt&&trt.ip, '10.30.0.80');
eq('iptables DNAT translates port 443->8443', trt&&trt.port, 8443);

/* ===== FortiGate VIP ===== */
const fg = `config firewall vip
edit "web-vip"
set extip 203.0.113.30
set mappedip "10.40.0.80"
set extport 443
set mappedport 8080
set portforward enable
set protocol tcp
next
end
config firewall policy
edit 1
set srcintf "wan1"
set dstintf "dmz"
set srcaddr "all"
set dstaddr "web-vip"
set service "HTTPS"
set action accept
next
end`;
const mf = E.rulesFortigate(fg);
console.log('  FGT dnat:', JSON.stringify(mf.nat.dnat));
const trf=E.translateDest(mf,'203.0.113.30',443,'tcp');
eq('FortiGate VIP translates ip', trf&&trf.ip, '10.40.0.80');
eq('FortiGate VIP translates port 443->8080', trf&&trf.port, 8080);
// policy matches VIP by its extip
eq('FGT policy permits traffic to VIP extip:443', E.evalDevice(mf,{sip:'1.2.3.4',dip:'203.0.113.30',proto:'tcp',dport:443,fromZone:'wan1',toZone:'dmz'}).decision, 'permit');

console.log(`\n${pass}/${pass+fail} NAT + ASA-semantics checks passed`);
process.exit(fail?1:0);
