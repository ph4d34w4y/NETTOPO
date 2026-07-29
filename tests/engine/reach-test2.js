const E = require('../../src/reach-engine.js');
let pass=0, fail=0;
const eq=(name,got,want)=>{ const ok=got===want; console.log((ok?'PASS':'FAIL')+'  '+name+(ok?'':`  got=${JSON.stringify(got)} want=${JSON.stringify(want)}`)); ok?pass++:fail++; };

/* ===== nested object-groups + object network + service group ===== */
const asa = `hostname asa2
object network web1
 host 10.20.0.80
object network web2
 host 10.20.0.81
object-group network WEB_SERVERS
 network-object object web1
 network-object object web2
object-group network DMZ_ALL
 group-object WEB_SERVERS
 network-object 10.20.9.0 255.255.255.0
object-group service WEB_PORTS tcp
 port-object eq 80
 port-object eq 443
access-list outside_in extended permit tcp any object-group DMZ_ALL object-group WEB_PORTS
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
interface GigabitEthernet0/0
 nameif outside
 ip address 203.0.113.2 255.255.255.0
interface GigabitEthernet0/1
 nameif dmz
 ip address 10.20.0.1 255.255.255.0`;
const m = E.rulesCisco(asa);
console.log('  rules:', m.rules.length, '| acls:', Object.keys(m.acls), '| bindings:', JSON.stringify(m.bindings));
// nested group resolves web1+web2+10.20.9.0/24, ports 80/443
eq('nested group: permit 443 to web1 (via object)', E.evalDevice(m,{sip:'1.2.3.4',dip:'10.20.0.80',proto:'tcp',dport:443,fromZone:'outside',toZone:'dmz'}).decision, 'permit');
eq('nested group: permit 80 to web2', E.evalDevice(m,{sip:'1.2.3.4',dip:'10.20.0.81',proto:'tcp',dport:80,fromZone:'outside',toZone:'dmz'}).decision, 'permit');
eq('nested group: permit to nested subnet 10.20.9.5:443', E.evalDevice(m,{sip:'1.2.3.4',dip:'10.20.9.5',proto:'tcp',dport:443,fromZone:'outside',toZone:'dmz'}).decision, 'permit');
eq('service group: deny 8080 (not in WEB_PORTS)', E.evalDevice(m,{sip:'1.2.3.4',dip:'10.20.0.80',proto:'tcp',dport:8080,fromZone:'outside',toZone:'dmz'}).decision, 'deny');
eq('deny to host outside the groups', E.evalDevice(m,{sip:'1.2.3.4',dip:'10.20.5.5',proto:'tcp',dport:443,fromZone:'outside',toZone:'dmz'}).decision, 'deny');

/* ===== binding direction: ACL only applies inbound on 'outside' ===== */
// Traffic entering on 'dmz' (fromZone=dmz) has NO inbound ACL bound -> permit (no filtering)
eq('no ACL bound on dmz ingress -> permit', E.evalDevice(m,{sip:'10.20.0.80',dip:'1.2.3.4',proto:'tcp',dport:443,fromZone:'dmz',toZone:'outside'}).decision, 'permit');
// Traffic inbound on outside but wrong port -> denied by bound ACL implicit/explicit deny
eq('inbound outside ACL denies unlisted', E.evalDevice(m,{sip:'1.2.3.4',dip:'10.20.0.80',proto:'tcp',dport:22,fromZone:'outside',toZone:'dmz'}).decision, 'deny');

/* ===== IOS interface-applied ACL ===== */
const ios = `hostname r2
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 ip access-group 100 in
access-list 100 permit tcp 192.168.1.0 0.0.0.255 any eq 443
access-list 100 deny ip any any`;
const mi = E.rulesCisco(ios);
console.log('  IOS bindings:', JSON.stringify(mi.bindings));
// ingress interface zone = ifname 'GigabitEthernet0/0' (no nameif)
eq('IOS inbound ACL permit 443 from lan', E.evalDevice(mi,{sip:'192.168.1.9',dip:'8.8.8.8',proto:'tcp',dport:443,fromZone:'GigabitEthernet0/0',toZone:null}).decision, 'permit');
eq('IOS inbound ACL deny 22', E.evalDevice(mi,{sip:'192.168.1.9',dip:'8.8.8.8',proto:'tcp',dport:22,fromZone:'GigabitEthernet0/0',toZone:null}).decision, 'deny');

/* ===== cycle guard on self-referential group ===== */
const cyc = `object-group network G1
 group-object G2
object-group network G2
 group-object G1
 network-object host 10.0.0.5
access-list x extended permit ip any object-group G1
access-group x in interface inside`;
const mc = E.rulesCisco(cyc);
eq('cycle-safe group still resolves member', E.evalDevice(mc,{sip:'1.1.1.1',dip:'10.0.0.5',proto:'tcp',dport:1,fromZone:'inside',toZone:null}).decision, 'permit');

console.log(`\n${pass}/${pass+fail} enhanced engine checks passed`);
process.exit(fail?1:0);
