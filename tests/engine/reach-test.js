const E = require('../../src/reach-engine.js');
let pass=0, fail=0;
const eq=(name,got,want)=>{ const ok=got===want; console.log((ok?'PASS':'FAIL')+'  '+name+(ok?'':`  got=${got} want=${want}`)); ok?pass++:fail++; };

/* ===== Cisco ASA: extended ACL with masks ===== */
const cisco = `hostname asa1
access-list outside_in extended permit tcp any host 10.20.0.80 eq 443
access-list outside_in extended permit tcp 192.168.1.0 255.255.255.0 10.20.0.0 255.255.255.0 eq 22
access-list outside_in extended deny ip any any`;
const mc = E.rulesCisco(cisco);
console.log('  cisco rules parsed:', mc.rules.length, '| default:', mc.defaultAction);
eq('ASA permit https any->host', E.evalDevice(mc,{sip:'8.8.8.8',dip:'10.20.0.80',proto:'tcp',dport:443,fromZone:null,toZone:null}).decision, 'permit');
eq('ASA deny http (wrong port) -> explicit deny', E.evalDevice(mc,{sip:'8.8.8.8',dip:'10.20.0.80',proto:'tcp',dport:80}).decision, 'deny');
eq('ASA permit ssh from 192.168.1.0/24', E.evalDevice(mc,{sip:'192.168.1.50',dip:'10.20.0.5',proto:'tcp',dport:22}).decision, 'permit');
eq('ASA deny ssh from other subnet', E.evalDevice(mc,{sip:'172.16.0.1',dip:'10.20.0.5',proto:'tcp',dport:22}).decision, 'deny');

/* ===== Cisco IOS ACL with wildcard mask ===== */
const ios = `hostname r1
access-list 101 permit tcp 192.168.10.0 0.0.0.255 any eq 80
access-list 101 deny ip any any`;
const mi = E.rulesCisco(ios);
eq('IOS wildcard permit http from 192.168.10.0/24', E.evalDevice(mi,{sip:'192.168.10.9',dip:'1.2.3.4',proto:'tcp',dport:80}).decision, 'permit');
eq('IOS wildcard denies outside subnet', E.evalDevice(mi,{sip:'192.168.11.9',dip:'1.2.3.4',proto:'tcp',dport:80}).decision, 'deny');

/* ===== iptables with chain policy ===== */
const ipt = `*filter
:FORWARD DROP [0:0]
-A FORWARD -s 10.0.0.0/8 -d 192.168.5.0/24 -p tcp --dport 443 -j ACCEPT
-A FORWARD -p tcp --dport 22 -j ACCEPT
COMMIT`;
const mt = E.rulesIptables(ipt);
console.log('  iptables rules:', mt.rules.length, '| default:', mt.defaultAction);
eq('iptables permit 443 matching s/d', E.evalDevice(mt,{sip:'10.1.2.3',dip:'192.168.5.10',proto:'tcp',dport:443}).decision, 'permit');
eq('iptables default DROP for unmatched', E.evalDevice(mt,{sip:'1.2.3.4',dip:'5.6.7.8',proto:'tcp',dport:8080}).decision, 'deny');
eq('iptables permit ssh anywhere', E.evalDevice(mt,{sip:'1.2.3.4',dip:'5.6.7.8',proto:'tcp',dport:22}).decision, 'permit');

/* ===== FortiGate with address + service objects + zones ===== */
const fg = `config firewall address
edit "lan-net"
set subnet 192.168.100.0 255.255.255.0
next
edit "web-server"
set subnet 10.100.0.80 255.255.255.255
next
end
config firewall service custom
edit "APP-8443"
set tcp-portrange 8443
next
end
config firewall policy
edit 1
set srcintf "internal"
set dstintf "dmz"
set srcaddr "lan-net"
set dstaddr "web-server"
set service "HTTPS" "APP-8443"
set action accept
next
edit 2
set srcintf "internal"
set dstintf "wan1"
set srcaddr "all"
set dstaddr "all"
set service "ALL"
set action deny
next
end`;
const mf = E.rulesFortigate(fg);
console.log('  fortigate rules:', mf.rules.length, '| zoneScoped:', mf.zoneScoped);
eq('FGT permit lan->web 443 (builtin svc)', E.evalDevice(mf,{sip:'192.168.100.9',dip:'10.100.0.80',proto:'tcp',dport:443,fromZone:'internal',toZone:'dmz'}).decision, 'permit');
eq('FGT permit lan->web 8443 (custom svc)', E.evalDevice(mf,{sip:'192.168.100.9',dip:'10.100.0.80',proto:'tcp',dport:8443,fromZone:'internal',toZone:'dmz'}).decision, 'permit');
eq('FGT deny lan->web wrong port 22', E.evalDevice(mf,{sip:'192.168.100.9',dip:'10.100.0.80',proto:'tcp',dport:22,fromZone:'internal',toZone:'dmz'}).decision, 'deny');
eq('FGT explicit deny internal->wan', E.evalDevice(mf,{sip:'192.168.100.9',dip:'8.8.8.8',proto:'tcp',dport:443,fromZone:'internal',toZone:'wan1'}).decision, 'deny');
eq('FGT zone mismatch -> default deny', E.evalDevice(mf,{sip:'192.168.100.9',dip:'10.100.0.80',proto:'tcp',dport:443,fromZone:'dmz',toZone:'internal'}).decision, 'deny');

/* ===== Juniper zones + apps ===== */
const jun = `set applications application custom-8080 protocol tcp destination-port 8080
set security zones security-zone trust address-book address lan 192.168.20.0/24
set security policies from-zone trust to-zone dmz policy p1 match source-address lan
set security policies from-zone trust to-zone dmz policy p1 match destination-address any
set security policies from-zone trust to-zone dmz policy p1 match application junos-https
set security policies from-zone trust to-zone dmz policy p1 then permit
set security policies from-zone trust to-zone dmz policy p2 match source-address any
set security policies from-zone trust to-zone dmz policy p2 match destination-address any
set security policies from-zone trust to-zone dmz policy p2 match application custom-8080
set security policies from-zone trust to-zone dmz policy p2 then permit`;
const mj = E.rulesJuniper(jun);
console.log('  juniper rules:', mj.rules.length);
eq('JunOS permit trust->dmz https from lan', E.evalDevice(mj,{sip:'192.168.20.5',dip:'10.5.5.5',proto:'tcp',dport:443,fromZone:'trust',toZone:'dmz'}).decision, 'permit');
eq('JunOS deny https from non-lan (src no match) -> default', E.evalDevice(mj,{sip:'172.16.0.1',dip:'10.5.5.5',proto:'tcp',dport:443,fromZone:'trust',toZone:'dmz'}).decision, 'deny');
eq('JunOS permit custom-8080 any->any', E.evalDevice(mj,{sip:'172.16.0.1',dip:'10.5.5.5',proto:'tcp',dport:8080,fromZone:'trust',toZone:'dmz'}).decision, 'permit');
eq('JunOS deny wrong zone', E.evalDevice(mj,{sip:'192.168.20.5',dip:'10.5.5.5',proto:'tcp',dport:443,fromZone:'untrust',toZone:'dmz'}).decision, 'deny');

/* ===== uncertainty flagging on unresolved object ===== */
const fgU = `config firewall policy
edit 1
set srcintf "internal"
set dstintf "dmz"
set srcaddr "undefined-group"
set dstaddr "all"
set service "HTTPS"
set action accept
next
end`;
const mu = E.rulesFortigate(fgU);
const ru = E.evalDevice(mu,{sip:'1.2.3.4',dip:'5.6.7.8',proto:'tcp',dport:443,fromZone:'internal',toZone:'dmz'});
eq('unresolved src object -> default deny', ru.decision, 'deny');
eq('unresolved src object -> flagged uncertain', ru.uncertain, true);

console.log(`\n${pass}/${pass+fail} reachability engine checks passed`);
process.exit(fail?1:0);
