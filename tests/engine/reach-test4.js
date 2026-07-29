const E = require('../../src/reach-engine.js');
let pass=0, fail=0;
const eq=(name,got,want)=>{ const ok=got===want; console.log((ok?'PASS':'FAIL')+'  '+name+(ok?'':`  got=${JSON.stringify(got)} want=${JSON.stringify(want)}`)); ok?pass++:fail++; };

/* ===== IPv6 helpers ===== */
eq('isIPv6 detects', E.isIPv6('2001:db8::1'), true);
eq('isIPv6 rejects v4', E.isIPv6('10.0.0.1'), false);
eq('v6 netKey', E.netKey('2001:db8:0:0:0:0:0:1', 64), '2001:db8::/64');
eq('v6 cidrContains true', E.cidrContains('2001:db8::/32','2001:db8:1234::5'), true);
eq('v6 cidrContains false', E.cidrContains('2001:db8::/32','2001:db9::5'), false);
eq('v4/v6 family mismatch no match', E.cidrContains('10.0.0.0/8','2001:db8::1'), false);

/* ===== Palo Alto PAN-OS ===== */
const pa = `set deviceconfig system hostname PA-1
set address web-srv ip-netmask 10.10.0.80/32
set address lan-net ip-netmask 192.168.1.0/24
set service tcp-8443 protocol tcp port 8443
set rulebase security rules allow-web from untrust to dmz source any destination web-srv service application-default action allow
set rulebase security rules allow-app from trust to dmz source lan-net destination web-srv service tcp-8443 action allow
set rulebase security rules deny-all from any to any source any destination any service any action deny`;
const mp = E.rulesPaloalto(pa);
console.log('  PA rules:', mp.rules.length);
eq('PA permit untrust->dmz to web-srv (app-default any)', E.evalDevice(mp,{sip:'1.2.3.4',dip:'10.10.0.80',proto:'tcp',dport:443,fromZone:'untrust',toZone:'dmz'}).decision, 'permit');
eq('PA permit trust->dmz 8443 from lan-net', E.evalDevice(mp,{sip:'192.168.1.9',dip:'10.10.0.80',proto:'tcp',dport:8443,fromZone:'trust',toZone:'dmz'}).decision, 'permit');
eq('PA deny 8443 from wrong source', E.evalDevice(mp,{sip:'172.16.0.1',dip:'10.10.0.80',proto:'tcp',dport:8443,fromZone:'trust',toZone:'dmz'}).decision, 'deny');
eq('PA deny-all catches unmatched zone', E.evalDevice(mp,{sip:'1.1.1.1',dip:'2.2.2.2',proto:'tcp',dport:80,fromZone:'trust',toZone:'untrust'}).decision, 'deny');

/* ===== Arista EOS ===== */
const ar = `hostname arista-1
ip access-list DMZ-IN
   10 permit tcp 10.20.0.0/24 host 192.168.5.50 eq 3306
   20 permit tcp any any eq 443
   30 deny ip any any
interface Ethernet1
   ip address 10.20.0.1/24
   ip access-group DMZ-IN in`;
const ma = E.rulesArista(ar);
console.log('  Arista rules:', ma.rules.length, '| bindings:', JSON.stringify(ma.bindings));
eq('Arista permit 3306 from 10.20.0.0/24', E.evalDevice(ma,{sip:'10.20.0.9',dip:'192.168.5.50',proto:'tcp',dport:3306,fromZone:'Ethernet1',toZone:null}).decision, 'permit');
eq('Arista permit 443 any', E.evalDevice(ma,{sip:'1.2.3.4',dip:'5.6.7.8',proto:'tcp',dport:443,fromZone:'Ethernet1',toZone:null}).decision, 'permit');
eq('Arista deny 3306 from other src', E.evalDevice(ma,{sip:'172.16.0.1',dip:'192.168.5.50',proto:'tcp',dport:3306,fromZone:'Ethernet1',toZone:null}).decision, 'deny');
eq('Arista deny 22', E.evalDevice(ma,{sip:'1.2.3.4',dip:'5.6.7.8',proto:'tcp',dport:22,fromZone:'Ethernet1',toZone:null}).decision, 'deny');

/* ===== Arista IPv6 ACL ===== */
const ar6 = `ip access-list V6
   10 permit tcp 2001:db8:a::/64 any eq 443
   20 deny ip any any
interface Ethernet2
   ip access-group V6 in`;
const ma6=E.rulesArista(ar6);
eq('Arista v6 permit from 2001:db8:a::/64', E.evalDevice(ma6,{sip:'2001:db8:a::5',dip:'2001:db8:b::1',proto:'tcp',dport:443,fromZone:'Ethernet2',toZone:null}).decision, 'permit');
eq('Arista v6 deny other prefix', E.evalDevice(ma6,{sip:'2001:db8:c::5',dip:'2001:db8:b::1',proto:'tcp',dport:443,fromZone:'Ethernet2',toZone:null}).decision, 'deny');

/* ===== source NAT (iptables MASQUERADE) ===== */
const ipt = `*nat
-A POSTROUTING -s 192.168.1.0/24 -j MASQUERADE
COMMIT
*filter
:FORWARD DROP [0:0]
COMMIT`;
const mt=E.rulesIptables(ipt);
console.log('  iptables snat:', JSON.stringify(mt.nat.snat));
const ts=E.translateSource(mt,'192.168.1.50',null,null);
eq('iptables MASQUERADE translates source', ts && ts.ip, '(interface address)');
eq('iptables SNAT no match outside net', E.translateSource(mt,'10.0.0.5',null,null), null);

console.log(`\n${pass}/${pass+fail} vendor + ipv6 + snat checks passed`);
process.exit(fail?1:0);
