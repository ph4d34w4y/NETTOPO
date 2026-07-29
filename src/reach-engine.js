/* NetTopo reachability engine.  Author: ph4ad34w4y.  MIT License. */
/* ============================ reachability engine ============================
 * Normalizes vendor rulesets into a common IR, then evaluates a 5-tuple
 * (src ip, dst ip, proto, dport) against a device's rules with first-match-wins
 * and an explicit default action. Path reachability walks each hop.
 * Standalone-testable: no DOM, no globals beyond ip helpers passed in.
 */

/* ---- ip helpers (mirror app) ---- */
function ip2int(ip){ const p=String(ip).split('.'); if(p.length!==4)return null; let n=0; for(const x of p){const v=+x; if(!Number.isInteger(v)||v<0||v>255)return null; n=(n*256)+v;} return n>>>0; }
function int2ip(n){ return [(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255].join('.'); }
function mask2bits(mask){ const n=ip2int(mask); if(n===null)return null; let b=0,z=false; for(let i=31;i>=0;i--){ if((n>>>i)&1){ if(z)return null; b++; } else z=true; } return b; }
function wildcardToBits(wc){ // cisco wildcard (inverted mask) -> bits
  const n=ip2int(wc); if(n===null)return null; const m=(~n)>>>0; return mask2bits(int2ip(m)); }
/* ---- IPv6 support ---- */
function isIPv6(s){ if(typeof s!=='string')return false; s=s.split('/')[0]; return s.includes(':') && /^[0-9a-fA-F:]+$/.test(s) && (s.match(/::/g)||[]).length<=1; }
function ip6ToBig(s){
  s=s.split('/')[0]; if(!s.includes(':'))return null;
  let parts;
  if (s.includes('::')){
    const [head,tail]=s.split('::');
    const h=head?head.split(':').filter(x=>x!==''):[], t=tail?tail.split(':').filter(x=>x!==''):[];
    const miss=8-(h.length+t.length); if(miss<0)return null;
    parts=[...h,...Array(miss).fill('0'),...t];
  } else parts=s.split(':');
  if (parts.length!==8) return null;
  let n=0n;
  for (const p of parts){ const v=parseInt(p||'0',16); if(isNaN(v)||v<0||v>0xffff)return null; n=(n<<16n)+BigInt(v); }
  return n;
}
function big6ToStr(n){
  const g=[]; for(let i=0;i<8;i++){ g.unshift((n & 0xffffn).toString(16)); n>>=16n; }
  return g.join(':').replace(/(^|:)0(:0)*(:|$)/,'::').replace(/:::+/,'::');
}
function net6Key(ip,bits){ const n=ip6ToBig(ip); if(n==null)return null; const shift=BigInt(128-bits); const base=(n>>shift)<<shift; return big6ToStr(base)+'/'+bits; }
function cidr6Contains(key,ip){ const [base,b]=key.split('/'); const bits=+b; const bb=ip6ToBig(base),h=ip6ToBig(ip); if(bb==null||h==null)return false; const shift=BigInt(128-bits); return (bb>>shift)===(h>>shift); }
function netKey(ip,bits){
  if (typeof ip==='string' && ip.includes(':')) return net6Key(ip,bits);
  const n=ip2int(ip); if(n===null||bits==null)return null; const m=bits===0?0:(0xFFFFFFFF<<(32-bits))>>>0; return int2ip((n&m)>>>0)+'/'+bits; }
function cidrContains(key,ip){
  if (key.includes(':')) return isIPv6(ip) && cidr6Contains(key,ip);
  if (isIPv6(ip)) return false;
  const [base,b]=key.split('/'); const bits=+b, bb=ip2int(base), h=ip2int(ip); if(bb===null||h===null)return false; const m=bits===0?0:(0xFFFFFFFF<<(32-bits))>>>0; return ((h&m)>>>0)===((bb&m)>>>0); }
function isIPv4(s){ return ip2int(s)!==null; }
function isIP(s){ return isIPv4(s)||isIPv6(s); }

/* ---- service name resolution ---- */
const PORTNAME = { http:80, www:80, https:443, ssh:22, telnet:23, ftp:21, 'ftp-data':20, smtp:25, domain:53, dns:53,
  ntp:123, snmp:161, snmptrap:162, tftp:69, syslog:514, ldap:389, ldaps:636, rdp:3389, 'ms-wbt-server':3389,
  smb:445, 'microsoft-ds':445, netbios:139, pop3:110, imap:143, imaps:993, pop3s:995, sip:5060,
  bgp:179, radius:1812, sqlnet:1521, mysql:3306, postgresql:5432, 'ms-sql-s':1433, vnc:5900, 'http-alt':8080 };
// vendor built-in service objects -> {proto, ports:[[lo,hi]]}
const BUILTIN_SVC = {
  // FortiGate
  ALL:{proto:'ip'}, 'ALL_TCP':{proto:'tcp'}, 'ALL_UDP':{proto:'udp'}, 'ALL_ICMP':{proto:'icmp'},
  HTTPS:{proto:'tcp',ports:[[443,443]]}, HTTP:{proto:'tcp',ports:[[80,80]]}, SSH:{proto:'tcp',ports:[[22,22]]},
  TELNET:{proto:'tcp',ports:[[23,23]]}, FTP:{proto:'tcp',ports:[[21,21]]}, DNS:{proto:'udp',ports:[[53,53]]},
  SMTP:{proto:'tcp',ports:[[25,25]]}, NTP:{proto:'udp',ports:[[123,123]]}, SNMP:{proto:'udp',ports:[[161,162]]},
  PING:{proto:'icmp'}, 'ALL_ICMP6':{proto:'icmp'}, SYSLOG:{proto:'udp',ports:[[514,514]]},
  RDP:{proto:'tcp',ports:[[3389,3389]]}, SMB:{proto:'tcp',ports:[[445,445]]}, LDAP:{proto:'tcp',ports:[[389,389]]},
  'MS-SQL':{proto:'tcp',ports:[[1433,1433]]}, MYSQL:{proto:'tcp',ports:[[3306,3306]]}, POSTGRES:{proto:'tcp',ports:[[5432,5432]]},
  // Juniper junos-*
  'junos-https':{proto:'tcp',ports:[[443,443]]}, 'junos-http':{proto:'tcp',ports:[[80,80]]},
  'junos-ssh':{proto:'tcp',ports:[[22,22]]}, 'junos-telnet':{proto:'tcp',ports:[[23,23]]},
  'junos-ftp':{proto:'tcp',ports:[[21,21]]}, 'junos-dns-udp':{proto:'udp',ports:[[53,53]]},
  'junos-dns-tcp':{proto:'tcp',ports:[[53,53]]}, 'junos-smtp':{proto:'tcp',ports:[[25,25]]},
  'junos-ntp':{proto:'udp',ports:[[123,123]]}, 'junos-snmp':{proto:'udp',ports:[[161,161]]},
  'junos-ping':{proto:'icmp'}, 'junos-icmp-all':{proto:'icmp'}, 'junos-ms-rdp':{proto:'tcp',ports:[[3389,3389]]},
  'junos-smb':{proto:'tcp',ports:[[445,445]]}, 'junos-ldap':{proto:'tcp',ports:[[389,389]]},
  'junos-postgresql':{proto:'tcp',ports:[[5432,5432]]}, any:{proto:'ip'} };

function resolvePort(tok){
  if (tok==null) return null;
  const s=String(tok).toLowerCase();
  if (/^\d+$/.test(s)) return +s;
  if (PORTNAME[s]!=null) return PORTNAME[s];
  return null; // unknown name
}

/* ---- rule IR ----
 * rule = { action:'permit'|'deny', proto:'ip'|'tcp'|'udp'|'icmp',
 *          src:{any}|{cidr}|{unresolved}, dst:..., dports:null|[[lo,hi]]|{unresolved},
 *          from:zone|null, to:zone|null, raw, seq }
 * device model = { name, rules:[...], defaultAction:'deny'|'permit', zoneScoped:bool }
 */
const ANY = {any:true};
function portsFromEqRange(kind, a, b){
  if (kind==='eq'){ const p=resolvePort(a); return p==null?{unresolved:String(a)}:[[p,p]]; }
  if (kind==='range'){ const lo=resolvePort(a),hi=resolvePort(b); return (lo==null||hi==null)?{unresolved:a+'-'+b}:[[lo,hi]]; }
  if (kind==='gt'){ const p=resolvePort(a); return p==null?{unresolved:String(a)}:[[p+1,65535]]; }
  if (kind==='lt'){ const p=resolvePort(a); return p==null?{unresolved:String(a)}:[[1,p-1]]; }
  return null;
}

/* ---- Cisco ACL extractor (IOS + ASA) ---- */
function rulesCisco(text){
  const rules=[]; let seq=0;
  const acls={};                 // ACL name -> ordered rules
  const bindings=[];             // {acl, zone(nameif or ifname), dir}
  // --- object model ---
  const netGroups={};            // name -> {items:[{cidr}|{group:name}]}
  const svcGroups={};            // name -> {proto, ports:[[lo,hi]], groups:[name]}
  const objNet={};               // object network NAME -> cidr
  const nameifOf={};             // interface line context -> nameif
  const secLevels={};            // nameif -> security-level
  let sameSecInter=false;
  const dnat=[];                 // {mappedIp, mappedPort, proto, realIp, realPort, realIfc, mappedIfc}
  const objHost={};              // object network NAME -> host ip (for NAT real ip)
  let ctx=null, ctxName=null, curIf=null, curIfName=null;
  const lines=text.split(/\r?\n/);
  // pass 1: objects + interface bindings
  for (const raw of lines){
    const line=raw.replace(/\s+$/,''); const t=line.trim(); let m;
    const indented=/^\s+/.test(line);
    if (!indented){
      ctx=null; ctxName=null;
      if ((m=t.match(/^object-group\s+network\s+(\S+)/i))){ ctx='ng'; ctxName=m[1]; netGroups[ctxName]=netGroups[ctxName]||{items:[]}; }
      else if ((m=t.match(/^object-group\s+service\s+(\S+)(?:\s+(tcp|udp|tcp-udp))?/i))){ ctx='sg'; ctxName=m[1]; svcGroups[ctxName]=svcGroups[ctxName]||{proto:(m[2]||'ip').replace('tcp-udp','ip'),ports:[],groups:[]}; }
      else if ((m=t.match(/^object\s+network\s+(\S+)/i))){ ctx='on'; ctxName=m[1]; objNet[ctxName]=null; }
      else if ((m=t.match(/^interface\s+(\S+.*)$/i))){ ctx='if'; curIfName=m[1].trim(); curIf={nameif:null}; }
      else if ((m=t.match(/^access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)/i))){ bindings.push({acl:m[1], dir:m[2].toLowerCase(), zone:m[3]}); }
      continue;
    }
    // indented lines belong to ctx
    if (ctx==='ng'){
      if ((m=t.match(/^network-object\s+host\s+(\d+\.\d+\.\d+\.\d+)/i))) netGroups[ctxName].items.push({cidr:netKey(m[1],32)});
      else if ((m=t.match(/^network-object\s+object\s+(\S+)/i))) netGroups[ctxName].items.push({obj:m[1]});
      else if ((m=t.match(/^network-object\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i))){ const b=mask2bits(m[2]); netGroups[ctxName].items.push(b!=null?{cidr:netKey(m[1],b)}:{cidr:null}); }
      else if ((m=t.match(/^network-object\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)/i))) netGroups[ctxName].items.push({cidr:netKey(m[1],+m[2])});
      else if ((m=t.match(/^group-object\s+(\S+)/i))) netGroups[ctxName].items.push({group:m[1]});
    } else if (ctx==='sg'){
      if ((m=t.match(/^port-object\s+eq\s+(\S+)/i))){ const p=resolvePort(m[1]); if(p!=null) svcGroups[ctxName].ports.push([p,p]); }
      else if ((m=t.match(/^port-object\s+range\s+(\S+)\s+(\S+)/i))){ const lo=resolvePort(m[1]),hi=resolvePort(m[2]); if(lo!=null&&hi!=null) svcGroups[ctxName].ports.push([lo,hi]); }
      else if ((m=t.match(/^service-object\s+(?:tcp|udp)\s+destination\s+eq\s+(\S+)/i))){ const p=resolvePort(m[1]); if(p!=null) svcGroups[ctxName].ports.push([p,p]); }
      else if ((m=t.match(/^group-object\s+(\S+)/i))) svcGroups[ctxName].groups.push(m[1]);
    } else if (ctx==='on'){
      if ((m=t.match(/^host\s+(\d+\.\d+\.\d+\.\d+)/i))){ objNet[ctxName]=netKey(m[1],32); objHost[ctxName]=m[1]; }
      else if ((m=t.match(/^subnet\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i))){ const b=mask2bits(m[2]); objNet[ctxName]=b!=null?netKey(m[1],b):null; }
      else if ((m=t.match(/^subnet\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)/i))) objNet[ctxName]=netKey(m[1],+m[2]);
      // object NAT: nat (realIfc,mappedIfc) static MAPPED_IP [service tcp REAL_PORT MAPPED_PORT]
      else if ((m=t.match(/^nat\s+\((\S+?),(\S+?)\)\s+static\s+(\d+\.\d+\.\d+\.\d+)(?:\s+service\s+(tcp|udp)\s+(\d+)\s+(\d+))?/i))){
        const realIp=objHost[ctxName];
        if (realIp) dnat.push({ realIfc:m[1], mappedIfc:m[2], mappedIp:m[3],
          proto: m[4]?m[4].toLowerCase():null, realPort: m[5]?+m[5]:null, mappedPort: m[6]?+m[6]:null, realIp });
      }
    } else if (ctx==='if'){
      if ((m=t.match(/^nameif\s+(\S+)/i))) nameifOf[curIfName]=m[1];
      else if ((m=t.match(/^security-level\s+(\d+)/i)) && nameifOf[curIfName]) secLevels[nameifOf[curIfName]]=+m[1];
      else if ((m=t.match(/^ip\s+access-group\s+(\S+)\s+(in|out)/i))){ bindings.push({acl:m[1], dir:m[2].toLowerCase(), zone:(nameifOf[curIfName]||curIfName), _ifname:curIfName}); }
    }
  }
  // second sweep for security-level lines that appeared before nameif was seen, and same-security + IOS static NAT
  { let ifName=null, nif=null;
    for (const raw of lines){
      const t=raw.trim(); let m;
      if (!/^\s/.test(raw)){
        if ((m=t.match(/^interface\s+(\S+.*)$/i))){ ifName=m[1].trim(); nif=null; }
        else if (/^same-security-traffic\s+permit\s+inter-interface/i.test(t)) sameSecInter=true;
        else if ((m=t.match(/^ip\s+nat\s+inside\s+source\s+static\s+(tcp|udp)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)/i)))
          dnat.push({ mappedIp:m[4], mappedPort:+m[5], proto:m[1].toLowerCase(), realIp:m[2], realPort:+m[3] });
        else if ((m=t.match(/^ip\s+nat\s+inside\s+source\s+static\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i)))
          dnat.push({ mappedIp:m[2], mappedPort:null, proto:null, realIp:m[1], realPort:null });
        else ifName=null;
      } else if (ifName){
        if ((m=t.match(/^nameif\s+(\S+)/i))) nif=m[1];
        else if ((m=t.match(/^security-level\s+(\d+)/i)) && nif) secLevels[nif]=+m[1];
      }
    }
  }
  // fix bindings whose zone was an ifname resolved to nameif later
  for (const b of bindings){ if (b._ifname && nameifOf[b._ifname]) b.zone=nameifOf[b._ifname]; }
  // recursive resolution
  const resolveNetGroup = (name, seen=new Set()) => {
    if (seen.has(name)) return []; seen.add(name);
    const g=netGroups[name]; if(!g) return [{unresolved:name}];
    const out=[];
    for (const it of g.items){
      if (it.cidr!==undefined) out.push(it.cidr?{cidr:it.cidr}:{unresolved:name});
      else if (it.group) out.push(...resolveNetGroup(it.group, seen));
      else if (it.obj) out.push(objNet[it.obj]?{cidr:objNet[it.obj]}:{unresolved:it.obj});
    }
    return out.length?out:[{unresolved:name}];
  };
  const resolveSvcGroup = (name, seen=new Set()) => {
    if (seen.has(name)) return {ports:[]}; seen.add(name);
    const g=svcGroups[name]; if(!g) return {unresolved:name};
    let ports=[...g.ports];
    for (const sub of g.groups){ const r=resolveSvcGroup(sub,seen); if(r.ports) ports.push(...r.ports); }
    return {ports, proto:g.proto};
  };
  const parseAddr = (toks,i) => {
    const tk=toks[i];
    if (tk==='any'||tk==='any4') return [[ANY], i+1];
    if (tk==='host') return [[{cidr:netKey(toks[i+1],32)}], i+2];
    if (tk==='object-group'){ const nm=toks[i+1]; return [resolveNetGroup(nm), i+2]; }
    if (tk==='object'){ const nm=toks[i+1]; return [[objNet[nm]?{cidr:objNet[nm]}:{unresolved:nm}], i+2]; }
    if (isIPv4(tk)){
      if (isIPv4(toks[i+1])){
        const asBits=mask2bits(toks[i+1]); const wcBits=wildcardToBits(toks[i+1]);
        const bits=asBits!=null?asBits:(wcBits!=null?wcBits:32);
        return [[{cidr:netKey(tk,bits)}], i+2];
      }
      return [[{cidr:netKey(tk,32)}], i+1];
    }
    return [[{unresolved:tk}], i+1];
  };
  const parsePort = (toks,i) => {
    if (!toks[i]) return [null,i];
    const kw=toks[i].toLowerCase();
    if (kw==='eq') return [portsFromEqRange('eq',toks[i+1]), i+2];
    if (kw==='range') return [portsFromEqRange('range',toks[i+1],toks[i+2]), i+3];
    if (kw==='gt') return [portsFromEqRange('gt',toks[i+1]), i+2];
    if (kw==='lt') return [portsFromEqRange('lt',toks[i+1]), i+2];
    if (kw==='object-group'){ const r=resolveSvcGroup(toks[i+1]); return [r.unresolved?{unresolved:r.unresolved}:r.ports, i+2]; }
    return [null,i];
  };
  // pass 2: access-list rules
  for (const raw of lines){
    const line=raw.trim();
    const m=line.match(/^access-list\s+(\S+)\s+(?:extended\s+)?(permit|deny)\s+(\S+)\s+(.*)$/i);
    if (!m) continue;
    const aclName=m[1], action=m[2].toLowerCase(), proto=m[3].toLowerCase();
    const toks=m[4].trim().split(/\s+/);
    let i=0;
    // optional source service group before src on some ASA forms is rare; skip
    const [srcs,i2]=parseAddr(toks,i); i=i2;
    // optional source port (rare) — check
    let sPort=null;
    if (toks[i] && /^(eq|range|gt|lt)$/i.test(toks[i])){ const [pp,ni]=parsePort(toks,i); i=ni; /* source port ignored for dest-based match */ }
    const [dsts,i3]=parseAddr(toks,i); i=i3;
    let dports=null;
    if (toks[i]){ const [pp,ni]=parsePort(toks,i); if(pp!==null){ dports=pp; i=ni; } }
    const pr=['ip','tcp','udp','icmp'].includes(proto)?proto:'ip';
    acls[aclName]=acls[aclName]||[];
    for (const s of srcs) for (const d of dsts){
      const r={ action, proto:pr, src:s, dst:d, dports, from:null, to:null, raw:line, seq:seq++, acl:aclName };
      rules.push(r); acls[aclName].push(r);
    }
  }
  return { rules, acls, bindings, secLevels, sameSecInter, nat:{dnat}, defaultAction:'deny', zoneScoped:false };
}

/* ---- iptables extractor ---- */
function rulesIptables(text){
  const rules=[]; let seq=0; const chainPolicy={}; const dnat=[]; const snat=[];
  for (const raw of text.split(/\r?\n/)){
    const line=raw.trim();
    let m;
    // DNAT / port-forward in nat table PREROUTING
    if ((m=line.match(/^(?:iptables\s+(?:-t\s+nat\s+)?)?-A\s+PREROUTING\s+(.*-j\s+DNAT.*)$/i))){
      const body=' '+m[1]+' ';
      const dip=(body.match(/\s-d\s+(\d+\.\d+\.\d+\.\d+)/)||[])[1];
      const proto=(body.match(/\s-p\s+(\S+)/)||[])[1];
      const dport=(body.match(/--dport\s+(\d+)/)||[])[1];
      const to=body.match(/--to-destination\s+(\d+\.\d+\.\d+\.\d+)(?::(\d+))?/);
      if (dip && to) dnat.push({ mappedIp:dip, mappedPort:dport?+dport:null, proto:proto?proto.toLowerCase():null, realIp:to[1], realPort:to[2]?+to[2]:null });
      continue;
    }
    // SNAT / MASQUERADE in POSTROUTING
    if ((m=line.match(/^(?:iptables\s+(?:-t\s+nat\s+)?)?-A\s+POSTROUTING\s+(.*-j\s+(?:SNAT|MASQUERADE).*)$/i))){
      const body=' '+m[1]+' ';
      const sm2=body.match(/\s-s\s+(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?/);
      const to=body.match(/--to-source\s+(\d+\.\d+\.\d+\.\d+)/);
      snat.push({ realNet: sm2?netKey(sm2[1], sm2[2]!==undefined?+sm2[2]:32):null,
                  mappedIp: to?to[1]:'(interface address)', fromZone:null, toZone:null });
      continue;
    }
    if ((m=line.match(/^:(\S+)\s+(ACCEPT|DROP|REJECT)/))){ chainPolicy[m[1]]=m[2]==='ACCEPT'?'permit':'deny'; continue; }
    m=line.match(/^(?:iptables\s+)?-A\s+(\S+)\s+(.*)$/);
    if (!m) continue;
    const chain=m[1], body=' '+m[2]+' ';
    if (!/-j\s+(ACCEPT|DROP|REJECT)/.test(body)) continue;
    const action=/-j\s+ACCEPT/.test(body)?'permit':'deny';
    let proto='ip'; const pm=body.match(/\s-p\s+(\S+)/); if(pm) proto=pm[1].toLowerCase();
    let src=ANY, dst=ANY;
    const sm=body.match(/\s-s\s+(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?/); if(sm) src={cidr:netKey(sm[1],sm[2]!==undefined?+sm[2]:32)};
    const dm=body.match(/\s-d\s+(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?/); if(dm) dst={cidr:netKey(dm[1],dm[2]!==undefined?+dm[2]:32)};
    let dports=null;
    const dp=body.match(/--dport\s+(\d+)(?::(\d+))?/); if(dp) dports=[[+dp[1], dp[2]?+dp[2]:+dp[1]]];
    const mp=body.match(/--dports\s+([\d,]+)/); if(mp) dports=mp[1].split(',').map(x=>[+x,+x]);
    rules.push({ action, proto:['ip','tcp','udp','icmp'].includes(proto)?proto:'ip', src, dst, dports, from:null, to:null, raw:line, seq:seq++ });
  }
  const def = chainPolicy['FORWARD'] || chainPolicy['INPUT'] || 'deny';
  return { rules, nat:{dnat,snat}, defaultAction:def, zoneScoped:false };
}

/* ---- FortiGate extractor ---- */
function rulesFortigate(text){
  const rules=[]; let seq=0;
  // address objects
  const addr={}; const svc={}; const vip={}; const dnat=[];
  const stack=[]; let edit=null, cur=null, ctx='';
  const unq=s=>s?s.replace(/^"(.*)"$/,'$1'):s;
  for (const raw of text.split(/\r?\n/)){
    const line=raw.trim(); let m;
    if ((m=line.match(/^config\s+(.+)$/i))){ stack.push(m[1].toLowerCase().trim()); ctx=stack[stack.length-1]; continue; }
    if (/^end$/i.test(line)){ stack.pop(); ctx=stack[stack.length-1]||''; cur=null; edit=null; continue; }
    if ((m=line.match(/^edit\s+(.+)$/i))){ edit=unq(m[1]);
      if (ctx==='firewall address') cur={type:'addr',name:edit,cidr:null};
      else if (ctx==='firewall service custom') cur={type:'svc',name:edit,proto:'ip',ports:null};
      else if (ctx==='firewall vip') cur={type:'vip',name:edit,extip:null,mappedip:null,extport:null,mappedport:null,proto:'tcp',portforward:false};
      else if (ctx==='firewall policy') cur={type:'pol',id:edit,srcaddr:[],dstaddr:[],service:[],action:'deny',srcintf:[],dstintf:[]};
      else cur=null;
      continue; }
    if (/^next$/i.test(line)){
      if (cur && cur.type==='addr') addr[cur.name]=cur.cidr;
      if (cur && cur.type==='svc') svc[cur.name]={proto:cur.proto,ports:cur.ports};
      if (cur && cur.type==='vip'){ vip[cur.name]=cur;
        if (cur.extip && cur.mappedip) dnat.push({ mappedIp:cur.extip, mappedPort:cur.portforward&&cur.extport?+cur.extport:null,
          proto:cur.portforward?cur.proto:null, realIp:cur.mappedip, realPort:cur.portforward&&cur.mappedport?+cur.mappedport:null }); }
      if (cur && cur.type==='pol') rules._pols=(rules._pols||[]).concat(cur);
      cur=null; edit=null; continue; }
    if ((m=line.match(/^set\s+(\S+)\s+(.+)$/i))){
      const k=m[1].toLowerCase(), v=m[2].trim();
      if (cur && cur.type==='addr'){
        if (k==='subnet'){ const p=v.split(/\s+/); const b=p[1]?(/^\d+$/.test(p[1])?+p[1]:mask2bits(p[1])):32; cur.cidr=isIPv4(p[0])?netKey(p[0],b):null; }
      } else if (cur && cur.type==='svc'){
        if (k==='tcp-portrange'){ cur.proto='tcp'; cur.ports=v.split(/\s+/).map(r=>{const x=r.split('-');return [+x[0], x[1]?+x[1]:+x[0]];}); }
        else if (k==='udp-portrange'){ cur.proto='udp'; cur.ports=v.split(/\s+/).map(r=>{const x=r.split('-');return [+x[0], x[1]?+x[1]:+x[0]];}); }
        else if (k==='protocol' && /icmp/i.test(v)) cur.proto='icmp';
      } else if (cur && cur.type==='vip'){
        if (k==='extip') cur.extip=unq(v.split(/[\s-]/)[0]);
        else if (k==='mappedip') cur.mappedip=unq(v.replace(/"/g,'').split(/[\s-]/)[0]);
        else if (k==='extport') cur.extport=unq(v.split(/[\s-]/)[0]);
        else if (k==='mappedport') cur.mappedport=unq(v.split(/[\s-]/)[0]);
        else if (k==='protocol') cur.proto=v.toLowerCase();
        else if (k==='portforward' && /enable/i.test(v)) cur.portforward=true;
      } else if (cur && cur.type==='pol'){
        const list=unq(v).split(/"\s+"/).map(unq);
        if (k==='srcaddr') cur.srcaddr=list; else if (k==='dstaddr') cur.dstaddr=list;
        else if (k==='service') cur.service=list; else if (k==='action') cur.action=v.toLowerCase();
        else if (k==='srcintf') cur.srcintf=list; else if (k==='dstintf') cur.dstintf=list;
      }
    }
  }
  const resolveAddr = nm => {
    if (/^all$/i.test(nm)) return ANY;
    if (vip[nm]) return vip[nm].extip?{cidr:netKey(vip[nm].extip,32)}:{unresolved:nm};  // VIP matched by its external ip
    if (addr[nm]!==undefined) return addr[nm]?{cidr:addr[nm]}:{unresolved:nm};
    return {unresolved:nm};
  };
  const resolveSvc = nm => {
    if (/^all$/i.test(nm)) return {proto:'ip',ports:null};
    if (svc[nm]) return svc[nm];
    if (BUILTIN_SVC[nm]) return {proto:BUILTIN_SVC[nm].proto, ports:BUILTIN_SVC[nm].ports||null};
    if (BUILTIN_SVC[nm.toUpperCase()]) { const b=BUILTIN_SVC[nm.toUpperCase()]; return {proto:b.proto,ports:b.ports||null}; }
    return {proto:'ip',ports:null,unresolved:nm};
  };
  for (const p of (rules._pols||[])){
    const action = p.action==='accept'?'permit':'deny';
    for (const sa of (p.srcaddr.length?p.srcaddr:['all'])) for (const da of (p.dstaddr.length?p.dstaddr:['all'])) for (const sv of (p.service.length?p.service:['ALL'])){
      const s=resolveAddr(sa), d=resolveAddr(da), svcr=resolveSvc(sv);
      rules.push({ action, proto:svcr.proto||'ip', src:s, dst:d,
        dports: svcr.ports || (svcr.unresolved?{unresolved:svcr.unresolved}:null),
        from:(p.srcintf[0]||null), to:(p.dstintf[0]||null), raw:`policy ${p.id}: ${sa}→${da} ${sv} ${p.action}`, seq:seq++ });
    }
  }
  delete rules._pols;
  return { rules, nat:{dnat}, defaultAction:'deny', zoneScoped:true, intfZone:null };
}

/* ---- Juniper extractor (set-format) ---- */
function rulesJuniper(text){
  const rules=[]; let seq=0;
  const addrBook={}; // "zone:name" or "global:name" -> cidr ; also name->cidr
  const apps={};     // name -> {proto,ports}
  const pol={};      // key from|to|name -> {src:[],dst:[],app:[],action}
  for (const raw of text.split(/\r?\n/)){
    const line=raw.trim(); let m;
    if ((m=line.match(/^set\s+security\s+address-book\s+\S+\s+address\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)/))) addrBook[m[1]]=netKey(m[2],+m[3]);
    else if ((m=line.match(/^set\s+security\s+zones\s+security-zone\s+\S+\s+address-book\s+address\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)/))) addrBook[m[1]]=netKey(m[2],+m[3]);
    else if ((m=line.match(/^set\s+applications\s+application\s+(\S+)\s+(.*)$/))){
      const nm=m[1]; apps[nm]=apps[nm]||{proto:'ip',ports:null}; const rest=m[2];
      let mm; if((mm=rest.match(/protocol\s+(\S+)/))) apps[nm].proto=mm[1].toLowerCase();
      if((mm=rest.match(/destination-port\s+(\d+)(?:-(\d+))?/))) apps[nm].ports=[[+mm[1], mm[2]?+mm[2]:+mm[1]]];
    }
    else if ((m=line.match(/^set\s+security\s+policies\s+from-zone\s+(\S+)\s+to-zone\s+(\S+)\s+policy\s+(\S+)\s+(.*)$/))){
      const key=m[1]+'|'+m[2]+'|'+m[3];
      const p=pol[key]||(pol[key]={from:m[1],to:m[2],name:m[3],src:[],dst:[],app:[],action:null});
      const rest=m[4]; let mm;
      if((mm=rest.match(/match\s+source-address\s+(\S+)/))) p.src.push(mm[1]);
      if((mm=rest.match(/match\s+destination-address\s+(\S+)/))) p.dst.push(mm[1]);
      if((mm=rest.match(/match\s+application\s+(\S+)/))) p.app.push(mm[1]);
      if(/then\s+permit/.test(rest)) p.action='permit';
      if(/then\s+deny|then\s+reject/.test(rest)) p.action='deny';
    }
  }
  const resolveAddr = nm => /^any$/i.test(nm)?ANY : (addrBook[nm]?{cidr:addrBook[nm]}:{unresolved:nm});
  const resolveApp = nm => {
    if (/^any$/i.test(nm)) return {proto:'ip',ports:null};
    if (apps[nm]) return apps[nm];
    if (BUILTIN_SVC[nm]) return {proto:BUILTIN_SVC[nm].proto, ports:BUILTIN_SVC[nm].ports||null};
    return {proto:'ip',ports:null,unresolved:nm};
  };
  for (const key in pol){
    const p=pol[key]; const action=p.action||'deny';
    for (const sa of (p.src.length?p.src:['any'])) for (const da of (p.dst.length?p.dst:['any'])) for (const ap of (p.app.length?p.app:['any'])){
      const s=resolveAddr(sa), d=resolveAddr(da), a=resolveApp(ap);
      rules.push({ action, proto:a.proto||'ip', src:s, dst:d, dports:a.ports||(a.unresolved?{unresolved:a.unresolved}:null),
        from:p.from, to:p.to, raw:`policy ${p.name} (${p.from}->${p.to}): ${sa}→${da} ${ap} ${action}`, seq:seq++ });
    }
  }
  return { rules, defaultAction:'deny', zoneScoped:true };
}

/* ---- evaluator ---- */
function addrMatch(spec, ip){
  if (!spec) return {match:false};
  if (spec.any) return {match:true};
  if (spec.cidr) return {match: spec.cidr && cidrContains(spec.cidr, ip)};
  if (spec.unresolved) return {match:false, uncertain:true};
  return {match:false};
}
function portMatch(dports, proto, dport){
  if (dports==null) return {match:true};              // any port
  if (dports.unresolved) return {match:false, uncertain:true};
  if (proto==='icmp') return {match:true};
  if (dport==null) return {match:true};
  for (const [lo,hi] of dports) if (dport>=lo && dport<=hi) return {match:true};
  return {match:false};
}
function matchRule(r, pkt){
  if (r.proto!=='ip' && pkt.proto!=='ip' && r.proto!==pkt.proto) return {match:false};
  const sm=addrMatch(r.src, pkt.sip);
  const dm=addrMatch(r.dst, pkt.dip);
  const pm=portMatch(r.dports, pkt.proto, pkt.dport);
  if (sm.match && dm.match && pm.match) return {match:true};
  const couldMatch = (sm.match||sm.uncertain)&&(dm.match||dm.uncertain)&&(pm.match||pm.uncertain);
  return {match:false, uncertain:(sm.uncertain||dm.uncertain||pm.uncertain)&&couldMatch};
}
function evalAcl(rulesList, pkt){
  // one ACL: first-match wins, implicit deny at end
  let uncertain=false;
  for (const r of rulesList){
    const mr=matchRule(r,pkt);
    if (mr.match) return { decision:r.action, rule:r, uncertain };
    if (mr.uncertain) uncertain=true;
  }
  return { decision:'deny', rule:null, implicit:true, uncertain };
}
/* destination NAT translation: returns {ip, port, rule} or null */
function translateDest(model, dip, dport, proto){
  const dnat = model.nat && model.nat.dnat;
  if (!dnat || !dnat.length) return null;
  for (const n of dnat){
    if (n.mappedIp !== dip) continue;
    if (n.proto && proto!=='ip' && n.proto!==proto) continue;
    if (n.mappedPort!=null && dport!=null && n.mappedPort!==dport) continue;
    return { ip:n.realIp, port:(n.realPort!=null?n.realPort:dport), rule:n };
  }
  return null;
}
function evalDevice(model, pkt){
  // pkt: {sip, dip, proto, dport, fromZone, toZone}
  const useSec = model.secLevels && Object.keys(model.secLevels).length>0;
  if (model.acls && (model.bindings && model.bindings.length || useSec)){
    const inbound = (model.bindings||[]).filter(b=>b.dir==='in' && b.zone===pkt.fromZone).map(b=>b.acl);
    const outbound= (model.bindings||[]).filter(b=>b.dir==='out'&& b.zone===pkt.toZone ).map(b=>b.acl);
    const applicable=[...new Set([...inbound,...outbound])];
    if (applicable.length===0){
      // no ACL on these interfaces → ASA security-level default if known
      const si=model.secLevels?.[pkt.fromZone], se=model.secLevels?.[pkt.toZone];
      if (si!=null && se!=null){
        if (si>se) return { decision:'permit', rule:null, implicit:true, note:`security-level ${si}→${se} (high→low, allowed)` };
        if (si<se) return { decision:'deny', rule:null, implicit:true, note:`security-level ${si}→${se} (low→high, default deny)` };
        return model.sameSecInter
          ? { decision:'permit', rule:null, implicit:true, note:`same security-level ${si} (same-security permit)` }
          : { decision:'deny', rule:null, implicit:true, note:`same security-level ${si} (default deny)` };
      }
      return { decision:'permit', rule:null, implicit:true, note:'no ACL bound on this interface/direction' };
    }
    let uncertain=false, lastPermit=null;
    for (const aclName of applicable){
      const res=evalAcl(model.acls[aclName]||[], pkt);
      if (res.uncertain) uncertain=true;
      if (res.decision==='deny') return { decision:'deny', rule:res.rule, implicit:res.implicit, uncertain, boundAcl:aclName };
      lastPermit=res.rule;
    }
    return { decision:'permit', rule:lastPermit, uncertain };
  }
  // Flat fallback
  let uncertainSkipped=false;
  for (const r of model.rules){
    if (model.zoneScoped && (r.from||r.to)){
      if (r.from && pkt.fromZone && r.from!==pkt.fromZone) continue;
      if (r.to && pkt.toZone && r.to!==pkt.toZone) continue;
    }
    const mr=matchRule(r,pkt);
    if (mr.match) return { decision:r.action, rule:r };
    if (mr.uncertain) uncertainSkipped=true;
  }
  return { decision:model.defaultAction, rule:null, implicit:true, uncertain:uncertainSkipped };
}

/* ---- Palo Alto PAN-OS (set format) ---- */
function rulesPaloalto(text){
  const rules=[]; let seq=0;
  const addr={}, addrGrp={}, svc={}, svcGrp={}, pol={};
  const dnat=[], snat=[];
  const unq=s=>s?s.replace(/^"(.*)"$/,'$1').replace(/^'(.*)'$/,'$1'):s;
  for (const raw of text.split(/\r?\n/)){
    const t=raw.trim(); let m;
    if ((m=t.match(/^set\s+address\s+(\S+)\s+ip-netmask\s+(\S+)/i))){ const v=unq(m[2]); addr[m[1]]= v.includes('/')?netKey(v.split('/')[0],+v.split('/')[1]) : netKey(v, v.includes(':')?128:32); }
    else if ((m=t.match(/^set\s+address\s+(\S+)\s+ip-range\s+/i))) addr[m[1]]=null;
    else if ((m=t.match(/^set\s+address-group\s+(\S+)\s+static\s+\[?\s*(.+?)\s*\]?$/i))) addrGrp[m[1]]=m[2].split(/\s+/).map(unq);
    else if ((m=t.match(/^set\s+service\s+(\S+)\s+protocol\s+(tcp|udp)\s+port\s+(\S+)/i))){
      const ports=unq(m[3]).split(',').map(r=>{const x=r.split('-');return [+x[0], x[1]?+x[1]:+x[0]];});
      svc[m[1]]={proto:m[2].toLowerCase(), ports};
    }
    else if ((m=t.match(/^set\s+service-group\s+(\S+)\s+members\s+\[?\s*(.+?)\s*\]?$/i))) svcGrp[m[1]]=m[2].split(/\s+/).map(unq);
    else if ((m=t.match(/^set\s+rulebase\s+security\s+rules\s+(\S+)\s+(.*)$/i))){
      const name=unq(m[1]);
      const p=pol[name]||(pol[name]={from:[],to:[],src:[],dst:[],svc:[],action:null});
      // tokenize the remainder into keyword clauses (handles both one-per-line and combined forms)
      let rest=m[2].trim();
      const KW={from:'from',to:'to',source:'src',destination:'dst',service:'svc'};
      // strip brackets, split into tokens
      const toks=rest.replace(/[\[\]]/g,' ').split(/\s+/).filter(Boolean);
      let field=null;
      for (let k=0;k<toks.length;k++){
        const tok=toks[k];
        const low=tok.toLowerCase();
        if (KW[low]!==undefined){ field=KW[low]; continue; }
        if (low==='action'){ field='action'; continue; }
        if (low==='application'||low==='category'||low==='profile-setting'||low==='log-setting'||low==='rule-type'){ field='_skip'; continue; }
        if (field==='action'){ p.action=/allow/i.test(tok)?'permit':'deny'; field=null; continue; }
        if (field==='_skip') continue;
        if (field && p[field]) p[field].push(unq(tok));
      }
    }
  }
  const resolveAddr = nm => {
    if (/^any$/i.test(nm)) return [ANY];
    if (addr[nm]!==undefined) return [addr[nm]?{cidr:addr[nm]}:{unresolved:nm}];
    if (addrGrp[nm]) return addrGrp[nm].flatMap(resolveAddr);
    if (/\//.test(nm) && isIP(nm.split('/')[0])) { const [ip,b]=nm.split('/'); return [{cidr:netKey(ip,+b)}]; }
    if (isIP(nm)) return [{cidr:netKey(nm, nm.includes(':')?128:32)}];
    return [{unresolved:nm}];
  };
  const resolveSvc = nm => {
    if (/^any$/i.test(nm)||/^application-default$/i.test(nm)) return [{proto:'ip',ports:null}];
    if (svc[nm]) return [svc[nm]];
    if (svcGrp[nm]) return svcGrp[nm].flatMap(resolveSvc);
    if (BUILTIN_SVC[nm]) return [{proto:BUILTIN_SVC[nm].proto,ports:BUILTIN_SVC[nm].ports||null}];
    return [{proto:'ip',ports:null,unresolved:nm}];
  };
  for (const name in pol){
    const p=pol[name]; const action=p.action||'deny';
    const froms=p.from.length?p.from:['any'], tos=p.to.length?p.to:['any'];
    const srcs=p.src.length?p.src:['any'], dsts=p.dst.length?p.dst:['any'], svcs=p.svc.length?p.svc:['any'];
    for (const fz of froms) for (const tz of tos)
      for (const sa of srcs) for (const da of dsts) for (const sv of svcs)
        for (const s of resolveAddr(sa)) for (const d of resolveAddr(da)) for (const svr of resolveSvc(sv))
          rules.push({ action, proto:svr.proto||'ip', src:s, dst:d,
            dports: svr.ports||(svr.unresolved?{unresolved:svr.unresolved}:null),
            from:(/^any$/i.test(fz)?null:fz), to:(/^any$/i.test(tz)?null:tz),
            raw:`rule ${name} (${fz}->${tz}): ${sa}→${da} ${sv} ${action}`, seq:seq++ });
  }
  return { rules, nat:{dnat,snat}, defaultAction:'deny', zoneScoped:true };
}

/* ---- Arista EOS ---- */
function rulesArista(text){
  const rules=[]; let seq=0;
  const acls={}; const bindings=[];
  let curAcl=null, curIf=null;
  for (const raw of text.split(/\r?\n/)){
    const line=raw.replace(/\s+$/,''); const t=line.trim(); let m;
    const indented=/^\s+/.test(line);
    if (!indented){
      curIf=null;
      if ((m=t.match(/^ip\s+access-list\s+(?:standard\s+|extended\s+)?(\S+)/i))){ curAcl=m[1]; acls[curAcl]=acls[curAcl]||[]; continue; }
      if ((m=t.match(/^interface\s+(\S+)/i))){ curIf=m[1]; curAcl=null; continue; }
      curAcl=null;
    } else if (curAcl){
      m=t.match(/^(?:\d+\s+)?(permit|deny)\s+(\S+)\s+(.*)$/i);
      if (!m) continue;
      const action=m[1].toLowerCase(), proto=m[2].toLowerCase();
      const toks=m[3].trim().split(/\s+/); let i=0;
      const parseA = () => {
        const tk=toks[i];
        if (tk==='any'){ i++; return ANY; }
        if (tk==='host'){ const ip=toks[i+1]; i+=2; return {cidr:netKey(ip, ip.includes(':')?128:32)}; }
        if (/\//.test(tk)){ const [ip,b]=tk.split('/'); i++; return {cidr:netKey(ip,+b)}; }
        if (isIP(tk)){ i++; return {cidr:netKey(tk, tk.includes(':')?128:32)}; }
        i++; return {unresolved:tk};
      };
      const src=parseA(); const dst=parseA();
      let dports=null;
      if (toks[i] && /^(eq|range|gt|lt)$/i.test(toks[i])){
        const kw=toks[i].toLowerCase();
        if (kw==='eq'){ const p=resolvePort(toks[i+1]); dports=p!=null?[[p,p]]:{unresolved:toks[i+1]}; i+=2; }
        else if (kw==='range'){ const lo=resolvePort(toks[i+1]),hi=resolvePort(toks[i+2]); dports=(lo!=null&&hi!=null)?[[lo,hi]]:{unresolved:toks[i+1]}; i+=3; }
        else { const p=resolvePort(toks[i+1]); dports=p!=null?(kw==='gt'?[[p+1,65535]]:[[1,p-1]]):{unresolved:toks[i+1]}; i+=2; }
      }
      const pr=['ip','tcp','udp','icmp'].includes(proto)?proto:'ip';
      const r={action,proto:pr,src,dst,dports,from:null,to:null,raw:t,seq:seq++,acl:curAcl};
      rules.push(r); acls[curAcl].push(r);
    } else if (curIf){
      if ((m=t.match(/^ip\s+access-group\s+(\S+)\s+(in|out)/i))) bindings.push({acl:m[1],dir:m[2].toLowerCase(),zone:curIf});
    }
  }
  return { rules, acls, bindings, defaultAction:'deny', zoneScoped:false };
}

/* ---- Hirschmann HiOS (industrial switch, IOS-like ACLs) ---- */
function rulesHirschmann(text){ return rulesArista(text); }

/* ---- Moxa secure router/switch firewall ---- */
function rulesMoxa(text){
  const rules=[]; let seq=0;
  // Moxa firewall rules: "Index Action Src-IP Dst-IP Protocol Src-Port Dst-Port" style, or CLI "firewall ... "
  for (const raw of text.split(/\r?\n/)){
    const t=raw.trim(); let m;
    // CLI form: firewall filter <idx> action accept/drop src-ip X/Y dst-ip X/Y protocol tcp dst-port N
    if ((m=t.match(/^(?:firewall\s+)?(?:filter\s+)?(?:rule\s+)?\d*\s*(accept|permit|drop|deny)\s+(.*)$/i)) && /(?:src-ip|dst-ip|source|dest)/i.test(t)){
      const action=/accept|permit/i.test(m[1])?'permit':'deny';
      const body=m[2];
      const sip=(body.match(/src-ip\s+(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?/i));
      const dip=(body.match(/dst-ip\s+(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?/i));
      const pr=(body.match(/protocol\s+(tcp|udp|icmp|any)/i)||[])[1];
      const dpt=(body.match(/dst-port\s+(\d+)(?:-(\d+))?/i));
      rules.push({ action,
        proto: pr && !/any/i.test(pr) ? pr.toLowerCase():'ip',
        src: sip?{cidr:netKey(sip[1], sip[2]?+sip[2]:32)}:ANY,
        dst: dip?{cidr:netKey(dip[1], dip[2]?+dip[2]:32)}:ANY,
        dports: dpt?[[+dpt[1], dpt[2]?+dpt[2]:+dpt[1]]]:null,
        from:null,to:null, raw:t, seq:seq++ });
    }
  }
  // default policy
  let def='deny';
  const dm=text.match(/firewall\s+(?:default\s+)?policy\s+(accept|permit|drop|deny)/i);
  if (dm) def=/accept|permit/i.test(dm[1])?'permit':'deny';
  return { rules, defaultAction:def, zoneScoped:false };
}

/* ---- Siemens SCALANCE S (industrial firewall) ---- */
function rulesScalance(text){
  const rules=[]; let seq=0;
  for (const raw of text.split(/\r?\n/)){
    const t=raw.trim(); let m;
    // representative: "rule <n> from <zone> to <zone> src <ip/cidr|any> dst <ip/cidr|any> service <tcp/443|any> action allow/drop"
    if ((m=t.match(/^(?:rule\s+\d*\s+)?(?:packet\s+filter\s+)?(?:from\s+(\S+)\s+to\s+(\S+)\s+)?src\s+(\S+)\s+dst\s+(\S+)\s+(?:service\s+(\S+)\s+)?action\s+(allow|permit|drop|deny|reject)/i))){
      const action=/allow|permit/i.test(m[6])?'permit':'deny';
      const parseAddr=v=>/^any$/i.test(v)?ANY:(v.includes('/')?{cidr:netKey(v.split('/')[0],+v.split('/')[1])}:(isIP(v)?{cidr:netKey(v,v.includes(':')?128:32)}:{unresolved:v}));
      let proto='ip', dports=null;
      if (m[5] && !/any/i.test(m[5])){ const sv=m[5].split('/'); if(['tcp','udp','icmp'].includes(sv[0].toLowerCase())) proto=sv[0].toLowerCase(); if(sv[1]){ const p=resolvePort(sv[1]); if(p!=null) dports=[[p,p]]; } }
      rules.push({ action, proto, src:parseAddr(m[3]), dst:parseAddr(m[4]), dports,
        from:m[1]||null, to:m[2]||null, raw:t, seq:seq++ });
    }
  }
  return { rules, defaultAction:'deny', zoneScoped: /from\s+\S+\s+to\s+\S+/i.test(text) };
}

/* ---- SEL (Schweitzer) security gateway ---- */
function rulesSel(text){
  const rules=[]; let seq=0;
  for (const raw of text.split(/\r?\n/)){
    const t=raw.trim(); let m;
    if ((m=t.match(/^access-?rule\s+\d*\s*(permit|allow|deny|block)\s+source\s+(\S+)\s+destination\s+(\S+)(?:\s+service\s+(\S+))?/i))){
      const action=/permit|allow/i.test(m[1])?'permit':'deny';
      const pa=v=>/^any$/i.test(v)?ANY:(v.includes('/')?{cidr:netKey(v.split('/')[0],+v.split('/')[1])}:(isIP(v)?{cidr:netKey(v,v.includes(':')?128:32)}:{unresolved:v}));
      let proto='ip', dports=null;
      if (m[4] && !/any/i.test(m[4])){ const sv=m[4].split('/'); if(['tcp','udp','icmp'].includes(sv[0].toLowerCase())) proto=sv[0].toLowerCase(); if(sv[1]){ const p=resolvePort(sv[1]); if(p!=null) dports=[[p,p]]; } }
      rules.push({ action, proto, src:pa(m[2]), dst:pa(m[3]), dports, from:null, to:null, raw:t, seq:seq++ });
    }
  }
  let def='deny'; if (/default\s+(permit|allow)/i.test(text)) def='permit';
  return { rules, defaultAction:def, zoneScoped:false };
}

/* ---- Phoenix Contact mGuard ---- */
function rulesMguard(text){
  const rules=[]; let seq=0;
  for (const raw of text.split(/\r?\n/)){
    const t=raw.trim(); let m;
    if ((m=t.match(/^firewall\s+(?:incoming|outgoing|forward)?\s*\d*\s*from\s+(\S+)\s+to\s+(\S+)\s+(.*?)action\s+(accept|permit|drop|reject|deny)/i))){
      const action=/accept|permit/i.test(m[4])?'permit':'deny';
      const pa=v=>/^any$/i.test(v)||/^0\.0\.0\.0\/0$/.test(v)?ANY:(v.includes('/')?{cidr:netKey(v.split('/')[0],+v.split('/')[1])}:(isIP(v)?{cidr:netKey(v,v.includes(':')?128:32)}:{unresolved:v}));
      const mid=m[3]||'';
      let proto='ip'; const pm=mid.match(/protocol\s+(tcp|udp|icmp)/i); if(pm) proto=pm[1].toLowerCase();
      let dports=null; const dp=mid.match(/(?:dport|port)\s+(\d+)(?:-(\d+))?/i); if(dp) dports=[[+dp[1], dp[2]?+dp[2]:+dp[1]]];
      rules.push({ action, proto, src:pa(m[1]), dst:pa(m[2]), dports, from:null, to:null, raw:t, seq:seq++ });
    }
  }
  let def='deny'; if (/firewall\s+policy\s+(accept|permit)/i.test(text)) def='permit';
  return { rules, defaultAction:def, zoneScoped:false };
}

/* ---- Waterfall unidirectional security gateway (data diode) ---- */
function rulesWaterfall(text){
  const rules=[]; let seq=0;
  let srcSide=null, dstSide=null; const replicated=[];
  for (const raw of text.split(/\r?\n/)){
    const t=raw.trim(); let m;
    if ((m=t.match(/^(?:replication\s+)?source-?side\s+(\S+).*?destination-?side\s+(\S+)/i))){ srcSide=m[1]; dstSide=m[2]; }
    else if ((m=t.match(/^replicate\s+(?:server\s+)?(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?(?:\s+protocol\s+(tcp|udp))?(?:\s+port\s+(\d+))?/i)))
      replicated.push({ ip:m[1], bits:m[2]?+m[2]:32, proto:m[3]?m[3].toLowerCase():'ip', port:m[4]?+m[4]:null });
  }
  for (const r of replicated)
    rules.push({ action:'permit', proto:r.proto, src:ANY, dst:{cidr:netKey(r.ip,r.bits)},
      dports:r.port?[[r.port,r.port]]:null, from:srcSide, to:dstSide,
      raw:`replicate ${r.ip}${r.port?':'+r.port:''} ${srcSide||'src'}→${dstSide||'dst'}`, seq:seq++ });
  rules.push({ action:'deny', proto:'ip', src:ANY, dst:ANY, dports:null, from:dstSide, to:srcSide,
    raw:`unidirectional gateway: ${dstSide||'dst'}→${srcSide||'src'} physically blocked (data diode)`, seq:seq++ });
  return { rules, defaultAction:'deny', zoneScoped:true, unidirectional:{srcSide,dstSide} };
}

/* reusable first-match evaluator for a bare rule list (used by L2 port ACLs) */
function evalRuleList(rulesList, pkt, defaultAction){
  let uncertain=false;
  for (const r of (rulesList||[])){
    const mr=matchRule(r,pkt);
    if (mr.match) return { decision:r.action, rule:r, uncertain };
    if (mr.uncertain) uncertain=true;
  }
  return { decision:defaultAction||'deny', rule:null, implicit:true, uncertain };
}

function translateSource(model, sip, fromZone, toZone){
  const snat = model.nat && model.nat.snat;
  if (!snat || !snat.length) return null;
  for (const n of snat){
    if (n.realNet && !cidrContains(n.realNet, sip)) continue;
    if (n.fromZone && fromZone && n.fromZone!==fromZone) continue;
    if (n.toZone && toZone && n.toZone!==toZone) continue;
    return { ip:n.mappedIp, rule:n };
  }
  return null;
}

module.exports = { ip2int,int2ip,mask2bits,wildcardToBits,netKey,cidrContains,isIPv4,isIPv6,isIP,resolvePort,
  rulesCisco,rulesIptables,rulesFortigate,rulesJuniper,rulesPaloalto,rulesArista,
  rulesHirschmann,rulesMoxa,rulesScalance,rulesSel,rulesMguard,rulesWaterfall,
  evalDevice,evalRuleList,translateDest,translateSource,PORTNAME,BUILTIN_SVC };
