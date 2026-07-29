/* ---- pfSense extractor (XML) ---- */
function rulesPfsense(text){
  const rules=[]; let seq=0;
  let doc; try{ doc=new DOMParser().parseFromString(text,'application/xml'); }catch(e){ return {rules:[],defaultAction:'deny',zoneScoped:false}; }
  if (doc.querySelector('parsererror')) return {rules:[],defaultAction:'deny',zoneScoped:false};
  const addrOf = el => {
    if (!el) return ANY;
    if (el.querySelector(':scope > any')) return ANY;
    const net=el.querySelector(':scope > network')?.textContent;
    const addr=el.querySelector(':scope > address')?.textContent;
    if (addr && /\d+\.\d+\.\d+\.\d+/.test(addr)){ const [ip,bits]=addr.split('/'); return {cidr:netKey(ip, bits?+bits:32)}; }
    if (net && /\d+\.\d+\.\d+\.\d+/.test(net)){ const [ip,bits]=net.split('/'); return {cidr:netKey(ip, bits?+bits:32)}; }
    return {unresolved: net||addr||'alias'};
  };
  const portOf = el => {
    if (!el) return null;
    const p=el.querySelector(':scope > port')?.textContent;
    if (!p) return null;
    if (/^\d+$/.test(p)) return [[+p,+p]];
    const rp=resolvePort(p); return rp!=null?[[rp,rp]]:{unresolved:p};
  };
  for (const r of doc.querySelectorAll('filter > rule')){
    const type=r.querySelector(':scope > type')?.textContent||'pass';
    if (/disabled/.test(r.innerHTML) && r.querySelector(':scope > disabled')) continue;
    const action = type==='pass'?'permit':'deny';
    let proto=(r.querySelector(':scope > protocol')?.textContent||'ip').toLowerCase();
    if (proto==='tcp/udp') proto='ip';
    const src=addrOf(r.querySelector(':scope > source'));
    const dst=addrOf(r.querySelector(':scope > destination'));
    const dports=portOf(r.querySelector(':scope > destination'));
    rules.push({ action, proto:['ip','tcp','udp','icmp'].includes(proto)?proto:'ip', src, dst, dports,
      from:(r.querySelector(':scope > interface')?.textContent||null), to:null,
      raw:`${type} on ${r.querySelector(':scope > interface')?.textContent||'?'}${r.querySelector(':scope > descr')?.textContent?' — '+r.querySelector(':scope > descr').textContent:''}`, seq:seq++ });
  }
  return { rules, defaultAction:'deny', zoneScoped:false };
}
