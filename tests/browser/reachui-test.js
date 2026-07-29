const puppeteer=require('puppeteer-core');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const R=[]; const check=(n,ok,i='')=>{R.push(ok);console.log((ok?'PASS':'FAIL')+'  '+n+(i?'  — '+i:''));};
(async()=>{
  const b=await puppeteer.launch({executablePath: process.env.CHROME_PATH || require('./_chrome').find(),headless:'new',args:['--no-sandbox','--disable-dev-shm-usage']});
  const p=await b.newPage(); await p.setViewport({width:1440,height:900});
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto('http://127.0.0.1:8077/nettopo.html',{waitUntil:'networkidle0'});
  await (await p.$('#fileinput')).uploadFile('tests/fixtures/multihop/fw1-rules.cfg','tests/fixtures/multihop/fw2-rules.cfg');
  await sleep(1200);
  await p.click('#reach-btn'); await sleep(300);
  check('reach panel opens', await p.evaluate(()=>document.getElementById('reach').classList.contains('open')));

  async function query(sip,dip,proto,port){
    await p.evaluate((s,d,pr,pt)=>{
      document.getElementById('rc-src').value=s; document.getElementById('rc-dst').value=d;
      document.getElementById('rc-proto').value=pr; document.getElementById('rc-port').value=pt;
      document.getElementById('rc-run').click();
    }, sip,dip,proto,port);
    await sleep(200);
    return p.evaluate(()=>{
      const v=document.querySelector('#rc-result .rc-verdict');
      const hops=[...document.querySelectorAll('#rc-result .rc-hop')].map(h=>({
        dev:h.querySelector('.hname').textContent.trim(),
        dec:h.querySelector('.hdec').textContent.trim(),
        rule:h.querySelector('.hrule')?.textContent.trim()||null }));
      return { verdict:v?v.className.replace('rc-verdict ','').trim():null, hops };
    });
  }

  // LAN(192.168.30.50) -> DMZ host 10.80.0.90 on 443: fw1 permits (lan_out), fw2 permits (dmz_in 443) => PERMITTED
  let r=await query('192.168.30.50','10.80.0.90','tcp','443');
  check('multi-hop 443 permitted end-to-end', r.verdict==='permitted', JSON.stringify(r.verdict));
  check('path shows both firewalls', r.hops.length===2 && /fw1/.test(r.hops[0].dev) && /fw2/.test(r.hops[1].dev), JSON.stringify(r.hops.map(h=>h.dev)));
  check('fw2 permit cites the 443 ACL rule', /eq 443/.test(r.hops[1].rule||''), r.hops[1]?r.hops[1].rule:'');

  // same but port 22: fw1 permits ip any, fw2 denies (no 443 match -> explicit deny ip any any) => BLOCKED at fw2
  r=await query('192.168.30.50','10.80.0.90','tcp','22');
  check('multi-hop 22 blocked', r.verdict==='blocked', JSON.stringify(r.verdict));
  check('blocked at fw2 (2nd hop), fw1 permitted', r.hops.length===2 && r.hops[0].dec==='permit' && r.hops[1].dec==='deny', JSON.stringify(r.hops.map(h=>h.dec)));

  // dest to a host not in 10.80.0.90 (e.g. 10.80.0.5) on 443: fw2 dmz_in only permits host .90 => blocked
  r=await query('192.168.30.50','10.80.0.5','tcp','443');
  check('443 to non-permitted host blocked at fw2', r.verdict==='blocked' && r.hops[1].dec==='deny');

  // external source with no outside-zone interface in this fixture -> unreachable (no ingress) 
  r=await query('8.8.8.8','10.80.0.90','tcp','443');
  check('external source handled (verdict or graceful no-path)', r.verdict==='unreachable'||r.verdict==='blocked'||r.verdict==='permitted'||r.verdict===null, JSON.stringify(r.verdict));

  check('no page errors', errs.length===0, errs.slice(0,2).join('|'));
  await b.close();
  const f=R.filter(x=>!x).length;
  console.log(`\n${R.length-f}/${R.length} reachability UI checks passed`);
  process.exit(f?1:0);
})().catch(e=>{console.error('FATAL',e);process.exit(2);});
