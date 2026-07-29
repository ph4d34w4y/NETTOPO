const puppeteer=require('puppeteer-core');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const R=[]; const check=(n,ok,i='')=>{R.push(ok);console.log((ok?'PASS':'FAIL')+'  '+n+(i?'  — '+i:''));};
(async()=>{
  const b=await puppeteer.launch({executablePath: process.env.CHROME_PATH || require('./_chrome').find(),headless:'new',args:['--no-sandbox','--disable-dev-shm-usage']});
  const p=await b.newPage(); await p.setViewport({width:1440,height:900});
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto('http://127.0.0.1:8077/nettopo.html',{waitUntil:'networkidle0'});
  await (await p.$('#fileinput')).uploadFile('tests/fixtures/attack/edge.cfg','tests/fixtures/attack/flows.csv');
  await sleep(1200);

  // --- binding-aware reachability ---
  await p.click('#reach-btn'); await sleep(300);
  async function q(sip,dip,proto,port){
    await p.evaluate((s,d,pr,pt)=>{ document.getElementById('rc-src').value=s;document.getElementById('rc-dst').value=d;
      document.getElementById('rc-proto').value=pr;document.getElementById('rc-port').value=pt;document.getElementById('rc-run').click(); },sip,dip,proto,port);
    await sleep(150);
    return p.evaluate(()=>{ const v=document.querySelector('#rc-result .rc-verdict'); return v?v.className.replace('rc-verdict ','').trim():null; });
  }
  // outside(198.51.100.66) -> web 10.10.0.80:443 => permitted by outside_in inbound ACL
  check('binding: external->web 443 permitted', await q('198.51.100.66','10.10.0.80','tcp','443')==='permitted');
  // outside -> web 22 => denied by outside_in
  check('binding: external->web 22 blocked', await q('198.51.100.66','10.10.0.80','tcp','22')==='blocked');
  // dmz(10.10.0.80) -> inside db 192.168.5.50:3306 => permitted by dmz_in inbound ACL
  check('binding: dmz->db 3306 permitted', await q('10.10.0.80','192.168.5.50','tcp','3306')==='permitted');
  // dmz -> inside db 22 => denied by dmz_in
  check('binding: dmz->db 22 blocked', await q('10.10.0.80','192.168.5.50','tcp','22')==='blocked');
  // KEY binding test: outside->inside directly on 3306. Ingress=outside (outside_in applies, denies non-web).
  // outside_in only permits 443 to 10.10.0.80, so outside->192.168.5.50:3306 must be BLOCKED at ingress outside_in
  check('binding: external->inside db blocked at outside ACL (direction-aware)', await q('198.51.100.66','192.168.5.50','tcp','3306')==='blocked');

  // --- attack simulation ---
  await p.click('#attack-btn'); await sleep(300);
  check('attack panel opens', await p.evaluate(()=>document.getElementById('attack').classList.contains('open')));
  await p.evaluate(()=>{ document.getElementById('ak-origin').value='198.51.100.66'; document.getElementById('ak-run').click(); });
  await sleep(2500);
  const sim = await p.evaluate(()=>{
    const assets=[...document.querySelectorAll('#ak-result .ak-asset')].map(a=>({
      ip:a.querySelector('.aip').textContent.trim(), svc:a.querySelector('.asvc').textContent.trim(),
      path:a.querySelector('.apath').textContent.replace(/\s+/g,' ').trim(), crit:a.classList.contains('crit') }));
    const summary=[...document.querySelectorAll('#ak-result .ak-summary .schip')].map(s=>s.textContent.trim());
    return {assets, summary};
  });
  console.log('  reachable assets:', JSON.stringify(sim.assets,null,1));
  check('attack: web server (10.10.0.80) reachable from outside', sim.assets.some(a=>a.ip==='10.10.0.80'));
  check('attack: db (192.168.5.50) reachable via stepping stone through web', sim.assets.some(a=>a.ip==='192.168.5.50' && /10\.10\.0\.80/.test(a.path)));
  check('attack: db marked critical (MySQL)', sim.assets.some(a=>a.ip==='192.168.5.50' && a.crit));
  check('attack: shows a critical count', sim.summary.some(s=>/critical/.test(s)));

  check('no page errors', errs.length===0, errs.slice(0,2).join('|'));
  await b.close();
  const f=R.filter(x=>!x).length;
  console.log(`\n${R.length-f}/${R.length} binding+attack checks passed`);
  process.exit(f?1:0);
})().catch(e=>{console.error('FATAL',e);process.exit(2);});
