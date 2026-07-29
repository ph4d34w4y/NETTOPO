const puppeteer=require('puppeteer-core');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const R=[]; const check=(n,ok,i='')=>{R.push(ok);console.log((ok?'PASS':'FAIL')+'  '+n+(i?'  — '+i:''));};
(async()=>{
  const b=await puppeteer.launch({executablePath: process.env.CHROME_PATH || require('./_chrome').find(),headless:'new',args:['--no-sandbox','--disable-dev-shm-usage']});
  const p=await b.newPage(); await p.setViewport({width:1440,height:900});
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto('http://127.0.0.1:8077/nettopo.html',{waitUntil:'networkidle0'});
  await (await p.$('#fileinput')).uploadFile('tests/fixtures/natsim/asa-nat.cfg','tests/fixtures/natsim/flows.csv');
  await sleep(1200);
  await p.click('#reach-btn'); await sleep(300);
  async function q(sip,dip,proto,port){
    await p.evaluate((s,d,pr,pt)=>{ document.getElementById('rc-src').value=s;document.getElementById('rc-dst').value=d;
      document.getElementById('rc-proto').value=pr;document.getElementById('rc-port').value=pt;document.getElementById('rc-run').click(); },sip,dip,proto,port);
    await sleep(150);
    return p.evaluate(()=>{
      const v=document.querySelector('#rc-result .rc-verdict');
      const flow=document.querySelector('#rc-result .rc-flow')?.textContent||'';
      return { verdict:v?v.className.replace('rc-verdict ','').trim():null, flow };
    });
  }
  // NAT: external hits public 203.0.113.10:443 -> translate to 10.50.0.80:443 -> permitted by outside_in
  let r=await q('198.51.100.5','203.0.113.10','tcp','443');
  check('NAT: external->public IP:443 permitted (translated)', r.verdict==='permitted', JSON.stringify(r.verdict));
  check('NAT: translation shown in result', /NAT:/.test(r.flow) && /10\.50\.0\.80/.test(r.flow), r.flow);
  // external hits public IP on 22 -> no NAT match on that port -> dest 203.0.113.10 is outside subnet, evaluate: outside_in permits only 443 to real host; 22 to public IP won't translate, dest = 203.0.113.10 (outside net) -> path to itself? 
  r=await q('198.51.100.5','203.0.113.10','tcp','22');
  check('NAT: external->public IP:22 not permitted (no forward)', r.verdict!=='permitted', JSON.stringify(r.verdict));

  // ASA security-level: inside(100)->outside(0), dest in outside subnet, no outbound ACL -> permit (high->low)
  r=await q('10.50.0.9','203.0.113.5','tcp','443');
  check('ASA sec-level: inside->outside permitted (high->low, no ACL)', r.verdict==='permitted', JSON.stringify(r.verdict));

  // --- attack sim hits the port-forward ---
  await p.click('#attack-btn'); await sleep(300);
  await p.evaluate(()=>{ document.getElementById('ak-origin').value='198.51.100.5'; document.getElementById('ak-run').click(); });
  await sleep(2500);
  const sim=await p.evaluate(()=>[...document.querySelectorAll('#ak-result .ak-asset')].map(a=>({
    ip:a.querySelector('.aip').textContent.trim(), svc:a.querySelector('.asvc').textContent.trim()})));
  console.log('  sim assets:', JSON.stringify(sim));
  check('attack sim: reaches real internal host via port-forward', sim.some(a=>a.ip==='10.50.0.80'), JSON.stringify(sim.map(a=>a.ip)));

  check('no page errors', errs.length===0, errs.slice(0,2).join('|'));
  await b.close();
  const f=R.filter(x=>!x).length;
  console.log(`\n${R.length-f}/${R.length} NAT+ASA integration checks passed`);
  process.exit(f?1:0);
})().catch(e=>{console.error('FATAL',e);process.exit(2);});
