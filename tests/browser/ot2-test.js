const puppeteer=require('puppeteer-core');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const R=[]; const check=(n,ok,i='')=>{R.push(ok);console.log((ok?'PASS':'FAIL')+'  '+n+(i?'  — '+i:''));};
(async()=>{
  const b=await puppeteer.launch({executablePath: process.env.CHROME_PATH || require('./_chrome').find(),headless:'new',args:['--no-sandbox','--disable-dev-shm-usage']});
  const p=await b.newPage(); await p.setViewport({width:1440,height:900});
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto('http://127.0.0.1:8077/nettopo.html',{waitUntil:'networkidle0'});
  await (await p.$('#fileinput')).uploadFile('tests/fixtures/ot2/sel.cfg','tests/fixtures/ot2/mguard.cfg','tests/fixtures/ot2/waterfall.cfg','tests/fixtures/ot2/pvlan-switch.cfg');
  await sleep(1600);
  const fl=await p.evaluate(()=>[...document.querySelectorAll('#filelist li')].map(li=>li.innerText.replace(/\s+/g,' ')));
  console.log('  files:', JSON.stringify(fl));
  check('SEL classified', fl.some(t=>/SEL/.test(t)));
  check('mGuard classified', fl.some(t=>/mGuard/.test(t)));
  check('Waterfall classified', fl.some(t=>/Waterfall/.test(t)));

  await p.click('#reach-btn'); await sleep(300);
  async function q(sip,dip,proto,port){
    await p.evaluate((s,d,pr,pt)=>{document.getElementById('rc-src').value=s;document.getElementById('rc-dst').value=d;
      document.getElementById('rc-proto').value=pr;document.getElementById('rc-port').value=pt;document.getElementById('rc-run').click();},sip,dip,proto,port);
    await sleep(150);
    return p.evaluate(()=>{const v=document.querySelector('#rc-result .rc-verdict');
      const hops=[...document.querySelectorAll('#rc-result .rc-hop')].map(h=>h.textContent.replace(/\s+/g,' ').trim());
      return {verdict:v?v.className.replace('rc-verdict ','').trim():null, hops};});
  }
  // SEL: engineering access telnet permitted
  check('SEL permit engineering telnet', (await q('10.7.1.9','10.7.2.10','tcp','23')).verdict==='permitted');
  // mGuard: Modbus permitted
  check('mGuard permit Modbus 502', (await q('192.168.50.9','10.8.0.5','tcp','502')).verdict==='permitted');

  // --- L2 private-VLAN isolation: two hosts in VLAN 100 (isolated) cannot reach each other ---
  let r=await q('10.10.100.50','10.10.100.60','tcp','502');
  check('PVLAN isolation blocks intra-VLAN host-to-host', r.verdict==='blocked', JSON.stringify(r.verdict));
  check('PVLAN isolation note shown', r.hops.some(h=>/isolation|isolated/i.test(h)), JSON.stringify(r.hops));
  // host to gateway (SVI) still allowed even when isolated
  r=await q('10.10.100.50','10.10.100.1','tcp','443');
  check('isolated host can still reach gateway/SVI', r.verdict==='permitted', JSON.stringify(r.verdict));
  // --- L2 port ACL: VLAN 200 has PORTFILTER (permit 443, deny else) ---
  r=await q('10.10.200.50','10.10.200.60','tcp','443');
  check('port ACL permits 443 intra-VLAN', r.verdict==='permitted', JSON.stringify(r.verdict));
  r=await q('10.10.200.50','10.10.200.60','tcp','22');
  check('port ACL blocks 22 intra-VLAN', r.verdict==='blocked', JSON.stringify(r.verdict));
  check('port ACL note shown', r.hops.some(h=>/port ACL/i.test(h)), JSON.stringify(r.hops));

  // --- DRIFT: set baseline, modify (clear + reload with an added permit rule), compare ---
  await p.click('#drift-btn'); await sleep(200);
  await p.evaluate(()=>document.getElementById('df-baseline').click()); await sleep(300);
  // clear all and load a modified sel config (adds a new permit rule)
  await p.evaluate(()=>document.getElementById('clear-btn').click()); await sleep(300);
  const fs=require('fs');
  fs.writeFileSync('/tmp/sel-v2.cfg', fs.readFileSync('tests/fixtures/ot2/sel.cfg','utf8').replace('access-rule 2 deny','access-rule 2 permit source 10.7.9.0/24 destination 10.7.2.20 service tcp/502\naccess-rule 3 deny'));
  await (await p.$('#fileinput')).uploadFile('/tmp/sel-v2.cfg','tests/fixtures/ot2/mguard.cfg','tests/fixtures/ot2/waterfall.cfg','tests/fixtures/ot2/pvlan-switch.cfg');
  await sleep(1500);
  await p.click('#drift-btn'); await sleep(200);
  await p.evaluate(()=>document.getElementById('df-compare').click()); await sleep(400);
  const drift=await p.evaluate(()=>({
    adds:[...document.querySelectorAll('#df-body .df-row.add')].map(r=>r.textContent.trim()),
    dels:[...document.querySelectorAll('#df-body .df-row.del')].map(r=>r.textContent.trim()),
    summary:[...document.querySelectorAll('#df-body .df-summary .schip')].map(s=>s.textContent.trim())
  }));
  console.log('  drift adds:', JSON.stringify(drift.adds));
  console.log('  drift summary:', JSON.stringify(drift.summary));
  check('drift detects added permit rule', drift.adds.some(t=>/10\.7\.2\.20|502/.test(t)), JSON.stringify(drift.adds));
  check('drift summary flags new permit', drift.summary.some(t=>/new permit/.test(t)));

  check('no page errors', errs.length===0, errs.slice(0,3).join('|'));
  await b.close();
  const f=R.filter(x=>!x).length;
  console.log(`\n${R.length-f}/${R.length} OT2 + L2-PVLAN + drift checks passed`);
  process.exit(f?1:0);
})().catch(e=>{console.error('FATAL',e);process.exit(2);});
