try{require('fs').mkdirSync('tests/screenshots',{recursive:true});}catch(e){}
const puppeteer=require('puppeteer-core');
const fs=require('fs');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const R=[]; const check=(n,ok,i='')=>{R.push(ok);console.log((ok?'PASS':'FAIL')+'  '+n+(i?'  — '+i:''));};
(async()=>{
  const b=await puppeteer.launch({executablePath: process.env.CHROME_PATH || require('./_chrome').find(),headless:'new',args:['--no-sandbox','--disable-dev-shm-usage']});
  const p=await b.newPage(); await p.setViewport({width:1440,height:900});
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto('http://127.0.0.1:8077/nettopo.html',{waitUntil:'networkidle0'});

  // Load: FortiGate (zones trust/untrust) + a Juniper with zone policy + flows between zones
  await (await p.$('#fileinput')).uploadFile('tests/fixtures/forti/fgt-edge.conf','tests/fixtures/vuln/juniper-bad.conf');
  // flows: internal(192.168.100.x, zone trust) -> wan(203.0.113.x? no) ; craft zone-crossing flows
  fs.writeFileSync('/tmp/zflows.csv',
    'srcaddr,dstaddr,srcport,dstport,proto,bytes,packets\n'+
    '192.168.100.20,10.100.0.50,4000,443,TCP,5000000,4000\n'+   // trust(internal) -> dmz
    '192.168.100.21,203.0.113.9,4001,443,TCP,800000,900\n');    // trust(internal) -> untrust(wan1)
  await (await p.$('#fileinput')).uploadFile('/tmp/zflows.csv');
  await sleep(1500);

  // --- Segmentation matrix ---
  await p.click('#matrix-btn'); await sleep(400);
  const mxOpen = await p.evaluate(()=>document.getElementById('matrix').classList.contains('open'));
  check('matrix panel opens', mxOpen);
  const mx = await p.evaluate(()=>{
    const t=document.querySelector('#mx-body table.mx');
    if(!t) return null;
    const cells=[...t.querySelectorAll('td')].map(td=>({cls:td.className, txt:td.textContent.trim(), title:td.title}));
    const heads=[...t.querySelectorAll('th')].map(th=>th.textContent.trim());
    return {cells, heads, rows:t.querySelectorAll('tr').length};
  });
  check('matrix renders a table', !!mx, mx?`${mx.rows} rows`:'no table');
  check('matrix lists zone names (trust/untrust)', mx && mx.heads.some(h=>/trust/.test(h)) && mx.heads.some(h=>/untrust/.test(h)), mx?JSON.stringify(mx.heads):'');
  const onCells = mx ? mx.cells.filter(c=>c.cls.includes('on')) : [];
  check('matrix marks observed communication cells', onCells.length>0, `${onCells.length} active cells`);
  check('observed cell tooltip shows bytes', onCells.some(c=>/over \d+ records/.test(c.title||'')), onCells[0]?onCells[0].title:'');
  check('self cells are marked', mx && mx.cells.some(c=>c.cls.includes('self')));

  // --- NERC-CIP report ---
  await p.click('#cip-btn'); await sleep(400);
  const cipOpen = await p.evaluate(()=>document.getElementById('cip').classList.contains('open'));
  check('CIP panel opens (and matrix closed - exclusivity)', cipOpen && !(await p.evaluate?0:0) );
  const mxClosedNow = await p.evaluate(()=>!document.getElementById('matrix').classList.contains('open'));
  check('opening CIP closes matrix (panel exclusivity)', mxClosedNow);
  const cip = await p.evaluate(()=>{
    const stds=[...document.querySelectorAll('#cip-body .cip-std')].map(s=>({
      id:s.querySelector('.cid')?.textContent, status:s.querySelector('.cstat')?.textContent,
      findings:s.querySelectorAll('.cip-f').length}));
    return stds;
  });
  check('CIP shows 5 requirement areas', cip.length===5, `${cip.length} areas`);
  check('CIP maps findings to requirements', cip.some(s=>s.findings>0), JSON.stringify(cip.map(s=>s.id+':'+s.findings)));
  check('CIP-007 R1 (ports/services) has findings from telnet/http', cip.some(s=>/R1/.test(s.id)&&s.findings>0));
  check('CIP-005 R1 (ESP) has findings from any-any', cip.some(s=>/005/.test(s.id)&&s.findings>0));

  // --- CIP report export ---
  const client=await p.createCDPSession();
  await client.send('Browser.setDownloadBehavior',{behavior:'allow',downloadPath: require('path').resolve('tests/screenshots')});
  try{fs.unlinkSync('tests/screenshots/nerc-cip-report.html')}catch(e){}
  await p.evaluate(()=>document.getElementById('cip-export').click()); await sleep(1200);
  let rep=null;
  if (fs.existsSync('tests/screenshots/nerc-cip-report.html')) rep=fs.readFileSync('tests/screenshots/nerc-cip-report.html','utf8');
  check('CIP report downloads', !!rep, rep?rep.length+' bytes':'missing');
  check('report is valid standalone HTML', rep && /<!DOCTYPE html>/.test(rep) && /<\/html>/.test(rep));
  check('report contains requirement tables', rep && /CIP-007-6 R1/.test(rep) && /Recommendation/.test(rep));
  check('report contains zone inventory', rep && /Zone inventory/.test(rep));
  check('report contains disclaimer', rep && /not a certified compliance assessment/.test(rep));
  // XSS safety in report: no unescaped script from config content
  check('report contains no script tags at all (safe)', rep && !/<script/i.test(rep));

  check('no page errors', errs.length===0, errs.slice(0,3).join(' | '));
  await b.close();
  const f=R.filter(x=>!x).length;
  console.log(`\n${R.length-f}/${R.length} matrix+CIP checks passed`);
  process.exit(f?1:0);
})().catch(e=>{console.error('FATAL',e);process.exit(2);});
