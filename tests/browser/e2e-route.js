const puppeteer=require('puppeteer-core');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const R=[]; const check=(n,ok,i='')=>{R.push(ok);console.log((ok?'PASS':'FAIL')+'  '+n+(i?'  — '+i:''));};
(async()=>{
  const b=await puppeteer.launch({executablePath: process.env.CHROME_PATH || require('./_chrome').find(),headless:'new',args:['--no-sandbox','--disable-dev-shm-usage']});
  const p=await b.newPage(); await p.setViewport({width:1440,height:900});
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto('http://127.0.0.1:8077/nettopo.html',{waitUntil:'networkidle0'});
  await (await p.$('#fileinput')).uploadFile('tests/fixtures/testfiles/route-fw.cfg','tests/fixtures/testfiles/route-flows.csv');
  await sleep(1500);

  // helper to read flow edges as {src,tgt,routed}
  const edges = async () => p.evaluate(()=>[...document.querySelectorAll('#canvas line')]
    .filter(l=>l.classList.contains('flowline') || (l.getAttribute('stroke')||'').match(/#4fc3f7|#ffb74d|#81c784|#b0bec5/))
    .map(l=>{const d=l.__data__;return {s:d.source.id,t:d.target.id,r:!!d.routed};}));

  // ROUTING ON (default)
  let E = await edges();
  const devId = 'dev:path-fw';
  const crossSrc='host:192.168.20.10', crossDst='host:10.50.0.80';
  const directCross = E.some(e=>(e.s===crossSrc&&e.t===crossDst)||(e.s===crossDst&&e.t===crossSrc));
  const segIn  = E.some(e=>e.r && ((e.s===crossSrc&&e.t===devId)||(e.s===devId&&e.t===crossSrc)));
  const segOut = E.some(e=>e.r && ((e.s===crossDst&&e.t===devId)||(e.s===devId&&e.t===crossDst)));
  check('cross-subnet flow does NOT draw a direct host→host edge', !directCross);
  check('cross-subnet flow routes IN to the firewall', segIn);
  check('cross-subnet flow routes OUT of the firewall', segOut);
  check('routed segments are tagged routed=true', segIn&&segOut);

  // intra-subnet flow stays direct (does not touch the firewall)
  const intra = E.some(e=>!e.r && ((e.s==='host:192.168.20.10'&&e.t==='host:192.168.20.11')||(e.s==='host:192.168.20.11'&&e.t==='host:192.168.20.10')));
  check('intra-subnet flow stays a direct edge (no firewall crossing)', intra);

  // ROUTING OFF -> direct edge returns
  await p.click('#route-toggle'); await sleep(1200);
  E = await edges();
  const directNow = E.some(e=>(e.s===crossSrc&&e.t===crossDst)||(e.s===crossDst&&e.t===crossSrc));
  const anyRouted = E.some(e=>e.r);
  check('toggle OFF restores direct host→host edge', directNow);
  check('toggle OFF removes all routed segments', !anyRouted);
  await p.click('#route-toggle'); await sleep(1000); // back on

  // AGG mode: subnet -> firewall -> subnet
  await p.click('#agg-toggle'); await sleep(1200);
  E = await edges();
  const netA='net:192.168.20.0/24', netB='net:10.50.0.0/24';
  const aggIn  = E.some(e=>e.r && ((e.s===netA&&e.t===devId)||(e.s===devId&&e.t===netA)));
  const aggOut = E.some(e=>e.r && ((e.s===netB&&e.t===devId)||(e.s===devId&&e.t===netB)));
  const aggDirect = E.some(e=>(e.s===netA&&e.t===netB)||(e.s===netB&&e.t===netA));
  check('aggregate mode routes subnet→firewall→subnet', aggIn&&aggOut&&!aggDirect, JSON.stringify({aggIn,aggOut,aggDirect}));

  check('no page errors', errs.length===0, errs.slice(0,2).join(' | '));
  await b.close();
  const f=R.filter(x=>!x).length;
  console.log(`\n${R.length-f}/${R.length} routing checks passed`);
  process.exit(f?1:0);
})().catch(e=>{console.error('FATAL',e);process.exit(2);});
