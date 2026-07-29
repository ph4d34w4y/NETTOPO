const puppeteer=require('puppeteer-core');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const R=[]; const check=(n,ok,i='')=>{R.push(ok);console.log((ok?'PASS':'FAIL')+'  '+n+(i?'  — '+i:''));};
(async()=>{
  const b=await puppeteer.launch({executablePath: process.env.CHROME_PATH || require('./_chrome').find(),headless:'new',args:['--no-sandbox','--disable-dev-shm-usage']});
  const p=await b.newPage(); await p.setViewport({width:1440,height:900});
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto('http://127.0.0.1:8077/nettopo.html',{waitUntil:'networkidle0'});
  await (await p.$('#fileinput')).uploadFile('tests/fixtures/forti/fgt-edge.conf');
  await sleep(1200);
  const fl = await p.evaluate(()=>[...document.querySelectorAll('#filelist li')].map(li=>li.innerText.replace(/\s+/g,' ')));
  check('FortiGate file classified as CFG', fl.some(t=>/FortiGate/.test(t)&&/CFG/.test(t)), JSON.stringify(fl));
  // parse correctness via detail panel
  await p.evaluate(()=>{ for(const n of document.querySelectorAll('#canvas g.node')) if(n.querySelector('rect')){n.dispatchEvent(new MouseEvent('click',{bubbles:true}));break;} });
  await sleep(300);
  const d = await p.evaluate(()=>document.getElementById('d-body').innerText);
  check('hostname parsed', await p.evaluate(()=>document.getElementById('d-title').innerText)==='FGT-edge');
  check('3 interfaces parsed', /wan1/.test(d)&&/internal/.test(d)&&/dmz/.test(d));
  check('interface IPs parsed', /203\.0\.113\.5\/24/.test(d)&&/192\.168\.100\.1\/24/.test(d)&&/10\.100\.0\.1\/24/.test(d));
  check('zones applied to interfaces', /trust/.test(d)&&/untrust/.test(d));
  // findings
  await p.click('#findings-btn'); await sleep(300);
  const F=await p.evaluate(()=>[...document.querySelectorAll('#f-list .f-title')].map(e=>e.textContent));
  check('audit: telnet mgmt on interface', F.some(t=>/Telnet management enabled/.test(t)));
  check('audit: http mgmt on interface', F.some(t=>/Unencrypted HTTP management/.test(t)));
  check('audit: any-any accept policy', F.some(t=>/all→all accept/.test(t)));
  check('audit: default SNMP community', F.some(t=>/Default SNMP community/.test(t)));
  check('no page errors', errs.length===0, errs.slice(0,2).join('|'));
  await b.close();
  const f=R.filter(x=>!x).length;
  console.log(`\n${R.length-f}/${R.length} FortiGate checks passed`);
  process.exit(f?1:0);
})().catch(e=>{console.error('FATAL',e);process.exit(2);});
