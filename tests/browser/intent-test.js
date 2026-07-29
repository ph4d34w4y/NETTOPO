const puppeteer=require('puppeteer-core');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const R=[]; const check=(n,ok,i='')=>{R.push(ok);console.log((ok?'PASS':'FAIL')+'  '+n+(i?'  — '+i:''));};
(async()=>{
  const b=await puppeteer.launch({executablePath: process.env.CHROME_PATH || require('./_chrome').find(),headless:'new',args:['--no-sandbox','--disable-dev-shm-usage']});
  const p=await b.newPage(); await p.setViewport({width:1440,height:900});
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto('http://127.0.0.1:8077/nettopo.html',{waitUntil:'networkidle0'});
  await (await p.$('#fileinput')).uploadFile('tests/fixtures/intent/fw.cfg','tests/fixtures/intent/flows.csv');
  await sleep(1500);
  await p.click('#intent-btn'); await sleep(600);
  const iv=await p.evaluate(()=>{
    const unexpected=[...document.querySelectorAll('#iv-body .iv-row.unexpected')].map(r=>r.textContent.replace(/\s+/g,' ').trim());
    const unused=[...document.querySelectorAll('#iv-body .iv-row.unused')].map(r=>r.textContent.replace(/\s+/g,' ').trim());
    return {unexpected, unused};
  });
  console.log('  unexpected:', JSON.stringify(iv.unexpected));
  console.log('  unused:', JSON.stringify(iv.unused));
  check('panel opens & renders', await p.evaluate(()=>document.getElementById('intent').classList.contains('open')));
  check('observed-but-not-allowed flags the 3306 flow', iv.unexpected.some(t=>/10\.60\.0\.80.*3306|3306/.test(t)), JSON.stringify(iv.unexpected));
  check('3306 flow shows blocked at fw', iv.unexpected.some(t=>/blocked at intent-fw/.test(t)));
  check('unused permit flags the never-used 22 rule', iv.unused.some(t=>/10\.60\.0\.90 eq 22/.test(t)), JSON.stringify(iv.unused));
  check('443 rule NOT listed as unused (it was used)', !iv.unused.some(t=>/10\.60\.0\.80 eq 443/.test(t)));
  check('no page errors', errs.length===0, errs.slice(0,2).join('|'));
  await b.close();
  const f=R.filter(x=>!x).length;
  console.log(`\n${R.length-f}/${R.length} intent-vs-reality checks passed`);
  process.exit(f?1:0);
})().catch(e=>{console.error('FATAL',e);process.exit(2);});
