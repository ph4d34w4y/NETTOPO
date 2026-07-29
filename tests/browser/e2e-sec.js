try{require('fs').mkdirSync('tests/screenshots',{recursive:true});}catch(e){}
const puppeteer = require('puppeteer-core');
const sleep = ms => new Promise(r=>setTimeout(r,ms));
const results = [];
const check = (n,ok,i='') => { results.push(ok); console.log((ok?'PASS':'FAIL')+'  '+n+(i?'  — '+i:'')); };
(async () => {
  const browser = await puppeteer.launch({
    executablePath: process.env.CHROME_PATH || require('./_chrome').find(),
    headless:'new', args:['--no-sandbox','--disable-dev-shm-usage']});
  const page = await browser.newPage();
  await page.setViewport({width:1440,height:900});
  const errors=[]; let dialogs=0;
  page.on('pageerror',e=>errors.push(String(e)));
  page.on('dialog',d=>{dialogs++;d.dismiss();});
  await page.goto('http://127.0.0.1:8077/nettopo.html',{waitUntil:'networkidle0'});

  check('CSP + SRI: both libraries load', await page.evaluate(()=>!!window.d3 && !!window.XLSX));
  check('prototype chain frozen', await page.evaluate(()=>Object.isFrozen(Object.prototype)&&Object.isFrozen(Array.prototype)));

  await (await page.$('#fileinput')).uploadFile('tests/fixtures/testfiles/evil.cfg','tests/fixtures/testfiles/evil.csv');
  await sleep(1500);

  const xss = await page.evaluate(()=>({
    x1:window.__xss1, x2:window.__xss2, x3:window.__xss3, x4:window.__xss4, x5:window.__xss5,
    injectedImgs:[...document.images].filter(i=>i.src.endsWith('/x')).length,
    injectedScripts:[...document.scripts].filter(s=>s.textContent.includes('__xss')).length
  }));
  check('no XSS payload executed from config/flow content',
    !xss.x1&&!xss.x2&&!xss.x3&&!xss.x4&&!xss.x5, JSON.stringify(xss));
  check('no injected elements in DOM', xss.injectedImgs===0 && xss.injectedScripts===0);

  const listText = await page.$eval('#filelist', el=>el.innerText);
  check('hostile hostname shown as inert text', listText.includes('<img'), JSON.stringify(listText.slice(0,120)));

  await page.evaluate(()=>{
    for (const n of document.querySelectorAll('#canvas g.node'))
      if (n.querySelector('rect')){ n.dispatchEvent(new MouseEvent('click',{bubbles:true})); break; }
  });
  await sleep(300);
  const detailSafe = await page.evaluate(()=>{
    const b=document.getElementById('d-body');
    return { open:document.getElementById('detail').classList.contains('open'),
      hasPayloadText: b.innerText.includes('onclick'), liveTags: b.querySelectorAll('img,svg,script,b').length };
  });
  check('detail panel renders payloads as text, zero live elements',
    detailSafe.open && detailSafe.hasPayloadText && detailSafe.liveTags===0, JSON.stringify(detailSafe));

  await page.evaluate(()=>{
    for (const n of document.querySelectorAll('#canvas g.node')){
      const d = n.__data__;
      if (d && d.label && d.label.includes('img src')){ n.dispatchEvent(new MouseEvent('mousemove',{bubbles:true,clientX:400,clientY:300})); break; }
    }
  });
  await sleep(200);
  check('tooltip escapes hostile labels', await page.evaluate(()=>
    document.getElementById('tooltip').querySelectorAll('img,svg,script').length===0));

  check('prototype not polluted after parsing', await page.evaluate(()=>
    ({}).polluted===undefined && Object.prototype.polluted===undefined));

  await page.click('#clear-btn'); await sleep(300);
  await page.click('#sample-btn'); await sleep(1500);
  const nodes = await page.evaluate(()=>document.querySelectorAll('#canvas g.node').length);
  check('app still fully functional (sample renders)', nodes>10, nodes+' nodes');

  const client = await page.createCDPSession();
  await client.send('Browser.setDownloadBehavior',{behavior:'allow',downloadPath: require('path').resolve('tests/screenshots')});
  const fs=require('fs'); try{fs.unlinkSync('tests/screenshots/network-topology.svg')}catch(e){}
  await page.click('#export-btn'); await sleep(1200);
  check('SVG export works under CSP', fs.existsSync('tests/screenshots/network-topology.svg'));

  check('zero dialogs, zero page errors', dialogs===0 && errors.length===0, errors.slice(0,2).join('|'));
  await browser.close();
  const fails=results.filter(r=>!r).length;
  console.log(`\n${results.length-fails}/${results.length} security checks passed`);
  process.exit(fails?1:0);
})().catch(e=>{console.error('FATAL',e);process.exit(2);});
