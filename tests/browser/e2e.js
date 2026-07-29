try{require('fs').mkdirSync('tests/screenshots',{recursive:true});}catch(e){}
const puppeteer = require('puppeteer-core');
const path = require('path');
const sleep = ms => new Promise(r=>setTimeout(r,ms));
const results = [];
const check = (name, ok, info='') => { results.push({name, ok, info}); console.log((ok?'PASS':'FAIL')+'  '+name+(info?'  — '+info:'')); };

(async () => {
  const browser = await puppeteer.launch({
    executablePath: process.env.CHROME_PATH || require('./_chrome').find(),
    headless: 'new',
    args: ['--no-sandbox','--disable-dev-shm-usage','--window-size=1440,900']
  });
  const page = await browser.newPage();
  await page.setViewport({width:1440, height:900});
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  page.on('console', m => { if (m.type()==='error') errors.push(m.text()); });

  await page.goto('http://127.0.0.1:8077/nettopo.html', {waitUntil:'networkidle0'});
  check('page loads without JS errors', errors.length===0, errors.join(' | '));
  check('empty state visible on load', await page.$eval('#empty', el=>getComputedStyle(el).display) !== 'none');

  // ---- 1. sample data ----
  await page.click('#sample-btn');
  await sleep(1800);
  const hdr1 = await page.$eval('#hdr-stats', el=>el.textContent);
  check('sample data loads', /3 devices/.test(hdr1) && /flow records/.test(hdr1), hdr1);
  const counts1 = await page.evaluate(() => ({
    nodes: document.querySelectorAll('#canvas g.node').length,
    links: document.querySelectorAll('#canvas line').length,
    empty: getComputedStyle(document.getElementById('empty')).display
  }));
  check('graph rendered (nodes>10, links>10, empty hidden)',
    counts1.nodes>10 && counts1.links>10 && counts1.empty==='none', JSON.stringify(counts1));
  await page.screenshot({path:'tests/screenshots/1-sample-topology.png'});

  // ---- 2. click device node -> detail panel ----
  await page.evaluate(() => {
    const g = window.currentGraph || null;
  });
  const opened = await page.evaluate(() => {
    // find the device node group for edge-fw1 and dispatch a click
    const nodes = [...document.querySelectorAll('#canvas g.node')];
    for (const n of nodes){
      if (n.querySelector('rect')) { n.dispatchEvent(new MouseEvent('click',{bubbles:true})); return true; }
    }
    return false;
  });
  await sleep(300);
  const detail = await page.evaluate(() => ({
    open: document.getElementById('detail').classList.contains('open'),
    title: document.getElementById('d-title').textContent,
    body: document.getElementById('d-body').innerText.slice(0,400)
  }));
  check('device detail panel opens', opened && detail.open, detail.title);
  check('detail shows interfaces & ACLs',
    /Interfaces/.test(detail.body) && /Polic/i.test(detail.body), detail.title);
  await page.screenshot({path:'tests/screenshots/2-device-detail.png'});
  await page.click('#d-close');

  // ---- 3. every parser via real file upload ----
  const input = await page.$('#fileinput');
  await input.uploadFile(
    'tests/fixtures/testfiles/branch-rtr.cfg','tests/fixtures/testfiles/srx-lab.conf','tests/fixtures/testfiles/gw.rules',
    'tests/fixtures/testfiles/pfsense-backup.xml','tests/fixtures/testfiles/flows.nfdump.txt',
    'tests/fixtures/testfiles/capture.nf5','tests/fixtures/testfiles/flows.xlsx');
  await sleep(2200);
  const filelist = await page.evaluate(() =>
    [...document.querySelectorAll('#filelist li')].map(li => li.innerText.replace(/\s+/g,' ').trim()));
  console.log('  file list:', JSON.stringify(filelist, null, 1));
  const kinds = filelist.join(' || ');
  check('Cisco IOS parsed', /branch-rtr\.cfg.*Cisco/.test(kinds));
  check('Juniper hierarchical parsed', /srx-lab\.conf.*Juniper/.test(kinds));
  check('iptables parsed', /gw\.rules.*iptables/.test(kinds));
  check('pfSense XML parsed', /pfsense-backup\.xml.*pfSense/.test(kinds));
  check('nfdump text parsed', /flows\.nfdump\.txt.*nfdump.*3 records/.test(kinds));
  check('NetFlow v5 binary parsed', /capture\.nf5.*NetFlow v5.*3 records/.test(kinds));
  check('Excel flows parsed', /flows\.xlsx.*Excel.*3 records/.test(kinds));
  check('no ERR badges', !/ERR/.test(kinds));
  const hdr2 = await page.$eval('#hdr-stats', el=>el.textContent);
  check('all 7 devices in graph', /7 devices/.test(hdr2), hdr2);
  await page.screenshot({path:'tests/screenshots/3-all-formats.png'});

  // ---- 4. filters ----
  await page.click('#proto-checks input[data-proto="UDP"]'); // uncheck UDP
  await sleep(900);
  const udpGone = await page.evaluate(() =>
    ![...document.querySelectorAll('#canvas line')].some(l => l.getAttribute('stroke')==='#ffb74d'));
  check('protocol filter removes UDP edges', udpGone);
  await page.click('#proto-checks input[data-proto="UDP"]'); // recheck
  await sleep(600);

  await page.type('#searchbox', '172.31.50');
  await sleep(300);
  const dimmed = await page.evaluate(() => {
    const ns = [...document.querySelectorAll('#canvas g.node')];
    return { faded: ns.filter(n=>n.getAttribute('opacity')==='0.15').length, total: ns.length };
  });
  check('search dims non-matching nodes', dimmed.faded>0 && dimmed.faded<dimmed.total, JSON.stringify(dimmed));
  await page.evaluate(()=>{ const s=document.getElementById('searchbox'); s.value=''; s.dispatchEvent(new Event('input')); });

  await page.click('#agg-toggle');
  await sleep(1200);
  const aggCounts = await page.evaluate(() => document.querySelectorAll('#canvas g.node').length);
  check('subnet aggregation reduces node count', aggCounts < counts1.nodes, `now ${aggCounts} nodes`);
  await page.screenshot({path:'tests/screenshots/4-aggregated.png'});
  await page.click('#agg-toggle');
  await sleep(800);

  // ---- 5. v9 rejection message ----
  const fs = require('fs');
  const v9 = Buffer.alloc(24); v9.writeUInt16BE(9,0);
  fs.writeFileSync('tests/fixtures/testfiles/bad.v9', v9);
  await (await page.$('#fileinput')).uploadFile('tests/fixtures/testfiles/bad.v9');
  await sleep(500);
  const v9row = await page.evaluate(() =>
    [...document.querySelectorAll('#filelist li')].map(li=>li.innerText).find(t=>t.includes('bad.v9')));
  check('v9 binary rejected with guidance', /ERR/.test(v9row||''), (v9row||'').replace(/\s+/g,' '));

  // ---- 6. SVG export ----
  const client = await page.createCDPSession();
  await client.send('Browser.setDownloadBehavior', {behavior:'allow', downloadPath: require('path').resolve('tests/screenshots')});
  await page.click('#export-btn');
  await sleep(1200);
  const svgOk = fs.existsSync('tests/screenshots/network-topology.svg') && fs.statSync('tests/screenshots/network-topology.svg').size > 5000;
  check('SVG export downloads', svgOk, svgOk ? fs.statSync('tests/screenshots/network-topology.svg').size+' bytes' : 'missing');

  // ---- 7. clear ----
  await page.click('#clear-btn');
  await sleep(400);
  check('clear resets to empty state',
    await page.$eval('#empty', el=>getComputedStyle(el).display)==='flex');

  check('zero JS errors across whole session', errors.length===0, errors.slice(0,3).join(' | '));
  await browser.close();
  const fails = results.filter(r=>!r.ok).length;
  console.log(`\n${results.length-fails}/${results.length} checks passed`);
  process.exit(fails?1:0);
})().catch(e=>{ console.error('FATAL', e); process.exit(2); });
