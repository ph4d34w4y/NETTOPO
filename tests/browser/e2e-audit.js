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
  const errors=[]; page.on('pageerror',e=>errors.push(String(e)));
  await page.goto('http://127.0.0.1:8077/nettopo.html',{waitUntil:'networkidle0'});

  await (await page.$('#fileinput')).uploadFile(
    'tests/fixtures/vuln/cisco-bad.cfg','tests/fixtures/vuln/juniper-bad.conf','tests/fixtures/vuln/iptables-bad.rules',
    'tests/fixtures/vuln/pfsense-bad.xml','tests/fixtures/vuln/flows-bad.csv');
  await sleep(2000);

  await page.click('#findings-btn'); await sleep(400);
  const F = await page.evaluate(()=> [...document.querySelectorAll('#f-list .finding')].map(c=>({
    sev: c.querySelector('.schip').textContent.trim(),
    title: c.querySelector('.f-title').textContent.trim()
  })));
  const titles = F.map(f=>f.title);
  const has = t => titles.some(x=>x.includes(t));
  console.log('  total findings:', F.length);
  console.log('  by severity:', JSON.stringify(F.reduce((a,f)=>(a[f.sev]=(a[f.sev]||0)+1,a),{})));

  // config rules
  check('Cisco: permit any any', has('permit any→any'));
  check('Cisco: mgmt port from any', has('Management port reachable'));
  check('Cisco: telnet mgmt', has('Telnet enabled for device'));
  check('Cisco: http mgmt', has('Unencrypted HTTP management'));
  check('Cisco: default SNMP community', has('Default SNMP community'));
  check('Cisco: SNMP RW', has('write access'));
  check('Cisco: enable password', has('enable password'));
  check('Cisco: type 7 password', has('Type 7 password'));
  check('Cisco: SSHv1', has('SSH protocol version 1'));
  check('Cisco: small-servers', has('Legacy diagnostic service'));
  check('Cisco: no pw encryption', has('Password encryption service disabled'));
  check('Juniper: telnet', has('Telnet service enabled'));
  check('Juniper: ftp', has('FTP service enabled'));
  check('Juniper: http mgmt', has('Unencrypted web management'));
  check('Juniper: default SNMP', has('Default SNMP community'));
  check('Juniper: any-any policy', has('Overly permissive security policy'));
  check('iptables: default ACCEPT', has('Default policy ACCEPT'));
  check('iptables: unconditional accept', has('Unconditional ACCEPT'));
  check('iptables: telnet', has('Telnet (tcp/23) allowed'));
  check('iptables: ftp', has('FTP (tcp/21) allowed'));
  check('iptables: smb', has('SMB/NetBIOS allowed'));
  check('pfSense: http gui', has('Web GUI served over unencrypted'));
  check('pfSense: any-any pass', has('Overly permissive pass rule'));
  // flow rules
  check('Flow: external->mgmt', has('External access to internal management'));
  check('Flow: telnet observed', has('Telnet traffic observed'));
  check('Flow: port scan', has('Port scan pattern'));
  check('Flow: network sweep', has('Network sweep pattern'));
  check('Flow: large exfil', has('Large outbound transfer'));
  check('Flow: icmp tunnel', has('large ICMP'));

  // UI: badge count + panel render
  const badge = await page.$eval('#f-count', el=>el.textContent);
  check('findings badge shows count', +badge === F.length, 'badge='+badge+' cards='+F.length);
  const summaryChips = await page.evaluate(()=>document.querySelectorAll('#f-summary .schip').length);
  check('severity summary chips present', summaryChips>=2, summaryChips+' chips');

  // node ring highlight
  const rings = await page.evaluate(()=>{
    let hi=0,med=0;
    document.querySelectorAll('#canvas g.node').forEach(n=>{
      const el = n.querySelector('rect,circle'); const s = el.getAttribute('stroke');
      if (s==='#ff5c7a') hi++; else if (s==='#ffc857') med++;
    });
    return {hi,med};
  });
  check('flagged nodes get severity rings', rings.hi>0, JSON.stringify(rings));

  // sorted high-first
  const sevSeq = F.map(f=>f.sev);
  const ord={high:0,medium:1,low:2,info:3};
  check('findings sorted by severity', sevSeq.every((s,i)=>i===0||ord[sevSeq[i-1]]<=ord[s]));

  // CSV export w/ formula-injection guard
  const fs=require('fs'); try{fs.unlinkSync('tests/screenshots/nettopo-findings.csv')}catch(e){}
  const client = await page.createCDPSession();
  await client.send('Browser.setDownloadBehavior',{behavior:'allow',downloadPath: require('path').resolve('tests/screenshots')});
  await page.evaluate(()=>{ const el=document.getElementById('findings'); if(!el.classList.contains('open')) document.getElementById('findings-btn').click(); }); await sleep(300);
  await page.evaluate(()=>document.getElementById('f-export').click()); await sleep(1000);
  let csvOk=false, csvGuard=false;
  if (fs.existsSync('tests/screenshots/nettopo-findings.csv')){
    const csv = fs.readFileSync('tests/screenshots/nettopo-findings.csv','utf8');
    csvOk = csv.split('\r\n').length >= F.length;
    csvGuard = !/,=|,\+(?!\d)|,@/.test(csv);  // leading formula chars neutralized
  }
  check('CSV export downloads with all rows', csvOk);
  check('CSV formula-injection guard active', csvGuard);

  // false-positive check: clean sample should yield far fewer, mostly from intentional sample issues
  await page.click('#clear-btn'); await sleep(300);
  await page.click('#sample-btn'); await sleep(1500);
  await page.click('#findings-btn'); await sleep(300);
  const sampleFindings = await page.evaluate(()=> [...document.querySelectorAll('#f-list .f-title')].map(c=>c.textContent.trim()));
  check('clean-ish sample yields findings (from seeded issues)', sampleFindings.length>=3, sampleFindings.length+' findings');
  check('sample flags telnet + snmp + http from seeded config/flow',
    sampleFindings.some(t=>t.includes('Telnet')) &&
    sampleFindings.some(t=>t.includes('SNMP')) &&
    sampleFindings.some(t=>t.includes('HTTP')), JSON.stringify([...new Set(sampleFindings)]));

  check('zero page errors', errors.length===0, errors.slice(0,2).join(' | '));
  await browser.close();
  const fails=results.filter(r=>!r).length;
  console.log(`\n${results.length-fails}/${results.length} audit checks passed`);
  process.exit(fails?1:0);
})().catch(e=>{console.error('FATAL',e);process.exit(2);});
