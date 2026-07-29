const puppeteer=require('puppeteer-core');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const R=[]; const check=(n,ok,i='')=>{R.push(ok);console.log((ok?'PASS':'FAIL')+'  '+n+(i?'  — '+i:''));};
(async()=>{
  const b=await puppeteer.launch({executablePath: process.env.CHROME_PATH || require('./_chrome').find(),headless:'new',args:['--no-sandbox','--disable-dev-shm-usage']});
  const p=await b.newPage(); await p.setViewport({width:1440,height:900});
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto('http://127.0.0.1:8077/nettopo.html',{waitUntil:'networkidle0'});
  await (await p.$('#fileinput')).uploadFile('tests/fixtures/ot/switch.cfg','tests/fixtures/ot/moxa.cfg','tests/fixtures/ot/scalance.cfg');
  await sleep(1500);
  const fl=await p.evaluate(()=>[...document.querySelectorAll('#filelist li')].map(li=>li.innerText.replace(/\s+/g,' ')));
  console.log('  files:', JSON.stringify(fl));
  check('Moxa classified', fl.some(t=>/Moxa/.test(t)));
  check('SCALANCE classified', fl.some(t=>/SCALANCE/.test(t)));
  check('industrial switch (Cisco) classified', fl.some(t=>/Cisco|ie-switch/.test(t)));

  await p.click('#reach-btn'); await sleep(300);
  async function q(sip,dip,proto,port){
    await p.evaluate((s,d,pr,pt)=>{document.getElementById('rc-src').value=s;document.getElementById('rc-dst').value=d;
      document.getElementById('rc-proto').value=pr;document.getElementById('rc-port').value=pt;document.getElementById('rc-run').click();},sip,dip,proto,port);
    await sleep(150);
    return p.evaluate(()=>{
      const v=document.querySelector('#rc-result .rc-verdict');
      const hops=[...document.querySelectorAll('#rc-result .rc-hop')].map(h=>h.textContent.replace(/\s+/g,' ').trim());
      return { verdict:v?v.className.replace('rc-verdict ','').trim():null, hops };
    });
  }
  // L2: two hosts in same VLAN 10 subnet (10.1.10.x) -> L2 direct, not filtered
  let r=await q('10.1.10.50','10.1.10.60','tcp','22');
  check('L2: same-VLAN traffic permitted (switched)', r.verdict==='permitted', JSON.stringify(r.verdict));
  check('L2: shows switched-at-layer-2 note', r.hops.some(h=>/layer.?2|switched/i.test(h)), JSON.stringify(r.hops));
  // inter-VLAN: 10.1.10.x -> 10.1.20.5:502 crosses SVI, permitted by inter_vlan ACL
  r=await q('10.1.10.50','10.1.20.5','tcp','502');
  check('inter-VLAN Modbus 502 permitted via L3 ACL', r.verdict==='permitted', JSON.stringify(r.verdict));
  // inter-VLAN other port blocked
  r=await q('10.1.10.50','10.1.20.5','tcp','22');
  check('inter-VLAN 22 blocked by L3 ACL', r.verdict==='blocked', JSON.stringify(r.verdict));
  // Moxa: Modbus permitted
  r=await q('192.168.10.5','192.168.20.10','tcp','502');
  check('Moxa Modbus 502 permitted', r.verdict==='permitted', JSON.stringify(r.verdict));

  // VLAN labels in topology
  const vlanLabels=await p.evaluate(()=>{
    const g=window.currentGraph; if(!g) return [];
    return g.nodes.filter(n=>n.vlan).map(n=>n.vlan);
  });
  check('topology labels VLANs', vlanLabels.length>=2, JSON.stringify(vlanLabels));

  check('no page errors', errs.length===0, errs.slice(0,2).join('|'));
  await b.close();
  const f=R.filter(x=>!x).length;
  console.log(`\n${R.length-f}/${R.length} OT + L2 checks passed`);
  process.exit(f?1:0);
})().catch(e=>{console.error('FATAL',e);process.exit(2);});
