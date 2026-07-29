const puppeteer=require('puppeteer-core');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const R=[]; const check=(n,ok,i='')=>{R.push(ok);console.log((ok?'PASS':'FAIL')+'  '+n+(i?'  — '+i:''));};
(async()=>{
  const b=await puppeteer.launch({executablePath: process.env.CHROME_PATH || require('./_chrome').find(),headless:'new',args:['--no-sandbox','--disable-dev-shm-usage']});
  const p=await b.newPage(); await p.setViewport({width:1440,height:900});
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto('http://127.0.0.1:8077/nettopo.html',{waitUntil:'networkidle0'});
  await (await p.$('#fileinput')).uploadFile('tests/fixtures/vendors/pa.conf','tests/fixtures/vendors/arista.conf');
  await sleep(1500);
  const fl=await p.evaluate(()=>[...document.querySelectorAll('#filelist li')].map(li=>li.innerText.replace(/\s+/g,' ')));
  check('Palo Alto classified', fl.some(t=>/Palo Alto/.test(t)), JSON.stringify(fl));
  check('Arista classified', fl.some(t=>/Arista/.test(t)));
  // reachability across the PA (zones)
  await p.click('#reach-btn'); await sleep(300);
  async function q(sip,dip,proto,port){
    await p.evaluate((s,d,pr,pt)=>{document.getElementById('rc-src').value=s;document.getElementById('rc-dst').value=d;
      document.getElementById('rc-proto').value=pr;document.getElementById('rc-port').value=pt;document.getElementById('rc-run').click();},sip,dip,proto,port);
    await sleep(150);
    return p.evaluate(()=>{const v=document.querySelector('#rc-result .rc-verdict');return v?v.className.replace('rc-verdict ','').trim():null;});
  }
  check('PA: untrust->dmz web 443 permitted', await q('198.51.100.9','10.10.0.80','tcp','443')==='permitted');
  // (loose-any rule intentionally present so any-any finding fires; 22 is permitted by it)
  check('Arista: 40-net -> 10.30.0.90 443 permitted', await q('192.168.40.9','10.30.0.90','tcp','443')==='permitted');
  check('Arista: 40-net -> 10.30.0.90 22 blocked', await q('192.168.40.9','10.30.0.90','tcp','22')==='blocked');
  // findings from PA any-any and audit
  await p.click('#findings-btn'); await sleep(300);
  const F=await p.evaluate(()=>[...document.querySelectorAll('#f-list .f-title')].map(e=>e.textContent));
  check('PA any-any allow flagged', F.some(t=>/any→any allow/.test(t)), JSON.stringify([...new Set(F)]));
  check('no page errors', errs.length===0, errs.slice(0,2).join('|'));
  await b.close();
  const f=R.filter(x=>!x).length;
  console.log(`\n${R.length-f}/${R.length} new-vendor checks passed`);
  process.exit(f?1:0);
})().catch(e=>{console.error('FATAL',e);process.exit(2);});
