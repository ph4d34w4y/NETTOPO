const puppeteer=require('puppeteer-core');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const R=[]; const check=(n,ok,i='')=>{R.push(ok);console.log((ok?'PASS':'FAIL')+'  '+n+(i?'  — '+i:''));};
(async()=>{
  const b=await puppeteer.launch({executablePath: process.env.CHROME_PATH || require('./_chrome').find(),headless:'new',args:['--no-sandbox','--disable-dev-shm-usage']});
  const p=await b.newPage(); await p.setViewport({width:1440,height:900});
  const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto('http://127.0.0.1:8077/nettopo.html',{waitUntil:'networkidle0'});
  await (await p.$('#fileinput')).uploadFile('tests/fixtures/multihop/fw1.cfg','tests/fixtures/multihop/fw2.cfg','tests/fixtures/multihop/flows.csv');
  await sleep(1500);
  const edges = await p.evaluate(()=>[...document.querySelectorAll('#canvas line')]
    .map(l=>l.__data__).filter(d=>d&&d.type==='flow')
    .map(d=>({s:d.source.id,t:d.target.id,r:!!d.routed})));
  const ids = new Set(); edges.forEach(e=>{ids.add(e.s);ids.add(e.t);});
  const S='host:192.168.30.50', D='host:10.80.0.90', F1='dev:fw1', F2='dev:fw2', T='net:172.16.0.0/30';
  const hasSeg=(a,z)=>edges.some(e=>(e.s===a&&e.t===z)||(e.s===z&&e.t===a));
  check('no direct src->dst edge', !hasSeg(S,D));
  check('segment src -> fw1', hasSeg(S,F1));
  check('segment fw1 -> transit subnet', hasSeg(F1,T));
  check('segment transit subnet -> fw2', hasSeg(T,F2));
  check('segment fw2 -> dst', hasSeg(F2,D));
  check('all path segments tagged routed', edges.filter(e=>[S,D,F1,F2,T].includes(e.s)&&[S,D,F1,F2,T].includes(e.t)).every(e=>e.r));
  // status line reflects hop count / routable
  const status = await p.evaluate(()=>document.getElementById('status').innerText);
  check('no unroutable flows (path was found)', !/not routable/.test(status), status);
  check('no page errors', errs.length===0, errs.slice(0,2).join('|'));
  await b.close();
  const f=R.filter(x=>!x).length;
  console.log(`\n${R.length-f}/${R.length} multi-hop checks passed`);
  process.exit(f?1:0);
})().catch(e=>{console.error('FATAL',e);process.exit(2);});
