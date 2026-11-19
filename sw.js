'use strict';
const BASE=new URL(self.registration.scope), READ=new URL('read/',BASE).pathname;
const DB='politics-review-v1@'+BASE.pathname;
const SHELL={'index.html':'text/html;charset=utf-8','shelf.css':'text/css;charset=utf-8','desk.js':'text/javascript;charset=utf-8','vault.js':'text/javascript;charset=utf-8'};
const TYPES={html:'text/html;charset=utf-8',js:'text/javascript;charset=utf-8',css:'text/css;charset=utf-8',json:'application/json;charset=utf-8',csv:'text/csv;charset=utf-8',txt:'text/plain;charset=utf-8',pdf:'application/pdf',webp:'image/webp',woff:'font/woff'};
const P=BASE.origin+READ;
const CSP=`default-src 'none'; script-src ${P}; style-src ${P} 'unsafe-inline'; font-src ${P}; img-src ${P} data: blob:; connect-src ${P}; object-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'`;
let seq=0, active=null, recoverFlight=null;
const fault=code=>Object.assign(new Error(code),{code});
self.addEventListener('install',event=>event.waitUntil((async()=>{
  await Promise.allSettled(Object.keys(SHELL).map(file=>warmShell(file)));
  await self.skipWaiting();
})()));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
function database(){
  return new Promise((done,fail)=>{
    const r=indexedDB.open(DB,1);
    r.onupgradeneeded=()=>r.result.createObjectStore('vault');
    r.onsuccess=()=>done(r.result); r.onerror=()=>fail(fault('storage'));
  });
}
async function record(mode,kind,id,data,guard){
  const d=await database();
  try{return await new Promise((done,fail)=>{
    if(guard&&!guard())return fail(fault('worker'));
    const tx=d.transaction('vault',mode), s=tx.objectStore('vault');
    const call=kind==='get'?s.get(id):kind==='delete'?s.delete(id):s.put(data,id);
    tx.oncomplete=()=>done(call.result);
    tx.onerror=tx.onabort=()=>fail(fault('storage'));
  });}finally{d.close()}
}
const get=id=>record('readonly','get',id);
const put=(id,v,guard)=>record('readwrite','put',id,v,guard);
const del=(id,guard)=>record('readwrite','delete',id,undefined,guard);
function b64(s){
  const raw=atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4));
  return Uint8Array.from(raw,c=>c.charCodeAt(0));
}
function permitted(key) {
  return key instanceof CryptoKey && key.type==='secret' && !key.extractable && key.algorithm.name==='AES-GCM' && key.algorithm.length===256 && key.usages.length===1 && key.usages[0]==='decrypt';
}
const MFIELDS=['schema','id','prefix','chunkSize','total','size','sha256'];
function canonicalB64(value,bytes){
  if(typeof value!=='string'||!/^[a-zA-Z0-9_-]+$/.test(value)||value.length!==Math.ceil(bytes*8/6))return false;
  try{const decoded=b64(value);return decoded.length===bytes&&btoa(String.fromCharCode(...decoded)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')===value}catch{return false}
}
function valid(m){
  return m!==null&&typeof m==='object'&&!Array.isArray(m)&&Object.keys(m).length===MFIELDS.length&&MFIELDS.every(k=>Object.hasOwn(m,k))&&m.schema===1
    &&canonicalB64(m.id,16)&&canonicalB64(m.prefix,8)
    &&Number.isSafeInteger(m.chunkSize)&&m.chunkSize>=256*1024&&m.chunkSize<=4*1024*1024&&Number.isSafeInteger(m.size)&&m.size>100&&m.size<=256*1024*1024
    &&Number.isSafeInteger(m.total)&&m.total===Math.ceil(m.size/m.chunkSize)&&m.total>0&&m.total<=1000&&typeof m.sha256==='string'&&/^[a-f0-9]{64}$/.test(m.sha256);
}
async function retrieve(url){
  const ctrl=new AbortController(), deadline=setTimeout(()=>ctrl.abort(),25000);
  try{
    const r=await fetch(new URL(url,BASE),{cache:'no-store',mode:'same-origin',credentials:'omit',redirect:'error',signal:ctrl.signal});
    if(!r.ok)throw fault('network');
    if(!url.endsWith('.json'))return await r.arrayBuffer();
    if(Number(r.headers.get('Content-Length'))>8192)throw fault('package');
    const text=await r.text();if(text.length>8192)throw fault('package');
    return JSON.parse(text);
  }catch(e){throw e instanceof SyntaxError||e?.code==='package'?fault('package'):fault('network')}finally{clearTimeout(deadline)}
}
async function lookupManifest(){
  let m;
  try{m=await retrieve('manifest.json')}catch(e){if(e?.code!=='network')throw e;m=await get('manifest').catch(()=>null);if(!m)throw e}
  if(!valid(m))throw fault('package');
  return m;
}
function memo(ctx,i){
  if(ctx.tid!==seq)return Promise.reject(fault('worker'));
  if(ctx.blocks.has(i))return ctx.blocks.get(i);
  const task=async()=>{
    const m=ctx.m, tag='chunk:'+m.id+':'+i, file='sealed/'+String(i).padStart(3,'0')+'.bin';
    const expected=Math.min(m.size-i*m.chunkSize,m.chunkSize)+16;
    const iv=new Uint8Array(12);iv.set(b64(m.prefix));new DataView(iv.buffer).setUint32(8,i);
    const additionalData=new TextEncoder().encode('PR1:'+m.id+':'+i+':'+m.total+':'+m.size+':'+m.chunkSize+':'+m.sha256);
    const dec=buf=>crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData,tagLength:128},ctx.key,buf);
    let c=await get(tag).catch(()=>null), out=null;
    if(c instanceof ArrayBuffer&&c.byteLength===expected)try{out=await dec(c)}catch{
      if(!ctx.confirmed)throw fault('key');
    }
    if(!out){
      c=await retrieve(file);
      if(c.byteLength!==expected)throw fault('package');
      try{out=await dec(c)}catch{throw fault(ctx.confirmed?'package':'key')}
      // Keep ciphertext only; browsers may choose to evict it without losing study records.
      await put(tag,c).catch(()=>{});
    }
    if(ctx.tid!==seq)throw fault('worker');
    return new Uint8Array(out);
  };
  const p=task().catch(e=>{ctx.blocks.delete(i);throw e});
  ctx.blocks.set(i,p);
  if(ctx.blocks.size>3)ctx.blocks.delete(ctx.blocks.keys().next().value);
  return p;
}
async function span(ctx,start,len){
  if(!Number.isSafeInteger(start)||!Number.isSafeInteger(len)||start<0||len<0||start+len>ctx.m.size)throw fault('package');
  const out=new Uint8Array(len);let offset=0;
  while(offset<len){
    const block=Math.floor((start+offset)/ctx.m.chunkSize), from=(start+offset)%ctx.m.chunkSize;
    const bytes=await memo(ctx,block), n=Math.min(len-offset,bytes.length-from);
    if(n<=0)throw fault('package');
    out.set(bytes.subarray(from,from+n),offset);offset+=n;
  }
  return out;
}
function suffix(name){return name.split('.').at(-1).toLowerCase()}
function safe(name){
  return name.length<=128&&name.split('/').every(x=>/^[a-z0-9][a-z0-9_.-]*$/i.test(x)&&!x.includes('..'))&&Object.hasOwn(TYPES,suffix(name));
}
async function directory(ctx){
  const end=ctx.m.size-22, e=new DataView((await span(ctx,end,22)).buffer);
  const count=e.getUint16(10,true), start=e.getUint32(16,true), length=e.getUint32(12,true);
  if(e.getUint32(0,true)!==0x06054b50||e.getUint16(4,true)!==0||e.getUint16(6,true)!==0||e.getUint16(8,true)!==count||e.getUint16(20,true)!==0||count<1||count>1500||length>1024*1024||start+length!==end)throw fault('package');
  const v=new DataView((await span(ctx,start,length)).buffer), b=new Uint8Array(v.buffer), files=new Map(), decode=new TextDecoder('utf-8',{fatal:true});
  const u16=p=>v.getUint16(p,true), u32=p=>v.getUint32(p,true);
  let p=0;
  try{
    for(let i=0;i<count;i++){
      if(p+46>length||u32(p)!==0x02014b50||u16(p+10)!==0||u16(p+8)&9)throw fault('package');
      const len=u32(p+24), local=u32(p+42), nl=u16(p+28), next=p+46+nl+u16(p+30)+u16(p+32);
      if(next>length||len!==u32(p+20)||len>20*1024*1024||local+30+nl+len>start)throw fault('package');
      const name=decode.decode(b.subarray(p+46,p+46+nl));
      if(!safe(name)||files.has(name))throw fault('package');
      files.set(name,{local,len,start});p=next;
    }
  }catch{throw fault('package')}
  if(p!==length||!files.has('versions.html')||!files.has('index.html'))throw fault('package');
  return files;
}
async function baseOf(ctx,name,file){
  const hdr=new DataView((await span(ctx,file.local,30)).buffer), n=hdr.getUint16(26,true), extra=hdr.getUint16(28,true);
  const start=file.local+30+n+extra;
  if(n!==name.length||extra>1024||start+file.len>file.start||hdr.getUint32(0,true)!==0x04034b50||hdr.getUint16(8,true)!==0||(hdr.getUint16(6,true)&9)||hdr.getUint32(18,true)!==file.len||hdr.getUint32(22,true)!==file.len)throw fault('package');
  const actual=new TextDecoder().decode(await span(ctx,file.local+30,n));
  if(actual!==name)throw fault('package');
  return start;
}
async function open(key,remembered,token,owner){
  if(!permitted(key))throw fault('key');
  const m=await lookupManifest();
  const ctx={m,key,blocks:new Map(),tid:token,confirmed:false,remembered:remembered===true,owner};
  ctx.files=await directory(ctx);
  if(token!==seq)throw fault('worker');
  ctx.confirmed=true;
  ctx.offlineReady=(await get('offline:'+m.id+':'+m.sha256).catch(()=>null))===true;
  await put('manifest',m).catch(()=>{});
  return ctx;
}
function shell(client){
  if(client?.type!=='window')return false;
  const u=new URL(client.url);
  return u.origin===BASE.origin&&(u.pathname===BASE.pathname||u.pathname===new URL('index.html',BASE).pathname);
}
function ask(client){
  return new Promise(done=>{
    const ch=new MessageChannel(), timer=setTimeout(()=>{ch.port1.close();done(null)},500);
    ch.port1.onmessage=({data})=>{ch.port1.close();clearTimeout(timer);done(permitted(data)?data:null)};
    try{client.postMessage({action:'VAULT_RESUPPLY'},[ch.port2])}catch{clearTimeout(timer);ch.port1.close();done(null)}
  });
}
async function stillOwned(ctx){
  return ctx.remembered||(typeof ctx.owner==='string'&&shell(await self.clients.get(ctx.owner)));
}
async function recover(supplied,owner=null){
  if(active){
    const ctx=active;
    if(await stillOwned(ctx)&&ctx.tid===seq)return owner&&ctx.owner!==owner&&!ctx.remembered?null:ctx;
    if(active===ctx){++seq;ctx.blocks.clear();active=null}
  }
  if(recoverFlight){
    const r=await recoverFlight;
    return owner&&r?.owner!==owner&&!r?.remembered?null:r;
  }
  const token=seq;
  recoverFlight=(async()=>{
    let stored=await get('remembered').catch(()=>null), candidate=permitted(supplied)?supplied:null, candidateOwner=candidate?owner:null;
    if(!candidate&&!permitted(stored)&&!owner){
      const all=(await self.clients.matchAll({type:'window',includeUncontrolled:false})).filter(shell);
      const keys=await Promise.all(all.map(ask)), i=keys.findIndex(permitted);
      if(i!==-1){candidate=keys[i];candidateOwner=all[i].id}
    }
    if(!permitted(stored)&&!candidate)return null;
    const r=await open(candidate||stored,permitted(stored),token,candidateOwner);
    if(token===seq&&await stillOwned(r)&&token===seq){active=r;return r}
    return null;
  })().finally(()=>{recoverFlight=null});
  return recoverFlight;
}
const snapshot=(ctx=active)=>({unlocked:!!ctx,remembered:ctx?.remembered===true,offlineReady:ctx?.offlineReady===true});
self.addEventListener('message',event=>{
  if(!shell(event.source)||!event.ports[0])return;
  const port=event.ports[0], data=event.data||{};
  event.waitUntil((async()=>{
    try{
      if(data.action==='status'){
        port.postMessage({ok:true,state:snapshot(await recover(data.key,event.source.id))});
        return;
      }
      else if(data.action==='unlock'){
        const token=++seq;
        active?.blocks.clear();active=null;
        const r=await open(data.key,data.remember===true,token,event.source.id);
        if(token!==seq)throw fault('worker');
        if(data.remember===true)await put('remembered',data.key,()=>token===seq);
        else await del('remembered',()=>token===seq);
        if(token!==seq)throw fault('worker');
        active=r;
      }else if(data.action==='prepareOffline'){
        const ctx=await recover(data.key,event.source.id);
        if(!ctx)throw fault('key');
        let complete;
        try{
          try{complete=new Uint8Array(ctx.m.size)}catch{throw fault('storage')}
          for(let i=0;i<ctx.m.total;i++){
            const tag='chunk:'+ctx.m.id+':'+i;
            complete.set(await memo(ctx,i),i*ctx.m.chunkSize);
            if(!(await get(tag))?.byteLength)throw fault('storage');
            port.postMessage({progress:{done:i+1,total:ctx.m.total}});
          }
          const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',complete));
          if(Array.from(digest,x=>x.toString(16).padStart(2,'0')).join('')!==ctx.m.sha256)throw fault('package');
          if(!await stillOwned(ctx))throw fault('worker');
          await put('offline:'+ctx.m.id+':'+ctx.m.sha256,true,()=>ctx.tid===seq);
          ctx.offlineReady=true;
        }finally{if(complete)complete.fill(0)}
      }else if(data.action==='lock'){
        ++seq;active?.blocks.clear();active=null;
        await del('remembered');
        const windows=await self.clients.matchAll({type:'window',includeUncontrolled:false});
        for(const client of windows.filter(shell))client.postMessage({action:'VAULT_LOCKED'});
      }else throw fault('worker');
      port.postMessage({ok:true,state:snapshot()});
    }catch(e){port.postMessage({ok:false,error:e?.code||'worker'})}finally{port.close()}
  })());
});
function resp(body,status=404,other={}){
  return new Response(body,{status,headers:{'Cache-Control':'no-store','Content-Security-Policy':CSP,'Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Robots-Tag':'noindex, nofollow','Content-Type':'text/plain;charset=utf-8',...other}});
}
function bounds(header,total){
  if(!header)return [0,total-1,200];
  const m=/^bytes=(\d*)-(\d*)$/.exec(header);
  if(!m||!total||(!m[1]&&!m[2]))return null;
  const x=Number(m[1]),y=Number(m[2]);
  if(!Number.isSafeInteger(x)||!Number.isSafeInteger(y))return null;
  const first=m[1]?x:Math.max(0,total-y), last=m[2]&&m[1]?Math.min(y,total-1):total-1;
  return first<total&&first<=last?[first,last,206]:null;
}
async function privateResponse(req,u){
  const name=u.pathname.slice(READ.length);
  if(!safe(name))return resp('文件不存在。');
  if(req.method!=='GET'&&req.method!=='HEAD')return resp('不支持的请求。',405,{Allow:'GET, HEAD'});
  try{
    const ctx=await recover();
    if(!ctx)return resp('请先在研习本入口解锁，再打开这个页面。',423);
    if(!ctx.remembered&&req.mode==='navigate'&&req.destination!=='iframe')return resp('请在已解锁的研习本窗口内阅读。',423);
    const f=ctx.files.get(name);
    if(!f)return resp('文件不存在。');
    const range=bounds(req.headers.get('Range'),f.len);
    if(!range)return resp(null,416,{'Content-Range':'bytes */'+f.len,'Accept-Ranges':'bytes'});
    const [first,last,status]=range, length=last-first+1, head={'Content-Type':TYPES[suffix(name)],'Content-Length':String(length),'Accept-Ranges':'bytes'};
    if(status===206)head['Content-Range']=`bytes ${first}-${last}/${f.len}`;
    if(req.method==='HEAD')return seq===ctx.tid?resp(null,status,head):resp('已锁定。',423);
    const start=await baseOf(ctx,name,f), bytes=await span(ctx,start+first,length);
    if(seq!==ctx.tid||!await stillOwned(ctx)||seq!==ctx.tid)return resp('已锁定。',423);
    return resp(bytes,status,head);
  }catch(e){
    if(e?.code==='network')return resp('这个文件暂未缓存在本机，请联网后重试。',503);
    if(e?.code==='worker'||e?.code==='key')return resp('书库已锁定，请返回入口。',423);
    return resp('本机未能读取该文件。',422);
  }
}
async function warmShell(name){
  const ctrl=new AbortController(), timeout=setTimeout(()=>ctrl.abort(),9000);
  try{
    const response=await fetch(new URL(name,BASE),{cache:'no-store',mode:'same-origin',credentials:'omit',redirect:'error',signal:ctrl.signal});
    if(!response.ok||response.type!=='basic')return;
    const bytes=await response.arrayBuffer();
    if(bytes.byteLength<=1024*1024)await put('shell:'+name,bytes);
  }finally{clearTimeout(timeout)}
}
async function publicShell(req,name){
  try{
    const r=await fetch(req);
    if(r.ok&&r.type==='basic'&&!r.redirected){
      const buf=await r.clone().arrayBuffer();
      if(buf.byteLength<=1024*1024)await put('shell:'+name,buf).catch(()=>{});
    }
    return r;
  }catch{
    const hit=await get('shell:'+name).catch(()=>null);
    return hit?new Response(hit,{headers:{'Content-Type':SHELL[name],'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}}):resp('请先联网打开研习本入口。',503);
  }
}
self.addEventListener('fetch',event=>{
  const u=new URL(event.request.url);
  if(u.origin===BASE.origin&&u.pathname.startsWith(READ)){
    event.respondWith(privateResponse(event.request,u));
    return;
  }
  if(u.origin===BASE.origin&&u.pathname.startsWith(BASE.pathname)&&event.request.method==='GET'){
    const file=u.pathname.slice(BASE.pathname.length)||'index.html';
    if(Object.hasOwn(SHELL,file))event.respondWith(publicShell(event.request,file));
  }
});
