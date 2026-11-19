(() => {
  'use strict';
  const sw = navigator.serviceWorker, base = new URL('./', location.href);
  const script = new URL('sw.js?v=2', base).href;
  let inMemory = null, started = null, epoch = 0;
  const error = code => new Error(code);
  const current = worker => worker?.scriptURL === script;
  function request(action, data, progress) {
    return new Promise((resolve,reject) => {
      const worker=sw?.controller;
      if (!current(worker)) return reject(error('worker'));
      const ch=new MessageChannel();
      const timer=setTimeout(()=>{ch.port1.close();reject(error('timeout'))},240000);
      ch.port1.onmessage=({data:r})=>{
        if(r?.progress){
          try{progress?.(r.progress)}catch{}
          return;
        }
        clearTimeout(timer);
        ch.port1.close();
        if (r?.ok) resolve(r.state); else reject(error(r?.error || 'worker'));
      };
      worker.postMessage({action,...data},[ch.port2]);
    });
  }
  function start() {
    if (started) return started;
    started=(async()=>{
      if(!window.isSecureContext||!sw||!crypto?.subtle||!window.indexedDB) throw error('unsupported');
      const reg=await sw.register(script,{scope:base.href,updateViaCache:'none'});
      if(reg.scope!==base.href) throw error('worker');
      if(!current(sw.controller)) await new Promise((resolve,reject)=>{
        const off=()=>sw.removeEventListener('controllerchange',check);
        const timer=setTimeout(()=>{off();reject(error('timeout'))},16000);
        function check(){if(current(sw.controller)){off();clearTimeout(timer);resolve()}}
        sw.addEventListener('controllerchange',check);
        check();
      });
    })().catch(e=>{started=null;throw error(e.message==='unsupported'||e.message==='timeout' ? e.message : 'worker')});
    return started;
  }
  sw?.addEventListener('message',e=>{
    if(!current(e.source))return;
    if(e.data?.action==='VAULT_LOCKED'){inMemory=null;++epoch;window.dispatchEvent(new Event('vault:locked'));return}
    if(e.data?.action!=='VAULT_RESUPPLY'||!e.ports[0])return;
    try{e.ports[0].postMessage(inMemory);e.ports[0].close()}catch{}
  });
  function decode(code){
    const value=String(code??'').trim();
    if(!/^[A-Za-z0-9_-]{43}$/.test(value))throw error('key');
    try{
      const bin=atob(value.replace(/-/g,'+').replace(/_/g,'/')+'=');
      if(bin.length!==32||btoa(bin).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')!==value)throw error('key');
      return Uint8Array.from(bin,c=>c.charCodeAt(0));
    }catch{throw error('key')}
  }
  const status=async()=>{await start();return request('status',{key:inMemory})};
  const unlock=async(code,remember=false)=>{
    const generation=++epoch;
    const raw=decode(code); let key;
    try{key=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt'])}finally{raw.fill(0)}
    await start();
    if(generation!==epoch)throw error('worker');
    const state=await request('unlock',{key,remember:remember===true});
    if(generation!==epoch)throw error('worker');
    inMemory=key;
    return state;
  };
  const lock=async()=>{++epoch;inMemory=null;await start();return request('lock')};
  const prepareOffline=async(progress)=>{await start();return request('prepareOffline',{key:inMemory},progress)};
  window.StudyVault=Object.freeze({start,status,unlock,lock,prepareOffline});
})();
