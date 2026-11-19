(() => {
'use strict';
const $=id=>document.getElementById(id);
if(window.self!==window.top){try{if(window.parent.document.getElementById('reader')?.contentWindow===window){window.parent.dispatchEvent(new Event('study-home'));return}}catch{}}
const API=window.StudyVault, base=new URL('./',location.href);
const text={unsupported:'当前窗口不支持本机解锁，请用最新的系统浏览器打开。',worker:'本机书房未就绪。请联网刷新，或改用系统浏览器。',timeout:'连接超时，请检查网络后重试。',network:'所需资料尚未缓存在本机。请联网后再试。',package:'资料未通过校验或不完整。请重新联网再试。',key:'密钥不匹配。请完整复制私下收到的阅读密钥。',storage:'浏览器未能保存资料。请检查存储空间或退出无痕模式。'};
const msg=(s,err=false)=>{$('state').textContent=s;$('state').classList.toggle('error',err)};
const err=e=>text[e?.message]||'书房暂未就绪。请联网后重新打开。';
function controls(yes){$('key').disabled=!yes;$('unlock').disabled=!yes;$('remember').disabled=!yes;$('reveal').disabled=!yes}
function hiddenKey(){const x=$('key');x.type='password';$('reveal').setAttribute('aria-pressed','false');$('reveal').setAttribute('aria-label','显示密钥');$('reveal').textContent='显示'}
function go(page){$('reader').src=new URL('read/'+page,base).href}
let stateToken=0,saving=false,showing=false,ready=false;
function enter(r={}){showing=true;document.body.classList.add('reading');$('gate').hidden=true;$('study').hidden=false;$('offline-box').hidden=true;go('versions.html');if(r.offlineReady)$('offline-state').textContent='本机已保存完整离线版。'}
function exit(message){cleanupPDF();++stateToken;showing=false;saving=false;$('reader').removeAttribute('src');$('study').hidden=true;$('gate').hidden=false;document.body.classList.remove('reading');$('key').value='';$('remember').checked=false;$('offline-box').hidden=true;$('offline-state').textContent='把整套加密资料保存在这个浏览器，之后没有网络也能读。';$('save-offline').disabled=false;hiddenKey();controls(ready);$('prog').hidden=true;msg(message||'已锁定，本机记住的密钥已移除。')}
$('reveal').onclick=()=>{const el=$('key'),on=el.type==='password';el.type=on?'text':'password';$('reveal').setAttribute('aria-pressed',String(on));$('reveal').setAttribute('aria-label',on?'隐藏密钥':'显示密钥');$('reveal').textContent=on?'隐藏':'显示';el.focus()};
$('form').onsubmit=async e=>{e.preventDefault();if(!ready||$('unlock').disabled)return;const code=$('key').value.trim();if(!code){msg('请先粘贴阅读密钥。',true);$('key').focus();return}
 const token=++stateToken;controls(false);hiddenKey();$('key').value='';msg('正在校验密钥并读取书目…');$('prog').hidden=false;
 try{const r=await API.unlock(code,$('remember').checked);if(token!==stateToken)return;if(!r.unlocked)throw Error('key');$('prog').hidden=true;enter(r)}catch(ex){if(token!==stateToken)return;controls(true);$('prog').hidden=true;msg(err(ex),true);$('key').focus()}};
let examWatch,pdfWatch,pdfDetach=()=>{};
function hideSave(){const a=$('device-save');a.removeAttribute('href');a.removeAttribute('download');a.setAttribute('aria-disabled','true');$('filename').textContent='正在准备当前 PDF…';}
function publishSave(blob,filename){const a=$('device-save');a.href=blob;a.download=filename||'研习本.pdf';a.setAttribute('aria-disabled','false');$('filename').textContent=a.download.replace(/^肖八_/,'').replace(/_/g,' · ');}
function cleanupPDF(){pdfWatch?.disconnect();pdfWatch=null;pdfDetach();pdfDetach=()=>{};hideSave();$('devicebar').hidden=true}
function enableDeviceSave(doc,win){const link=doc.getElementById('down'),status=doc.getElementById('loading');if(!link||!win.URL.createObjectURL)return;$('devicebar').hidden=false;hideSave();
 let active=true,current='',blobURL='',pending=null,version=0;
 const say=s=>{if(status)status.textContent=s};
 function reset(){hideSave();if(blobURL)win.URL.revokeObjectURL(blobURL);blobURL='';pending=null}
 async function prepare(){const raw=link.getAttribute('href')||'';if(!active||raw.startsWith('blob:'))return;
   const u=new URL(raw,doc.baseURI),want=new URL('read/pdf/',base);if(u.origin!==want.origin||!u.pathname.startsWith(want.pathname)||!/^([qa][1-8]?)\.pdf$/.test(u.pathname.slice(want.pathname.length)))return;
   const path=u.href;if(current===path&&blobURL){link.href=blobURL;publishSave(blobURL,link.download);return}if(current===path&&pending)return pending;
   const token=++version;reset();current=path;pending=(async()=>{try{const r=await win.fetch(path,{cache:'no-store',credentials:'omit'});if(!r.ok)throw 0;const b=await r.blob();if(b.size<5||(await b.slice(0,5).text())!=='%PDF-')throw 0;if(!active||token!==version)return;blobURL=win.URL.createObjectURL(new win.Blob([b],{type:'application/pdf'}));link.href=blobURL;publishSave(blobURL,link.download)}
   catch{if(active&&token===version){current='';$('filename').textContent='文件未准备好，请在书架中重试';say('本机文件未准备好，请重试或点「打开 PDF」。')}}finally{if(token===version)pending=null}})();return pending}
 function click(e){if(link.getAttribute('href')?.startsWith('blob:'))return;const requested=new URL(link.getAttribute('href')||'',doc.baseURI).href;e.preventDefault();say('正在准备当前 PDF…');prepare().then(()=>{if(!active||!blobURL||requested!==current)return;say('文件已准备，可点下载或长按保存。');link.click()})}
 link.addEventListener('click',click);pdfWatch=new MutationObserver(()=>{prepare()});pdfWatch.observe(link,{attributes:true,attributeFilter:['href']});prepare();
 pdfDetach=()=>{active=false;++version;link.removeEventListener('click',click);reset()};
}
function inspectMode(){examWatch?.disconnect();cleanupPDF();const toggle=on=>{$('catalog').hidden=on;$('shelf').hidden=on;};toggle(false);try{const f=$('reader'),doc=f.contentDocument;if(doc?.body.classList.contains('pdf-shelf'))enableDeviceSave(doc,f.contentWindow);if(!doc?.body.classList.contains('exam'))return;const footer=doc.getElementById('footer'),room=doc.getElementById('room');if(!footer||!room)return;const sync=()=>toggle(!room.hidden&&footer.hidden);sync();examWatch=new MutationObserver(sync);for(const el of [footer,room])examWatch.observe(el,{attributes:true,attributeFilter:['hidden']});}catch{}}
$('reader').addEventListener('load',inspectMode);
$('catalog').onclick=()=>go('versions.html');$('shelf').onclick=()=>go('pdf.html');window.addEventListener('study-home',()=>go('versions.html'));
$('lock').onclick=async()=>{if(!showing)return;$('lock').disabled=true;try{await API.lock();exit()}catch(e){exit('锁定状态未能确认。请联网后重试锁定。清除网站数据也会清除本机练习记录。');msg($('state').textContent,true)}finally{$('lock').disabled=false}};
window.addEventListener('vault:locked',()=>exit());
$('offline').onclick=()=>{const p=$('offline-box');p.hidden=!p.hidden;$('offline').setAttribute('aria-expanded',String(!p.hidden));if(!p.hidden)$('save-offline').focus()};
$('close-offline').onclick=()=>{$('offline-box').hidden=true;$('offline').setAttribute('aria-expanded','false');$('offline').focus()};
$('save-offline').onclick=async()=>{if(saving)return;saving=true;const token=stateToken,b=$('save-offline'),p=$('offprog'),out=$('offline-state');b.disabled=true;p.hidden=false;p.removeAttribute('value');out.textContent='正在保存整套资料，请保持书房打开…';
 try{await API.prepareOffline((arg,y)=>{if(token!==stateToken)return;const done=typeof arg==='number'?arg:arg?.done,total=typeof y==='number'?y:arg?.total;if(Number.isFinite(done)&&Number.isFinite(total)&&total>0){p.max=total;p.value=done;out.textContent='正在保存并校验资料：'+done+' / '+total;}});if(token!==stateToken)return;out.textContent='整套资料已保存并校验，可以离线重开。未选择记住密钥时，重新打开仍需解锁。'}
 catch(e){if(token===stateToken)out.textContent='尚未保存完整。'+err(e)}finally{if(token===stateToken){p.hidden=true;b.disabled=false;saving=false}}};
(async()=>{controls(false);try{if(!API)throw Error('unsupported');await API.start();ready=true;const r=await API.status();if(r.unlocked){enter(r);return}controls(true);msg('密钥只在这个浏览器内使用。')}catch(e){controls(ready);msg(err(e),true)}})();
})();
