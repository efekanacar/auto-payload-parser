/* Auto Payload Parser — no network, storage, eval or HTML interpolation. */
(function () {
'use strict';
const MAX = 1024 * 1024;
function parsePayload(source) {
 const rows = []; let format = '', warning = '';
 const add = (field,value,type,path) => rows.push({field,value,type,path});
 function flatten(value,path='',field='$',depth=0) {
  if(depth>80) throw new Error('Veri iç içe geçme sınırı (80) aşıldı.');
  if(value!==null && typeof value==='object') {
   const entries=Object.entries(value);
   if(!entries.length) add(field,Array.isArray(value)?'[]':'{}',Array.isArray(value)?'array':'object',path||'$');
   for(const [key,v] of entries) {const p=Array.isArray(value)?`${path}[${key}]`:(path?`${path}.${key}`:key);flatten(v,p,key,depth+1);}
  } else add(field,value===null?'null':String(value),value===null?'null':typeof value,path||'$');
 }
 function decode(v){try{return decodeURIComponent(v.replace(/\+/g,' '));}catch{warning='Bazı URL kodlamaları bozuk; ilgili değerler olduğu gibi gösterildi.';return v;}}
 function pairs(s,prefix='') {
  for(const part of s.split('&')){if(!part)continue;const eq=part.indexOf('=');const key=decode(eq<0?part:part.slice(0,eq));const v=decode(eq<0?'':part.slice(eq+1));add(key,v,'string',prefix+key);}
 }
 const raw=String(source).trim();
 if(!raw)return {rows,format:'Format bekleniyor',warning};
 if(new TextEncoder().encode(source).length>MAX) return {rows,format:'Boyut sınırı',warning:'En fazla 1 MB veri ayrıştırılabilir.'};
 try {
  if(/^[{\[]/.test(raw)) {flatten(JSON.parse(raw));format=raw[0]==='['?'JSON Array':'JSON';}
  else if(/^[A-Z]+\s+\S+\s+HTTP\/\d(?:\.\d)?(?:\r?\n|$)/.test(raw)) {
   format='Raw HTTP request';const lines=raw.split(/\r?\n/);const [method,path,version]=lines.shift().split(/\s+/);
   add('method',method,'string','request.method');add('path',path,'string','request.path');add('version',version,'string','request.version');
   let line;const headers=[];
   while(lines.length&&(line=lines.shift())!==''){const match=/^([^\s:]+):\s*(.*)$/.exec(line);if(!match)throw new Error('Geçersiz HTTP header satırı.');headers.push(match);add(match[1],match[2],'string','headers.'+match[1]);}
   const body=lines.join('\n');const ct=headers.find(h=>h[1].toLowerCase()==='content-type')?.[2]||'';
   if(body){if(/json/i.test(ct)||/^[{\[]/.test(body.trim()))flatten(JSON.parse(body),'body','body');else if(/application\/x-www-form-urlencoded/i.test(ct))pairs(body,'body.');else add('body',body,'string','body');}
   const q=path.indexOf('?');if(q>=0)pairs(path.slice(q+1),'query.');
  }
  else if(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(raw)) {
   format='JWT';const parts=raw.split('.');
   const segment=s=>{if(s.length%4===1)throw new Error('Geçersiz Base64url segmenti.');const binary=atob(s.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(s.length/4)*4,'='));return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(binary,c=>c.charCodeAt(0))));};
   const head=segment(parts[0]),body=segment(parts[1]);if(!head||typeof head!=='object'||Array.isArray(head)||typeof head.alg!=='string'||!body||typeof body!=='object'||Array.isArray(body))throw new Error('JWT header veya payload nesnesi geçersiz.');
   flatten(head,'header','header');flatten(body,'payload','payload');warning='JWT yalnızca decode edildi. İmza, geçerlilik ve güvenilirlik doğrulanmadı.';
  }
  else if(/^https?:\/\/\S+$/i.test(raw)&&raw.includes('?')) {const url=new URL(raw);format='URL Query Parameters';pairs(url.search.slice(1));}
  else if(/^\??[^\s=&?#]+=[^\r\n]*(?:&[^\s=&?#]+(?:=[^\r\n]*)?)*$/.test(raw)) {format=raw.startsWith('?')?'URL Query Parameters':'URL-encoded / Key=Value';pairs(raw.replace(/^\?/,''));}
  else if(!/^https?:\/\//i.test(raw)&&raw.split(/\r?\n/).every(l=>!l.trim()||/^\s*[A-Za-z0-9_.\[\]-]+\s*[=:]/.test(l))){
   format='Key / Value';for(const line of raw.split(/\r?\n/)){if(!line.trim())continue;const m=/^\s*([^=:]+?)\s*[=:]\s*(.*)$/.exec(line);add(m[1],m[2],'string',m[1]);}
  }
  else {
   format='IOC / Düz metin';const seen=new Set();const spans=[];
   const collect=(regex,type,valid=()=>true)=>{for(const match of raw.matchAll(regex)){let v=match[0].replace(/[.,;!?)\]}]+$/,'');const start=match.index,end=start+v.length;if(spans.some(s=>start>=s[0]&&end<=s[1])||!valid(v))continue;const key=type+':'+(['URL','hash'].includes(type)?v.toLowerCase():v.toLowerCase());if(seen.has(key))continue;seen.add(key);spans.push([start,end]);add(type,v,type,`ioc[${rows.length}]`);}};
   collect(/\bhttps?:\/\/[^\s<>"']+/gi,'URL',v=>{try{return !!new URL(v).hostname;}catch{return false;}});
   collect(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b/gi,'email');
   collect(/\bCVE-\d{4}-\d{4,}\b/gi,'CVE');
   collect(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g,'IPv4',v=>v.split('.').every(x=>Number(x)<=255));
   collect(/\b(?:[a-f0-9]{128}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi,'hash');
   collect(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi,'domain',v=>v.length<=253);
   if(!rows.length)warning='Bilinen bir veri formatı veya IOC bulunamadı.';
  }
 }catch(e){rows.length=0;warning='Ayrıştırılamadı: '+e.message;format=format||'Geçersiz JSON';}
 return {rows,format,warning};
}
function csv(rows){const cell=v=>'"'+(/^[=+@\-\t\r\n]/.test(String(v))?"'":'')+String(v).replace(/"/g,'""')+'"';return '\uFEFF'+[['Field','Value','Type','Path'],...rows.map(r=>[r.field,r.value,r.type,r.path])].map(r=>r.map(cell).join(',')).join('\r\n');}
if(typeof module!=='undefined'&&module.exports)module.exports={parsePayload,csv};
if(typeof document==='undefined')return;
const $=id=>document.getElementById(id);let result={rows:[]},visible=[],timer,toastTimer;
const toast=msg=>{$('toast').textContent=msg;$('toast').style.display='block';clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').style.display='none',2500);};
async function copy(text){try{await navigator.clipboard.writeText(text);toast('Panoya kopyalandı');}catch{toast('Panoya erişilemedi. HTTPS veya localhost kullanın.');}}
function render(){const term=$('search').value.toLocaleLowerCase('tr');visible=result.rows.filter(r=>(r.field+' '+r.value).toLocaleLowerCase('tr').includes(term));$('rows').replaceChildren();const fragment=document.createDocumentFragment();for(const r of visible){const tr=document.createElement('tr');for(const key of ['field','value','type','path']){const td=document.createElement('td');td.textContent=r[key];if(key==='value'){const b=document.createElement('button');b.textContent='⧉';b.title='Değeri kopyala';b.setAttribute('aria-label',r.field+' değerini kopyala');b.addEventListener('click',()=>copy(r.value));td.append(b);}tr.append(td);}fragment.append(tr);}$('rows').append(fragment);$('empty').hidden=visible.length>0;$('empty').querySelector('h3').textContent=result.rows.length?'Eşleşme bulunamadı.':'Henüz sonuç yok.';$('count').textContent=result.rows.length;$('summary').textContent=`${visible.length} / ${result.rows.length} alan gösteriliyor`;for(const id of ['copy','csv','json'])$(id).disabled=!visible.length;}
function run(){clearTimeout(timer);result=parsePayload($('input').value);$('size').textContent=`${$('input').value.length.toLocaleString('tr')} karakter · En fazla 1 MB`;$('format').textContent=result.format;$('notice').textContent=result.warning;render();}
$('input').addEventListener('input',()=>{clearTimeout(timer);timer=setTimeout(run,300);});$('parse').addEventListener('click',run);$('search').addEventListener('input',render);$('clear').addEventListener('click',()=>{$('input').value='';$('search').value='';$('file').value='';run();$('input').focus();});
$('copy').addEventListener('click',()=>copy(JSON.stringify(visible,null,2)));
function download(text,type,ext){const url=URL.createObjectURL(new Blob([text],{type}));const a=document.createElement('a');a.href=url;a.download='payload-results.'+ext;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
$('csv').addEventListener('click',()=>download(csv(visible),'text/csv;charset=utf-8','csv'));$('json').addEventListener('click',()=>download(JSON.stringify(visible,null,2),'application/json','json'));
$('file').addEventListener('change',async e=>{const f=e.target.files[0];if(!f)return;try{if(f.size>MAX)throw new Error('Dosya en fazla 1 MB olabilir.');if(!/\.(txt|json)$/i.test(f.name))throw new Error('Yalnızca TXT ve JSON dosyaları desteklenir.');$('input').value=await f.text();run();}catch(err){$('notice').textContent=err.message;}finally{e.target.value='';}});run();
})();



