const assert=require('node:assert/strict');
const {parsePayload:p,csv}=require('./script.js');
let count=0;function test(name,fn){fn();console.log('OK '+name);count++;}
test('Basit JSON',()=>assert.equal(p('{"a":1}').rows[0].type,'number'));
test('Nested JSON ve array',()=>assert.equal(p('{"items":[{"name":"x"}]}').rows[0].path,'items[0].name'));
test('Query string',()=>assert.deepEqual(p('?a=hello+world&a=2').rows.map(x=>x.value),['hello world','2']));
test('HTTP POST JSON',()=>{const r=p('POST /api?x=1 HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{"ok":true}');assert.equal(r.warning,'');assert(r.rows.some(x=>x.path==='body.ok'));assert(r.rows.some(x=>x.path==='query.x'));});
test('Form',()=>assert.equal(p('name=Efe&text=%C3%A7').rows[1].value,'ç'));
test('JWT Unicode',()=>{const enc=x=>Buffer.from(JSON.stringify(x)).toString('base64url');const r=p(enc({alg:'none'})+'.'+enc({name:'Çağrı 😀'})+'.');assert.equal(r.rows[1].value,'Çağrı 😀');assert.match(r.warning,/doğrulanmadı/);});
test('IOC ve tekrarlar',()=>{const r=p('Bulgular 192.168.1.1 192.168.1.1 999.2.3.4 example.com https://host.test/a analyst@mail.test CVE-2025-12345 '+ 'a'.repeat(64));assert.equal(r.rows.length,6);});
test('Bozuk JSON',()=>{assert.equal(p('{"a":}').rows.length,0);assert(p('{"a":}').warning);});
test('Bozuk URL encoding',()=>assert(p('a=%ZZ').warning));
test('Key value satırları',()=>assert.equal(p('user: analyst\nip: 10.0.0.1').rows.length,2));
test('HTTP form body',()=>assert(p('POST / HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\na=b').rows.some(x=>x.path==='body.a')));
test('Boş nesne ve null',()=>assert.equal(p('{"a":{},"b":null}').rows.length,2));
test('HTML güvenli veri olarak kalır',()=>assert.equal(p('{"a":"<script>alert(1)</script>"}').rows[0].value,'<script>alert(1)</script>'));
test('Boyut sınırı',()=>assert.match(p('a'.repeat(1048577)).warning,/1 MB/));
test('CSV formül ve tırnak',()=>assert(csv([{field:'x',value:'=1+1',type:'string',path:'x'}]).includes("\"'=1+1\"")));
test('Geçersiz JWT',()=>assert(p('e.e.e').warning));
console.log(`${count} test geçti.`);

