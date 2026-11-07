import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeIP, isPublicIP, connectionContext, redactReport } from '../server/evidence.mjs';
import { registryURL, fetchJSON, internetdb } from '../server/collectors.mjs';
import { createApp, settings } from '../server/index.mjs';

test('address normalization handles mapped IPv6 without accepting arbitrary text', () => {
  assert.equal(normalizeIP('::ffff:127.0.0.1'),'127.0.0.1');
  assert.equal(normalizeIP('::ffff:7f00:1'),'127.0.0.1');
  assert.equal(normalizeIP('127.0.0.1; whoami'),null);
  assert.equal(normalizeIP('fe80::1%eth0'),null);
});

test('public-record gate rejects local, shared, documentation and multicast addresses', () => {
  for (const ip of ['127.0.0.1','10.1.2.3','172.31.2.3','192.168.1.1','100.64.2.3','169.254.1.1','198.51.100.2','203.0.113.4','224.0.0.1','::1','fc00::1','fe80::1','2001:db8::1','::ffff:10.0.0.1','::ffff:a00:1']) assert.equal(isPublicIP(ip),false,ip);
  for (const ip of ['1.1.1.1','8.8.8.8','2606:4700:4700::1111']) assert.equal(isPublicIP(ip),true,ip);
});

test('untrusted forwarding and fingerprint headers never become observed evidence', () => {
  const req = {socket:{remoteAddress:'127.0.0.1'},httpVersion:'1.1',headers:{'x-forwarded-for':'8.8.8.8','x-ja4-fingerprint':'t13_example'}};
  const result = connectionContext(req,[]);
  assert.equal(result.ip,'127.0.0.1'); assert.equal(result.ja4,null); assert.equal(result.fromProxy,false);
});

test('single approved ingress uses rightmost forwarded address and validates fingerprints', () => {
  const req = {socket:{remoteAddress:'::ffff:127.0.0.1'},httpVersion:'1.1',headers:{'x-forwarded-for':'198.51.100.2, 1.1.1.1','x-ja4-fingerprint':'<script>','x-ja3-fingerprint':'a'.repeat(32)}};
  const result = connectionContext(req,['127.0.0.1']);
  assert.equal(result.ip,'1.1.1.1'); assert.equal(result.ja4,null); assert.equal(result.ja3,'a'.repeat(32));
});

test('RDAP selection uses longest prefix and rejects malicious bootstrap destinations', () => {
  const data = {services:[[['0.0.0.0/0'],['https://rdap.arin.net/registry/']],[['1.0.0.0/8'],['https://rdap.apnic.net/']]]};
  assert.equal(registryURL('1.1.1.1',data).hostname,'rdap.apnic.net');
  assert.throws(() => registryURL('1.1.1.1',{services:[[['0.0.0.0/0'],['http://127.0.0.1/']]]}));
});

test('HTTP adapter blocks unapproved URLs before calling fetch', async () => {
  let calls = 0; const fetcher = async () => { calls++; return Response.json({ok:true}); };
  for (const url of ['http://data.iana.org/','https://127.0.0.1/','https://user:password@data.iana.org/','https://data.iana.org:9443/']) await assert.rejects(fetchJSON(url,{hosts:new Set(['data.iana.org']),fetcher}));
  assert.equal(calls,0);
});

test('HTTP adapter limits chunked responses, disables redirects, and parses JSON', async () => {
  let seen;
  const fetcher = async (_url,options) => { seen = options; return new Response('x'.repeat(100)); };
  await assert.rejects(fetchJSON('https://data.iana.org/test',{hosts:new Set(['data.iana.org']),fetcher,maxBytes:30}),/too large/);
  assert.equal(seen.redirect,'error');
  const result = await fetchJSON('https://data.iana.org/test',{hosts:new Set(['data.iana.org']),fetcher:async()=>Response.json({services:[]})});
  assert.deepEqual(result,{services:[]});
});

test('report redaction removes connection identifiers without claiming anonymity', () => {
  const result = redactReport({evidence:[{field:'Public connection address',value:'1.1.1.1'},{field:'JA4 fingerprint',value:'example'},{field:'Registered network',value:'Example network'}]});
  assert.equal(result.evidence[0].value,'[redacted]'); assert.equal(result.evidence[1].value,'[redacted]'); assert.equal(result.evidence[2].value,'Example network'); assert.match(result.notice,/does not guarantee/);
});

async function app(t, changes = {}) {
  const server = createApp({...settings({}),...changes});
  await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}`;
}
const post = (url,body,headers={}) => fetch(url,{method:'POST',headers:{'content-type':'application/json',...headers},body:JSON.stringify(body)});

test('default app serves a CSP-protected local page and disabled external configuration', async t => {
  const base = await app(t); const page = await fetch(base);
  assert.equal(page.status,200); assert.match(page.headers.get('content-security-policy'),/frame-ancestors 'none'/); assert.equal(page.headers.get('cache-control'),'no-store');
  const data = await (await fetch(base+'/api/config')).json(); assert.deepEqual(data.checks,{ptr:false,rdap:false,internetdb:false});
});

test('API requires a consent object and rejects arbitrary targets', async t => {
  const base = await app(t);
  for (const body of [null,[],{}, {consent:false},{consent:true,ip:'1.1.1.1'}]) assert.equal((await post(base+'/api/connection',body)).status,400);
});

test('connection API ignores spoofed IP and transport headers', async t => {
  const base = await app(t);
  const response = await post(base+'/api/connection',{consent:true},{'x-forwarded-for':'8.8.8.8','x-ja4-fingerprint':'t13_test'});
  const data = await response.json(); assert.equal(data.publicAddress,false); assert.equal(data.evidence[0].value,'127.0.0.1'); assert.equal(data.evidence.some(x=>x.field==='JA4 fingerprint'),false);
});

test('cross-origin and disabled enrichment requests are rejected', async t => {
  const base = await app(t);
  assert.equal((await post(base+'/api/connection',{consent:true},{origin:'https://evil.invalid'})).status,403);
  assert.equal((await post(base+'/api/enrich',{consent:true,publicRecordsConsent:true,checks:['rdap']})).status,400);
});

test('even enabled adapters cannot send local addresses to a provider', async t => {
  const base = await app(t,{external:true,dnsServers:['1.1.1.1']});
  const response = await post(base+'/api/enrich',{consent:true,publicRecordsConsent:true,checks:['rdap']});
  assert.equal(response.status,400); assert.match((await response.json()).error,/No address was sent/);
});

test('API quota prevents unlimited repeated calls', async t => {
  const base = await app(t);
  for(let n=0;n<20;n++) assert.equal((await post(base+'/api/connection',{consent:true})).status,200);
  assert.equal((await post(base+'/api/connection',{consent:true})).status,429);
});

test('transport endpoint requires explicit operator origin and a trusted peer', async t => {
  const disabled = await app(t);
  assert.equal((await post(disabled+'/api/transport',{consent:true})).status,403);
  const base = await app(t,{transportOrigin:'https://transport.example.invalid',appOrigin:'https://lab.example.invalid',trusted:['127.0.0.1']});
  const response = await post(base+'/api/transport',{consent:true},{origin:'https://lab.example.invalid','x-ja4-fingerprint':'t13_example','x-forwarded-for':'1.1.1.1'});
  assert.equal(response.status,200); assert.equal(response.headers.get('access-control-allow-origin'),'https://lab.example.invalid');
  const data = await response.json(); assert.equal(data.trustedTransport,true); assert.equal(data.evidence.find(x=>x.field==='JA4 fingerprint').value,'t13_example');
});

test('InternetDB retains valid CVE identifiers and drops malformed values', async t => {
  t.mock.method(globalThis, 'fetch', async () => Response.json({
    vulns: ['CVE-2025-1234', 'cve-2024-12345', 'CVE-2025-nope', '<script>', null]
  }));
  const result = await internetdb('1.1.1.1');
  assert.equal(result.evidence.find(row => row.field === 'Unconfirmed CVE associations').value,
    'CVE-2025-1234, cve-2024-12345');
});

test('unconfigured collector names never pass the API gate through object prototypes', async t => {
  const base = await app(t, { external: true });
  for (const check of ['constructor', 'toString', '__proto__', null, {}, ['rdap']]) {
    const response = await post(base + '/api/enrich', {
      consent: true, publicRecordsConsent: true, checks: [check]
    }, { 'x-forwarded-for': '1.1.1.1' });
    assert.equal(response.status, 400);
    assert.match((await response.json()).error, /Select only configured checks/);
  }
});

test('browser export redacts IPv4 and IPv6 resolver receipts and preserves source state', () => {
  const source = {
    evidence: [{ field: 'Reported browser', value: 'Private browser details' }],
    receipts: [
      { check: 'ptr · complete', recipients: ['2001:4860:4860::8888, 1.1.1.1'] },
      { check: 'rdap · complete', recipients: ['rdap.apnic.net'] }
    ]
  };
  const result = redactReport(source);
  assert.equal(result.evidence[0].value, '[redacted]');
  assert.deepEqual(result.receipts[0].recipients, ['[resolver redacted]']);
  assert.deepEqual(result.receipts[1].recipients, ['rdap.apnic.net']);
  assert.equal(source.evidence[0].value, 'Private browser details');
  assert.equal(source.receipts[0].recipients[0], '2001:4860:4860::8888, 1.1.1.1');
});

test('browser redaction module is available from the app', async t => {
  const base = await app(t);
  const response = await fetch(base + '/report.mjs');
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type'), /javascript/);
  assert.match(await response.text(), /export function redactReport/);
});

test('similar media type names are not accepted as JSON', async t => {
  const base = await app(t);
  assert.equal((await post(base + '/api/connection', { consent: true }, {
    'content-type': 'application/jsonp'
  })).status, 415);
});
