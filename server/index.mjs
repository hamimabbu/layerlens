import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { lookup } from 'node:dns/promises';
import { createHmac, randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { connectionContext, evidence, isPublicIP, normalizeIP } from './evidence.mjs';
import { collectPublic } from './collectors.mjs';

const PUBLIC = fileURLToPath(new URL('../public/', import.meta.url));
const FILES = { '/': ['index.html','text/html'], '/styles.css': ['styles.css','text/css'], '/app.mjs': ['app.mjs','text/javascript'], '/report.mjs': ['report.mjs','text/javascript'], '/mark.svg': ['mark.svg','image/svg+xml'] };
export const settings = (env = process.env) => ({
  host: env.HOST || '127.0.0.1', port: Number(env.PORT || 8787),
  external: env.ENABLE_EXTERNAL_LOOKUPS === 'true', internetdb: env.ENABLE_INTERNETDB === 'true',
  dnsServers: (env.DNS_RESOLVERS || '').split(',').map(x => x.trim()).filter(x => normalizeIP(x)),
  trusted: (env.TRUSTED_PROXY_IPS || '').split(',').map(x => x.trim()).filter(Boolean),
  trustedHost: env.TRUSTED_PROXY_HOST || '',
  appOrigin: env.APP_ORIGIN || '', transportOrigin: checkedTransportOrigin(env.TRANSPORT_ORIGIN)
});

function checkedTransportOrigin(value) {
  if (!value) return '';
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash || !/^[a-z0-9.:[\]-]+$/i.test(url.hostname)) throw new Error('TRANSPORT_ORIGIN must be an HTTPS origin');
  return url.origin;
}

export function createApp(options = settings()) {
  const buckets = new Map(), salt = randomBytes(32);
  let peers = [...options.trusted], peerExpiry = 0;
  const headers = {
    'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer',
    'content-security-policy': `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self' ${options.transportOrigin || ''}; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`,
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), browsing-topics=()'
  };
  function send(res, code, data) { res.writeHead(code, { ...headers, 'content-type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(data)); }
  const cleanup = setInterval(() => { const now = Date.now(); for (const [key,value] of buckets) if (value.expires < now) buckets.delete(key); },1000); cleanup.unref();
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://localhost');
      const isTransport = url.pathname === '/api/transport';
      const approvedProbe = Boolean(options.transportOrigin && options.appOrigin && req.headers.origin === options.appOrigin);
      if (isTransport && req.method === 'OPTIONS') {
        if (!approvedProbe) { send(res,403,{error:'Diagnostic origin is not configured or approved'}); return; }
        res.writeHead(204,{...headers,'access-control-allow-origin':options.appOrigin,'access-control-allow-methods':'POST','access-control-allow-headers':'content-type','vary':'Origin'}); res.end(); return;
      }
      if (isTransport && approvedProbe) { res.setHeader('access-control-allow-origin',options.appOrigin); res.setHeader('vary','Origin'); }
      if (req.method === 'GET' && FILES[url.pathname]) {
        const [file, type] = FILES[url.pathname];
        res.writeHead(200, { ...headers, 'content-type': type + '; charset=utf-8' }); res.end(await readFile(PUBLIC + file)); return;
      }
      if (req.method === 'GET' && url.pathname === '/api/config') {
        send(res, 200, { version: '0.1.0', transportOrigin: options.transportOrigin && options.appOrigin ? options.transportOrigin : null, checks: { ptr: options.external && options.dnsServers.length > 0, rdap: options.external, internetdb: options.external && options.internetdb }, recipients: { ptr: options.dnsServers.join(', ') || 'Not configured', rdap: 'IANA bootstrap, then the selected regional internet registry', internetdb: 'Shodan InternetDB' }, retention: 'Results are request-scoped. Hashed rate counters are removed within 61 seconds. Hosting/proxy logs need separate configuration.' }); return;
      }
      if (req.method === 'GET' && url.pathname === '/healthz') { send(res, 200, { status: 'ok' }); return; }
      if (req.method !== 'POST' || !['/api/connection','/api/enrich','/api/transport'].includes(url.pathname)) { send(res,404,{error:'Not found'}); return; }
      if (isTransport && !approvedProbe) { send(res,403,{error:'Diagnostic origin is not configured or approved'}); return; }
      if (req.headers.origin) {
        let origin; try { origin = new URL(req.headers.origin); } catch { send(res,403,{error:'Invalid origin'}); return; }
        if ((!isTransport && origin.host !== req.headers.host) || !['http:','https:'].includes(origin.protocol)) { send(res,403,{error:'Cross-origin request rejected'}); return; }
      }
      if ((req.headers['content-type'] || '').split(';')[0].trim().toLowerCase() !== 'application/json') { send(res,415,{error:'JSON required'}); return; }
      let body = ''; for await (const chunk of req) { body += chunk; if (Buffer.byteLength(body) > 4096) { send(res,413,{error:'Request too large'}); return; } }
      let input; try { input = JSON.parse(body); } catch { send(res,400,{error:'Invalid JSON'}); return; }
      if (!input || typeof input !== 'object' || Array.isArray(input)) { send(res,400,{error:'JSON object required'}); return; }
      if (input.consent !== true) { send(res,400,{error:'An explicit choice is required'}); return; }
      if ('ip' in input || 'url' in input || 'host' in input || 'target' in input) { send(res,400,{error:'Arbitrary targets are not accepted'}); return; }
      if (options.trustedHost && Date.now() > peerExpiry) {
        try { peers = [...options.trusted, ...(await lookup(options.trustedHost, { all: true })).map(x => x.address)]; peerExpiry = Date.now() + 60000; }
        catch { peers = [...options.trusted]; peerExpiry = Date.now() + 5000; }
      }
      const context = connectionContext(req, peers);
      const now = Date.now(); for (const [key, value] of buckets) if (value.expires < now) buckets.delete(key);
      const key = createHmac('sha256', salt).update(context.ip || 'unknown').digest('hex');
      const counter = buckets.get(key) || { count: 0, expires: now + 60000 };
      if (counter.count >= 20 || buckets.size >= 2000 && !buckets.has(key)) { send(res,429,{error:'Please wait a minute before trying again'}); return; }
      counter.count++; buckets.set(key, counter);
      if (url.pathname === '/api/connection' || isTransport) {
        const transport = [];
        for (const [field,value] of [['JA3 fingerprint', context.ja3],['JA4 fingerprint', context.ja4],['HTTP/2 fingerprint', context.http2]]) transport.push(evidence(field,value,'Trusted Fingerproxy ingress','A connection pattern, not proof of identity or device ownership.', { kind: 'measured', subject: 'client-to-proxy connection' }));
        send(res,200,{ mode: 'live', evidence: isTransport ? transport : [evidence('Public connection address',context.ip,'Application socket / approved ingress','A public exit address can represent multiple people or devices.',{kind:'observed'}),evidence('Application connection',context.protocol,'Node HTTP server','This describes the application-side connection. It is not automatically browser-to-edge TLS.',{kind:'observed'})], publicAddress: isPublicIP(context.ip), trustedTransport: context.fromProxy, receipt: { check: isTransport ? 'Transport diagnostic' : 'Connection check', execution: isTransport ? 'Dedicated first-party TLS ingress' : 'Our server', recipients: [isTransport ? options.transportOrigin : 'This deployment'], sent: [isTransport ? 'A new diagnostic request and its protocol metadata. Browser cookies omitted.' : 'Ordinary request headers and connecting IP'], retained: 'No results database. Hashed rate counters are removed within 61 seconds; deployment logs are separate.' } }); return;
      }
      const enabled = { ptr: options.external && options.dnsServers.length > 0, rdap: options.external, internetdb: options.external && options.internetdb };
      const checks = input.checks;
      if (input.publicRecordsConsent !== true || !Array.isArray(checks) || !checks.length || checks.length > 3 || new Set(checks).size !== checks.length || checks.some(c => typeof c !== 'string' || !Object.hasOwn(enabled, c) || enabled[c] !== true)) { send(res,400,{error:'Select only configured checks and approve their recipients'}); return; }
      if (!isPublicIP(context.ip)) { send(res,400,{error:'This is a local or reserved connection. No address was sent to external providers.'}); return; }
      send(res,200,{ mode:'live', results: await collectPublic(context.ip, checks, options) });
    } catch { if (!res.headersSent) send(res,500,{error:'The check could not complete. No detailed request was logged.'}); else res.end(); }
  });
  server.requestTimeout = 10000; server.headersTimeout = 10000; server.keepAliveTimeout = 5000;
  server.on('close',() => clearInterval(cleanup));
  return server;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const options = settings();
  createApp(options).listen(options.port,options.host,() => console.log(`LayerLens: http://${options.host}:${options.port}`));
}
