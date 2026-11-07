// Tests for how the server behaves: files, methods, limits, quotas, timeouts and lookup errors.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import dgram from 'node:dgram';
import net from 'node:net';
import { cp, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isPublicIP, normalizeIP, rateLimitName } from '../server/evidence.mjs';
import { SourceError, collectPublic, fetchJSON, ptr } from '../server/collectors.mjs';
import { createApp, settings } from '../server/index.mjs';

const projectFolder = fileURLToPath(new URL('..', import.meta.url));

// Starts a server on a free port and stops it when the test ends.
async function listen(t, server) {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    server.closeAllConnections();
    return new Promise(resolve => server.close(resolve));
  });
  return `http://127.0.0.1:${server.address().port}`;
}

const startApp = (t, changes = {}) => listen(t, createApp({ ...settings({}), ...changes }));

function post(base, path, body, headers = {}) {
  return fetch(base + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body)
  });
}

// A server that trusts 127.0.0.1 as its proxy, so the test can choose the visitor address.
const behindProxy = t => startApp(t, { trusted: ['127.0.0.1'] });

async function callAs(base, ip) {
  const response = await post(base, '/api/connection', { consent: true }, { 'x-forwarded-for': ip });
  await response.arrayBuffer();
  return response.status;
}

/* ---------- Files and routes ---------- */

test('every file the page needs is served with the right content type', async t => {
  const base = await startApp(t);
  const types = {
    '/': 'text/html',
    '/styles.css': 'text/css',
    '/app.mjs': 'text/javascript',
    '/answers.mjs': 'text/javascript',
    '/content.mjs': 'text/javascript',
    '/browser-checks.mjs': 'text/javascript',
    '/report.mjs': 'text/javascript',
    '/mark.svg': 'image/svg+xml'
  };

  for (const [path, type] of Object.entries(types)) {
    const response = await fetch(base + path);
    assert.equal(response.status, 200, path);
    assert.ok(response.headers.get('content-type').startsWith(type), path);
    assert.ok((await response.text()).length > 100, `${path} should not be empty`);
  }
});

test('every script, style and module the page refers to can be loaded', async t => {
  const base = await startApp(t);
  const toVisit = ['/'];
  const seen = new Set();

  while (toVisit.length) {
    const path = toVisit.pop();
    if (seen.has(path)) continue;
    seen.add(path);

    const response = await fetch(base + path);
    assert.equal(response.status, 200, `${path} should load`);
    const content = await response.text();

    // Links in the page, like src="/app.mjs" or href="/styles.css"
    for (const match of content.matchAll(/(?:src|href)="(\/[^"#?]*)"/g)) toVisit.push(match[1]);
    // Imports between modules, like from './report.mjs'
    for (const match of content.matchAll(/from ['"]\.\/([\w-]+\.mjs)['"]/g)) toVisit.push('/' + match[1]);
  }

  for (const path of ['/app.mjs', '/answers.mjs', '/browser-checks.mjs', '/content.mjs', '/report.mjs', '/styles.css']) {
    assert.ok(seen.has(path), `${path} should be part of the page`);
  }
});

test('HEAD requests get the headers but no body', async t => {
  const base = await startApp(t);
  for (const path of ['/', '/app.mjs', '/api/config', '/healthz']) {
    const response = await fetch(base + path, { method: 'HEAD' });
    assert.equal(response.status, 200, path);
    assert.equal(await response.text(), '', path);
  }
});

test('a missing public file is an error, not an empty page', async t => {
  // Work on a copy of the project, so the real files stay as they are.
  const copy = await mkdtemp(join(tmpdir(), 'layerlens-test-'));
  t.after(() => rm(copy, { recursive: true, force: true }));
  await cp(join(projectFolder, 'server'), join(copy, 'server'), { recursive: true });
  await cp(join(projectFolder, 'public'), join(copy, 'public'), { recursive: true });
  await rm(join(copy, 'public', 'app.mjs'));

  const broken = await import(pathToFileURL(join(copy, 'server', 'index.mjs')).href);
  const base = await listen(t, broken.createApp(broken.settings({})));

  const missing = await fetch(base + '/app.mjs');
  assert.equal(missing.status, 500);
  assert.match((await missing.json()).error, /could not complete/);
  assert.equal((await fetch(base + '/')).status, 200); // the other files still work
});

test('wrong methods get 405 with an Allow header and unknown paths get 404', async t => {
  const base = await startApp(t);

  const wrongMethods = [
    ['POST', '/', 'GET, HEAD'],
    ['PUT', '/app.mjs', 'GET, HEAD'],
    ['DELETE', '/api/config', 'GET, HEAD'],
    ['POST', '/healthz', 'GET, HEAD'],
    ['GET', '/api/connection', 'POST'],
    ['PUT', '/api/enrich', 'POST'],
    ['OPTIONS', '/api/connection', 'POST']
  ];
  for (const [method, path, allow] of wrongMethods) {
    const response = await fetch(base + path, { method });
    assert.equal(response.status, 405, `${method} ${path}`);
    assert.equal(response.headers.get('allow'), allow, `${method} ${path}`);
  }

  for (const path of ['/nothing-here', '/app.mjs/', '/server/index.mjs', '/package.json', '/.env', '/api/']) {
    assert.equal((await fetch(base + path)).status, 404, path);
  }
});

test('security headers are on every kind of response', async t => {
  const base = await startApp(t);
  const responses = [
    await fetch(base + '/'),
    await fetch(base + '/app.mjs'),
    await fetch(base + '/api/config'),
    await fetch(base + '/nothing-here'),
    await fetch(base + '/', { method: 'POST' }),
    await post(base, '/api/connection', { consent: false }),
    await post(base, '/api/connection', '{not json'),
    await post(base, '/api/connection', { consent: true })
  ];

  for (const response of responses) {
    await response.arrayBuffer();
    const csp = response.headers.get('content-security-policy');
    assert.match(csp, /default-src 'self'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(response.headers.get('cross-origin-opener-policy'), 'same-origin');
  }
});

test('the config endpoint describes the deployment and never the visitor', async t => {
  const plain = await startApp(t);
  const config = await (await fetch(plain + '/api/config')).json();
  assert.equal(config.transportOrigin, null);
  assert.deepEqual(config.checks, { ptr: false, rdap: false, internetdb: false });
  assert.equal(JSON.stringify(config).includes('127.0.0.1'), false);
  assert.match((await fetch(plain + '/')).headers.get('content-security-policy'), /connect-src 'self';/);

  // The transport address is only passed on when the app origin is set too.
  const half = await startApp(t, { transportOrigin: 'https://transport.example.com' });
  assert.equal((await (await fetch(half + '/api/config')).json()).transportOrigin, null);

  const full = await startApp(t, { transportOrigin: 'https://transport.example.com', appOrigin: 'https://lab.example.com' });
  assert.equal((await (await fetch(full + '/api/config')).json()).transportOrigin, 'https://transport.example.com');
  assert.match((await fetch(full + '/')).headers.get('content-security-policy'), /connect-src 'self' https:\/\/transport\.example\.com;/);
});

/* ---------- Request rules ---------- */

test('request body size and content type rules', async t => {
  const base = await startApp(t);

  // A body of exactly 4096 bytes is accepted. One more byte is not.
  const bodyOfSize = size => {
    const start = '{"consent":true,"note":"';
    const end = '"}';
    return start + 'x'.repeat(size - start.length - end.length) + end;
  };
  assert.equal(Buffer.byteLength(bodyOfSize(4096)), 4096);
  assert.equal((await post(base, '/api/connection', bodyOfSize(4096))).status, 200);
  assert.equal((await post(base, '/api/connection', bodyOfSize(4097))).status, 413);

  // A charset part and capital letters are fine.
  for (const type of ['application/json; charset=utf-8', 'Application/JSON']) {
    const response = await post(base, '/api/connection', { consent: true }, { 'content-type': type });
    assert.equal(response.status, 200, type);
  }

  // Any other content type is refused.
  for (const type of ['text/plain', 'application/jsonp', 'application/json-seq', 'multipart/form-data']) {
    const response = await post(base, '/api/connection', { consent: true }, { 'content-type': type });
    assert.equal(response.status, 415, type);
  }

  // The body has to be one JSON object with consent set to true.
  for (const body of ['{nope', 'null', '[]', '"text"', '{}', '{"consent":"true"}', '{"consent":false}']) {
    assert.equal((await post(base, '/api/connection', body)).status, 400, body);
  }
});

test('a request can never name its own target', async t => {
  const base = await startApp(t);
  for (const key of ['ip', 'url', 'host', 'target']) {
    const response = await post(base, '/api/connection', { consent: true, [key]: '8.8.8.8' });
    assert.equal(response.status, 400, key);
    assert.match((await response.json()).error, /Arbitrary targets/, key);
  }
});

test('lookup choices must be unique, configured and approved', async t => {
  // Every case here is refused before a lookup starts, so no network is used.
  const base = await startApp(t, { external: true, dnsServers: ['1.1.1.1'], trusted: ['127.0.0.1'] });
  const send = body => post(base, '/api/enrich', { consent: true, ...body }, { 'x-forwarded-for': '1.1.1.1' });

  const refused = [
    { publicRecordsConsent: true, checks: [] }, // nothing chosen
    { publicRecordsConsent: true, checks: ['rdap', 'rdap'] }, // the same one twice
    { publicRecordsConsent: true, checks: ['rdap', 'ptr', 'internetdb', 'rdap'] }, // too many
    { publicRecordsConsent: true, checks: ['internetdb'] }, // not switched on by the operator
    { publicRecordsConsent: true, checks: 'rdap' }, // not a list
    { checks: ['rdap'] }, // the recipient was not approved
    { publicRecordsConsent: 'true', checks: ['rdap'] }
  ];

  for (const body of refused) {
    const response = await send(body);
    assert.equal(response.status, 400, JSON.stringify(body));
    assert.match((await response.json()).error, /Select only configured checks/);
  }
});

/* ---------- Visitor quota ---------- */

test('IPv6 visitors share one allowance per /64', async t => {
  const base = await behindProxy(t);

  for (let n = 1; n <= 20; n++) {
    assert.equal(await callAs(base, `2001:db8:1:1::${n.toString(16)}`), 200, `request ${n}`);
  }
  // A new address in the same /64 is still the same visitor.
  assert.equal(await callAs(base, '2001:db8:1:1:aaaa:bbbb:cccc:dddd'), 429);
  // A different /64 is a different visitor.
  assert.equal(await callAs(base, '2001:db8:1:2::1'), 200);
});

test('IPv4 visitors each get their own allowance', async t => {
  const base = await behindProxy(t);
  for (let n = 0; n < 20; n++) assert.equal(await callAs(base, '1.1.1.1'), 200);

  assert.equal(await callAs(base, '1.1.1.1'), 429);
  assert.equal(await callAs(base, '1.1.1.2'), 200);
});

test('the allowance comes back after a minute', async t => {
  const base = await behindProxy(t);
  const realNow = Date.now;
  let skipped = 0;
  t.mock.method(Date, 'now', () => realNow() + skipped);

  for (let n = 0; n < 20; n++) await callAs(base, '1.1.1.1');
  assert.equal(await callAs(base, '1.1.1.1'), 429);

  skipped = 61000;
  assert.equal(await callAs(base, '1.1.1.1'), 200);
});

test('the visitor table has a size limit', async t => {
  const base = await behindProxy(t);
  const address = n => `10.${n >> 8}.${n & 255}.7`;

  // 2000 different visitors fill the table.
  for (let first = 0; first < 2000; first += 100) {
    await Promise.all(Array.from({ length: 100 }, (_, i) => callAs(base, address(first + i))));
  }

  // A new visitor is refused while the table is full. One that is already in it can continue.
  assert.equal(await callAs(base, address(5000)), 429);
  assert.equal(await callAs(base, address(0)), 200);
});

test('rate limit names group IPv6 by /64 and keep IPv4 exact', () => {
  assert.equal(rateLimitName('1.2.3.4'), '1.2.3.4');
  assert.equal(rateLimitName('2001:db8:1:1::1'), rateLimitName('2001:db8:1:1:ffff:ffff:ffff:ffff'));
  assert.notEqual(rateLimitName('2001:db8:1:1::1'), rateLimitName('2001:db8:1:2::1'));
  assert.equal(rateLimitName(null), 'unknown');
});

/* ---------- Slow connections ---------- */

test('a connection that never finishes its request is closed', async t => {
  // A short timeout keeps the test quick. The real default is 10 seconds.
  const base = await startApp(t, { requestTimeout: 500 });
  const port = Number(new URL(base).port);
  const started = Date.now();

  const closedAfter = await new Promise(resolve => {
    const socket = net.connect(port, '127.0.0.1', () => {
      socket.write('POST /api/connection HTTP/1.1\r\nHost: localhost\r\n'); // the headers never end
    });
    socket.on('data', () => {}); // a 408 answer may arrive first, it does not matter
    socket.on('error', () => {});
    socket.on('close', () => resolve(Date.now() - started));
  });

  assert.ok(closedAfter < 3000, `the connection stayed open for ${closedAfter} ms`);
});

/* ---------- Address rules ---------- */

test('address classification follows the special-purpose registries', () => {
  const notPublic = [
    '0.0.0.0', '10.0.0.1', '100.64.0.1', '100.127.255.255', '127.0.0.1', '169.254.169.254', '172.16.0.1', '172.31.255.255',
    '192.0.0.1', '192.0.2.1', '192.168.0.1', '198.18.0.1', '198.19.255.255', '198.51.100.1', '203.0.113.1',
    '224.0.0.1', '239.255.255.255', '240.0.0.1', '255.255.255.255',
    '::', '::1', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1', '100::1',
    '2001::1', '2001:2::1', '2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff', '2001:db8::1', '2002::1', '3fff::1',
    '::ffff:10.0.0.1', '::ffff:7f00:1'
  ];
  const publicAddresses = [
    '1.1.1.1', '8.8.8.8', '9.9.9.9', '100.63.255.255', '100.128.0.1', '126.255.255.255', '128.0.0.1', '169.255.0.1',
    '172.15.255.255', '172.32.0.1', '192.0.1.1', '198.17.255.255', '198.20.0.1', '223.255.255.255',
    '2606:4700:4700::1111', '2001:4860:4860::8888', '2620:fe::fe', '2001:200::1', '2a00:1450:4001::1',
    '::ffff:8.8.8.8', '::ffff:808:808'
  ];

  for (const ip of notPublic) assert.equal(isPublicIP(ip), false, ip);
  for (const ip of publicAddresses) assert.equal(isPublicIP(ip), true, ip);
});

test('text that is not exactly one address is never public', () => {
  const notAddresses = ['', 'localhost', '1.1.1', '1.1.1.1.1', '256.1.1.1', '1.1.1.1/24', '8.8.8.8;whoami', 'fe80::1%eth0', '2606:4700:4700::1111::1', null, undefined, 42, {}, []];
  for (const value of notAddresses) assert.equal(isPublicIP(value), false, String(value));
});

test('normalizeIP writes mapped and mixed-case addresses in one plain form', () => {
  assert.equal(normalizeIP('::FFFF:1.2.3.4'), '1.2.3.4');
  assert.equal(normalizeIP('0:0:0:0:0:ffff:7f00:1'), '127.0.0.1');
  assert.equal(normalizeIP(' 2001:DB8::1 '), '2001:db8::1');
});

/* ---------- Lookup adapters ---------- */

// A stand-in for fetch that always gives the same answer.
const answer = (body, init) => async () => new Response(body, init);
const ask = fetcher => fetchJSON('https://data.iana.org/x', { hosts: new Set(['data.iana.org']), fetcher });

test('failed lookups give short messages that are safe to show', async () => {
  const cases = [
    ['a missing record', answer('', { status: 404 }), 'No record returned by this source'],
    ['a server error', answer('oops', { status: 500 }), 'Source unavailable'],
    ['text that is not JSON', answer('<html>'), 'Source returned data that could not be read'],
    ['a network error', async () => { throw new Error('connect ECONNREFUSED 10.0.0.5:443'); }, 'Source unavailable'],
    ['a timeout', async () => { throw new DOMException('timed out', 'TimeoutError'); }, 'Source did not answer in time'],
    ['a huge announced size', answer('{}', { headers: { 'content-length': '999999999' } }), 'Source response too large']
  ];

  for (const [name, fetcher, message] of cases) {
    await assert.rejects(ask(fetcher), error => error instanceof SourceError && error.message === message, name);
  }
});

test('a redirect is never followed and gets its own message', async () => {
  let calls = 0;
  const redirect = async () => {
    calls++;
    return new Response(null, { status: 307, headers: { location: 'https://rdap.registro.br/ip/200.160.2.3' } });
  };

  await assert.rejects(ask(redirect), error => error instanceof SourceError && error.message === 'Source redirected to a service that is not approved');
  assert.equal(calls, 1);
});

test('lookups ask for the RDAP media type, because LACNIC refuses plain application/json', async () => {
  // This stand-in behaves like the LACNIC server: a request without the RDAP media type gets a 406.
  const picky = async (_url, options) => {
    const accepted = /application\/rdap\+json/.test(options.headers.accept);
    return accepted ? Response.json({ name: 'EXAMPLE' }) : new Response('', { status: 406 });
  };

  assert.deepEqual(await ask(picky), { name: 'EXAMPLE' });
});

test('a failing source is reported as unavailable without internal details', async t => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('secret detail from 10.0.0.5'); });

  const results = await collectPublic('1.1.1.1', ['internetdb'], { dnsServers: [] });

  assert.deepEqual(results, [{
    check: 'internetdb',
    state: 'unavailable',
    message: 'Source unavailable',
    evidence: [],
    recipient: 'internetdb.shodan.io'
  }]);
});

test('one failing source does not stop the others', async t => {
  t.mock.method(globalThis, 'fetch', async url => {
    const address = String(url);
    if (address.startsWith('https://data.iana.org/')) {
      return Response.json({ services: [[['1.0.0.0/8'], ['https://rdap.apnic.net/']]] });
    }
    if (address.startsWith('https://rdap.apnic.net/')) {
      return Response.json({ name: 'EXAMPLE-NET', country: 'au', startAddress: '1.0.0.0', endAddress: '1.255.255.255' });
    }
    throw new Error('no network in tests');
  });

  const [registry, shodan] = await collectPublic('1.1.1.1', ['rdap', 'internetdb'], { dnsServers: [] });

  assert.equal(registry.state, 'complete');
  assert.equal(registry.recipient, 'rdap.apnic.net');
  const value = field => registry.evidence.find(row => row.field === field).value;
  assert.equal(value('Registered network'), 'EXAMPLE-NET');
  assert.equal(value('Registration country'), 'AU');
  assert.equal(value('Allocation range'), '1.0.0.0 – 1.255.255.255');
  assert.equal(shodan.state, 'unavailable');
});

test('local addresses are refused before any adapter runs', async t => {
  const fetchCalls = t.mock.method(globalThis, 'fetch', async () => Response.json({}));
  await assert.rejects(collectPublic('10.0.0.1', ['rdap', 'internetdb'], { dnsServers: [] }), /public connection address/i);
  assert.equal(fetchCalls.mock.callCount(), 0);
});

// A tiny DNS server for the tests. It answers every question the way the test tells it to.
// reply(name) returns { code, names }: code 0 is a normal answer, 2 is a server failure, 3 means the name does not exist.
async function fakeDNS(t, reply) {
  const socket = dgram.createSocket('udp4');
  const asked = [];

  socket.on('message', (query, remote) => {
    // The question starts after the 12 byte header. Each label has its length in front of it.
    const labels = [];
    let position = 12;
    while (query[position] !== 0) {
      labels.push(query.toString('ascii', position + 1, position + 1 + query[position]));
      position += query[position] + 1;
    }
    asked.push(labels.join('.'));

    const { code = 0, names = [] } = reply(labels.join('.'));
    const question = query.subarray(12, position + 5); // the name, a zero byte, then type and class

    const header = Buffer.alloc(12);
    query.copy(header, 0, 0, 2); // same id as the question
    header.writeUInt16BE(0x8180 + code, 2); // an answer, with recursion wanted and available, plus the result code
    header.writeUInt16BE(1, 4); // one question
    header.writeUInt16BE(names.length, 6); // number of answers

    const answers = names.map(host => {
      const labelsOfHost = host.split('.').map(label => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)]));
      const data = Buffer.concat([...labelsOfHost, Buffer.from([0])]);
      const fixed = Buffer.alloc(10);
      fixed.writeUInt16BE(12, 0); // type PTR
      fixed.writeUInt16BE(1, 2); // class IN
      fixed.writeUInt32BE(60, 4); // time to live
      fixed.writeUInt16BE(data.length, 8);
      return Buffer.concat([Buffer.from([0xc0, 0x0c]), fixed, data]);
    });

    socket.send(Buffer.concat([header, question, ...answers]), remote.port, remote.address);
  });

  await new Promise(resolve => socket.bind(0, '127.0.0.1', resolve));
  t.after(() => socket.close());
  return { server: `127.0.0.1:${socket.address().port}`, asked };
}

test('PTR lookups ask for the reverse name and return the names found', async t => {
  const dns = await fakeDNS(t, () => ({ names: ['host.example.invalid', 'second.example.invalid'] }));

  const result = await ptr('192.0.2.7', [dns.server]);
  assert.equal(dns.asked.at(-1), '7.2.0.192.in-addr.arpa');
  assert.equal(result.evidence[0].value, 'host.example.invalid, second.example.invalid');
  assert.equal(result.recipient, dns.server);

  await ptr('2001:db8::1', [dns.server]);
  assert.equal(dns.asked.at(-1), '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa');
});

test('PTR lookups show at most three names', async t => {
  const dns = await fakeDNS(t, () => ({ names: ['a.example.invalid', 'b.example.invalid', 'c.example.invalid', 'd.example.invalid'] }));

  const result = await ptr('192.0.2.7', [dns.server]);
  assert.equal(result.evidence[0].value, 'a.example.invalid, b.example.invalid, c.example.invalid');
});

test('a name that does not exist is an empty answer, not a failure', async t => {
  for (const answerToGive of [{ code: 3 }, { code: 0, names: [] }]) {
    const dns = await fakeDNS(t, () => answerToGive);
    const result = await ptr('192.0.2.7', [dns.server]);
    assert.equal(result.evidence[0].value, null);
    assert.equal(result.evidence[0].state, 'unavailable');
  }
});

test('a resolver that fails or is not there is reported as unavailable', async t => {
  const broken = await fakeDNS(t, () => ({ code: 2 }));
  const notThere = '127.0.0.1:9'; // nothing listens on this port

  for (const server of [broken.server, notThere]) {
    await assert.rejects(ptr('192.0.2.7', [server]), error => error instanceof SourceError && error.message === 'DNS lookup unavailable', server);
  }
});

/* ---------- Settings ---------- */

test('settings reads and checks the environment', () => {
  assert.equal(settings({}).host, '127.0.0.1');
  assert.equal(settings({}).port, 8787);
  assert.equal(settings({ TRANSPORT_ORIGIN: 'https://transport.example.com/' }).transportOrigin, 'https://transport.example.com');

  const badOrigins = [
    'http://transport.example.com',
    'https://transport.example.com/path',
    'https://user:pw@transport.example.com',
    'https://transport.example.com?x=1',
    'https://transport.example.com#top',
    'transport.example.com',
    'javascript:alert(1)'
  ];
  for (const origin of badOrigins) assert.throws(() => settings({ TRANSPORT_ORIGIN: origin }), /HTTPS origin/, origin);

  assert.deepEqual(settings({ DNS_RESOLVERS: '1.1.1.1, nope, 2001:4860:4860::8888, 999.1.1.1' }).dnsServers, ['1.1.1.1', '2001:4860:4860::8888']);
  assert.deepEqual(settings({ TRUSTED_PROXY_IPS: ' 10.0.0.1 , ,10.0.0.2 ' }).trusted, ['10.0.0.1', '10.0.0.2']);

  assert.equal(settings({ PORT: '9000' }).port, 9000);
  for (const port of ['abc', '-1', '70000', '80.5']) assert.throws(() => settings({ PORT: port }), /PORT must be/, port);
});

test('a wrong setting stops the program with one short message and no stack trace', () => {
  const script = join(projectFolder, 'server', 'index.mjs');

  for (const [name, value, words] of [['TRANSPORT_ORIGIN', 'http://bad.example.com', 'HTTPS origin'], ['PORT', 'abc', 'PORT must be']]) {
    const run = spawnSync(process.execPath, [script], { env: { ...process.env, [name]: value }, encoding: 'utf8', timeout: 10000 });

    assert.equal(run.status, 1, name);
    assert.ok(run.stderr.startsWith('LayerLens could not start: '), run.stderr);
    assert.ok(run.stderr.includes(words), run.stderr);
    assert.doesNotMatch(run.stderr, /\n\s+at /, name);
  }
});

test('.env.example lists exactly the settings the server reads', async () => {
  const example = await readFile(join(projectFolder, '.env.example'), 'utf8');
  const code = await readFile(join(projectFolder, 'server', 'index.mjs'), 'utf8');

  const documented = [...example.matchAll(/^#?\s*([A-Z][A-Z0-9_]+)=/gm)].map(match => match[1]);
  const used = [...new Set([...code.matchAll(/env\.([A-Z][A-Z0-9_]+)/g)].map(match => match[1]))];

  assert.deepEqual(documented.sort(), used.sort());
});

test('compose.yaml passes on every documented setting except HOST and PORT', async () => {
  const example = await readFile(join(projectFolder, '.env.example'), 'utf8');
  const compose = await readFile(join(projectFolder, 'compose.yaml'), 'utf8');

  // Inside the container HOST is fixed, and PORT stays at the default the Dockerfile and healthcheck use.
  const fixed = ['HOST', 'PORT'];
  const documented = [...example.matchAll(/^#?\s*([A-Z][A-Z0-9_]+)=/gm)].map(match => match[1]).filter(name => !fixed.includes(name));
  const passed = [...compose.matchAll(/^\s+([A-Z][A-Z0-9_]+):/gm)].map(match => match[1]).filter(name => !fixed.includes(name));

  assert.deepEqual(passed.sort(), documented.sort());
});
