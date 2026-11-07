import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { lookup } from 'node:dns/promises';
import { createHmac, randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { connectionContext, evidence, isPublicIP, normalizeIP, rateLimitName } from './evidence.mjs';
import { collectPublic } from './collectors.mjs';

const PUBLIC_DIR = fileURLToPath(new URL('../public/', import.meta.url));

// The only files the server will send. Anything else is a 404.
const FILES = {
  '/': ['index.html', 'text/html'],
  '/styles.css': ['styles.css', 'text/css'],
  '/app.mjs': ['app.mjs', 'text/javascript'],
  '/answers.mjs': ['answers.mjs', 'text/javascript'],
  '/content.mjs': ['content.mjs', 'text/javascript'],
  '/browser-checks.mjs': ['browser-checks.mjs', 'text/javascript'],
  '/report.mjs': ['report.mjs', 'text/javascript'],
  '/mark.svg': ['mark.svg', 'image/svg+xml']
};

const API_PATHS = ['/api/connection', '/api/enrich', '/api/transport'];
const READ_ONLY_PATHS = [...Object.keys(FILES), '/api/config', '/healthz'];

const MAX_BODY_BYTES = 4096;
const REQUESTS_PER_MINUTE = 20;
const MAX_TRACKED_VISITORS = 2000;
const REQUEST_TIMEOUT_MS = 10000;

const RETENTION_NOTE = 'No results database. Hashed rate counters are removed within 61 seconds; deployment logs are separate.';

export function settings(env = process.env) {
  return {
    host: env.HOST || '127.0.0.1',
    port: checkedPort(env.PORT),
    external: env.ENABLE_EXTERNAL_LOOKUPS === 'true',
    internetdb: env.ENABLE_INTERNETDB === 'true',
    dnsServers: splitList(env.DNS_RESOLVERS).filter(ip => normalizeIP(ip)),
    trusted: splitList(env.TRUSTED_PROXY_IPS),
    trustedHost: env.TRUSTED_PROXY_HOST || '',
    appOrigin: env.APP_ORIGIN || '',
    transportOrigin: checkedTransportOrigin(env.TRANSPORT_ORIGIN)
  };
}

function splitList(text = '') {
  return text.split(',').map(item => item.trim()).filter(Boolean);
}

// The port must be a whole number the system can listen on.
function checkedPort(value) {
  const port = Number(value || 8787);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('PORT must be a whole number from 0 to 65535');
  return port;
}

// The transport address must be a plain https origin, like https://transport.example.com
function checkedTransportOrigin(value) {
  if (!value) return '';

  const message = 'TRANSPORT_ORIGIN must be an HTTPS origin';
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(message);
  }

  const plainOrigin = url.pathname === '/' && !url.search && !url.hash && !url.username && !url.password;
  const safeHostname = /^[a-z0-9.:[\]-]+$/i.test(url.hostname);
  if (url.protocol !== 'https:' || !plainOrigin || !safeHostname) throw new Error(message);

  return url.origin;
}

function securityHeaders(options) {
  const connectFrom = options.transportOrigin ? `'self' ${options.transportOrigin}` : `'self'`;
  const policy = [
    `default-src 'self'`,
    `script-src 'self'`,
    `style-src 'self'`,
    `img-src 'self' blob:`,
    `connect-src ${connectFrom}`,
    `font-src 'self'`,
    `object-src 'none'`,
    `base-uri 'none'`,
    `frame-ancestors 'none'`,
    `form-action 'none'`
  ].join('; ');

  return {
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'cross-origin-opener-policy': 'same-origin',
    'content-security-policy': policy,
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), browsing-topics=()'
  };
}

// Which public-record checks the operator switched on.
function enabledChecks(options) {
  return {
    ptr: options.external && options.dnsServers.length > 0,
    rdap: options.external,
    internetdb: options.external && options.internetdb
  };
}

// What the page may know about this deployment. It never contains the visitor's address.
function publicConfig(options) {
  return {
    version: '0.1.0',
    transportOrigin: options.transportOrigin && options.appOrigin ? options.transportOrigin : null,
    checks: enabledChecks(options),
    recipients: {
      ptr: options.dnsServers.join(', ') || 'Not configured',
      rdap: 'IANA bootstrap, then the selected regional internet registry',
      internetdb: 'Shodan InternetDB'
    },
    retention: 'Results are request-scoped. Hashed rate counters are removed within 61 seconds. Hosting/proxy logs need separate configuration.'
  };
}

function connectionReport(context) {
  return {
    mode: 'live',
    evidence: [
      evidence('Public connection address', context.ip, 'Application socket / approved ingress', 'A public exit address can represent multiple people or devices.', { kind: 'observed' }),
      evidence('Application connection', context.protocol, 'Node HTTP server', 'This describes the application-side connection. It is not automatically browser-to-edge TLS.', { kind: 'observed' })
    ],
    publicAddress: isPublicIP(context.ip),
    trustedTransport: context.fromProxy,
    receipt: {
      check: 'Connection check',
      execution: 'Our server',
      recipients: ['This deployment'],
      sent: ['Ordinary request headers and connecting IP'],
      retained: RETENTION_NOTE
    }
  };
}

function transportReport(context, options) {
  const fingerprints = [
    ['JA3 fingerprint', context.ja3],
    ['JA4 fingerprint', context.ja4],
    ['HTTP/2 fingerprint', context.http2]
  ];
  const rows = fingerprints.map(([field, value]) =>
    evidence(field, value, 'Trusted Fingerproxy ingress', 'A connection pattern, not proof of identity or device ownership.', {
      kind: 'measured',
      subject: 'client-to-proxy connection'
    })
  );

  return {
    mode: 'live',
    evidence: rows,
    publicAddress: isPublicIP(context.ip),
    trustedTransport: context.fromProxy,
    receipt: {
      check: 'Transport diagnostic',
      execution: 'Dedicated first-party TLS ingress',
      recipients: [options.transportOrigin],
      sent: ['A new diagnostic request and its protocol metadata. Browser cookies omitted.'],
      retained: RETENTION_NOTE
    }
  };
}

// Checks the Origin header a browser adds to POST requests. Returns an error message, or null when fine.
function originProblem(req, isTransport) {
  if (!req.headers.origin) return null;

  let origin;
  try {
    origin = new URL(req.headers.origin);
  } catch {
    return 'Invalid origin';
  }

  // The transport endpoint is meant to be called from the main site, so only the scheme is checked there.
  const sameSite = isTransport || origin.host === req.headers.host;
  const webScheme = ['http:', 'https:'].includes(origin.protocol);
  return sameSite && webScheme ? null : 'Cross-origin request rejected';
}

// Reads the request body as text. Returns null when it is bigger than the limit.
async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) return null;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

// The visitor picked sources to look up. Each one must be configured, and nothing may be picked twice.
function choicesAreValid(input, enabled) {
  const checks = input.checks;
  if (input.publicRecordsConsent !== true) return false;
  if (!Array.isArray(checks) || checks.length === 0 || checks.length > 3) return false;
  if (new Set(checks).size !== checks.length) return false;
  return checks.every(check => typeof check === 'string' && Object.hasOwn(enabled, check) && enabled[check] === true);
}

// A small counter per visitor that forgets everything after a minute.
// Visitors are stored under a keyed hash, so the table never holds a readable address.
function createQuota() {
  const salt = randomBytes(32); // new on every start
  const visitors = new Map();

  function removeExpired() {
    const now = Date.now();
    for (const [key, entry] of visitors) {
      if (entry.expires < now) visitors.delete(key);
    }
  }

  // Returns true when this visitor may continue.
  function allow(ip) {
    removeExpired();
    const key = createHmac('sha256', salt).update(rateLimitName(ip)).digest('hex');
    const entry = visitors.get(key) || { count: 0, expires: Date.now() + 60000 };

    const tableFull = visitors.size >= MAX_TRACKED_VISITORS && !visitors.has(key);
    if (entry.count >= REQUESTS_PER_MINUTE || tableFull) return false;

    entry.count++;
    visitors.set(key, entry);
    return true;
  }

  return { allow, removeExpired };
}

// The list of proxies we trust: the fixed ones, plus whatever TRUSTED_PROXY_HOST currently points to.
function createPeerList(options) {
  let peers = [...options.trusted];
  let refreshAt = 0;

  return async function currentPeers() {
    if (!options.trustedHost || Date.now() <= refreshAt) return peers;
    try {
      const found = await lookup(options.trustedHost, { all: true });
      peers = [...options.trusted, ...found.map(entry => entry.address)];
      refreshAt = Date.now() + 60000;
    } catch {
      peers = [...options.trusted]; // if the name cannot be resolved, trust nobody extra
      refreshAt = Date.now() + 5000;
    }
    return peers;
  };
}

export function createApp(options = settings()) {
  const headers = securityHeaders(options);
  const quota = createQuota();
  const currentPeers = createPeerList(options);

  function send(res, code, data, extraHeaders = {}) {
    res.writeHead(code, { ...headers, ...extraHeaders, 'content-type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(data));
  }

  async function sendFile(res, [name, type]) {
    // Read first. If the file is missing this becomes a 500, not an empty 200.
    const content = await readFile(PUBLIC_DIR + name);
    res.writeHead(200, { ...headers, 'content-type': `${type}; charset=utf-8` });
    res.end(content);
  }

  function sendPreflight(res, approvedProbe) {
    if (!approvedProbe) return send(res, 403, { error: 'Diagnostic origin is not configured or approved' });
    res.writeHead(204, {
      ...headers,
      'access-control-allow-origin': options.appOrigin,
      'access-control-allow-methods': 'POST',
      'access-control-allow-headers': 'content-type',
      vary: 'Origin'
    });
    res.end();
  }

  async function handle(req, res) {
    let url;
    try {
      url = new URL(req.url, 'http://localhost');
    } catch {
      return send(res, 400, { error: 'Bad request' });
    }

    const path = url.pathname;
    const isTransport = path === '/api/transport';
    const approvedProbe = Boolean(options.transportOrigin && options.appOrigin && req.headers.origin === options.appOrigin);

    if (isTransport && req.method === 'OPTIONS') return sendPreflight(res, approvedProbe);
    if (isTransport && approvedProbe) {
      res.setHeader('access-control-allow-origin', options.appOrigin);
      res.setHeader('vary', 'Origin');
    }

    const isRead = req.method === 'GET' || req.method === 'HEAD';
    if (isRead && FILES[path]) return sendFile(res, FILES[path]);
    if (isRead && path === '/api/config') return send(res, 200, publicConfig(options));
    if (isRead && path === '/healthz') return send(res, 200, { status: 'ok' });

    if (READ_ONLY_PATHS.includes(path)) return send(res, 405, { error: 'Method not allowed' }, { allow: 'GET, HEAD' });
    if (!API_PATHS.includes(path)) return send(res, 404, { error: 'Not found' });
    if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed' }, { allow: 'POST' });

    return handleApi(req, res, path, isTransport, approvedProbe);
  }

  async function handleApi(req, res, path, isTransport, approvedProbe) {
    if (isTransport && !approvedProbe) return send(res, 403, { error: 'Diagnostic origin is not configured or approved' });

    const problem = originProblem(req, isTransport);
    if (problem) return send(res, 403, { error: problem });

    const contentType = (req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (contentType !== 'application/json') return send(res, 415, { error: 'JSON required' });

    const body = await readBody(req);
    if (body === null) return send(res, 413, { error: 'Request too large' });

    let input;
    try {
      input = JSON.parse(body);
    } catch {
      return send(res, 400, { error: 'Invalid JSON' });
    }
    if (!input || typeof input !== 'object' || Array.isArray(input)) return send(res, 400, { error: 'JSON object required' });
    if (input.consent !== true) return send(res, 400, { error: 'An explicit choice is required' });

    // The server decides whose address is used. A request can never name a target.
    if (['ip', 'url', 'host', 'target'].some(key => Object.hasOwn(input, key))) {
      return send(res, 400, { error: 'Arbitrary targets are not accepted' });
    }

    const context = connectionContext(req, await currentPeers());
    if (!quota.allow(context.ip)) return send(res, 429, { error: 'Please wait a minute before trying again' });

    if (path === '/api/connection') return send(res, 200, connectionReport(context));
    if (isTransport) return send(res, 200, transportReport(context, options));
    return handleEnrich(res, input, context);
  }

  async function handleEnrich(res, input, context) {
    if (!choicesAreValid(input, enabledChecks(options))) {
      return send(res, 400, { error: 'Select only configured checks and approve their recipients' });
    }
    if (!isPublicIP(context.ip)) {
      return send(res, 400, { error: 'This is a local or reserved connection. No address was sent to external providers.' });
    }
    send(res, 200, { mode: 'live', results: await collectPublic(context.ip, input.checks, options) });
  }

  const server = http.createServer({ connectionsCheckingInterval: 1000 }, async (req, res) => {
    try {
      await handle(req, res);
    } catch {
      if (!res.headersSent) send(res, 500, { error: 'The check could not complete. No detailed request was logged.' });
      else res.end();
    }
  });

  // Slow or stalled connections are closed instead of waiting forever.
  // (Node only checks these timers once per connectionsCheckingInterval, which is set above.)
  const timeout = options.requestTimeout ?? REQUEST_TIMEOUT_MS;
  server.requestTimeout = timeout;
  server.headersTimeout = timeout;
  server.keepAliveTimeout = 5000;

  const cleanup = setInterval(quota.removeExpired, 1000);
  cleanup.unref();
  server.on('close', () => clearInterval(cleanup));

  return server;
}

// Close cleanly when Docker or the terminal asks the program to stop.
function stopOnSignal(server) {
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, () => {
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(0), 3000).unref(); // do not wait for slow connections
    });
  }
}

// Start the server only when this file is run directly (npm start), not when tests import it.
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  // A wrong setting should end with one clear line, not a stack trace.
  const failToStart = error => {
    console.error(`LayerLens could not start: ${error.message}`);
    process.exit(1);
  };

  let options;
  try {
    options = settings();
  } catch (error) {
    failToStart(error);
  }

  const server = createApp(options);
  server.on('error', failToStart);
  server.listen(options.port, options.host, () => console.log(`LayerLens: http://${options.host}:${options.port}`));
  stopOnSignal(server);
}
