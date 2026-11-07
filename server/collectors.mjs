import { Resolver } from 'node:dns/promises';
import { isIP } from 'node:net';
import { inCIDR, isPublicIP, evidence, normalizeIP, parseIP } from './evidence.mjs';

// The only servers an RDAP lookup may be sent to. The IANA list tells us which one to use,
// but the answer is only trusted if it is on this list.
const RDAP_HOSTS = new Set(['rdap.arin.net', 'rdap.db.ripe.net', 'rdap.apnic.net', 'rdap.lacnic.net', 'rdap.afrinic.net']);
const ONE_DAY = 24 * 60 * 60 * 1000;

// The IANA bootstrap file is public reference data, so keeping it for a day is fine.
const bootstrapCache = new Map();

// An error whose message is safe to show to the visitor. Any other error is shown as "Source unavailable".
export class SourceError extends Error {}

// Downloads one JSON document from an approved https address, with size and time limits.
export async function fetchJSON(url, { hosts, fetcher = fetch, maxBytes = 262144, timeout = 5000 } = {}) {
  const target = new URL(url);
  const wrongPort = target.port && target.port !== '443';
  if (target.protocol !== 'https:' || target.username || target.password || wrongPort || !hosts?.has(target.hostname)) {
    throw new SourceError('Unapproved source');
  }

  let response;
  try {
    response = await fetcher(target, {
      redirect: 'manual', // never followed: a redirect could point somewhere we did not approve
      signal: AbortSignal.timeout(timeout),
      // RDAP servers answer to application/rdap+json, and LACNIC refuses plain application/json with a 406.
      headers: { accept: 'application/rdap+json, application/json', 'user-agent': 'LayerLens/0.1.0' }
    });
  } catch (error) {
    throw new SourceError(error.name === 'TimeoutError' ? 'Source did not answer in time' : 'Source unavailable');
  }

  if (response.status >= 300 && response.status < 400) {
    // Some registries hand a range to a national registry this app does not query.
    await response.body?.cancel().catch(() => {});
    throw new SourceError('Source redirected to a service that is not approved');
  }
  if (!response.ok) throw new SourceError(response.status === 404 ? 'No record returned by this source' : 'Source unavailable');
  if (Number(response.headers.get('content-length') || 0) > maxBytes) throw new SourceError('Source response too large');

  const text = await readLimited(response, maxBytes);
  try {
    return JSON.parse(text);
  } catch {
    throw new SourceError('Source returned data that could not be read');
  }
}

// Reads a response body but stops as soon as it gets bigger than the limit (the length header can lie).
async function readLimited(response, maxBytes) {
  if (!response.body) throw new SourceError('Source unavailable');

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxBytes) throw new SourceError('Source response too large');
      chunks.push(Buffer.from(value));
    }
  } catch (error) {
    throw error instanceof SourceError ? error : new SourceError('Source unavailable');
  } finally {
    await reader.cancel().catch(() => {});
  }
  return Buffer.concat(chunks).toString('utf8');
}

// Small helpers that clean values from outside before they reach the visitor.
function shortText(value, limit = 200) {
  return typeof value === 'string' && value.trim() ? value.trim().slice(0, limit) : null;
}

function countryCode(value) {
  return typeof value === 'string' && /^[a-z]{2}$/i.test(value) ? value.toUpperCase() : null;
}

// Picks the RDAP server for an address from the IANA list. The most specific matching range wins.
export function registryURL(ip, bootstrap) {
  const matches = [];
  for (const [prefixes, urls] of bootstrap.services || []) {
    for (const prefix of prefixes) {
      if (inCIDR(ip, prefix)) matches.push({ length: Number(prefix.split('/')[1]), urls });
    }
  }
  matches.sort((a, b) => b.length - a.length);

  for (const base of matches[0]?.urls || []) {
    const server = new URL(base);
    const approved = server.protocol === 'https:' && RDAP_HOSTS.has(server.hostname) && !server.username && !server.password && !server.port;
    if (approved) return new URL('ip/' + encodeURIComponent(ip), base.endsWith('/') ? base : base + '/');
  }
  throw new SourceError('No approved registry for this address');
}

async function getBootstrap(family) {
  const cached = bootstrapCache.get(family);
  if (cached && Date.now() - cached.time <= ONE_DAY) return cached.data;

  const data = await fetchJSON(`https://data.iana.org/rdap/${family}.json`, { hosts: new Set(['data.iana.org']) });
  bootstrapCache.set(family, { time: Date.now(), data });
  return data;
}

// Registry lookup: who the address block is registered to.
export async function rdap(ip) {
  const family = ip.includes(':') ? 'ipv6' : 'ipv4';
  const url = registryURL(ip, await getBootstrap(family));
  const data = await fetchJSON(url, { hosts: RDAP_HOSTS });

  const start = normalizeIP(data.startAddress);
  const end = normalizeIP(data.endAddress);
  const name = shortText(data.name) || shortText(data.handle) || 'Not supplied';

  return {
    recipient: url.hostname,
    evidence: [
      evidence('Registered network', name, url.hostname, 'Resource registration is not your name or employer.'),
      evidence('Registration country', countryCode(data.country), url.hostname, 'Registration country is not a measurement of your physical location.'),
      evidence('Allocation range', start && end ? `${start} – ${end}` : null, url.hostname, 'This range can include many subscribers and devices.')
    ]
  };
}

// The name a reverse lookup asks for: 1.2.3.4 becomes 4.3.2.1.in-addr.arpa.
// An IPv6 address gets one label for every hex digit, written backwards, under ip6.arpa.
function reverseName(ip) {
  if (isIP(ip) === 4) return ip.split('.').reverse().join('.') + '.in-addr.arpa';

  const digits = parseIP(ip).value.toString(16).padStart(32, '0');
  return [...digits].reverse().join('.') + '.ip6.arpa';
}

// Reverse DNS lookup through the DNS servers the operator chose.
export async function ptr(ip, servers) {
  const resolver = new Resolver({ timeout: 1500, tries: 1 });
  resolver.setServers(servers);

  let names;
  try {
    // resolvePtr is used instead of reverse(), because reverse() can report an unreachable server as "not found".
    names = await resolver.resolvePtr(reverseName(ip));
  } catch (error) {
    // "No record" is a normal answer. Anything else means the resolver could not be used.
    if (!['ENODATA', 'ENOTFOUND'].includes(error.code)) throw new SourceError('DNS lookup unavailable');
    names = [];
  }

  const shown = names.filter(name => typeof name === 'string').slice(0, 3).map(name => name.slice(0, 255));
  return {
    recipient: servers.join(', '),
    evidence: [
      evidence('Reverse DNS', shown.length ? shown.join(', ') : null, 'Configured DNS resolver', 'An address-associated name, not your computer’s personal name.')
    ]
  };
}

// Shodan InternetDB: records that already exist for this public address.
export async function internetdb(ip) {
  const data = await fetchJSON(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, { hosts: new Set(['internetdb.shodan.io']) });

  const ports = Array.isArray(data.ports) ? data.ports.filter(port => Number.isInteger(port) && port >= 1 && port <= 65535).slice(0, 40) : null;
  const hostnames = Array.isArray(data.hostnames) ? data.hostnames.filter(name => typeof name === 'string').slice(0, 5).map(name => name.slice(0, 100)) : null;
  const cves = Array.isArray(data.vulns) ? data.vulns.filter(id => typeof id === 'string' && /^CVE-\d{4}-\d+$/i.test(id)).slice(0, 30) : null;

  return {
    recipient: 'internetdb.shodan.io',
    evidence: [
      evidence('Indexed ports', ports && (ports.join(', ') || 'No ports listed'), 'Shodan InternetDB', 'Historical public-IP records. These services may not belong to your laptop.'),
      evidence('Indexed hostnames', hostnames && (hostnames.join(', ') || 'No hostnames listed'), 'Shodan InternetDB', 'Not a list of devices currently using this connection.'),
      evidence('Unconfirmed CVE associations', cves && (cves.join(', ') || 'No associations listed'), 'Shodan InternetDB', 'Indexed associations include unverified entries. Empty results do not establish safety.')
    ]
  };
}

// Where each check sends the address, shown to the visitor when a check fails.
function recipientFor(check, options) {
  if (check === 'ptr') return options.dnsServers.join(', ');
  if (check === 'internetdb') return 'internetdb.shodan.io';
  return 'IANA bootstrap and selected RIR';
}

// Runs the checks the visitor chose. One failing source does not stop the others.
export async function collectPublic(ip, checks, options) {
  if (!isPublicIP(ip)) {
    throw new Error('Public-record checks require a public connection address. Local and reserved addresses are not sent to providers.');
  }

  const adapters = {
    rdap: () => rdap(ip),
    ptr: () => ptr(ip, options.dnsServers),
    internetdb: () => internetdb(ip)
  };

  return Promise.all(checks.map(async check => {
    try {
      return { check, state: 'complete', ...(await adapters[check]()) };
    } catch (error) {
      const message = error instanceof SourceError ? error.message : 'Source unavailable';
      return { check, state: 'unavailable', message, evidence: [], recipient: recipientFor(check, options) };
    }
  }));
}
