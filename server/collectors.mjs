import { Resolver } from 'node:dns/promises';
import { inCIDR, isPublicIP, evidence } from './evidence.mjs';

const RDAP_HOSTS = new Set(['rdap.arin.net','rdap.db.ripe.net','rdap.apnic.net','rdap.lacnic.net','rdap.afrinic.net']);
let bootstrapCache = new Map();

export async function fetchJSON(url, { hosts, fetcher = fetch, maxBytes = 262144, timeout = 5000 } = {}) {
  const target = new URL(url);
  if (target.protocol !== 'https:' || target.username || target.password || target.port && target.port !== '443' || !hosts?.has(target.hostname)) throw new Error('Unapproved source');
  const response = await fetcher(target, { redirect: 'error', signal: AbortSignal.timeout(timeout), headers: { accept: 'application/json', 'user-agent': 'LayerLens/0.1.0' } });
  if (!response.ok) throw new Error(response.status === 404 ? 'No record returned by this source' : 'Source unavailable');
  if (Number(response.headers.get('content-length') || 0) > maxBytes) throw new Error('Source response too large');
  const reader = response.body.getReader(); let total = 0; const chunks = [];
  try {
    for (;;) { const { done, value } = await reader.read(); if (done) break; total += value.length; if (total > maxBytes) throw new Error('Source response too large'); chunks.push(Buffer.from(value)); }
  } finally { await reader.cancel().catch(() => {}); }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

export function registryURL(ip, bootstrap) {
  const matches = [];
  for (const [prefixes, urls] of bootstrap.services || []) {
    for (const prefix of prefixes) if (inCIDR(ip, prefix)) matches.push({ prefix: Number(prefix.split('/')[1]), urls });
  }
  matches.sort((a,b) => b.prefix - a.prefix);
  for (const base of matches[0]?.urls || []) {
    const target = new URL(base);
    if (target.protocol === 'https:' && RDAP_HOSTS.has(target.hostname) && !target.username && !target.password && !target.port) return new URL('ip/' + encodeURIComponent(ip), base.endsWith('/') ? base : base + '/');
  }
  throw new Error('No approved registry for this address');
}

export async function rdap(ip) {
  const family = ip.includes(':') ? 'ipv6' : 'ipv4';
  let entry = bootstrapCache.get(family);
  if (!entry || Date.now() - entry.time > 86400000) {
    entry = { time: Date.now(), data: await fetchJSON(`https://data.iana.org/rdap/${family}.json`, { hosts: new Set(['data.iana.org']) }) };
    bootstrapCache.set(family, entry); // Public reference data, not visitor results.
  }
  const url = registryURL(ip, entry.data);
  const data = await fetchJSON(url, { hosts: RDAP_HOSTS });
  return {
    recipient: url.hostname,
    evidence: [
      evidence('Registered network', String(data.name || data.handle || 'Not supplied').slice(0,200), url.hostname, 'Resource registration is not your name or employer.'),
      evidence('Registration country', data.country || null, url.hostname, 'Registration country is not a measurement of your physical location.'),
      evidence('Allocation range', data.startAddress && data.endAddress ? `${data.startAddress} – ${data.endAddress}` : null, url.hostname, 'This range can include many subscribers and devices.')
    ]
  };
}

export async function ptr(ip, servers) {
  const resolver = new Resolver({ timeout: 1500, tries: 1 }); resolver.setServers(servers);
  let values;
  try { values = await resolver.reverse(ip); } catch (error) { if (['ENODATA','ENOTFOUND'].includes(error.code)) values = []; else throw new Error('DNS lookup unavailable'); }
  return { recipient: servers.join(', '), evidence: [evidence('Reverse DNS', values.length ? values.slice(0,3).join(', ') : null, 'Configured DNS resolver', 'An address-associated name, not your computer’s personal name.')] };
}

export async function internetdb(ip) {
  const data = await fetchJSON(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, { hosts: new Set(['internetdb.shodan.io']) });
  return { recipient: 'internetdb.shodan.io', evidence: [
    evidence('Indexed ports', Array.isArray(data.ports) ? data.ports.filter(Number.isInteger).slice(0,40).join(', ') || 'No ports listed' : null, 'Shodan InternetDB', 'Historical public-IP records. These services may not belong to your laptop.'),
    evidence('Indexed hostnames', Array.isArray(data.hostnames) ? data.hostnames.slice(0,5).map(x => String(x).slice(0,100)).join(', ') || 'No hostnames listed' : null, 'Shodan InternetDB', 'Not a list of devices currently using this connection.'),
    evidence('Unconfirmed CVE associations', Array.isArray(data.vulns) ? data.vulns.filter(x => /^CVE-\d{4}-\d+$/i.test(x)).slice(0,30).join(', ') || 'No associations listed' : null, 'Shodan InternetDB', 'Indexed associations include unverified entries. Empty results do not establish safety.')
  ] };
}

export async function collectPublic(ip, checks, options) {
  if (!isPublicIP(ip)) throw new Error('Public-record checks require a public connection address. Local and reserved addresses are not sent to providers.');
  const adapters = { rdap: () => rdap(ip), ptr: () => ptr(ip, options.dnsServers), internetdb: () => internetdb(ip) };
  return Promise.all(checks.map(async check => {
    try { return { check, state: 'complete', ...(await adapters[check]()) }; }
    catch (error) { return { check, state: 'unavailable', message: error.message, evidence: [], recipient: check === 'ptr' ? options.dnsServers.join(', ') : check === 'internetdb' ? 'internetdb.shodan.io' : 'IANA bootstrap and selected RIR' }; }
  }));
}
