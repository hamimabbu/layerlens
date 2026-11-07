import { isIP } from 'node:net';

// Address ranges that a normal visitor does not connect from. These are never sent to a lookup provider.
const NOT_PUBLIC_IPV4 = [
  '0.0.0.0/8',       // "this network"
  '10.0.0.0/8',      // private
  '100.64.0.0/10',   // carrier-grade NAT
  '127.0.0.0/8',     // loopback
  '169.254.0.0/16',  // link-local
  '172.16.0.0/12',   // private
  '192.0.0.0/24',    // protocol assignments
  '192.0.2.0/24',    // documentation
  '192.88.99.0/24',  // old 6to4 relay
  '192.168.0.0/16',  // private
  '198.18.0.0/15',   // benchmarking
  '198.51.100.0/24', // documentation
  '203.0.113.0/24',  // documentation
  '224.0.0.0/4',     // multicast
  '240.0.0.0/4'      // reserved
];

// Everything outside 2000::/3 is rejected as well. These are the parts of it that are not real networks.
const NOT_PUBLIC_IPV6 = [
  '2001::/23',     // protocol assignments (Teredo, benchmarking, ORCHID and more)
  '2001:db8::/32', // documentation
  '2002::/16',     // 6to4
  '3fff::/20'      // documentation
];

// Turns text into a clean address, or null when it is not exactly one IP address.
export function normalizeIP(value = '') {
  if (typeof value !== 'string' || value.length > 100 || value.includes('%')) return null;

  const text = value.trim().toLowerCase();
  if (!isIP(text)) return null;

  // An IPv4 address written inside IPv6 (::ffff:1.2.3.4) is the same visitor as plain IPv4.
  if (text.startsWith('::ffff:') && isIP(text.slice(7)) === 4) return text.slice(7);

  const parsed = parseIP(text);
  const isMappedIPv4 = parsed.bits === 128 && parsed.value >> 32n === 0xffffn;
  if (isMappedIPv4) return numberToIPv4(Number(parsed.value & 0xffffffffn));

  return text;
}

function numberToIPv4(n) {
  return [24, 16, 8, 0].map(shift => (n >>> shift) & 255).join('.');
}

// Reads an address into one big number so ranges can be compared with simple maths.
export function parseIP(value) {
  const type = isIP(value || '');
  if (type === 4) {
    return { bits: 32, value: value.split('.').reduce((total, part) => (total << 8n) | BigInt(part), 0n) };
  }
  if (type !== 6) return null;

  const groups = expandIPv6(value.toLowerCase());
  return { bits: 128, value: groups.reduce((total, group) => (total << 16n) | BigInt('0x' + group), 0n) };
}

// Returns the eight 16-bit groups of an IPv6 address as hex text.
function expandIPv6(text) {
  // 1.2.3.4 at the end becomes two hex groups.
  if (text.includes('.')) {
    const cut = text.lastIndexOf(':');
    const bytes = text.slice(cut + 1).split('.').map(Number);
    const high = ((bytes[0] << 8) | bytes[1]).toString(16);
    const low = ((bytes[2] << 8) | bytes[3]).toString(16);
    text = text.slice(0, cut + 1) + high + ':' + low;
  }

  const halves = text.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  if (halves.length !== 2) return left;

  const right = halves[1] ? halves[1].split(':') : [];
  const zeros = Array(8 - left.length - right.length).fill('0');
  return [...left, ...zeros, ...right];
}

// True when the address is inside a range like 10.0.0.0/8.
export function inCIDR(ip, cidr) {
  const [network, prefixText] = cidr.split('/');
  const address = parseIP(ip);
  const range = parseIP(network);
  const prefix = Number(prefixText);

  const usable = address && range && address.bits === range.bits && Number.isInteger(prefix) && prefix >= 0 && prefix <= address.bits;
  if (!usable) return false;

  const unusedBits = BigInt(address.bits - prefix);
  return address.value >> unusedBits === range.value >> unusedBits;
}

// True only for an address that can belong to a real visitor on the public internet.
export function isPublicIP(input) {
  const ip = normalizeIP(input);
  if (!ip) return false;

  if (isIP(ip) === 4) return !NOT_PUBLIC_IPV4.some(range => inCIDR(ip, range));

  return inCIDR(ip, '2000::/3') && !NOT_PUBLIC_IPV6.some(range => inCIDR(ip, range));
}

// The name used for the rate limit. IPv6 visitors are grouped by /64, because one home or phone
// normally gets a whole /64 and could otherwise switch to a fresh address for every request.
export function rateLimitName(ip) {
  if (!ip) return 'unknown';
  const parsed = parseIP(ip);
  if (parsed?.bits !== 128) return ip;
  return 'v6:' + (parsed.value >> 64n).toString(16);
}

// Works out who connected. Forwarding and fingerprint headers only count when they come from a trusted proxy.
export function connectionContext(req, trusted = []) {
  const peer = normalizeIP(req.socket.remoteAddress);
  const fromProxy = trusted.map(normalizeIP).filter(Boolean).includes(peer);

  let ip = peer;
  if (fromProxy && typeof req.headers['x-forwarded-for'] === 'string') {
    // One trusted proxy adds the real visitor address at the right-hand end.
    ip = normalizeIP(req.headers['x-forwarded-for'].split(',').at(-1));
  }

  // Header values are only kept when they look exactly like the format they claim to be.
  const headers = fromProxy ? req.headers : {};
  const clean = (name, pattern, limit = 256) => {
    const value = headers[name];
    return typeof value === 'string' && value.length <= limit && pattern.test(value) ? value : null;
  };

  return {
    ip,
    fromProxy,
    ja3: clean('x-ja3-fingerprint', /^[a-f0-9]{32}$/i),
    ja4: clean('x-ja4-fingerprint', /^[a-z0-9_]+$/i),
    http2: clean('x-http2-fingerprint', /^[a-z0-9,;:|._-]+$/i, 2048),
    protocol: req.socket.encrypted ? req.socket.getProtocol?.() || 'TLS' : 'HTTP to application',
    appHttpVersion: req.httpVersion
  };
}

// One piece of evidence. Every row says where it came from and what it cannot prove.
export function evidence(field, value, source, limitation, extra = {}) {
  return {
    field,
    value,
    source,
    limitation,
    kind: 'provider-reported',
    subject: 'public connection',
    state: value == null ? 'unavailable' : 'available',
    retrievedAt: new Date().toISOString(),
    sourceObservedAt: null,
    ...extra
  };
}

export { redactReport } from '../public/report.mjs';
