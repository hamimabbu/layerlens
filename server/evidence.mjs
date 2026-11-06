import { isIP } from 'node:net';

export function normalizeIP(value = '') {
  if (typeof value !== 'string' || value.length > 100 || value.includes('%')) return null;
  value = value.trim().toLowerCase();
  if (!isIP(value)) return null;
  if (value.startsWith('::ffff:') && isIP(value.slice(7)) === 4) return value.slice(7);
  const parsed = parseIP(value);
  if (parsed?.bits === 128 && parsed.value >> 32n === 65535n) {
    const n = Number(parsed.value & 0xffffffffn);
    return [24, 16, 8, 0].map(s => (n >>> s) & 255).join('.');
  }
  return value;
}

export function parseIP(value) {
  const type = isIP(value || '');
  if (type === 4) return { bits: 32, value: value.split('.').reduce((n, p) => (n << 8n) | BigInt(p), 0n) };
  if (type !== 6) return null;
  let text = value.toLowerCase();
  if (text.includes('.')) {
    const cut = text.lastIndexOf(':');
    const bytes = text.slice(cut + 1).split('.').map(Number);
    text = text.slice(0, cut + 1) + ((bytes[0] << 8) | bytes[1]).toString(16) + ':' + ((bytes[2] << 8) | bytes[3]).toString(16);
  }
  const halves = text.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const groups = halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
  return { bits: 128, value: groups.reduce((n, p) => (n << 16n) | BigInt('0x' + p), 0n) };
}

export function inCIDR(ip, cidr) {
  const [network, prefixText] = cidr.split('/');
  const address = parseIP(ip), range = parseIP(network), prefix = Number(prefixText);
  if (!address || !range || address.bits !== range.bits || !Number.isInteger(prefix) || prefix < 0 || prefix > address.bits) return false;
  const shift = BigInt(address.bits - prefix);
  return address.value >> shift === range.value >> shift;
}

export function isPublicIP(input) {
  const ip = normalizeIP(input);
  if (!ip) return false;
  if (isIP(ip) === 4) {
    return !['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.0.0.0/24','192.0.2.0/24','192.168.0.0/16','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','240.0.0.0/4'].some(c => inCIDR(ip, c));
  }
  return inCIDR(ip, '2000::/3') && !['2001:db8::/32','2001:10::/28','2001:20::/28','2002::/16'].some(c => inCIDR(ip, c));
}

export function connectionContext(req, trusted = []) {
  const peer = normalizeIP(req.socket.remoteAddress);
  const fromProxy = trusted.map(normalizeIP).filter(Boolean).includes(peer);
  let ip = peer;
  if (fromProxy && typeof req.headers['x-forwarded-for'] === 'string') {
    // A single approved ingress appends the real client address at the right.
    ip = normalizeIP(req.headers['x-forwarded-for'].split(',').at(-1));
  }
  const headers = fromProxy ? req.headers : {};
  const clean = (key, pattern, limit = 256) => {
    const value = headers[key];
    return typeof value === 'string' && value.length <= limit && pattern.test(value) ? value : null;
  };
  return {
    ip, fromProxy,
    ja3: clean('x-ja3-fingerprint', /^[a-f0-9]{32}$/i),
    ja4: clean('x-ja4-fingerprint', /^[a-z0-9_]+$/i),
    http2: clean('x-http2-fingerprint', /^[a-z0-9,;:|._-]+$/i, 2048),
    protocol: req.socket.encrypted ? req.socket.getProtocol?.() || 'TLS' : 'HTTP to application',
    appHttpVersion: req.httpVersion
  };
}

export function evidence(field, value, source, limitation, extra = {}) {
  return { field, value, source, limitation, kind: 'provider-reported', subject: 'public connection', state: value == null ? 'unavailable' : 'available', retrievedAt: new Date().toISOString(), sourceObservedAt: null, ...extra };
}

export function redactReport(report) {
  const copy = structuredClone(report);
  copy.evidence = (copy.evidence || []).map(row => {
    if (/address|fingerprint|pattern|reverse dns|allocation range|latitude|longitude|timezone|resolution|display|language|user agent|renderer|model/i.test(row.field)) return { ...row, value: '[redacted]', redacted: true };
    return row;
  });
  return { ...copy, redacted: true, notice: 'Preview before sharing. Redaction does not guarantee anonymity.' };
}
