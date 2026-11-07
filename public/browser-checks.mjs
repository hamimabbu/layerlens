// Checks that run inside the tab. Nothing in this file talks to the server.

// One finding. Every row says where it came from and what it cannot prove.
export function row(field, value, source, limitation, extra = {}) {
  return {
    field,
    value,
    source,
    limitation,
    kind: 'browser-reported',
    subject: 'this browser',
    state: value == null ? 'unavailable' : 'available',
    retrievedAt: new Date().toISOString(),
    sourceObservedAt: null,
    ...extra
  };
}

// Reads the settings the visitor allowed. "hardware" and "pattern" are the two optional boxes.
export async function runBrowserChecks({ hardware = false, pattern = false } = {}) {
  const rows = basicRows();
  if (hardware) rows.push(...hardwareRows());
  if (pattern) rows.push(await patternRow(rows));
  return rows;
}

function basicRows() {
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || null;
  const languages = navigator.languages?.join(', ') || navigator.language;
  const dark = matchMedia('(prefers-color-scheme: dark)').matches;
  const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;

  return [
    row('Reported browser', navigator.userAgent, 'navigator.userAgent', 'User-Agent strings can be reduced, changed or spoofed. They do not prove a software version.'),
    row('Timezone setting', timezone, 'Intl.DateTimeFormat', 'A browser setting, not proof of physical location.'),
    row('Language preferences', languages, 'navigator.languages', 'Language preferences are not nationality.'),
    row('Display in CSS pixels', `${screen.width} × ${screen.height} · scale ${devicePixelRatio}`, 'Screen and devicePixelRatio', 'This is not your monitor model or its physical dimensions.'),
    row('Colour preference', dark ? 'Dark' : 'Light / not specified', 'CSS media query', 'This reflects a preference, not anything about your identity.'),
    row('Motion preference', reducedMotion ? 'Reduced motion' : 'No reduced-motion preference', 'CSS media query', 'This setting is used for accessibility. It does not establish a medical condition.')
  ];
}

function hardwareRows() {
  const memory = navigator.deviceMemory ? `${navigator.deviceMemory} GiB (coarse)` : null;

  return [
    row('Reported logical concurrency', navigator.hardwareConcurrency || null, 'navigator.hardwareConcurrency', 'Browsers can reduce this value. It is not verified physical CPU inventory.'),
    row('Approximate memory hint', memory, 'navigator.deviceMemory', 'This API is approximate, limited and unsupported in some browsers. Missing is a normal result.')
  ];
}

// A SHA-256 hash of the values above. It is computed here and never leaves the tab.
async function patternRow(rows) {
  if (!crypto.subtle) {
    return row('Local attribute pattern', null, 'Web Crypto', 'This feature needs a supported secure browser context.');
  }

  const bytes = new TextEncoder().encode(JSON.stringify(rows.map(item => [item.field, item.value])));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  const hex = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');

  return row('Local attribute pattern', hex, 'Web Crypto SHA-256 over selected values', 'A pattern for these attributes, not a unique person or a proven returning device.', { kind: 'derived' });
}
