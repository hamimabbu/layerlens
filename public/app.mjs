import { redactReport } from './report.mjs';
import { runBrowserChecks } from './browser-checks.mjs';
import { UNREADABLE, cleanReceipt, cleanRows, plainText } from './answers.mjs';
import { LAYERS, PRIVACY_INTRO, PRIVACY_SECTIONS, sampleGroups, sampleReceipts } from './content.mjs';

const byId = id => document.getElementById(id);

const state = {
  layer: 'browser', // the open layer: browser, connection or records
  mode: 'idle', // idle, sample or live
  groups: emptyGroups(),
  receipts: [],
  busy: false,
  config: null, // what the operator switched on, from /api/config
  generation: 0 // goes up on Reset and Sample, so answers that arrive late can be ignored
};

// Lets Reset and Sample cancel a request that is still running.
let activeRequest;

function emptyGroups() {
  return { browser: [], connection: [], records: [] };
}

// Makes an element and fills it with plain text. textContent never runs HTML, so server text is safe here.
function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text != null) element.textContent = text;
  if (className) element.className = className;
  return element;
}

function setStatus(text, isError = false) {
  byId('status').textContent = text;
  byId('status').classList.toggle('error', isError);
}

// Smooth scrolling is skipped for people who asked their system for less motion.
function scrollToWorkspace() {
  const calm = matchMedia('(prefers-reduced-motion: reduce)').matches;
  byId('workspace').scrollIntoView({ behavior: calm ? 'auto' : 'smooth' });
}

/* ---------- Talking to the server ---------- */

async function readJSON(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

async function post(path, body, signal) {
  let response;
  try {
    response = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      cache: 'no-store',
      signal
    });
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    throw new Error('The server could not be reached.');
  }

  const result = await readJSON(response);
  if (!response.ok) throw new Error(result?.error || 'The check could not complete');
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error(UNREADABLE);
  return result;
}

/* ---------- Drawing the page ---------- */

function selectLayer(layer) {
  state.layer = layer;

  for (const button of document.querySelectorAll('.layer')) {
    const active = button.dataset.layer === layer;
    button.classList.toggle('selected', active);
    button.setAttribute('aria-pressed', String(active));
  }

  const words = LAYERS[layer];
  byId('findings-label').textContent = words.label;
  byId('findings-title').textContent = words.title;
  byId('choice-title').textContent = words.choice;
  byId('choice-description').textContent = words.description;
  byId('run').replaceChildren(node('span', words.button), node('span', '→'));
  byId('run').disabled = state.busy;

  byId('browser-options').hidden = layer !== 'browser';
  byId('record-options').hidden = layer !== 'records';
  byId('transport-choice').hidden = layer !== 'connection' || !state.config?.transportOrigin;

  render();
}

function render() {
  const rows = state.groups[state.layer];
  renderCounts(rows);
  renderCards(rows);
  renderModePill();
  renderReceipts();
}

function renderCounts(rows) {
  const available = rows.filter(item => item.state === 'available').length;
  byId('available-count').textContent = rows.length ? available : '—';
  byId('unavailable-count').textContent = rows.length ? rows.length - available : '—';
  byId('finding-count').textContent = `${rows.length} finding${rows.length === 1 ? '' : 's'}`;
}

function renderCards(rows) {
  const container = byId('evidence');
  container.replaceChildren();
  if (!rows.length) container.append(emptyCard());
  for (const item of rows) container.append(evidenceCard(item));
}

function emptyCard() {
  const empty = node('div', null, 'empty');
  empty.append(
    node('div', '◎', 'empty-symbol'),
    node('h4', 'The interesting part starts with a question.'),
    node('p', 'Choose a check, or explore a clearly labelled sample. Unavailable information will stay unavailable.'),
    node('span', 'Every finding has a source and a limit.')
  );
  return empty;
}

function evidenceCard(item) {
  const missing = item.value == null;
  const card = node('article', null, 'evidence-card');
  card.append(
    node('h4', item.field),
    node('p', missing ? 'Not available' : String(item.value), 'evidence-value' + (missing ? ' missing' : ''))
  );

  const meta = node('div', null, 'evidence-meta');
  meta.append(node('span'), node('small', (state.mode === 'sample' ? 'SAMPLE · ' : '') + item.kind.toUpperCase()));
  card.append(meta);

  const time = item.retrievedAt ? new Date(item.retrievedAt).toLocaleTimeString() : 'at an unknown time';
  const details = node('details');
  details.append(
    node('summary', 'How did you know?'),
    node('p', `Source: ${item.source}`),
    node('p', item.limitation),
    node('p', `Subject: ${item.subject}. Retrieved ${time}.`)
  );
  card.append(details);

  return card;
}

function renderModePill() {
  const pill = byId('mode');
  if (state.mode === 'sample') {
    pill.className = 'mode-pill sample';
    pill.textContent = 'Illustrative sample · not your data';
  } else if (state.mode === 'live') {
    pill.className = 'mode-pill live';
    pill.textContent = 'Live results · this session';
  } else {
    pill.className = 'mode-pill ';
    pill.textContent = 'Ready when you are';
  }
}

function renderReceipts() {
  const container = byId('receipts');
  container.replaceChildren();
  if (!state.receipts.length) {
    container.append(node('p', 'Checks you choose will appear here, including their destinations and storage notes.', 'muted'));
  }

  for (const receipt of state.receipts) {
    const card = node('article', null, 'receipt-card');
    card.append(node('h3', (receipt.sample ? 'Sample · ' : '') + receipt.check));

    const lines = [
      ['Ran on', receipt.execution],
      ['Recipient', receipt.recipients.join(', ')],
      ['Read / sent', receipt.sent.join(', ')],
      ['Retention', receipt.retained]
    ];
    for (const [label, value] of lines) {
      const line = node('p');
      line.append(node('strong', label + ': '), document.createTextNode(value));
      card.append(line);
    }
    container.append(card);
  }
}

/* ---------- Running checks ---------- */

// The first real check wipes any sample data, so the two are never mixed.
function beginLive() {
  if (state.mode === 'sample') {
    state.groups = emptyGroups();
    state.receipts = [];
  }
  state.mode = 'live';
}

function chosenRecords() {
  return [...document.querySelectorAll('input[name="record"]:checked')].map(box => box.value);
}

async function run() {
  if (state.busy) return;
  const layer = state.layer;

  if (layer === 'records' && !(byId('external-consent').checked && chosenRecords().length)) {
    setStatus('Choose a configured source and approve the listed recipient first.', true);
    return;
  }

  beginLive();
  state.busy = true;
  const generation = state.generation;
  activeRequest = new AbortController();
  byId('run').disabled = true;
  setStatus('Reading only the checks you selected…');
  render();

  try {
    if (layer === 'browser') await runBrowserLayer(generation);
    else if (layer === 'connection') await runConnectionLayer(generation);
    else await runRecordsLayer(generation);
  } catch (error) {
    // Nothing is shown if the visitor already pressed Reset or Sample.
    if (generation === state.generation && error.name !== 'AbortError') setStatus(error.message, true);
  } finally {
    if (generation === state.generation) {
      state.busy = false;
      byId('run').disabled = false;
      render();
    }
  }
}

async function runBrowserLayer(generation) {
  const rows = await runBrowserChecks({ hardware: byId('hardware').checked, pattern: byId('pattern').checked });
  if (generation !== state.generation) return;

  state.groups.browser = rows;
  state.receipts.push({
    check: 'Browser check',
    execution: 'This tab',
    recipients: ['This browser'],
    sent: ['Selected local settings; no upload of these results'],
    retained: 'Tab memory until reset or reload.'
  });
  setStatus('Browser check complete. These collected results stayed in this tab.');
}

async function runConnectionLayer(generation) {
  const result = await post('/api/connection', { consent: true }, activeRequest.signal);
  const rows = cleanRows(result.evidence);
  const receipt = cleanReceipt(result.receipt);
  if (generation !== state.generation) return;

  state.groups.connection = rows;
  state.receipts.push(receipt);
  setStatus(result.publicAddress
    ? 'Connection evidence received. Unavailable transport fields need a configured trusted ingress.'
    : 'You are running locally. Public-network enrichment needs a real public connection; no external lookup was made.');
}

async function runRecordsLayer(generation) {
  const checks = chosenRecords();
  const result = await post('/api/enrich', { consent: true, publicRecordsConsent: true, checks }, activeRequest.signal);
  if (!Array.isArray(result.results)) throw new Error(UNREADABLE);

  const results = result.results.filter(item => item && typeof item === 'object');
  const rows = results.flatMap(item => cleanRows(item.evidence ?? []));
  if (generation !== state.generation) return;

  state.groups.records = rows;
  for (const item of results) {
    state.receipts.push({
      check: `${plainText(item.check)} · ${plainText(item.state)}`,
      execution: 'Our server',
      recipients: [plainText(item.recipient)],
      sent: ['Public connection address / reverse-address query'],
      retained: 'Request-scoped application results. Provider logging is outside this app’s reset control.'
    });
  }
  setStatus(results.map(item => item.state === 'complete' ? `${plainText(item.check)}: complete` : `${plainText(item.check)}: ${plainText(item.message)}`).join(' · '));
}

// The optional transport check goes to a separate first-party address, without cookies.
async function runTransport() {
  if (!state.config?.transportOrigin || state.busy) return;

  beginLive();
  state.busy = true;
  const generation = state.generation;
  activeRequest = new AbortController();
  byId('transport-run').disabled = true;
  setStatus('Requesting the separate transport endpoint you selected…');

  try {
    const response = await fetch(state.config.transportOrigin + '/api/transport', {
      method: 'POST',
      mode: 'cors',
      credentials: 'omit',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ consent: true }),
      cache: 'no-store',
      signal: activeRequest.signal
    });
    const result = await readJSON(response);
    if (!response.ok) throw new Error(result?.error || 'Transport diagnostic unavailable');

    const rows = cleanRows(result?.evidence);
    const receipt = cleanReceipt(result.receipt);
    if (generation !== state.generation) return;

    // New fingerprints replace the old ones. The address rows from the connection check stay.
    const kept = state.groups.connection.filter(item => !/fingerprint/i.test(item.field));
    state.groups.connection = [...kept, ...rows];
    state.receipts.push(receipt);
    setStatus(result.trustedTransport
      ? 'Transport report received. Patterns describe this diagnostic connection, not your identity.'
      : 'The diagnostic request did not arrive through a trusted transport collector. No fingerprints were accepted.');
  } catch (error) {
    if (generation === state.generation && error.name !== 'AbortError') {
      setStatus('Transport endpoint unavailable. Check its certificate and deployment configuration.', true);
    }
  } finally {
    byId('transport-run').disabled = false;
    if (generation === state.generation) {
      state.busy = false;
      render();
    }
  }
}

/* ---------- Sample, reset and dialogs ---------- */

function loadSample() {
  activeRequest?.abort();
  state.generation++;
  state.busy = false;
  state.mode = 'sample';
  state.groups = sampleGroups();
  state.receipts = sampleReceipts();
  selectLayer('browser');
  setStatus('Sample loaded. These values are illustrative; they are not your data.');
  scrollToWorkspace();
}

function reset() {
  activeRequest?.abort();
  state.generation++;
  state.busy = false;
  state.mode = 'idle';
  state.groups = emptyGroups();
  state.receipts = [];
  for (const box of document.querySelectorAll('input[type="checkbox"]')) box.checked = false;
  selectLayer('browser');
  setStatus('This tab’s results were cleared. Previously sent requests and provider logs cannot be recalled.');
}

function openDialog(title, content) {
  byId('modal-title').textContent = title;
  byId('modal-content').replaceChildren(...content);
  byId('modal').showModal();
}

function showPrivacy() {
  const content = [node('p', PRIVACY_INTRO)];
  for (const [title, body] of PRIVACY_SECTIONS) content.push(node('h3', title), node('p', body));
  openDialog('Your choice, in plain language', content);
}

function showExportPreview() {
  const findings = Object.values(state.groups).flat();
  if (!findings.length) {
    setStatus('Run a check or load a sample before exporting.');
    return;
  }

  const report = redactReport({
    project: 'LayerLens',
    mode: state.mode,
    exportedAt: new Date().toISOString(),
    evidence: findings,
    receipts: state.receipts
  });
  const json = JSON.stringify(report, null, 2);

  // The preview can scroll, so it must be reachable with the keyboard too.
  const preview = node('pre', json);
  preview.tabIndex = 0;
  preview.setAttribute('role', 'region');
  preview.setAttribute('aria-label', 'Redacted export, JSON');

  const download = node('button', 'Download this JSON', 'button primary');
  download.addEventListener('click', () => downloadText(json, 'layerlens-redacted.json'));

  openDialog('Preview before you share', [
    node('p', 'Exact connection identifiers and selected browser details have been removed. Remaining combinations can still be revealing.'),
    preview,
    download
  ]);
}

function downloadText(content, filename) {
  const url = URL.createObjectURL(new Blob([content], { type: 'application/json' }));
  const link = node('a');
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* ---------- Start ---------- */

for (const button of document.querySelectorAll('[data-layer]')) {
  button.addEventListener('click', () => {
    selectLayer(button.dataset.layer);
    setStatus(state.mode === 'sample'
      ? 'Illustrative sample. Running a real check will clear sample findings.'
      : 'Select a check to continue.');
  });
}
byId('sample').addEventListener('click', loadSample);
byId('browser-start').addEventListener('click', () => {
  selectLayer('browser');
  scrollToWorkspace();
  run();
});
byId('run').addEventListener('click', run);
byId('reset').addEventListener('click', reset);
byId('privacy-open').addEventListener('click', showPrivacy);
byId('export').addEventListener('click', showExportPreview);
byId('modal-close').addEventListener('click', () => byId('modal').close());
byId('transport-run').addEventListener('click', runTransport);

selectLayer('browser');
loadConfig();

// The configuration only says what the operator switched on. It never contains the visitor's address.
async function loadConfig() {
  try {
    const response = await fetch('/api/config', { cache: 'no-store' });
    const config = await response.json();
    state.config = config;

    for (const box of document.querySelectorAll('input[name="record"]')) {
      const enabled = Boolean(config.checks[box.value]);
      box.disabled = !enabled;
      byId('recipient-' + box.value).textContent = enabled ? config.recipients[box.value] : 'Operator has not enabled this check';
    }
    selectLayer(state.layer);
  } catch {
    for (const box of document.querySelectorAll('input[name="record"]')) box.disabled = true;
    setStatus('Configuration unavailable. Sample and local browser checks remain available.', false);
  }
}
