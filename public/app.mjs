const $ = id => document.getElementById(id);
const state = { layer: 'browser', mode: 'idle', groups: { browser: [], connection: [], records: [] }, receipts: [], busy: false, config: null, generation: 0 };
const labels = { browser: ['LOCAL BROWSER', 'A few facts. Their whole story.', 'A look around your browser', 'These selected checks run in this tab. Their results do not need to be sent to our server.', 'Run browser check'], connection: ['FIRST-PARTY CONNECTION', 'Your connection, with context.', 'A first-party connection check', 'Our server sees the connection address in an ordinary request. This check shows it to you. Transport patterns need a configured, trusted Fingerproxy ingress.', 'Inspect my connection'], records: ['OPTIONAL PUBLIC RECORDS', 'Public records are not a person.', 'Choose the sources first', 'These checks send your public connection address to the recipients listed below. The operator must configure them before they can run.', 'Run selected lookups'] };

function row(field, value, source, limitation, extra = {}) { return { field, value, source, limitation, kind: 'browser-reported', subject: 'this browser', state: value == null ? 'unavailable' : 'available', retrievedAt: new Date().toISOString(), sourceObservedAt: null, ...extra }; }
function node(tag, text, className) { const el = document.createElement(tag); if (text != null) el.textContent = text; if (className) el.className = className; return el; }
function status(text, error = false) { $('status').textContent = text; $('status').classList.toggle('error', error); }

function select(layer) {
  state.layer = layer;
  document.querySelectorAll('.layer').forEach(el => { const active = el.dataset.layer === layer; el.classList.toggle('selected', active); el.setAttribute('aria-pressed', String(active)); });
  const [label,title,choice,description,button] = labels[layer];
  $('findings-label').textContent = label; $('findings-title').textContent = title; $('choice-title').textContent = choice; $('choice-description').textContent = description;
  $('run').replaceChildren(node('span', button), node('span', '→')); $('run').disabled = state.busy;
  $('browser-options').hidden = layer !== 'browser'; $('record-options').hidden = layer !== 'records';
  $('transport-choice').hidden = layer !== 'connection' || !state.config?.transportOrigin;
  render();
}

function render() {
  const rows = state.groups[state.layer];
  const available = rows.filter(r => r.state === 'available').length;
  $('available-count').textContent = rows.length ? available : '—'; $('unavailable-count').textContent = rows.length ? rows.length - available : '—';
  $('finding-count').textContent = `${rows.length} finding${rows.length === 1 ? '' : 's'}`;
  const container = $('evidence'); container.replaceChildren();
  if (!rows.length) {
    const empty = node('div', null, 'empty'); empty.append(node('div','◎','empty-symbol'),node('h4','The interesting part starts with a question.'),node('p','Choose a check, or explore a clearly labelled sample. Unavailable information will stay unavailable.'),node('span','Every finding has a source and a limit.')); container.append(empty);
  }
  rows.forEach(item => {
    const card = node('article',null,'evidence-card'); card.append(node('h4',item.field),node('p',item.value == null ? 'Not available' : String(item.value),'evidence-value' + (item.value == null ? ' missing' : '')));
    const meta = node('div',null,'evidence-meta'); meta.append(node('span'),node('small',(state.mode === 'sample' ? 'SAMPLE · ' : '') + item.kind.toUpperCase())); card.append(meta);
    const details = node('details'); details.append(node('summary','How did you know?'),node('p',`Source: ${item.source}`),node('p',item.limitation),node('p',`Subject: ${item.subject}. Retrieved ${new Date(item.retrievedAt).toLocaleTimeString()}.`)); card.append(details); container.append(card);
  });
  const pill = $('mode'); pill.className = 'mode-pill ' + (state.mode === 'sample' ? 'sample' : state.mode === 'live' ? 'live' : ''); pill.textContent = state.mode === 'sample' ? 'Illustrative sample · not your data' : state.mode === 'live' ? 'Live results · this session' : 'Ready when you are';
  $('receipts').replaceChildren();
  if (!state.receipts.length) $('receipts').append(node('p','Checks you choose will appear here, including their destinations and storage notes.','muted'));
  state.receipts.forEach(receipt => {
    const el = node('article',null,'receipt-card'); el.append(node('h3',(receipt.sample ? 'Sample · ' : '') + receipt.check));
    for (const [label,value] of [['Ran on',receipt.execution],['Recipient',receipt.recipients.join(', ')],['Read / sent',receipt.sent.join(', ')],['Retention',receipt.retained]]) { const p = node('p'); p.append(node('strong',label + ': '),document.createTextNode(value)); el.append(p); }
    $('receipts').append(el);
  });
}

function beginLive() {
  if (state.mode === 'sample') { state.groups = { browser: [], connection: [], records: [] }; state.receipts = []; }
  state.mode = 'live';
}

async function browserCheck() {
  const rows = [
    row('Reported browser', navigator.userAgent, 'navigator.userAgent', 'User-Agent strings can be reduced, changed or spoofed. They do not prove a software version.'),
    row('Timezone setting', Intl.DateTimeFormat().resolvedOptions().timeZone || null, 'Intl.DateTimeFormat', 'A browser setting, not proof of physical location.'),
    row('Language preferences', navigator.languages?.join(', ') || navigator.language, 'navigator.languages', 'Language preferences are not nationality.'),
    row('Display in CSS pixels', `${screen.width} × ${screen.height} · scale ${devicePixelRatio}`, 'Screen and devicePixelRatio', 'This is not your monitor model or its physical dimensions.'),
    row('Colour preference', matchMedia('(prefers-color-scheme: dark)').matches ? 'Dark' : 'Light / not specified', 'CSS media query', 'This reflects a preference, not anything about your identity.'),
    row('Motion preference', matchMedia('(prefers-reduced-motion: reduce)').matches ? 'Reduced motion' : 'No reduced-motion preference', 'CSS media query', 'This setting is used for accessibility. It does not establish a medical condition.')
  ];
  if ($('hardware').checked) rows.push(row('Reported logical concurrency',navigator.hardwareConcurrency || null,'navigator.hardwareConcurrency','Browsers can reduce this value. It is not verified physical CPU inventory.'),row('Approximate memory hint',navigator.deviceMemory ? `${navigator.deviceMemory} GiB (coarse)` : null,'navigator.deviceMemory','This API is approximate, limited and unsupported in some browsers. Missing is a normal result.'));
  if ($('pattern').checked && crypto.subtle) {
    const bytes = new TextEncoder().encode(JSON.stringify(rows.map(r => [r.field,r.value])));
    const digest = await crypto.subtle.digest('SHA-256',bytes);
    const value = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2,'0')).join('');
    rows.push(row('Local attribute pattern',value,'Web Crypto SHA-256 over selected values','A pattern for these attributes, not a unique person or a proven returning device.',{kind:'derived'}));
  } else if ($('pattern').checked) rows.push(row('Local attribute pattern',null,'Web Crypto','This feature needs a supported secure browser context.'));
  return rows;
}

async function post(path, body, signal) {
  const response = await fetch(path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body),cache:'no-store',signal});
  const result = await response.json(); if (!response.ok) throw new Error(result.error || 'The check could not complete'); return result;
}

let activeRequest;
async function run() {
  if (state.busy) return;
  const layer = state.layer;
  if (layer === 'records' && (!$('external-consent').checked || ![...document.querySelectorAll('input[name="record"]:checked')].length)) { status('Choose a configured source and approve the listed recipient first.',true); return; }
  beginLive(); state.busy = true; const generation = state.generation; activeRequest = new AbortController(); $('run').disabled = true; status('Reading only the checks you selected…'); render();
  try {
    if (layer === 'browser') {
      const result = await browserCheck(); if (generation !== state.generation) return; state.groups.browser = result;
      state.receipts.push({ check:'Browser check',execution:'This tab',recipients:['This browser'],sent:['Selected local settings; no upload of these results'],retained:'Tab memory until reset or reload.' });
      status('Browser check complete. These collected results stayed in this tab.');
    } else if (layer === 'connection') {
      const result = await post('/api/connection',{consent:true},activeRequest.signal); if (generation !== state.generation) return; state.groups.connection = result.evidence; state.receipts.push(result.receipt);
      status(result.publicAddress ? 'Connection evidence received. Unavailable transport fields need a configured trusted ingress.' : 'You are running locally. Public-network enrichment needs a real public connection; no external lookup was made.');
    } else {
      const checks = [...document.querySelectorAll('input[name="record"]:checked')].map(x => x.value);
      const result = await post('/api/enrich',{consent:true,publicRecordsConsent:true,checks},activeRequest.signal); if (generation !== state.generation) return;
      state.groups.records = result.results.flatMap(r => r.evidence);
      result.results.forEach(r => state.receipts.push({check:r.check + ' · ' + r.state,execution:'Our server',recipients:[r.recipient],sent:['Public connection address / reverse-address query'],retained:'Request-scoped application results. Provider logging is outside this app’s reset control.'}));
      status(result.results.map(r => r.state === 'complete' ? `${r.check}: complete` : `${r.check}: ${r.message}`).join(' · '));
    }
  } catch (error) { if (generation === state.generation && error.name !== 'AbortError') status(error.message,true); }
  finally { if (generation === state.generation) { state.busy = false; $('run').disabled = false; render(); } }
}

function sample() {
  activeRequest?.abort(); state.generation++; state.busy = false; state.mode = 'sample';
  state.groups = {
    browser: [row('Reported browser','Example Browser / desktop','Illustrative fixture','This is a labelled sample, not information read from your device.'),row('Timezone setting','Europe/London','Illustrative fixture','A timezone setting does not establish physical location.'),row('Display in CSS pixels','1440 × 900 · scale 1','Illustrative fixture','Display values describe a capability, not a person.'),row('Approximate memory hint',null,'Illustrative fixture','An unsupported API is a normal result.')],
    connection: [row('Public connection address','198.51.100.42','Documentation address','This reserved example is not a real visitor address.',{kind:'sample',subject:'sample connection'}),row('Registered network','Example Research Network','Synthetic fixture','A network label is not proof of employment.',{kind:'sample'}),row('JA4 fingerprint','t13d1516h2_example_example','Synthetic fixture','Illustrative format only; no TLS handshake was captured.',{kind:'sample'})],
    records: [row('Reverse DNS','example.invalid','Synthetic fixture','An address-associated record is not a private computer hostname.',{kind:'sample'}),row('Registration country','GB','Synthetic fixture','A registration field is not a physical-location measurement.',{kind:'sample'})]
  };
  state.receipts = [{sample:true,check:'Sample exploration',execution:'This tab',recipients:['None beyond ordinary page hosting'],sent:['No network lookup'],retained:'Tab memory until reset or reload.'}];
  select('browser'); status('Sample loaded. These values are illustrative; they are not your data.'); $('workspace').scrollIntoView({behavior:'smooth'});
}

function reset() { activeRequest?.abort(); state.generation++; state.busy = false; state.mode = 'idle'; state.groups = {browser:[],connection:[],records:[]}; state.receipts = []; document.querySelectorAll('input[type="checkbox"]').forEach(el => { el.checked = false; }); select('browser'); status('This tab’s results were cleared. Previously sent requests and provider logs cannot be recalled.'); }
async function transportCheck() {
  if (!state.config?.transportOrigin || state.busy) return;
  beginLive(); state.busy = true; const generation = state.generation; activeRequest = new AbortController(); $('transport-run').disabled = true;
  status('Requesting the separate transport endpoint you selected…');
  try {
    const response = await fetch(state.config.transportOrigin + '/api/transport',{method:'POST',mode:'cors',credentials:'omit',headers:{'content-type':'application/json'},body:JSON.stringify({consent:true}),cache:'no-store',signal:activeRequest.signal});
    const result = await response.json(); if (!response.ok) throw new Error(result.error || 'Transport diagnostic unavailable'); if (generation !== state.generation) return;
    state.groups.connection = [...state.groups.connection.filter(r => !/fingerprint/i.test(r.field)),...result.evidence]; state.receipts.push(result.receipt);
    status(result.trustedTransport ? 'Transport report received. Patterns describe this diagnostic connection, not your identity.' : 'The diagnostic request did not arrive through a trusted transport collector. No fingerprints were accepted.');
  } catch(error) { if (generation === state.generation && error.name !== 'AbortError') status('Transport endpoint unavailable. Check its certificate and deployment configuration.',true); }
  finally { $('transport-run').disabled = false; if (generation === state.generation) { state.busy = false; render(); } }
}
function modal(title, content) { $('modal-title').textContent = title; $('modal-content').replaceChildren(...content); $('modal').showModal(); }
function privacy() {
  const content = [node('p','Choose the depth. Sample mode does not run lookups. Selected browser results are computed in your tab. A normal page load still sends an IP and request headers to the hosting infrastructure.')];
  for (const [title,text] of [['Connection checks','The same-origin server returns connection evidence after your click. Optional transport fingerprints use a separately requested, first-party diagnostic endpoint and are accepted only from a configured trusted peer.'],['Public records','Off by default. The operator must configure them, and you separately choose the checks and their recipients. DNS queries reach the configured resolver; registry queries reach IANA and the selected regional registry. Shodan is an optional additional recipient.'],['Retention','No accounts, analytics, cookies or results database are part of this application. Application results are request-scoped; browser results stay in memory. Hashed security counters are removed within 61 seconds. Hosting and proxy logs require separate operator configuration.'],['Limits','A fingerprint is not an identity. A network owner is not an employer. Indexed exposure records do not establish a current vulnerability on your laptop. Reset cannot erase another provider’s logs.']]) content.push(node('h3',title),node('p',text));
  modal('Your choice, in plain language',content);
}
function exportPreview() {
  const all = Object.values(state.groups).flat();
  if (!all.length) { status('Run a check or load a sample before exporting.'); return; }
  const sensitive = /address|fingerprint|pattern|reverse dns|allocation range|timezone|display|language|browser|renderer|model|hostname/i;
  const data = { project:'LayerLens',mode:state.mode,exportedAt:new Date().toISOString(),notice:'Redacted, not guaranteed anonymous. Preview before sharing.',evidence:all.map(r => ({...r,value:sensitive.test(r.field) ? '[redacted]' : r.value})),receipts:state.receipts.map(r => ({...r,recipients:r.recipients.map(x => /^\d/.test(x) ? '[resolver redacted]' : x)})) };
  const text = JSON.stringify(data,null,2); const pre = node('pre',text); const download = node('button','Download this JSON','button primary');
  download.addEventListener('click',() => { const url = URL.createObjectURL(new Blob([text],{type:'application/json'})); const a = node('a'); a.href = url; a.download = 'layerlens-redacted.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url),1000); });
  modal('Preview before you share',[node('p','Exact connection identifiers and selected browser details have been removed. Remaining combinations can still be revealing.'),pre,download]);
}

document.querySelectorAll('[data-layer]').forEach(el => el.addEventListener('click',() => { select(el.dataset.layer); status(state.mode === 'sample' ? 'Illustrative sample. Running a real check will clear sample findings.' : 'Select a check to continue.'); }));
$('sample').addEventListener('click',sample); $('browser-start').addEventListener('click',() => { select('browser'); $('workspace').scrollIntoView({behavior:'smooth'}); run(); });
$('run').addEventListener('click',run); $('reset').addEventListener('click',reset); $('privacy-open').addEventListener('click',privacy); $('export').addEventListener('click',exportPreview); $('modal-close').addEventListener('click',() => $('modal').close());
$('transport-run').addEventListener('click',transportCheck);
select('browser');
// Configuration contains operator policy only, not the visitor's address or browser results.
fetch('/api/config',{cache:'no-store'}).then(r => r.json()).then(config => {
  state.config = config;
  document.querySelectorAll('input[name="record"]').forEach(el => { el.disabled = !config.checks[el.value]; $('recipient-' + el.value).textContent = config.checks[el.value] ? config.recipients[el.value] : 'Operator has not enabled this check'; });
}).catch(() => { document.querySelectorAll('input[name="record"]').forEach(el => { el.disabled = true; }); status('Configuration unavailable. Sample and local browser checks remain available.'); });
