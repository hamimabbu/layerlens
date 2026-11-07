// All the wording and the made-up sample data used by the page.
import { row } from './browser-checks.mjs';

// Text that changes when the visitor picks a layer.
export const LAYERS = {
  browser: {
    label: 'LOCAL BROWSER',
    title: 'A few facts. Their whole story.',
    choice: 'A look around your browser',
    description: 'These selected checks run in this tab. Their results do not need to be sent to our server.',
    button: 'Run browser check'
  },
  connection: {
    label: 'FIRST-PARTY CONNECTION',
    title: 'Your connection, with context.',
    choice: 'A first-party connection check',
    description: 'Our server sees the connection address in an ordinary request. This check shows it to you. Transport patterns need a configured, trusted Fingerproxy ingress.',
    button: 'Inspect my connection'
  },
  records: {
    label: 'OPTIONAL PUBLIC RECORDS',
    title: 'Public records are not a person.',
    choice: 'Choose the sources first',
    description: 'These checks send your public connection address to the recipients listed below. The operator must configure them before they can run.',
    button: 'Run selected lookups'
  }
};

export const PRIVACY_INTRO = 'Choose the depth. Sample mode does not run lookups. Selected browser results are computed in your tab. A normal page load still sends an IP and request headers to the hosting infrastructure.';

export const PRIVACY_SECTIONS = [
  ['Connection checks', 'The same-origin server returns connection evidence after your click. Optional transport fingerprints use a separately requested, first-party diagnostic endpoint and are accepted only from a configured trusted peer.'],
  ['Public records', 'Off by default. The operator must configure them, and you separately choose the checks and their recipients. DNS queries reach the configured resolver; registry queries reach IANA and the selected regional registry. Shodan is an optional additional recipient.'],
  ['Retention', 'No accounts, analytics, cookies or results database are part of this application. Application results are request-scoped; browser results stay in memory. Hashed security counters are removed within 61 seconds. Hosting and proxy logs require separate operator configuration.'],
  ['Limits', 'A fingerprint is not an identity. A network owner is not an employer. Indexed exposure records do not establish a current vulnerability on your laptop. Reset cannot erase another provider’s logs.']
];

// Sample mode shows these invented values. They use documentation addresses and ".invalid" names on purpose.
export function sampleGroups() {
  return {
    browser: [
      row('Reported browser', 'Example Browser / desktop', 'Illustrative fixture', 'This is a labelled sample, not information read from your device.'),
      row('Timezone setting', 'Europe/London', 'Illustrative fixture', 'A timezone setting does not establish physical location.'),
      row('Display in CSS pixels', '1440 × 900 · scale 1', 'Illustrative fixture', 'Display values describe a capability, not a person.'),
      row('Approximate memory hint', null, 'Illustrative fixture', 'An unsupported API is a normal result.')
    ],
    connection: [
      row('Public connection address', '198.51.100.42', 'Documentation address', 'This reserved example is not a real visitor address.', { kind: 'sample', subject: 'sample connection' }),
      row('Registered network', 'Example Research Network', 'Synthetic fixture', 'A network label is not proof of employment.', { kind: 'sample' }),
      row('JA4 fingerprint', 't13d1516h2_example_example', 'Synthetic fixture', 'Illustrative format only; no TLS handshake was captured.', { kind: 'sample' })
    ],
    records: [
      row('Reverse DNS', 'example.invalid', 'Synthetic fixture', 'An address-associated record is not a private computer hostname.', { kind: 'sample' }),
      row('Registration country', 'GB', 'Synthetic fixture', 'A registration field is not a physical-location measurement.', { kind: 'sample' })
    ]
  };
}

export function sampleReceipts() {
  return [{
    sample: true,
    check: 'Sample exploration',
    execution: 'This tab',
    recipients: ['None beyond ordinary page hosting'],
    sent: ['No network lookup'],
    retained: 'Tab memory until reset or reload.'
  }];
}
