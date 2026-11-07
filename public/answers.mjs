// Checks answers from a server before the page shows them.
// A broken or hostile answer should end in an error message, never in a broken page.

export const UNREADABLE = 'The server sent an answer this page could not read.';
const MAX_TEXT = 2000;

// Turns any value into short plain text.
export function plainText(value) {
  return value == null ? '' : String(value).slice(0, MAX_TEXT);
}

// A list of findings. Anything that is not a list is an unreadable answer.
export function cleanRows(list) {
  if (!Array.isArray(list)) throw new Error(UNREADABLE);
  return list.map(cleanRow).filter(Boolean);
}

// A time is kept only when it is text that Date can read.
function cleanTime(value) {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value)) ? value : null;
}

function cleanRow(item) {
  if (!item || typeof item !== 'object' || Array.isArray(item)) return null;

  const simple = ['string', 'number', 'boolean'].includes(typeof item.value);
  const value = simple ? (typeof item.value === 'string' ? item.value.slice(0, MAX_TEXT) : item.value) : null;

  return {
    field: plainText(item.field) || 'Unnamed finding',
    value,
    source: plainText(item.source),
    limitation: plainText(item.limitation),
    kind: plainText(item.kind) || 'unknown',
    subject: plainText(item.subject),
    state: value == null ? 'unavailable' : 'available',
    retrievedAt: cleanTime(item.retrievedAt),
    sourceObservedAt: cleanTime(item.sourceObservedAt)
  };
}

export function cleanReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object') throw new Error(UNREADABLE);
  const list = value => (Array.isArray(value) ? value.map(plainText) : []);

  return {
    check: plainText(receipt.check) || 'Check',
    execution: plainText(receipt.execution),
    recipients: list(receipt.recipients),
    sent: list(receipt.sent),
    retained: plainText(receipt.retained)
  };
}
