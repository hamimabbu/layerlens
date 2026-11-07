// Used by both the browser export and the server-side checks.
export function redactReport(report) {
  const copy = structuredClone(report);
  const sensitive = /address|fingerprint|pattern|reverse dns|allocation range|latitude|longitude|timezone|resolution|display|language|user agent|browser|renderer|model|hostname/i;
  copy.evidence = (copy.evidence || []).map(row => sensitive.test(row.field)
    ? { ...row, value: '[redacted]', redacted: true }
    : row);
  if (copy.receipts) {
    copy.receipts = copy.receipts.map(receipt => /^ptr(?:\s|$)/i.test(receipt.check)
      ? { ...receipt, recipients: receipt.recipients.map(() => '[resolver redacted]') }
      : receipt);
  }
  return { ...copy, redacted: true, notice: 'Preview before sharing. Redaction does not guarantee anonymity.' };
}
