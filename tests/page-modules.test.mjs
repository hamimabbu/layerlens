// Tests for the small browser modules that do not need a page: answer checking, finding rows and sample data.
import test from 'node:test';
import assert from 'node:assert/strict';
import { UNREADABLE, cleanReceipt, cleanRows, plainText } from '../public/answers.mjs';
import { row } from '../public/browser-checks.mjs';
import { LAYERS, PRIVACY_SECTIONS, sampleGroups, sampleReceipts } from '../public/content.mjs';
import { isPublicIP } from '../server/evidence.mjs';

test('an answer that is not a list of findings is unreadable', () => {
  for (const answer of [undefined, null, {}, 'text', 5]) {
    assert.throws(() => cleanRows(answer), { message: UNREADABLE });
  }
});

test('broken items are dropped and odd values become unavailable', () => {
  const rows = cleanRows([
    null, 5, 'text', [],
    { field: 'Plain', value: 'a' },
    { field: 'Object', value: { nested: true } },
    { field: 'List', value: [1, 2] },
    { field: 'Zero', value: 0 },
    { field: 'False', value: false }
  ]);

  assert.deepEqual(rows.map(item => [item.field, item.value, item.state]), [
    ['Plain', 'a', 'available'],
    ['Object', null, 'unavailable'],
    ['List', null, 'unavailable'],
    ['Zero', 0, 'available'],
    ['False', false, 'available']
  ]);
});

test('long text is cut, missing names get defaults and times are checked', () => {
  const [long, empty, goodTime, badTime, seenTime] = cleanRows([
    { field: 'x'.repeat(6000), value: 'y'.repeat(6000), source: 's'.repeat(6000) },
    {},
    { field: 'A', retrievedAt: '2026-11-07T04:00:00.000Z' },
    { field: 'B', retrievedAt: 'not a date', sourceObservedAt: 12345 },
    { field: 'C', sourceObservedAt: '2026-11-06T10:00:00.000Z' }
  ]);

  assert.equal(long.field.length, 2000);
  assert.equal(long.value.length, 2000);
  assert.equal(long.source.length, 2000);
  assert.equal(empty.field, 'Unnamed finding');
  assert.equal(empty.kind, 'unknown');
  assert.equal(goodTime.retrievedAt, '2026-11-07T04:00:00.000Z');
  assert.equal(goodTime.sourceObservedAt, null);
  assert.equal(badTime.retrievedAt, null);
  assert.equal(badTime.sourceObservedAt, null);
  assert.equal(seenTime.sourceObservedAt, '2026-11-06T10:00:00.000Z');
});

test('receipts are checked in the same way', () => {
  for (const receipt of [undefined, null, 'text', 5]) {
    assert.throws(() => cleanReceipt(receipt), { message: UNREADABLE });
  }

  const receipt = cleanReceipt({ recipients: ['a', 5, null], sent: 'not a list', retained: 'r'.repeat(3000) });
  assert.deepEqual(receipt.recipients, ['a', '5', '']);
  assert.deepEqual(receipt.sent, []);
  assert.equal(receipt.check, 'Check');
  assert.equal(receipt.retained.length, 2000);
});

test('plainText turns empty values into empty text and cuts long ones', () => {
  assert.equal(plainText(null), '');
  assert.equal(plainText(undefined), '');
  assert.equal(plainText(12), '12');
  assert.equal(plainText('z'.repeat(5000)).length, 2000);
});

test('a browser finding is unavailable only when it has no value', () => {
  assert.equal(row('Memory', null, 'source', 'limit').state, 'unavailable');
  assert.equal(row('Memory', undefined, 'source', 'limit').state, 'unavailable');
  assert.equal(row('Count', 0, 'source', 'limit').state, 'available');
  assert.equal(row('Count', 4, 'source', 'limit').subject, 'this browser');
});

test('sample mode only shows documentation addresses and reserved names', () => {
  const values = Object.values(sampleGroups()).flat().map(item => item.value).filter(value => typeof value === 'string');

  const addresses = values.join(' ').match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? [];
  assert.ok(addresses.length > 0, 'the sample should include an address');
  for (const address of addresses) assert.equal(isPublicIP(address), false, address);

  const hostnames = values.join(' ').match(/\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/gi) ?? [];
  for (const name of hostnames.filter(name => !addresses.includes(name))) assert.match(name, /\.invalid$/, name);
});

test('every sample finding explains its limit and is clearly labelled as a sample', () => {
  for (const item of Object.values(sampleGroups()).flat()) {
    assert.ok(item.limitation.length > 10, item.field);
    assert.ok(item.source.length > 0, item.field);
  }
  assert.equal(sampleReceipts().every(receipt => receipt.sample === true), true);
});

test('every layer has all of its wording', () => {
  assert.deepEqual(Object.keys(LAYERS), ['browser', 'connection', 'records']);
  for (const layer of Object.values(LAYERS)) {
    for (const key of ['label', 'title', 'choice', 'description', 'button']) assert.ok(layer[key].length > 0, key);
  }
  assert.equal(PRIVACY_SECTIONS.length, 4);
  for (const [title, body] of PRIVACY_SECTIONS) assert.ok(title.length > 0 && body.length > 0, title);
});
