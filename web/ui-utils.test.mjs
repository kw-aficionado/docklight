import assert from 'node:assert/strict';
import test from 'node:test';
import { escapeHTML, formatNumber, parseConfigDocument, serializeConfigDocument } from './ui-utils.mjs';

test('escapeHTML encodes every HTML-sensitive character', () => {
  assert.equal(escapeHTML(`<img src=x onerror='run()'>&`), '&lt;img src=x onerror=&#39;run()&#39;&gt;&amp;');
});

test('formatNumber handles missing and numeric values', () => {
  assert.equal(formatNumber(null), '—');
  assert.equal(formatNumber(12345), new Intl.NumberFormat().format(12345));
});

test('config editor preserves comments, unsupported lines, spacing and CRLF', () => {
  const input = '# keep this\r\nexport APP_MODE = production\r\nraw unsupported line\r\n';
  const parsed = parseConfigDocument(input);
  assert.equal(parsed.newline, '\r\n');
  assert.equal(parsed.slots.filter((slot) => slot.raw !== undefined).length, 3);
  parsed.slots[1].value = 'maintenance';
  assert.equal(serializeConfigDocument(parsed.slots, parsed.newline), '# keep this\r\nexport APP_MODE = maintenance\r\nraw unsupported line\r\n');
});
