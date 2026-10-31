import assert from 'node:assert/strict';
import test from 'node:test';
import { escapeHTML, formatNumber } from './ui-utils.mjs';

test('escapeHTML encodes every HTML-sensitive character', () => {
  assert.equal(escapeHTML(`<img src=x onerror='run()'>&`), '&lt;img src=x onerror=&#39;run()&#39;&gt;&amp;');
});

test('formatNumber handles missing and numeric values', () => {
  assert.equal(formatNumber(null), '—');
  assert.equal(formatNumber(12345), new Intl.NumberFormat().format(12345));
});
