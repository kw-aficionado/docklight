export function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[character]);
}

export function formatNumber(value) {
  if (value == null) return '—';
  return new Intl.NumberFormat().format(value);
}

export function parseConfigDocument(content) {
  const newline = content.includes('\r\n') ? '\r\n' : '\n';
  const slots = content.split(/\r?\n/).map((line) => {
    const match = line.match(/^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_.-]*)(\s*[=:]\s*)(.*)$/);
    return match
      ? { prefix: match[1], key: match[2], separator: match[3], value: match[4] }
      : { raw: line };
  });
  return { newline, slots };
}

export function serializeConfigDocument(slots, newline) {
  return slots.map((slot) => slot.raw !== undefined
    ? slot.raw
    : `${slot.prefix}${slot.key}${slot.separator}${slot.value}`).join(newline);
}
