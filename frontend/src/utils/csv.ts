// Minimal client-side CSV export — every caller already has the rows loaded.
// RFC 4180 quoting for fields containing a comma/quote/newline. Fields
// starting with =, +, -, @, tab, or CR are defused with a leading `'` against
// CSV injection (Excel/Sheets treat them as formulas otherwise), since
// reason/evidence text is free-form and analyst-written.
const FORMULA_TRIGGER = /^[=+\-@\t\r]/;

function escapeCsvField(value: unknown): string {
  let str = value === null || value === undefined ? '' : String(value);
  if (FORMULA_TRIGGER.test(str)) {
    str = `'${str}`;
  }
  if (/[",\n\r]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

export function toCsv(headers: string[], rows: unknown[][]): string {
  const lines = [headers, ...rows].map((row) => row.map(escapeCsvField).join(','));
  // CRLF line endings + a leading BOM — Excel (still the primary consumer of
  // an audit CSV export) mis-detects encoding and mangles non-ASCII text
  // without the BOM, and splits rows incorrectly on bare \n on Windows.
  return '﻿' + lines.join('\r\n');
}

export function downloadCsv(filename: string, headers: string[], rows: unknown[][]): void {
  const csv = toCsv(headers, rows);
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
