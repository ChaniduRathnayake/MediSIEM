// frontend/src/utils/csv.ts
// Minimal client-side CSV export — no backend round-trip needed since every
// caller already has the rows loaded (closed cases, compliance rollups,
// ...). RFC 4180 quoting: wrap a field in double quotes and double up any
// embedded quote whenever it contains a comma, quote, or newline — reason/
// evidence text on a closed case is free-form and routinely contains all
// three, so getting this right matters more here than in a typical export.
// Fields starting with =, +, -, @, tab, or CR are interpreted as formulas by
// Excel/LibreOffice/Google Sheets on open — a real, well-documented
// vulnerability class ("CSV injection") whenever a field can contain text
// from a lower-privileged source. Reason/evidence here are free-form text
// written by whichever SOC analyst closed the case, opened later by an
// admin/auditor, so every field is defused the same way: a leading `'`
// forces spreadsheet apps to render it as literal text.
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
