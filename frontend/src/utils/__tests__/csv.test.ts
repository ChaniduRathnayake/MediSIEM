import { describe, test, expect } from 'vitest';
import { toCsv } from '../csv';

// Strip the leading BOM toCsv() prepends so string comparisons below are legible.
const withoutBom = (s: string) => s.replace(/^﻿/, '');

describe('toCsv — formula injection defusing', () => {
  // Regression test for the CSV/formula-injection finding from the security
  // review: a SOC analyst's free-text case-closure evidence is untrusted
  // input relative to whichever admin later exports and opens the file in
  // Excel — a leading =/+/-/@ must never reach the cell as a live formula.
  test.each(['=cmd|\'/C calc\'!A0', '+1+1', '-2+3', '@SUM(A1:A9)'])(
    'prefixes a leading formula-trigger character (%s) with a single quote',
    (payload) => {
      const csv = withoutBom(toCsv(['Evidence'], [[payload]]));
      const dataLine = csv.split('\r\n')[1];
      expect(dataLine.startsWith(`'${payload[0]}`) || dataLine.startsWith(`"'${payload[0]}`)).toBe(true);
      expect(dataLine).not.toMatch(/^[=+\-@]/);
    }
  );

  test('does not alter a field that does not start with a formula trigger', () => {
    const csv = withoutBom(toCsv(['Reason'], [['False positive - benign vendor scan']]));
    expect(csv.split('\r\n')[1]).toBe('False positive - benign vendor scan');
  });

  test('a formula trigger appearing mid-string (not leading) is left alone', () => {
    const csv = withoutBom(toCsv(['Notes'], [['price = 5']]));
    expect(csv.split('\r\n')[1]).toBe('price = 5');
  });
});

describe('toCsv — RFC 4180 quoting', () => {
  test('quotes and doubles embedded quotes', () => {
    const csv = withoutBom(toCsv(['Field'], [['She said "hello"']]));
    expect(csv.split('\r\n')[1]).toBe('"She said ""hello"""');
  });

  test('quotes fields containing a comma', () => {
    const csv = withoutBom(toCsv(['Field'], [['a, b, c']]));
    expect(csv.split('\r\n')[1]).toBe('"a, b, c"');
  });

  test('quotes fields containing a newline', () => {
    const csv = withoutBom(toCsv(['Field'], [['line1\nline2']]));
    expect(csv.split('\r\n')[1]).toBe('"line1\nline2"');
  });

  test('null/undefined values render as empty fields, not the string "null"', () => {
    const csv = withoutBom(toCsv(['A', 'B'], [[null, undefined]]));
    expect(csv.split('\r\n')[1]).toBe(',');
  });
});

describe('toCsv — structure', () => {
  test('joins header + rows with CRLF and a leading BOM', () => {
    const csv = toCsv(['A', 'B'], [['1', '2']]);
    expect(csv.startsWith('﻿')).toBe(true);
    expect(csv).toBe('﻿A,B\r\n1,2');
  });
});
