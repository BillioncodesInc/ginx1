import { describe, it, expect } from 'vitest';
import {
  parseDate,
  chunkArray,
  extractDomain,
  sleep,
  safeJsonParse,
  truncate,
  isNonEmptyString,
  normalizeDomain,
  calculateAge,
} from './utils';

describe('Utils', () => {
  describe('parseDate', () => {
    it('should parse valid date strings', () => {
      const date = parseDate('2024-01-15');
      expect(date).toBeInstanceOf(Date);
      expect(date?.getFullYear()).toBe(2024);
    });

    it('should return undefined for null/undefined', () => {
      expect(parseDate(null)).toBeUndefined();
      expect(parseDate(undefined)).toBeUndefined();
    });

    it('should return undefined for invalid date strings', () => {
      expect(parseDate('not-a-date')).toBeUndefined();
      expect(parseDate('invalid')).toBeUndefined();
    });

    it('should handle ISO date strings', () => {
      const date = parseDate('2024-01-01T00:00:00.000Z');
      expect(date).toBeInstanceOf(Date);
      expect(date?.getFullYear()).toBe(2024);
    });
  });

  describe('chunkArray', () => {
    it('should split array into chunks of specified size', () => {
      const arr = [1, 2, 3, 4, 5, 6, 7];
      const chunks = chunkArray(arr, 3);
      expect(chunks).toEqual([[1, 2, 3], [4, 5, 6], [7]]);
    });

    it('should handle empty arrays', () => {
      expect(chunkArray([], 3)).toEqual([]);
    });

    it('should handle arrays smaller than chunk size', () => {
      const arr = [1, 2];
      expect(chunkArray(arr, 5)).toEqual([[1, 2]]);
    });

    it('should handle chunk size of 1', () => {
      const arr = [1, 2, 3];
      expect(chunkArray(arr, 1)).toEqual([[1], [2], [3]]);
    });
  });

  describe('extractDomain', () => {
    it('should extract domain from full URL', () => {
      expect(extractDomain('https://www.example.com/path')).toBe('example.com');
      expect(extractDomain('http://test.org/')).toBe('test.org');
    });

    it('should remove www prefix', () => {
      expect(extractDomain('https://www.example.com')).toBe('example.com');
    });

    it('should handle URLs without protocol', () => {
      expect(extractDomain('example.com')).toBe('example.com');
      expect(extractDomain('www.example.com')).toBe('example.com');
    });

    it('should return null for invalid input', () => {
      expect(extractDomain('')).toBeNull();
    });
  });

  describe('sleep', () => {
    it('should delay for specified milliseconds', async () => {
      const start = Date.now();
      await sleep(50);
      const elapsed = Date.now() - start;
      expect(elapsed).toBeGreaterThanOrEqual(45); // Allow small margin
    });
  });

  describe('safeJsonParse', () => {
    it('should parse valid JSON', () => {
      expect(safeJsonParse('{"key": "value"}', {})).toEqual({ key: 'value' });
      expect(safeJsonParse('[1, 2, 3]', [])).toEqual([1, 2, 3]);
    });

    it('should return fallback for invalid JSON', () => {
      expect(safeJsonParse('invalid', 'default')).toBe('default');
      expect(safeJsonParse('{broken}', { fallback: true })).toEqual({ fallback: true });
    });

    it('should return fallback for null/undefined', () => {
      expect(safeJsonParse(null, [])).toEqual([]);
      expect(safeJsonParse(undefined, 'default')).toBe('default');
    });
  });

  describe('truncate', () => {
    it('should truncate strings longer than max length', () => {
      expect(truncate('Hello World!', 8)).toBe('Hello...');
    });

    it('should not truncate strings shorter than max length', () => {
      expect(truncate('Hello', 10)).toBe('Hello');
    });

    it('should handle exact length strings', () => {
      expect(truncate('Hello', 5)).toBe('Hello');
    });
  });

  describe('isNonEmptyString', () => {
    it('should return true for non-empty strings', () => {
      expect(isNonEmptyString('hello')).toBe(true);
      expect(isNonEmptyString('a')).toBe(true);
    });

    it('should return false for empty strings', () => {
      expect(isNonEmptyString('')).toBe(false);
      expect(isNonEmptyString('   ')).toBe(false);
    });

    it('should return false for non-strings', () => {
      expect(isNonEmptyString(null)).toBe(false);
      expect(isNonEmptyString(undefined)).toBe(false);
      expect(isNonEmptyString(123)).toBe(false);
      expect(isNonEmptyString({})).toBe(false);
    });
  });

  describe('normalizeDomain', () => {
    it('should lowercase domain', () => {
      expect(normalizeDomain('EXAMPLE.COM')).toBe('example.com');
    });

    it('should remove protocol', () => {
      expect(normalizeDomain('https://example.com')).toBe('example.com');
      expect(normalizeDomain('http://example.com')).toBe('example.com');
    });

    it('should remove www prefix', () => {
      expect(normalizeDomain('www.example.com')).toBe('example.com');
    });

    it('should remove trailing slash', () => {
      expect(normalizeDomain('example.com/')).toBe('example.com');
    });

    it('should handle all normalizations together', () => {
      expect(normalizeDomain('HTTPS://WWW.EXAMPLE.COM/')).toBe('example.com');
    });
  });

  describe('calculateAge', () => {
    const currentYear = new Date().getFullYear();

    it('should calculate age from birth year', () => {
      expect(calculateAge(2020)).toBe(currentYear - 2020);
      expect(calculateAge(2000)).toBe(currentYear - 2000);
    });

    it('should return 0 for null/undefined', () => {
      expect(calculateAge(null)).toBe(0);
      expect(calculateAge(undefined)).toBe(0);
    });
  });
});
