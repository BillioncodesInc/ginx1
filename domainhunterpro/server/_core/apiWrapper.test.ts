import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createLogger, safeApiCall, withTimeout, RateLimiter, RATE_LIMITS } from './apiWrapper';

describe('API Wrapper Utilities', () => {
  describe('createLogger', () => {
    it('should create a logger with module prefix', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      const logger = createLogger('TestModule');

      logger.info('Test message');

      expect(consoleSpy).toHaveBeenCalled();
      const logOutput = consoleSpy.mock.calls[0][0];
      expect(logOutput).toContain('[INFO]');
      expect(logOutput).toContain('[TestModule]');
      expect(logOutput).toContain('Test message');
      consoleSpy.mockRestore();
    });

    it('should log errors with error details', () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const logger = createLogger('TestModule');

      logger.error('Error occurred', new Error('Test error'));

      expect(consoleSpy).toHaveBeenCalled();
      const logOutput = consoleSpy.mock.calls[0][0];
      expect(logOutput).toContain('[ERROR]');
      expect(logOutput).toContain('[TestModule]');
      expect(logOutput).toContain('Error occurred');
      expect(logOutput).toContain('Test error');
      consoleSpy.mockRestore();
    });

    it('should log warnings', () => {
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      const logger = createLogger('TestModule');

      logger.warn('Warning message');

      expect(consoleSpy).toHaveBeenCalled();
      const logOutput = consoleSpy.mock.calls[0][0];
      expect(logOutput).toContain('[WARN]');
      expect(logOutput).toContain('[TestModule]');
      expect(logOutput).toContain('Warning message');
      consoleSpy.mockRestore();
    });
  });

  describe('safeApiCall', () => {
    it('should return result on success', async () => {
      const apiCall = vi.fn().mockResolvedValue('success');

      const result = await safeApiCall(apiCall, 'fallback');

      expect(result).toBe('success');
    });

    it('should return fallback on error', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const apiCall = vi.fn().mockRejectedValue(new Error('API failed'));

      const result = await safeApiCall(apiCall, 'fallback');

      expect(result).toBe('fallback');
      consoleSpy.mockRestore();
    });

    it('should not log error when logError is false', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const apiCall = vi.fn().mockRejectedValue(new Error('API failed'));

      await safeApiCall(apiCall, 'fallback', { logError: false });

      expect(consoleSpy).not.toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    it('should use custom label in error message', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const apiCall = vi.fn().mockRejectedValue(new Error('Custom error'));

      await safeApiCall(apiCall, 'fallback', { label: 'CustomAPI' });

      expect(consoleSpy).toHaveBeenCalledWith('[CustomAPI] Error: Custom error');
      consoleSpy.mockRestore();
    });
  });

  describe('withTimeout', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('should return result if completed before timeout', async () => {
      const promise = new Promise<string>((resolve) => {
        setTimeout(() => resolve('success'), 100);
      });

      const resultPromise = withTimeout(promise, 1000);
      await vi.advanceTimersByTimeAsync(100);
      const result = await resultPromise;

      expect(result).toBe('success');
    });

    it('should throw error if timeout exceeded', async () => {
      const promise = new Promise<string>((resolve) => {
        setTimeout(() => resolve('success'), 2000);
      });

      const resultPromise = withTimeout(promise, 100, 'Custom timeout message');

      // Advance to trigger timeout
      vi.advanceTimersByTime(100);

      await expect(resultPromise).rejects.toThrow('Custom timeout message');
    });

    it('should use default timeout message', async () => {
      const promise = new Promise<string>((resolve) => {
        setTimeout(() => resolve('success'), 2000);
      });

      const resultPromise = withTimeout(promise, 100);
      vi.advanceTimersByTime(100);

      await expect(resultPromise).rejects.toThrow('Operation timed out');
    });
  });

  describe('RateLimiter', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('should wait minimum delay between calls', async () => {
      const limiter = new RateLimiter(100);

      // First call should be immediate
      const start1 = Date.now();
      await limiter.wait();
      const elapsed1 = Date.now() - start1;
      expect(elapsed1).toBeLessThan(10);

      // Second call should wait
      const waitPromise = limiter.wait();
      await vi.advanceTimersByTimeAsync(100);
      await waitPromise;
    });

    it('should not wait if enough time has passed', async () => {
      const limiter = new RateLimiter(100);

      await limiter.wait();

      // Advance time past the delay
      await vi.advanceTimersByTimeAsync(150);

      // Next call should be immediate
      const start = Date.now();
      await limiter.wait();
      const elapsed = Date.now() - start;
      expect(elapsed).toBeLessThan(10);
    });
  });

  describe('RATE_LIMITS', () => {
    it('should have expected rate limits configured', () => {
      expect(RATE_LIMITS.WHOIS.delayMs).toBe(1000);
      expect(RATE_LIMITS.ARCHIVE.delayMs).toBe(500);
      expect(RATE_LIMITS.MOZ.delayMs).toBe(2000);
      expect(RATE_LIMITS.SECURITY.delayMs).toBe(1000);
      expect(RATE_LIMITS.VIRUSTOTAL.delayMs).toBe(15000);
    });
  });
});
