import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { withRetry, createRetryable, withRetryBatch, withRetrySequential } from './retry';

describe('Retry Utilities', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('withRetry', () => {
    it('should return result on first successful attempt', async () => {
      const fn = vi.fn().mockResolvedValue('success');

      const resultPromise = withRetry(fn, { maxRetries: 3 });
      await vi.runAllTimersAsync();
      const result = await resultPromise;

      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('should retry on failure and succeed', async () => {
      const fn = vi.fn()
        .mockRejectedValueOnce(new Error('Network error'))
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValue('success');

      const resultPromise = withRetry(fn, {
        maxRetries: 3,
        initialDelay: 100,
        jitter: false,
        isRetryable: () => true,
      });

      // Advance through retries
      await vi.runAllTimersAsync();
      const result = await resultPromise;

      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(3);
    });

    it('should throw after max retries exhausted', async () => {
      const fn = vi.fn().mockRejectedValue(new Error('Persistent error'));

      const resultPromise = withRetry(fn, {
        maxRetries: 2,
        initialDelay: 100,
        jitter: false,
        isRetryable: () => true,
      });

      await vi.runAllTimersAsync();

      await expect(resultPromise).rejects.toThrow('Persistent error');
      expect(fn).toHaveBeenCalledTimes(3); // Initial + 2 retries
    });

    it('should not retry non-retryable errors', async () => {
      const fn = vi.fn().mockRejectedValue(new Error('Fatal error'));

      const resultPromise = withRetry(fn, {
        maxRetries: 3,
        isRetryable: () => false,
      });

      await expect(resultPromise).rejects.toThrow('Fatal error');
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('should call onRetry callback for each retry', async () => {
      const onRetry = vi.fn();
      const fn = vi.fn()
        .mockRejectedValueOnce(new Error('Error 1'))
        .mockRejectedValueOnce(new Error('Error 2'))
        .mockResolvedValue('success');

      const resultPromise = withRetry(fn, {
        maxRetries: 3,
        initialDelay: 100,
        jitter: false,
        isRetryable: () => true,
        onRetry,
      });

      await vi.runAllTimersAsync();
      await resultPromise;

      expect(onRetry).toHaveBeenCalledTimes(2);
      expect(onRetry).toHaveBeenNthCalledWith(1, expect.any(Error), 1, expect.any(Number));
      expect(onRetry).toHaveBeenNthCalledWith(2, expect.any(Error), 2, expect.any(Number));
    });

    it('should apply exponential backoff', async () => {
      const fn = vi.fn()
        .mockRejectedValueOnce(new Error('Error'))
        .mockRejectedValueOnce(new Error('Error'))
        .mockResolvedValue('success');

      const resultPromise = withRetry(fn, {
        maxRetries: 3,
        initialDelay: 100,
        backoffMultiplier: 2,
        jitter: false,
        isRetryable: () => true,
      });

      // First attempt fails immediately
      await vi.advanceTimersByTimeAsync(0);
      expect(fn).toHaveBeenCalledTimes(1);

      // After 100ms (first retry)
      await vi.advanceTimersByTimeAsync(100);
      expect(fn).toHaveBeenCalledTimes(2);

      // After 200ms more (second retry, 100 * 2^1)
      await vi.advanceTimersByTimeAsync(200);
      expect(fn).toHaveBeenCalledTimes(3);

      await resultPromise;
    });
  });

  describe('createRetryable', () => {
    it('should create a retryable function', async () => {
      const originalFn = vi.fn().mockResolvedValue('result');
      const retryableFn = createRetryable(originalFn, { maxRetries: 2 });

      const resultPromise = retryableFn('arg1', 'arg2');
      await vi.runAllTimersAsync();
      const result = await resultPromise;

      expect(result).toBe('result');
      expect(originalFn).toHaveBeenCalledWith('arg1', 'arg2');
    });
  });

  describe('withRetryBatch', () => {
    it('should process all items successfully', async () => {
      const processor = vi.fn().mockImplementation((item: string) =>
        Promise.resolve(`result-${item}`)
      );

      const resultPromise = withRetryBatch(
        ['a', 'b', 'c'],
        processor,
        { maxRetries: 1 }
      );

      await vi.runAllTimersAsync();
      const results = await resultPromise;

      expect(results).toHaveLength(3);
      expect(results).toEqual(['result-a', 'result-b', 'result-c']);
    });

    it('should use fallback for failed items', async () => {
      const processor = vi.fn().mockImplementation((item: string) => {
        if (item === 'fail') {
          return Promise.reject(new Error('Failed'));
        }
        return Promise.resolve(`result-${item}`);
      });

      const resultPromise = withRetryBatch(
        ['a', 'fail', 'c'],
        processor,
        { maxRetries: 0, fallback: 'fallback', isRetryable: () => false }
      );

      await vi.runAllTimersAsync();
      const results = await resultPromise;

      expect(results).toHaveLength(3);
      expect(results[0]).toBe('result-a');
      expect(results[1]).toBe('fallback');
      expect(results[2]).toBe('result-c');
    });
  });

  describe('withRetrySequential', () => {
    it('should process items sequentially', async () => {
      const callOrder: string[] = [];
      const processor = vi.fn().mockImplementation(async (item: string) => {
        callOrder.push(item);
        return `result-${item}`;
      });

      const resultPromise = withRetrySequential(
        ['a', 'b', 'c'],
        processor,
        { delayBetween: 50 }
      );

      await vi.runAllTimersAsync();
      const results = await resultPromise;

      expect(callOrder).toEqual(['a', 'b', 'c']);
      expect(results).toEqual(['result-a', 'result-b', 'result-c']);
    });

    it('should use fallback for failed items', async () => {
      const processor = vi.fn()
        .mockResolvedValueOnce('success')
        .mockRejectedValueOnce(new Error('Error'))
        .mockResolvedValueOnce('success2');

      const resultPromise = withRetrySequential(
        ['item1', 'item2', 'item3'],
        processor,
        { maxRetries: 0, fallback: 'fallback', isRetryable: () => false }
      );

      await vi.runAllTimersAsync();
      const results = await resultPromise;

      expect(results).toEqual(['success', 'fallback', 'success2']);
    });
  });
});
