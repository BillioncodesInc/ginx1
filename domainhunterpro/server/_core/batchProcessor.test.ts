import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { processSequentially, processBatched, batchProcess, asyncMap } from './batchProcessor';

describe('Batch Processor', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('processSequentially', () => {
    it('should process items in order', async () => {
      const order: number[] = [];
      const processor = vi.fn().mockImplementation(async (item: number) => {
        order.push(item);
        return item * 2;
      });

      const resultPromise = processSequentially([1, 2, 3], processor);
      await vi.runAllTimersAsync();
      const result = await resultPromise;

      expect(order).toEqual([1, 2, 3]);
      expect(result.successful.map(r => r.result)).toEqual([2, 4, 6]);
      expect(result.failed).toHaveLength(0);
    });

    it('should handle failures with fallback', async () => {
      const processor = vi.fn()
        .mockResolvedValueOnce('success1')
        .mockRejectedValueOnce(new Error('Failed'))
        .mockResolvedValueOnce('success3');

      const resultPromise = processSequentially(
        ['a', 'b', 'c'],
        processor,
        { fallbackValue: (item) => `fallback-${item}`, maxRetries: 0 }
      );

      await vi.runAllTimersAsync();
      const result = await resultPromise;

      expect(result.successful.map(r => r.result)).toEqual([
        'success1',
        'fallback-b',
        'success3',
      ]);
    });

    it('should call onProgress callback', async () => {
      const onProgress = vi.fn();
      const processor = vi.fn().mockResolvedValue('result');

      const resultPromise = processSequentially(
        [1, 2, 3],
        processor,
        { onProgress }
      );

      await vi.runAllTimersAsync();
      await resultPromise;

      expect(onProgress).toHaveBeenCalledTimes(3);
      expect(onProgress).toHaveBeenNthCalledWith(1, 1, 3, 1);
      expect(onProgress).toHaveBeenNthCalledWith(2, 2, 3, 2);
      expect(onProgress).toHaveBeenNthCalledWith(3, 3, 3, 3);
    });

    it('should stop on error when stopOnError is true', async () => {
      const processor = vi.fn()
        .mockResolvedValueOnce('success1')
        .mockRejectedValueOnce(new Error('Stop here'))
        .mockResolvedValueOnce('success3');

      const resultPromise = processSequentially(
        ['a', 'b', 'c'],
        processor,
        { stopOnError: true, maxRetries: 0 }
      );

      await vi.runAllTimersAsync();
      const result = await resultPromise;

      expect(result.successful).toHaveLength(1);
      expect(result.failed).toHaveLength(1);
      expect(processor).toHaveBeenCalledTimes(2); // Stopped after failure
    });
  });

  describe('processBatched', () => {
    it('should process items in batches', async () => {
      const processor = vi.fn().mockImplementation(async (item: number) => item * 2);

      const resultPromise = processBatched(
        [1, 2, 3, 4, 5],
        processor,
        { batchSize: 2 }
      );

      await vi.runAllTimersAsync();
      const result = await resultPromise;

      expect(result.successful.map(r => r.result)).toEqual([2, 4, 6, 8, 10]);
      expect(result.total).toBe(5);
    });

    it('should handle failures within batches', async () => {
      let callCount = 0;
      const processor = vi.fn().mockImplementation(async (item: number) => {
        callCount++;
        if (item === 2) throw new Error('Failed');
        return item * 2;
      });

      const resultPromise = processBatched(
        [1, 2, 3],
        processor,
        { batchSize: 2, fallbackValue: () => -1, maxRetries: 0 }
      );

      await vi.runAllTimersAsync();
      const result = await resultPromise;

      expect(result.successful.map(r => r.result)).toContain(2);
      expect(result.successful.map(r => r.result)).toContain(-1); // Fallback for item 2
      expect(result.successful.map(r => r.result)).toContain(6);
    });
  });

  describe('batchProcess', () => {
    it('should return simple results array', async () => {
      const processor = vi.fn().mockImplementation(async (item: string) => `processed-${item}`);

      const resultPromise = batchProcess(
        ['a', 'b', 'c'],
        processor,
        { delayMs: 0 }
      );

      await vi.runAllTimersAsync();
      const results = await resultPromise;

      expect(results).toEqual(['processed-a', 'processed-b', 'processed-c']);
    });

    it('should use fallback value on failure', async () => {
      const processor = vi.fn()
        .mockResolvedValueOnce('success')
        .mockRejectedValueOnce(new Error('Error'))
        .mockResolvedValueOnce('success');

      const resultPromise = batchProcess(
        ['a', 'b', 'c'],
        processor,
        { delayMs: 0, fallbackValue: () => 'fallback' }
      );

      await vi.runAllTimersAsync();
      const results = await resultPromise;

      expect(results).toEqual(['success', 'fallback', 'success']);
    });
  });

  describe('asyncMap', () => {
    it('should map items with async processor', async () => {
      const processor = vi.fn().mockImplementation(async (item: number, index: number) => {
        return item * 2 + index;
      });

      const results = await asyncMap([10, 20, 30], processor);

      expect(results).toEqual([20, 41, 62]); // 10*2+0, 20*2+1, 30*2+2
    });

    it('should process in parallel when no concurrency limit', async () => {
      const startTimes: number[] = [];
      const processor = vi.fn().mockImplementation(async () => {
        startTimes.push(Date.now());
        await new Promise(resolve => setTimeout(resolve, 100));
        return 'done';
      });

      vi.useRealTimers(); // Need real timers for this test
      const results = await asyncMap([1, 2, 3], processor);

      expect(results).toHaveLength(3);
      // All should start at roughly the same time (parallel)
      const timeDiff = Math.max(...startTimes) - Math.min(...startTimes);
      expect(timeDiff).toBeLessThan(50); // Should be nearly simultaneous
    });

    it('should handle empty array', async () => {
      const processor = vi.fn();
      const results = await asyncMap([], processor);

      expect(results).toEqual([]);
      expect(processor).not.toHaveBeenCalled();
    });
  });
});
