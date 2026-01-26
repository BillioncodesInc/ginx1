/**
 * Generic batch processor utility
 * Reduces duplicate batch processing logic across scrapers
 */

import { sleep } from './utils';
import { withRetry, RetryOptions } from './retry';

export interface BatchProcessorOptions<T, R> extends RetryOptions {
  /** Delay between processing each item in milliseconds */
  delayBetween?: number;
  /** Maximum concurrent operations (default: 1 for sequential) */
  concurrency?: number;
  /** Batch size for parallel processing */
  batchSize?: number;
  /** Fallback value generator for failed items */
  fallbackValue?: (item: T, error: unknown) => R;
  /** Progress callback */
  onProgress?: (processed: number, total: number, item: T) => void;
  /** Stop processing on first error (default: false) */
  stopOnError?: boolean;
}

export interface BatchResult<T, R> {
  successful: { item: T; result: R }[];
  failed: { item: T; error: unknown }[];
  total: number;
}

/**
 * Process items sequentially with rate limiting and retry
 * This is the default mode for most API calls to respect rate limits
 */
export async function processSequentially<T, R>(
  items: T[],
  processor: (item: T) => Promise<R>,
  options: BatchProcessorOptions<T, R> = {}
): Promise<BatchResult<T, R>> {
  const {
    delayBetween = 0,
    fallbackValue,
    onProgress,
    stopOnError = false,
    ...retryOptions
  } = options;

  const successful: { item: T; result: R }[] = [];
  const failed: { item: T; error: unknown }[] = [];

  for (let i = 0; i < items.length; i++) {
    const item = items[i];

    try {
      const result = await withRetry(() => processor(item), retryOptions);
      successful.push({ item, result });
    } catch (error) {
      if (fallbackValue) {
        const fallback = fallbackValue(item, error);
        successful.push({ item, result: fallback });
      } else {
        failed.push({ item, error });
        if (stopOnError) {
          break;
        }
      }
    }

    if (onProgress) {
      onProgress(i + 1, items.length, item);
    }

    // Add delay between items (skip after last item)
    if (delayBetween > 0 && i < items.length - 1) {
      await sleep(delayBetween);
    }
  }

  return {
    successful,
    failed,
    total: items.length,
  };
}

/**
 * Process items in batches with concurrency
 * Each batch runs in parallel, batches run sequentially
 */
export async function processBatched<T, R>(
  items: T[],
  processor: (item: T) => Promise<R>,
  options: BatchProcessorOptions<T, R> = {}
): Promise<BatchResult<T, R>> {
  const {
    batchSize = 5,
    delayBetween = 0,
    fallbackValue,
    onProgress,
    ...retryOptions
  } = options;

  const successful: { item: T; result: R }[] = [];
  const failed: { item: T; error: unknown }[] = [];
  let processed = 0;

  // Split into batches
  const batches: T[][] = [];
  for (let i = 0; i < items.length; i += batchSize) {
    batches.push(items.slice(i, i + batchSize));
  }

  for (const batch of batches) {
    // Process batch in parallel
    const results = await Promise.allSettled(
      batch.map((item) =>
        withRetry(() => processor(item), retryOptions)
          .then((result) => ({ item, result, success: true as const }))
          .catch((error) => ({ item, error, success: false as const }))
      )
    );

    // Collect results
    for (const result of results) {
      if (result.status === 'fulfilled') {
        const { item, success } = result.value;
        if (success) {
          successful.push({ item, result: (result.value as any).result });
        } else {
          const error = (result.value as any).error;
          if (fallbackValue) {
            successful.push({ item, result: fallbackValue(item, error) });
          } else {
            failed.push({ item, error });
          }
        }
      }

      processed++;
      if (onProgress) {
        onProgress(processed, items.length, batch[0]);
      }
    }

    // Delay between batches
    if (delayBetween > 0 && batches.indexOf(batch) < batches.length - 1) {
      await sleep(delayBetween);
    }
  }

  return {
    successful,
    failed,
    total: items.length,
  };
}

/**
 * Process items with a simple results array (backward compatible)
 * Returns just the results array, using fallback for failed items
 */
export async function batchProcess<T, R>(
  items: T[],
  processor: (item: T) => Promise<R>,
  options: {
    delayMs?: number;
    fallbackValue?: (item: T) => R;
    label?: string;
  } = {}
): Promise<R[]> {
  const { delayMs = 1000, fallbackValue, label = 'Batch' } = options;

  const result = await processSequentially(items, processor, {
    delayBetween: delayMs,
    fallbackValue: fallbackValue
      ? (item, _error) => fallbackValue(item)
      : undefined,
    label,
    maxRetries: 2,
  });

  return result.successful.map((r) => r.result);
}

/**
 * Map over items with async processor and optional concurrency
 */
export async function asyncMap<T, R>(
  items: T[],
  processor: (item: T, index: number) => Promise<R>,
  options: { concurrency?: number } = {}
): Promise<R[]> {
  const { concurrency = Infinity } = options;

  if (concurrency === Infinity) {
    return Promise.all(items.map(processor));
  }

  const results: R[] = [];
  const executing: Promise<void>[] = [];

  for (let i = 0; i < items.length; i++) {
    const promise = processor(items[i], i).then((result) => {
      results[i] = result;
    });

    executing.push(promise as Promise<void>);

    if (executing.length >= concurrency) {
      await Promise.race(executing);
      // Remove completed promises
      executing.splice(
        executing.findIndex((p) => p === promise),
        1
      );
    }
  }

  await Promise.all(executing);
  return results;
}
