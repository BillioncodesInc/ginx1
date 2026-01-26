/**
 * Retry utility with exponential backoff for error recovery
 * Provides robust handling of transient failures in API calls
 */

import { sleep } from './utils';

export interface RetryOptions {
  /** Maximum number of retry attempts (default: 3) */
  maxRetries?: number;
  /** Initial delay in milliseconds (default: 1000) */
  initialDelay?: number;
  /** Maximum delay in milliseconds (default: 30000) */
  maxDelay?: number;
  /** Multiplier for exponential backoff (default: 2) */
  backoffMultiplier?: number;
  /** Whether to add jitter to delays (default: true) */
  jitter?: boolean;
  /** Custom function to determine if error is retryable */
  isRetryable?: (error: unknown) => boolean;
  /** Callback for each retry attempt */
  onRetry?: (error: unknown, attempt: number, delay: number) => void;
  /** Label for logging purposes */
  label?: string;
}

const DEFAULT_OPTIONS: Required<Omit<RetryOptions, 'onRetry' | 'isRetryable' | 'label'>> = {
  maxRetries: 3,
  initialDelay: 1000,
  maxDelay: 30000,
  backoffMultiplier: 2,
  jitter: true,
};

/**
 * Default function to determine if an error is retryable
 * Retries on network errors, timeouts, and 5xx server errors
 */
function defaultIsRetryable(error: unknown): boolean {
  if (!error) return false;

  const err = error as any;

  // Network errors
  if (err.code === 'ECONNRESET' || err.code === 'ETIMEDOUT' || err.code === 'ENOTFOUND') {
    return true;
  }

  // Axios/fetch errors with status codes
  const status = err.response?.status || err.status;
  if (status) {
    // Retry on 429 (rate limit) and 5xx server errors
    return status === 429 || (status >= 500 && status < 600);
  }

  // Timeout errors
  if (err.message?.includes('timeout') || err.message?.includes('ETIMEDOUT')) {
    return true;
  }

  // Rate limit messages
  if (err.message?.toLowerCase().includes('rate limit')) {
    return true;
  }

  return false;
}

/**
 * Calculate delay for a given retry attempt with optional jitter
 */
function calculateDelay(
  attempt: number,
  initialDelay: number,
  maxDelay: number,
  multiplier: number,
  jitter: boolean
): number {
  // Exponential backoff: initialDelay * (multiplier ^ attempt)
  let delay = initialDelay * Math.pow(multiplier, attempt);

  // Cap at maxDelay
  delay = Math.min(delay, maxDelay);

  // Add jitter (±25% random variation)
  if (jitter) {
    const jitterRange = delay * 0.25;
    delay = delay + (Math.random() * 2 - 1) * jitterRange;
  }

  return Math.round(delay);
}

/**
 * Execute a function with automatic retry on failure
 *
 * @example
 * ```typescript
 * const result = await withRetry(
 *   () => fetchDataFromApi(url),
 *   { maxRetries: 3, label: 'API fetch' }
 * );
 * ```
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const {
    maxRetries = DEFAULT_OPTIONS.maxRetries,
    initialDelay = DEFAULT_OPTIONS.initialDelay,
    maxDelay = DEFAULT_OPTIONS.maxDelay,
    backoffMultiplier = DEFAULT_OPTIONS.backoffMultiplier,
    jitter = DEFAULT_OPTIONS.jitter,
    isRetryable = defaultIsRetryable,
    onRetry,
    label = 'Operation',
  } = options;

  let lastError: unknown;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;

      // Check if we've exhausted retries
      if (attempt >= maxRetries) {
        break;
      }

      // Check if error is retryable
      if (!isRetryable(error)) {
        break;
      }

      // Calculate delay for this retry
      const delay = calculateDelay(attempt, initialDelay, maxDelay, backoffMultiplier, jitter);

      // Log retry attempt
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.warn(`[${label}] Attempt ${attempt + 1}/${maxRetries + 1} failed: ${errorMessage}. Retrying in ${delay}ms...`);

      // Callback if provided
      if (onRetry) {
        onRetry(error, attempt + 1, delay);
      }

      // Wait before retrying
      await sleep(delay);
    }
  }

  // All retries exhausted, throw the last error
  throw lastError;
}

/**
 * Create a retryable version of an async function
 *
 * @example
 * ```typescript
 * const retryableFetch = createRetryable(fetchData, { maxRetries: 3 });
 * const result = await retryableFetch(url, options);
 * ```
 */
export function createRetryable<TArgs extends unknown[], TResult>(
  fn: (...args: TArgs) => Promise<TResult>,
  options: RetryOptions = {}
): (...args: TArgs) => Promise<TResult> {
  return (...args: TArgs) => withRetry(() => fn(...args), options);
}

/**
 * Execute multiple async operations with retry, returning results for successful operations
 * Failed operations return undefined (or a fallback value)
 */
export async function withRetryBatch<T, R>(
  items: T[],
  processor: (item: T) => Promise<R>,
  options: RetryOptions & { fallback?: R } = {}
): Promise<(R | undefined)[]> {
  const { fallback, ...retryOptions } = options;

  return Promise.all(
    items.map(async (item) => {
      try {
        return await withRetry(() => processor(item), retryOptions);
      } catch (error) {
        const label = retryOptions.label || 'Batch item';
        console.error(`[${label}] Failed after all retries:`, error);
        return fallback;
      }
    })
  );
}

/**
 * Execute operations sequentially with retry and rate limiting
 */
export async function withRetrySequential<T, R>(
  items: T[],
  processor: (item: T) => Promise<R>,
  options: RetryOptions & { delayBetween?: number; fallback?: R } = {}
): Promise<(R | undefined)[]> {
  const { delayBetween = 0, fallback, ...retryOptions } = options;
  const results: (R | undefined)[] = [];

  for (const item of items) {
    try {
      const result = await withRetry(() => processor(item), retryOptions);
      results.push(result);
    } catch (error) {
      const label = retryOptions.label || 'Sequential item';
      console.error(`[${label}] Failed after all retries:`, error);
      results.push(fallback);
    }

    if (delayBetween > 0 && items.indexOf(item) < items.length - 1) {
      await sleep(delayBetween);
    }
  }

  return results;
}

export { defaultIsRetryable };
