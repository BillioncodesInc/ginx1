/**
 * Enhanced rate limiting using Bottleneck
 * Provides sophisticated rate limiting with reservoir, clustering, and backpressure
 */

import Bottleneck from 'bottleneck';

export interface RateLimiterConfig {
  /** Maximum concurrent requests */
  maxConcurrent?: number;
  /** Minimum time between requests in ms */
  minTime?: number;
  /** Maximum requests per interval */
  reservoir?: number;
  /** Interval for reservoir refill in ms */
  reservoirRefreshInterval?: number;
  /** Amount to refill reservoir by */
  reservoirRefreshAmount?: number;
  /** Timeout for each job in ms */
  highWater?: number;
  /** Strategy when highWater is reached */
  strategy?: Bottleneck.Strategy;
}

// Pre-configured rate limiters for different services
const SERVICE_CONFIGS: Record<string, RateLimiterConfig> = {
  whois: {
    maxConcurrent: 1,
    minTime: 1000,
    reservoir: 30,
    reservoirRefreshInterval: 60000,
    reservoirRefreshAmount: 30,
  },
  archive: {
    maxConcurrent: 2,
    minTime: 500,
    reservoir: 60,
    reservoirRefreshInterval: 60000,
    reservoirRefreshAmount: 60,
  },
  moz: {
    maxConcurrent: 1,
    minTime: 2000,
    reservoir: 25,
    reservoirRefreshInterval: 60000,
    reservoirRefreshAmount: 25,
  },
  ahrefs: {
    maxConcurrent: 1,
    minTime: 1000,
    reservoir: 30,
    reservoirRefreshInterval: 60000,
    reservoirRefreshAmount: 30,
  },
  security: {
    maxConcurrent: 2,
    minTime: 1000,
    reservoir: 30,
    reservoirRefreshInterval: 60000,
    reservoirRefreshAmount: 30,
  },
  virustotal: {
    maxConcurrent: 1,
    minTime: 15000,
    reservoir: 4,
    reservoirRefreshInterval: 60000,
    reservoirRefreshAmount: 4,
  },
  safebrowsing: {
    maxConcurrent: 5,
    minTime: 100,
    reservoir: 300,
    reservoirRefreshInterval: 60000,
    reservoirRefreshAmount: 300,
  },
  // Generic default
  default: {
    maxConcurrent: 3,
    minTime: 500,
  },
};

// Cache of created limiters
const limiters = new Map<string, Bottleneck>();

/**
 * Get or create a rate limiter for a service
 */
export function getRateLimiter(service: string): Bottleneck {
  const key = service.toLowerCase();

  if (limiters.has(key)) {
    return limiters.get(key)!;
  }

  const config = SERVICE_CONFIGS[key] || SERVICE_CONFIGS.default;
  const limiter = new Bottleneck(config);

  // Add error handling
  limiter.on('error', (error) => {
    console.error(`[RateLimiter:${service}] Error:`, error);
  });

  // Add debug logging in development
  if (process.env.NODE_ENV !== 'production') {
    limiter.on('depleted', () => {
      console.debug(`[RateLimiter:${service}] Reservoir depleted, waiting for refill`);
    });
  }

  limiters.set(key, limiter);
  return limiter;
}

/**
 * Create a custom rate limiter with specific configuration
 */
export function createRateLimiter(name: string, config: RateLimiterConfig): Bottleneck {
  const limiter = new Bottleneck(config);
  limiters.set(name.toLowerCase(), limiter);
  return limiter;
}

/**
 * Execute a function with rate limiting
 */
export async function withRateLimit<T>(
  service: string,
  fn: () => Promise<T>,
  options?: { priority?: number; weight?: number }
): Promise<T> {
  const limiter = getRateLimiter(service);
  return limiter.schedule(options || {}, fn);
}

/**
 * Batch process items with rate limiting
 */
export async function batchWithRateLimit<T, R>(
  service: string,
  items: T[],
  processor: (item: T) => Promise<R>,
  options?: {
    priority?: number;
    weight?: number;
    onProgress?: (completed: number, total: number) => void;
  }
): Promise<R[]> {
  const limiter = getRateLimiter(service);
  let completed = 0;

  const promises = items.map((item) =>
    limiter.schedule(
      { priority: options?.priority, weight: options?.weight },
      async () => {
        const result = await processor(item);
        completed++;
        options?.onProgress?.(completed, items.length);
        return result;
      }
    )
  );

  return Promise.all(promises);
}

/**
 * Get current status of a rate limiter
 */
export function getRateLimiterStatus(service: string): {
  running: number;
  queued: number;
  reservoir: number | null;
} {
  const limiter = getRateLimiter(service);
  const counts = limiter.counts();

  return {
    running: counts.RUNNING,
    queued: counts.QUEUED,
    reservoir: (limiter as any).reservoir?.() ?? null,
  };
}

/**
 * Stop all rate limiters (for graceful shutdown)
 */
export async function stopAllRateLimiters(): Promise<void> {
  const stopPromises: Promise<void>[] = [];
  limiters.forEach((limiter) => {
    stopPromises.push(limiter.stop({ dropWaitingJobs: false }));
  });
  await Promise.all(stopPromises);
  limiters.clear();
}

/**
 * Disconnect and clear all rate limiters
 */
export function disconnectAllRateLimiters(): void {
  limiters.forEach((limiter) => {
    limiter.disconnect();
  });
  limiters.clear();
}
