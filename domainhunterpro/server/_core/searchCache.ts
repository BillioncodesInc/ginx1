/**
 * In-memory cache for search results
 * Avoids re-scraping identical queries within TTL window
 */

import type { EnrichedDomainResult } from "../scrapers/expiredDomainsScraper";

interface CachedSearch {
  keyword: string;
  maxPages: number;
  results: EnrichedDomainResult[];
  timestamp: number;
  expiresAt: number;
}

// Cache storage
const searchCache = new Map<string, CachedSearch>();

// Cache configuration
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const MAX_CACHE_SIZE = 100; // Maximum number of cached searches

/**
 * Generate cache key from search parameters
 */
function getCacheKey(keyword: string, maxPages: number): string {
  return `${keyword.toLowerCase()}:${maxPages}`;
}

/**
 * Get cached search results if available and not expired
 */
export function getCachedSearch(keyword: string, maxPages: number): EnrichedDomainResult[] | null {
  const key = getCacheKey(keyword, maxPages);
  const cached = searchCache.get(key);

  if (!cached) {
    return null;
  }

  // Check if expired
  if (Date.now() > cached.expiresAt) {
    searchCache.delete(key);
    return null;
  }

  return cached.results;
}

/**
 * Store search results in cache
 */
export function setCachedSearch(keyword: string, maxPages: number, results: EnrichedDomainResult[]): void {
  const key = getCacheKey(keyword, maxPages);
  const now = Date.now();

  // Enforce max cache size (LRU-style: remove oldest entries)
  if (searchCache.size >= MAX_CACHE_SIZE) {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;

    searchCache.forEach((v, k) => {
      if (v.timestamp < oldestTime) {
        oldestTime = v.timestamp;
        oldestKey = k;
      }
    });

    if (oldestKey) {
      searchCache.delete(oldestKey);
    }
  }

  searchCache.set(key, {
    keyword: keyword.toLowerCase(),
    maxPages,
    results,
    timestamp: now,
    expiresAt: now + CACHE_TTL_MS,
  });
}

/**
 * Clear all expired entries from cache
 */
export function clearExpiredCache(): void {
  const now = Date.now();
  const keysToDelete: string[] = [];

  searchCache.forEach((cached, key) => {
    if (now > cached.expiresAt) {
      keysToDelete.push(key);
    }
  });

  keysToDelete.forEach(key => searchCache.delete(key));
}

/**
 * Clear entire cache
 */
export function clearAllCache(): void {
  searchCache.clear();
}

/**
 * Get cache statistics
 */
export function getCacheStats(): { size: number; keys: string[] } {
  return {
    size: searchCache.size,
    keys: Array.from(searchCache.keys()),
  };
}

/**
 * Check if a search is cached (without returning results)
 */
export function isCached(keyword: string, maxPages: number): boolean {
  return getCachedSearch(keyword, maxPages) !== null;
}
