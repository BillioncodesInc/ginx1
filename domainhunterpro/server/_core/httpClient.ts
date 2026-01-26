/**
 * Enhanced HTTP client with built-in retry, timeout, and error handling
 * Uses axios-retry for automatic retries on transient failures
 */

import axios, { AxiosInstance, AxiosError, AxiosRequestConfig } from 'axios';
import axiosRetry, { IAxiosRetryConfig, isNetworkOrIdempotentRequestError } from 'axios-retry';
import { withRateLimit } from './rateLimiter';

export interface HttpClientConfig {
  /** Base URL for all requests */
  baseURL?: string;
  /** Default timeout in ms (default: 15000) */
  timeout?: number;
  /** Maximum retries (default: 3) */
  maxRetries?: number;
  /** Base delay between retries in ms (default: 1000) */
  retryDelay?: number;
  /** Whether to use exponential backoff (default: true) */
  exponentialBackoff?: boolean;
  /** Service name for rate limiting */
  rateLimitService?: string;
  /** Custom headers */
  headers?: Record<string, string>;
}

const DEFAULT_TIMEOUT = 15000;
const DEFAULT_RETRIES = 3;
const DEFAULT_RETRY_DELAY = 1000;

/**
 * Check if an error is retryable
 */
function isRetryableError(error: AxiosError): boolean {
  // Network errors are always retryable
  if (isNetworkOrIdempotentRequestError(error)) {
    return true;
  }

  // Retry on specific status codes
  const status = error.response?.status;
  if (status) {
    // 429: Rate limited
    // 500-599: Server errors (except 501 Not Implemented)
    return status === 429 || (status >= 500 && status !== 501);
  }

  // Retry on timeout
  if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
    return true;
  }

  return false;
}

/**
 * Calculate retry delay with optional exponential backoff
 * Also handles Retry-After header for rate limiting
 */
function calculateRetryDelay(
  retryCount: number,
  error: AxiosError,
  baseDelay: number,
  exponential: boolean
): number {
  // Check for Retry-After header (rate limiting)
  const retryAfter = error.response?.headers?.['retry-after'];
  if (retryAfter) {
    const seconds = parseInt(retryAfter, 10);
    if (!isNaN(seconds)) {
      return seconds * 1000;
    }
  }

  // Exponential backoff with jitter
  if (exponential) {
    const exponentialDelay = baseDelay * Math.pow(2, retryCount - 1);
    const jitter = Math.random() * 0.3 * exponentialDelay; // 0-30% jitter
    return exponentialDelay + jitter;
  }

  return baseDelay;
}

/**
 * Create a configured axios instance with retry support
 */
export function createHttpClient(config: HttpClientConfig = {}): AxiosInstance {
  const {
    baseURL,
    timeout = DEFAULT_TIMEOUT,
    maxRetries = DEFAULT_RETRIES,
    retryDelay = DEFAULT_RETRY_DELAY,
    exponentialBackoff = true,
    headers = {},
  } = config;

  const client = axios.create({
    baseURL,
    timeout,
    headers: {
      'User-Agent': 'DomainHunterPro/1.0',
      ...headers,
    },
  });

  // Configure retry behavior
  const retryConfig: IAxiosRetryConfig = {
    retries: maxRetries,
    retryCondition: isRetryableError,
    retryDelay: (retryCount, error) =>
      calculateRetryDelay(retryCount, error, retryDelay, exponentialBackoff),
    onRetry: (retryCount, error, requestConfig) => {
      if (process.env.NODE_ENV !== 'production') {
        console.debug(
          `[HTTP] Retry ${retryCount}/${maxRetries} for ${requestConfig.url}: ${error.message}`
        );
      }
    },
  };

  axiosRetry(client, retryConfig);

  return client;
}

/**
 * Pre-configured HTTP clients for different services
 */
export const httpClients = {
  whois: createHttpClient({
    timeout: 10000,
    maxRetries: 2,
    retryDelay: 1000,
  }),

  archive: createHttpClient({
    baseURL: 'https://web.archive.org',
    timeout: 15000,
    maxRetries: 2,
    retryDelay: 500,
  }),

  moz: createHttpClient({
    baseURL: 'https://lsapi.seomoz.com/v2',
    timeout: 15000,
    maxRetries: 3,
    retryDelay: 2000,
  }),

  ahrefs: createHttpClient({
    baseURL: 'https://api.ahrefs.com/v3',
    timeout: 20000,
    maxRetries: 2,
    retryDelay: 1000,
  }),

  security: createHttpClient({
    timeout: 10000,
    maxRetries: 2,
    retryDelay: 1000,
  }),

  virustotal: createHttpClient({
    baseURL: 'https://www.virustotal.com/api/v3',
    timeout: 30000,
    maxRetries: 2,
    retryDelay: 15000,
  }),

  safebrowsing: createHttpClient({
    baseURL: 'https://safebrowsing.googleapis.com/v4',
    timeout: 10000,
    maxRetries: 3,
    retryDelay: 100,
  }),

  // Generic client for one-off requests
  generic: createHttpClient(),
};

/**
 * Make a GET request with rate limiting
 */
export async function rateLimitedGet<T>(
  service: keyof typeof httpClients,
  url: string,
  config?: AxiosRequestConfig
): Promise<T> {
  const client = httpClients[service];
  return withRateLimit(service, async () => {
    const response = await client.get<T>(url, config);
    return response.data;
  });
}

/**
 * Make a POST request with rate limiting
 */
export async function rateLimitedPost<T, D = unknown>(
  service: keyof typeof httpClients,
  url: string,
  data?: D,
  config?: AxiosRequestConfig
): Promise<T> {
  const client = httpClients[service];
  return withRateLimit(service, async () => {
    const response = await client.post<T>(url, data, config);
    return response.data;
  });
}

export type { AxiosInstance, AxiosError, AxiosRequestConfig };
