/**
 * Unified API call wrapper with consistent error handling
 * Reduces code duplication across scrapers
 */

import axios, { AxiosRequestConfig, AxiosError } from 'axios';
import { withRetry, RetryOptions } from './retry';

export interface ApiCallOptions extends RetryOptions {
  /** Request timeout in milliseconds (default: 15000) */
  timeout?: number;
  /** Custom headers */
  headers?: Record<string, string>;
  /** Whether to throw on non-2xx status codes (default: true) */
  throwOnError?: boolean;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  status?: number;
}

const DEFAULT_TIMEOUT = 15000;

/**
 * Log levels for structured logging
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LOG_LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

/**
 * Get current log level from environment
 */
function getCurrentLogLevel(): LogLevel {
  const envLevel = process.env.LOG_LEVEL?.toLowerCase();
  if (envLevel && envLevel in LOG_LEVEL_PRIORITY) {
    return envLevel as LogLevel;
  }
  return process.env.NODE_ENV === 'production' ? 'info' : 'debug';
}

/**
 * Check if JSON logging is enabled
 */
function isJsonLogging(): boolean {
  return process.env.LOG_FORMAT === 'json';
}

/**
 * Format a log entry
 */
function formatLog(
  level: LogLevel,
  module: string,
  message: string,
  data?: Record<string, unknown>
): string {
  const timestamp = new Date().toISOString();

  if (isJsonLogging()) {
    return JSON.stringify({
      timestamp,
      level,
      module,
      message,
      ...data,
    });
  }

  const prefix = `[${timestamp}] [${level.toUpperCase()}] [${module}]`;
  const dataStr = data && Object.keys(data).length > 0
    ? ` ${JSON.stringify(data)}`
    : '';
  return `${prefix} ${message}${dataStr}`;
}

/**
 * Check if a log should be output based on current level
 */
function shouldLog(level: LogLevel): boolean {
  const currentLevel = getCurrentLogLevel();
  return LOG_LEVEL_PRIORITY[level] >= LOG_LEVEL_PRIORITY[currentLevel];
}

export interface Logger {
  debug: (msg: string, data?: Record<string, unknown>) => void;
  info: (msg: string, data?: Record<string, unknown>) => void;
  warn: (msg: string, data?: Record<string, unknown>) => void;
  error: (msg: string, error?: unknown, data?: Record<string, unknown>) => void;
}

/**
 * Create a structured logger for a specific module
 * Supports:
 * - Log levels (debug, info, warn, error) controlled by LOG_LEVEL env var
 * - JSON output format via LOG_FORMAT=json env var
 * - Timestamps and module prefixes
 * - Error stack trace extraction
 */
export function createLogger(module: string): Logger {
  return {
    debug: (msg: string, data?: Record<string, unknown>) => {
      if (shouldLog('debug')) {
        console.log(formatLog('debug', module, msg, data));
      }
    },
    info: (msg: string, data?: Record<string, unknown>) => {
      if (shouldLog('info')) {
        console.log(formatLog('info', module, msg, data));
      }
    },
    warn: (msg: string, data?: Record<string, unknown>) => {
      if (shouldLog('warn')) {
        console.warn(formatLog('warn', module, msg, data));
      }
    },
    error: (msg: string, error?: unknown, data?: Record<string, unknown>) => {
      if (shouldLog('error')) {
        const errorData: Record<string, unknown> = { ...data };
        if (error instanceof Error) {
          errorData.error = error.message;
          if (process.env.NODE_ENV !== 'production') {
            errorData.stack = error.stack;
          }
        } else if (error) {
          errorData.error = String(error);
        }
        console.error(formatLog('error', module, msg, errorData));
      }
    },
  };
}

/**
 * Safe GET request with retry and error handling
 */
export async function safeGet<T>(
  url: string,
  options: ApiCallOptions = {}
): Promise<ApiResponse<T>> {
  const { timeout = DEFAULT_TIMEOUT, headers, throwOnError = false, ...retryOptions } = options;

  try {
    const response = await withRetry(
      async () => {
        const res = await axios.get<T>(url, {
          timeout,
          headers,
        });
        return res;
      },
      { label: 'GET request', ...retryOptions }
    );

    return {
      success: true,
      data: response.data,
      status: response.status,
    };
  } catch (error) {
    const axiosError = error as AxiosError;
    const errorMsg = axiosError.message || 'Unknown error';
    const status = axiosError.response?.status;

    if (throwOnError) {
      throw error;
    }

    return {
      success: false,
      error: errorMsg,
      status,
    };
  }
}

/**
 * Safe POST request with retry and error handling
 */
export async function safePost<T, D = unknown>(
  url: string,
  data?: D,
  options: ApiCallOptions = {}
): Promise<ApiResponse<T>> {
  const { timeout = DEFAULT_TIMEOUT, headers, throwOnError = false, ...retryOptions } = options;

  try {
    const response = await withRetry(
      async () => {
        const res = await axios.post<T>(url, data, {
          timeout,
          headers: {
            'Content-Type': 'application/json',
            ...headers,
          },
        });
        return res;
      },
      { label: 'POST request', ...retryOptions }
    );

    return {
      success: true,
      data: response.data,
      status: response.status,
    };
  } catch (error) {
    const axiosError = error as AxiosError;
    const errorMsg = axiosError.message || 'Unknown error';
    const status = axiosError.response?.status;

    if (throwOnError) {
      throw error;
    }

    return {
      success: false,
      error: errorMsg,
      status,
    };
  }
}

/**
 * Safe API call that returns a fallback value on error
 * Useful for non-critical API calls where a default is acceptable
 */
export async function safeApiCall<T>(
  apiCall: () => Promise<T>,
  fallback: T,
  options: { label?: string; logError?: boolean } = {}
): Promise<T> {
  const { label = 'API', logError = true } = options;

  try {
    return await apiCall();
  } catch (error) {
    if (logError) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      console.error(`[${label}] Error: ${errorMsg}`);
    }
    return fallback;
  }
}

/**
 * Execute API call with timeout
 */
export async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  timeoutMessage: string = 'Operation timed out'
): Promise<T> {
  let timeoutId: NodeJS.Timeout;

  const timeoutPromise = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
  });

  try {
    const result = await Promise.race([promise, timeoutPromise]);
    clearTimeout(timeoutId!);
    return result;
  } catch (error) {
    clearTimeout(timeoutId!);
    throw error;
  }
}

/**
 * Rate limit configuration for different services
 */
export const RATE_LIMITS = {
  WHOIS: { delayMs: 1000, maxPerMinute: 30 },
  ARCHIVE: { delayMs: 500, maxPerMinute: 60 },
  MOZ: { delayMs: 2000, maxPerMinute: 25 },
  SECURITY: { delayMs: 1000, maxPerMinute: 30 },
  GOOGLE_SAFE_BROWSING: { delayMs: 100, maxPerMinute: 300 },
  VIRUSTOTAL: { delayMs: 15000, maxPerMinute: 4 }, // Free tier is very limited
} as const;

/**
 * Simple rate limiter class
 */
export class RateLimiter {
  private lastCall: number = 0;
  private readonly minDelay: number;

  constructor(minDelayMs: number) {
    this.minDelay = minDelayMs;
  }

  async wait(): Promise<void> {
    const now = Date.now();
    const elapsed = now - this.lastCall;

    if (elapsed < this.minDelay) {
      await new Promise(resolve => setTimeout(resolve, this.minDelay - elapsed));
    }

    this.lastCall = Date.now();
  }
}
