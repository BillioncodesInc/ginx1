/**
 * Production-grade logging using Pino
 * Provides structured logging with log levels, formatting, and transports
 */

import pino, { Logger as PinoLogger, LoggerOptions } from 'pino';

// Determine environment
const isDevelopment = process.env.NODE_ENV !== 'production';
const logLevel = process.env.LOG_LEVEL || (isDevelopment ? 'debug' : 'info');

// Pino configuration
const pinoOptions: LoggerOptions = {
  level: logLevel,
  // Use pretty printing in development
  transport: isDevelopment
    ? {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:standard',
          ignore: 'pid,hostname',
        },
      }
    : undefined,
  // JSON format in production (default behavior)
  formatters: {
    level: (label) => ({ level: label }),
  },
  // Add timestamp
  timestamp: pino.stdTimeFunctions.isoTime,
  // Base properties for all logs
  base: {
    env: process.env.NODE_ENV || 'development',
  },
};

// Create root logger
const rootLogger = pino(pinoOptions);

export interface ModuleLogger {
  debug: (msg: string, data?: Record<string, unknown>) => void;
  info: (msg: string, data?: Record<string, unknown>) => void;
  warn: (msg: string, data?: Record<string, unknown>) => void;
  error: (msg: string, error?: unknown, data?: Record<string, unknown>) => void;
  child: (bindings: Record<string, unknown>) => ModuleLogger;
  /** Pino logger instance for advanced usage */
  pino: PinoLogger;
}

/**
 * Create a logger for a specific module
 * Provides consistent logging interface across the application
 *
 * @example
 * const logger = createModuleLogger('UserService');
 * logger.info('User created', { userId: '123' });
 * logger.error('Failed to create user', error, { email: 'user@example.com' });
 */
export function createModuleLogger(module: string): ModuleLogger {
  const childLogger = rootLogger.child({ module });

  const wrapLogger = (logger: PinoLogger): ModuleLogger => ({
    debug: (msg: string, data?: Record<string, unknown>) => {
      if (data) {
        logger.debug(data, msg);
      } else {
        logger.debug(msg);
      }
    },

    info: (msg: string, data?: Record<string, unknown>) => {
      if (data) {
        logger.info(data, msg);
      } else {
        logger.info(msg);
      }
    },

    warn: (msg: string, data?: Record<string, unknown>) => {
      if (data) {
        logger.warn(data, msg);
      } else {
        logger.warn(msg);
      }
    },

    error: (msg: string, error?: unknown, data?: Record<string, unknown>) => {
      const errorData: Record<string, unknown> = { ...data };

      if (error instanceof Error) {
        errorData.err = {
          message: error.message,
          name: error.name,
          stack: isDevelopment ? error.stack : undefined,
        };
      } else if (error !== undefined) {
        errorData.err = String(error);
      }

      if (Object.keys(errorData).length > 0) {
        logger.error(errorData, msg);
      } else {
        logger.error(msg);
      }
    },

    child: (bindings: Record<string, unknown>) => wrapLogger(logger.child(bindings)),

    pino: logger,
  });

  return wrapLogger(childLogger);
}

/**
 * Log HTTP requests (middleware-compatible)
 */
export function createRequestLogger() {
  return createModuleLogger('HTTP');
}

/**
 * Log database operations
 */
export function createDbLogger() {
  return createModuleLogger('Database');
}

/**
 * Log API calls to external services
 */
export function createApiLogger(service: string) {
  return createModuleLogger(`API:${service}`);
}

/**
 * Log scraper operations
 */
export function createScraperLogger(scraper: string) {
  return createModuleLogger(`Scraper:${scraper}`);
}

/**
 * Performance timing utility
 */
export function createTimer(logger: ModuleLogger, operation: string) {
  const start = Date.now();

  return {
    end: (data?: Record<string, unknown>) => {
      const duration = Date.now() - start;
      logger.debug(`${operation} completed`, { ...data, durationMs: duration });
      return duration;
    },
    endWithInfo: (data?: Record<string, unknown>) => {
      const duration = Date.now() - start;
      logger.info(`${operation} completed`, { ...data, durationMs: duration });
      return duration;
    },
  };
}

/**
 * Express/HTTP request logging middleware
 */
export function httpLoggingMiddleware() {
  const httpLogger = createRequestLogger();

  return (req: any, res: any, next: any) => {
    const start = Date.now();
    const requestId = Math.random().toString(36).substring(7);

    // Log request
    httpLogger.debug('Incoming request', {
      requestId,
      method: req.method,
      url: req.url,
      userAgent: req.headers['user-agent'],
    });

    // Log response on finish
    res.on('finish', () => {
      const duration = Date.now() - start;
      const level = res.statusCode >= 400 ? 'warn' : 'info';

      httpLogger[level]('Request completed', {
        requestId,
        method: req.method,
        url: req.url,
        statusCode: res.statusCode,
        durationMs: duration,
      });
    });

    next();
  };
}

// Export root logger for direct access if needed
export { rootLogger };
export type { PinoLogger };
