import axios from 'axios';
import { withRetry } from '../_core/retry';
import { createLogger, RATE_LIMITS } from '../_core/apiWrapper';

const logger = createLogger('Moz API');
const MOZ_API_BASE = 'https://lsapi.seomoz.com/v2';

export interface MozMetrics {
  domainAuthority: number;
  pageAuthority: number;
  spamScore: number;
  linkCount: number;
  error?: string;
}

const DEFAULT_MOZ_METRICS: MozMetrics = {
  domainAuthority: 0,
  pageAuthority: 0,
  spamScore: 0,
  linkCount: 0,
};

/**
 * Get Moz metrics for a domain
 * With retry logic for transient failures
 * @param domain - Domain name (e.g., example.com)
 * @returns Moz metrics including DA, PA, spam score
 */
export async function getMozMetrics(domain: string): Promise<MozMetrics> {
  const token = process.env.MOZ_API_TOKEN;

  if (!token) {
    logger.warn('Token not configured');
    return {
      ...DEFAULT_MOZ_METRICS,
      error: 'API token not configured',
    };
  }

  try {
    const response = await withRetry(
      () => axios.post(
        `${MOZ_API_BASE}/url_metrics`,
        { targets: [domain] },
        {
          headers: {
            'Authorization': `Basic ${token}`,
            'Content-Type': 'application/json',
          },
          timeout: 15000,
        }
      ),
      {
        maxRetries: 2,
        initialDelay: RATE_LIMITS.MOZ.delayMs,
        label: `Moz ${domain}`,
        isRetryable: (error: unknown) => {
          const err = error as any;
          const status = err.response?.status;
          // Retry on rate limit (429) or server errors (5xx)
          return status === 429 || (status >= 500 && status < 600);
        },
      }
    );

    if (!response.data || !response.data.results || response.data.results.length === 0) {
      logger.warn(`No data returned for ${domain}`);
      return {
        ...DEFAULT_MOZ_METRICS,
        error: 'No data available',
      };
    }

    const metrics = response.data.results[0];

    return {
      domainAuthority: Math.round(metrics.domain_authority || 0),
      pageAuthority: Math.round(metrics.page_authority || 0),
      spamScore: Math.round(metrics.spam_score || 0),
      linkCount: metrics.external_pages || 0,
    };
  } catch (error: any) {
    logger.error(`Error fetching metrics for ${domain}`, error);

    return {
      ...DEFAULT_MOZ_METRICS,
      error: error.message,
    };
  }
}

/**
 * Batch get Moz metrics for multiple domains
 * With retry logic for transient failures
 * @param domains - Array of domain names
 * @returns Map of domain to Moz metrics
 */
export async function batchGetMozMetrics(domains: string[]): Promise<Map<string, MozMetrics>> {
  const token = process.env.MOZ_API_TOKEN;
  const results = new Map<string, MozMetrics>();

  if (!token) {
    logger.warn('Token not configured');
    domains.forEach(domain => {
      results.set(domain, {
        ...DEFAULT_MOZ_METRICS,
        error: 'API token not configured',
      });
    });
    return results;
  }

  try {
    // Moz API supports batch requests - use retry for resilience
    const response = await withRetry(
      () => axios.post(
        `${MOZ_API_BASE}/url_metrics`,
        { targets: domains },
        {
          headers: {
            'Authorization': `Basic ${token}`,
            'Content-Type': 'application/json',
          },
          timeout: 30000,
        }
      ),
      {
        maxRetries: 3,
        initialDelay: RATE_LIMITS.MOZ.delayMs,
        label: 'Moz Batch',
        isRetryable: (error: unknown) => {
          const err = error as any;
          const status = err.response?.status;
          return status === 429 || (status >= 500 && status < 600);
        },
      }
    );

    if (response.data && response.data.results) {
      response.data.results.forEach((metrics: any, index: number) => {
        const domain = domains[index];
        results.set(domain, {
          domainAuthority: Math.round(metrics.domain_authority || 0),
          pageAuthority: Math.round(metrics.page_authority || 0),
          spamScore: Math.round(metrics.spam_score || 0),
          linkCount: metrics.external_pages || 0,
        });
      });
    }

    return results;
  } catch (error: any) {
    logger.error('Batch request failed after retries', error);

    // Return zeros for all domains on error
    domains.forEach(domain => {
      results.set(domain, {
        ...DEFAULT_MOZ_METRICS,
        error: error.message,
      });
    });

    return results;
  }
}

/**
 * Test Moz API connectivity
 */
export async function testMozApi(): Promise<boolean> {
  try {
    const result = await getMozMetrics('example.com');
    return !result.error;
  } catch {
    return false;
  }
}
