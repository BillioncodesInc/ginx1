// @ts-ignore - no types available for whois-json
import whois from 'whois-json';
import { parseDate } from '../_core/utils';
import { withRetry } from '../_core/retry';
import { createLogger, RATE_LIMITS } from '../_core/apiWrapper';

const logger = createLogger('WHOIS');

// Type for raw WHOIS response from whois-json library
interface WhoisRawResponse {
  domainName?: string;
  registrar?: string;
  creationDate?: string;
  createdDate?: string;
  expirationDate?: string;
  registryExpiryDate?: string;
  updatedDate?: string;
  nameServer?: string | string[];
  status?: string | string[];
}

export interface WhoisResult {
  domainName: string;
  isAvailable: boolean;
  registrar?: string;
  creationDate?: Date;
  expirationDate?: Date;
  updatedDate?: Date;
  nameServers?: string[];
  status?: string[];
  error?: string;
}

/**
 * Check domain availability and get WHOIS information
 * With retry logic for transient failures
 */
export async function checkDomainWhois(domain: string): Promise<WhoisResult> {
  try {
    const data = await withRetry<WhoisRawResponse>(
      () => whois(domain, {
        follow: 3,
        timeout: 10000,
      }),
      {
        maxRetries: 2,
        initialDelay: RATE_LIMITS.WHOIS.delayMs,
        label: `WHOIS ${domain}`,
        isRetryable: (error: unknown) => {
          const err = error as any;
          // Retry on timeout or connection errors
          return err.code === 'ETIMEDOUT' ||
                 err.code === 'ECONNRESET' ||
                 err.message?.includes('timeout');
        },
      }
    );

    // Check if domain is available
    const isAvailable =
      !data ||
      (typeof data === 'object' && Object.keys(data).length === 0) ||
      (data.domainName === undefined && data.registrar === undefined);

    if (isAvailable) {
      return {
        domainName: domain,
        isAvailable: true,
      };
    }

    return {
      domainName: domain,
      isAvailable: false,
      registrar: data.registrar,
      creationDate: parseDate(data.creationDate || data.createdDate),
      expirationDate: parseDate(data.expirationDate || data.registryExpiryDate),
      updatedDate: parseDate(data.updatedDate),
      nameServers: Array.isArray(data.nameServer)
        ? data.nameServer
        : data.nameServer
          ? [data.nameServer]
          : undefined,
      status: Array.isArray(data.status)
        ? data.status
        : data.status
          ? [data.status]
          : undefined,
    };
  } catch (error: any) {
    logger.error(`lookup failed for ${domain}`, error);

    // If WHOIS fails after retries, assume domain might be available
    // (Some registrars block WHOIS lookups)
    return {
      domainName: domain,
      isAvailable: true, // Optimistic assumption
      error: error.message,
    };
  }
}

/**
 * Batch check multiple domains with rate limiting and error recovery
 */
export async function batchCheckDomains(domains: string[]): Promise<WhoisResult[]> {
  const { batchProcess } = await import('../_core/batchProcessor');

  return batchProcess(domains, checkDomainWhois, {
    delayMs: RATE_LIMITS.WHOIS.delayMs,
    fallbackValue: (domain) => ({
      domainName: domain,
      isAvailable: true,
      error: 'Failed to check domain',
    }),
    label: 'WHOIS Batch',
  });
}

/**
 * Quick availability check (faster, less detailed)
 */
export async function quickAvailabilityCheck(domain: string): Promise<boolean> {
  try {
    const result = await checkDomainWhois(domain);
    return result.isAvailable;
  } catch {
    return true; // Assume available on error
  }
}
