import axios from 'axios';
import { withRetry } from '../_core/retry';
import { createLogger, RATE_LIMITS, safeApiCall } from '../_core/apiWrapper';

const logger = createLogger('Archive');

export interface ArchiveData {
  domainName: string;
  snapshotCount: number;
  firstSnapshot?: Date;
  lastSnapshot?: Date;
  birthYear?: number;
  archiveUrl?: string;
  error?: string;
}

/**
 * Parse Wayback Machine timestamp (format: YYYYMMDDhhmmss)
 */
function parseWaybackTimestamp(ts: string): Date {
  const year = parseInt(ts.substring(0, 4));
  const month = parseInt(ts.substring(4, 6)) - 1;
  const day = parseInt(ts.substring(6, 8));
  return new Date(year, month, day);
}

/**
 * Get domain archive data from Wayback Machine
 * With retry logic and fallback to availability API
 */
export async function getArchiveData(domain: string): Promise<ArchiveData> {
  try {
    // Wayback Machine CDX API with retry
    const response = await withRetry(
      () => axios.get('https://web.archive.org/cdx/search/cdx', {
        params: {
          url: domain,
          output: 'json',
          fl: 'timestamp',
          collapse: 'timestamp:8', // Group by year/month
          limit: 10000,
        },
        timeout: 15000,
      }),
      {
        maxRetries: 2,
        initialDelay: RATE_LIMITS.ARCHIVE.delayMs,
        label: `Archive CDX ${domain}`,
      }
    );

    if (!response.data || response.data.length <= 1) {
      // No snapshots found
      return {
        domainName: domain,
        snapshotCount: 0,
      };
    }

    // First row is headers, skip it
    const snapshots = response.data.slice(1);
    const timestamps = snapshots.map((row: any[]) => row[0]);

    if (timestamps.length === 0) {
      return {
        domainName: domain,
        snapshotCount: 0,
      };
    }

    const firstTimestamp = timestamps[0];
    const lastTimestamp = timestamps[timestamps.length - 1];

    const firstSnapshot = parseWaybackTimestamp(firstTimestamp);
    const lastSnapshot = parseWaybackTimestamp(lastTimestamp);
    const birthYear = firstSnapshot.getFullYear();

    return {
      domainName: domain,
      snapshotCount: timestamps.length,
      firstSnapshot,
      lastSnapshot,
      birthYear,
      archiveUrl: `https://web.archive.org/web/*/${domain}`,
    };
  } catch (error: any) {
    logger.error(`CDX lookup failed for ${domain}`, error);

    // Try availability API as fallback with retry
    const fallbackResult = await safeApiCall(
      async () => {
        const availResponse = await withRetry(
          () => axios.get(`https://archive.org/wayback/available?url=${domain}`, {
            timeout: 10000,
          }),
          { maxRetries: 1, label: `Archive Fallback ${domain}` }
        );

        if (availResponse.data?.archived_snapshots?.closest?.timestamp) {
          const timestamp = availResponse.data.archived_snapshots.closest.timestamp;
          const year = parseInt(timestamp.substring(0, 4));

          return {
            domainName: domain,
            snapshotCount: 1, // At least one snapshot
            birthYear: year,
            archiveUrl: `https://web.archive.org/web/*/${domain}`,
          };
        }
        return null;
      },
      null,
      { label: 'Archive Fallback' }
    );

    if (fallbackResult) {
      return fallbackResult;
    }

    return {
      domainName: domain,
      snapshotCount: 0,
      error: error.message,
    };
  }
}

/**
 * Batch check archives for multiple domains with rate limiting
 */
export async function batchGetArchiveData(domains: string[]): Promise<ArchiveData[]> {
  const { batchProcess } = await import('../_core/batchProcessor');

  return batchProcess(domains, getArchiveData, {
    delayMs: RATE_LIMITS.ARCHIVE.delayMs,
    fallbackValue: (domain) => ({
      domainName: domain,
      snapshotCount: 0,
      error: 'Failed to fetch archive data',
    }),
    label: 'Archive Batch',
  });
}

/**
 * Get snapshot count only (faster)
 */
export async function getSnapshotCount(domain: string): Promise<number> {
  try {
    const data = await getArchiveData(domain);
    return data.snapshotCount;
  } catch {
    return 0;
  }
}
