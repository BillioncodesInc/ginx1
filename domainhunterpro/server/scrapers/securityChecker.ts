import axios from 'axios';
import { withRetry } from '../_core/retry';
import { createLogger, RATE_LIMITS, safeApiCall } from '../_core/apiWrapper';

const logger = createLogger('Security');

// Sub-types for security check results
interface SafeBrowsingResult {
  isSafe: boolean;
  threats: string[];
  checked: boolean;
}

interface SpamhausResult {
  isListed: boolean;
  lists: string[];
  checked: boolean;
}

interface VirusTotalResult {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  checked: boolean;
}

export interface SecurityCheckResult {
  // Google Safe Browsing
  safeBrowsing: SafeBrowsingResult;
  // Spamhaus blacklist check
  spamhaus: SpamhausResult;
  // VirusTotal (if API key provided)
  virusTotal: VirusTotalResult;
  // Overall assessment
  overallRisk: 'low' | 'medium' | 'high' | 'unknown';
  riskScore: number; // 0-100, higher = more risky
}

/**
 * Check domain against Google Safe Browsing API
 * Free API with 10,000 requests/day
 * API Documentation: https://developers.google.com/safe-browsing/v4/lookup-api
 */
export async function checkGoogleSafeBrowsing(domain: string): Promise<SafeBrowsingResult> {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  if (!apiKey) {
    logger.info('API key not configured (GOOGLE_SAFE_BROWSING_API_KEY)');
    return { isSafe: true, threats: [], checked: false };
  }

  const defaultResult: SafeBrowsingResult = { isSafe: true, threats: [], checked: false };

  return safeApiCall<SafeBrowsingResult>(
    async () => {
      return withRetry<SafeBrowsingResult>(
        async () => {
          const response = await axios.post(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
            {
              client: {
                clientId: 'domain-hunter-pro',
                clientVersion: '1.0.0',
              },
              threatInfo: {
                threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                platformTypes: ['ANY_PLATFORM'],
                threatEntryTypes: ['URL'],
                threatEntries: [
                  { url: `http://${domain}` },
                  { url: `https://${domain}` },
                ],
              },
            },
            { timeout: 10000 }
          );

          const threats = response.data.matches?.map((m: any) => m.threatType) || [];

          return {
            isSafe: threats.length === 0,
            threats,
            checked: true,
          };
        },
        {
          maxRetries: 2,
          initialDelay: 1000,
          isRetryable: (error: any) => {
            const status = error.response?.status;
            // Retry on rate limit (429) or server errors (5xx)
            return status === 429 || (status >= 500 && status < 600);
          },
          onRetry: (error, attempt) => {
            logger.warn(`Safe Browsing retry ${attempt} for ${domain}: ${error}`);
          },
          label: 'SafeBrowsing',
        }
      );
    },
    defaultResult,
    { label: 'SafeBrowsing', logError: true }
  );
}

/**
 * Check domain against DNS blacklists
 * 
 * IMPORTANT: Spamhaus has moved to DQS (Data Query Service) requiring a free account key.
 * Public DNS resolvers are now blocked. Users must sign up at spamhaus.org for a DQS key.
 * 
 * We also check other free DNSBLs that don't require keys.
 */
export async function checkSpamhaus(domain: string): Promise<SecurityCheckResult['spamhaus']> {
  const dns = await import('dns').then(m => m.promises);
  const lists: string[] = [];
  
  // Spamhaus DQS key (free account required from spamhaus.org)
  const spamhausDqsKey = process.env.SPAMHAUS_DQS_KEY;
  
  // Domain-based blacklists
  const domainBlacklists: { name: string; query: string }[] = [];
  
  // If Spamhaus DQS key is configured, use their service
  if (spamhausDqsKey) {
    // Spamhaus DQS format: domain.dqskey.dbl.dq.spamhaus.net
    domainBlacklists.push(
      { name: 'DBL', query: `${domain}.${spamhausDqsKey}.dbl.dq.spamhaus.net` },
      { name: 'ZRD', query: `${domain}.${spamhausDqsKey}.zrd.dq.spamhaus.net` }, // Zero Reputation Domain
    );
  }
  
  // Free DNSBLs that don't require keys (may have rate limits)
  domainBlacklists.push(
    { name: 'SURBL', query: `${domain}.multi.surbl.org` },
    { name: 'URIBL', query: `${domain}.multi.uribl.com` },
  );
  
  // Check domain-based blacklists
  for (const bl of domainBlacklists) {
    try {
      const result = await dns.resolve4(bl.query);
      if (result && result.length > 0) {
        const ip = result[0];
        // Valid listing returns 127.0.0.x
        // Error codes like 127.255.255.254 indicate blocked/error
        if (ip.startsWith('127.0.0.') && !ip.startsWith('127.255.')) {
          lists.push(bl.name);
        } else if (ip === '127.255.255.254') {
          logger.warn(`DNSBL ${bl.name}: Public resolver blocked - configure DQS key`);
        }
      }
    } catch (error: any) {
      // NXDOMAIN means not listed (good)
      if (error.code !== 'ENOTFOUND' && error.code !== 'ENODATA') {
        logger.debug(`DNSBL ${bl.name} check error: ${error.code || error.message}`);
      }
    }
  }

  // Check IP-based blacklists if domain resolves
  try {
    const ips = await dns.resolve4(domain);
    if (ips && ips.length > 0) {
      const ip = ips[0];
      const reversedIp = ip.split('.').reverse().join('.');
      
      const ipBlacklists: { name: string; query: string }[] = [];
      
      // Spamhaus ZEN with DQS key
      if (spamhausDqsKey) {
        ipBlacklists.push(
          { name: 'ZEN', query: `${reversedIp}.${spamhausDqsKey}.zen.dq.spamhaus.net` },
        );
      }
      
      // Free IP blacklists
      ipBlacklists.push(
        { name: 'BARRACUDA', query: `${reversedIp}.b.barracudacentral.org` },
      );
      
      for (const bl of ipBlacklists) {
        try {
          const result = await dns.resolve4(bl.query);
          if (result && result.length > 0) {
            const ip = result[0];
            if (ip.startsWith('127.0.0.') && !ip.startsWith('127.255.')) {
              lists.push(bl.name);
            }
          }
        } catch {
          // Not listed or error
        }
      }
    }
  } catch {
    // Domain doesn't resolve - that's fine for expired domains
  }

  // Determine if check was actually performed
  const checked = domainBlacklists.length > 0;

  return {
    isListed: lists.length > 0,
    lists,
    checked,
  };
}

/**
 * Check domain against VirusTotal
 * Free tier: 4 requests/minute, 500/day
 * API Documentation: https://developers.virustotal.com/reference/domain-info
 */
export async function checkVirusTotal(domain: string): Promise<VirusTotalResult> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!apiKey) {
    logger.info('API key not configured (VIRUSTOTAL_API_KEY)');
    return { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, checked: false };
  }

  const defaultResult: VirusTotalResult = {
    malicious: 0,
    suspicious: 0,
    harmless: 0,
    undetected: 0,
    checked: false,
  };

  return safeApiCall<VirusTotalResult>(
    async () => {
      return withRetry<VirusTotalResult>(
        async () => {
          const response = await axios.get(
            `https://www.virustotal.com/api/v3/domains/${domain}`,
            {
              headers: {
                'x-apikey': apiKey,
              },
              timeout: 15000,
            }
          );

          const stats = response.data.data?.attributes?.last_analysis_stats || {};

          return {
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            harmless: stats.harmless || 0,
            undetected: stats.undetected || 0,
            checked: true,
          };
        },
        {
          maxRetries: 2,
          initialDelay: RATE_LIMITS.VIRUSTOTAL.delayMs,
          isRetryable: (error: any) => {
            const status = error.response?.status;
            // 404 = domain not in database (clean), don't retry
            if (status === 404) return false;
            // Retry on rate limit (429) or server errors (5xx)
            return status === 429 || (status >= 500 && status < 600);
          },
          onRetry: (error, attempt) => {
            logger.warn(`VirusTotal retry ${attempt} for ${domain}: ${error}`);
          },
          label: 'VirusTotal',
        }
      );
    },
    defaultResult,
    { label: 'VirusTotal', logError: true }
  );
}

/**
 * Calculate overall risk score based on all checks
 */
function calculateRiskScore(result: Omit<SecurityCheckResult, 'overallRisk' | 'riskScore'>): { overallRisk: SecurityCheckResult['overallRisk']; riskScore: number } {
  let riskScore = 0;
  let checksPerformed = 0;

  // Safe Browsing (weight: 40)
  if (result.safeBrowsing.checked) {
    checksPerformed++;
    if (!result.safeBrowsing.isSafe) {
      riskScore += 40;
    }
  }

  // Spamhaus (weight: 30)
  if (result.spamhaus.checked) {
    checksPerformed++;
    if (result.spamhaus.isListed) {
      riskScore += 30;
    }
  }

  // VirusTotal (weight: 30)
  if (result.virusTotal.checked) {
    checksPerformed++;
    const vtTotal = result.virusTotal.malicious + result.virusTotal.suspicious;
    if (vtTotal > 0) {
      // Scale based on number of detections
      riskScore += Math.min(30, vtTotal * 5);
    }
  }

  // If no checks were performed, return unknown
  if (checksPerformed === 0) {
    return { overallRisk: 'unknown', riskScore: 0 };
  }

  // Determine risk level
  let overallRisk: SecurityCheckResult['overallRisk'];
  if (riskScore >= 50) {
    overallRisk = 'high';
  } else if (riskScore >= 20) {
    overallRisk = 'medium';
  } else {
    overallRisk = 'low';
  }

  return { overallRisk, riskScore };
}

/**
 * Perform comprehensive security check on a domain
 */
export async function performSecurityCheck(domain: string): Promise<SecurityCheckResult> {
  logger.info(`Checking domain: ${domain}`);

  // Run all checks in parallel
  const [safeBrowsing, spamhaus, virusTotal] = await Promise.all([
    checkGoogleSafeBrowsing(domain),
    checkSpamhaus(domain),
    checkVirusTotal(domain),
  ]);

  const partialResult = { safeBrowsing, spamhaus, virusTotal };
  const { overallRisk, riskScore } = calculateRiskScore(partialResult);

  return {
    ...partialResult,
    overallRisk,
    riskScore,
  };
}

/**
 * Batch check multiple domains (with rate limiting)
 */
export async function batchSecurityCheck(domains: string[]): Promise<Map<string, SecurityCheckResult>> {
  const results = new Map<string, SecurityCheckResult>();
  
  // Process in batches of 5 to avoid rate limits
  const batchSize = 5;
  for (let i = 0; i < domains.length; i += batchSize) {
    const batch = domains.slice(i, i + batchSize);
    
    const batchResults = await Promise.all(
      batch.map(domain => performSecurityCheck(domain))
    );
    
    batch.forEach((domain, index) => {
      results.set(domain, batchResults[index]);
    });
    
    // Wait between batches to respect rate limits
    if (i + batchSize < domains.length) {
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
  
  return results;
}

/**
 * Convert security check result to spam score (0-100)
 * For compatibility with existing spam score field
 */
export function securityResultToSpamScore(result: SecurityCheckResult): number {
  return result.riskScore;
}

/**
 * Check if domain has clean history based on security checks
 */
export function hasCleanSecurityHistory(result: SecurityCheckResult): boolean {
  return result.overallRisk === 'low' || result.overallRisk === 'unknown';
}
