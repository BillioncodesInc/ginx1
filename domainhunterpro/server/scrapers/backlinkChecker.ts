/**
 * Backlink Checker Module
 *
 * Fetches backlink data from various sources:
 * 1. Ahrefs API v3 (if API key configured) - Enterprise plan required
 * 2. Majestic API (if API key configured)
 * 3. Moz Link Explorer API (if API key configured)
 * 4. Ahrefs Free Backlink Checker (via puppeteer-extra stealth scraping) - Fallback
 *
 * NOTE: Ahrefs API v2 was discontinued on November 1, 2025.
 * The current implementation uses API v3 endpoints.
 *
 * Uses puppeteer-extra with stealth plugin for improved anti-bot evasion.
 */

import { getAppSetting } from "../db";
import { createLogger } from "../_core/apiWrapper";
import {
  createStealthPage,
  stealthNavigate,
  humanScroll,
  closePage,
  type Page,
} from "../_core/stealthBrowser";

const logger = createLogger('Backlink');

export interface BacklinkResult {
  sourceUrl: string;
  sourceTitle?: string;
  targetUrl: string;
  anchorText?: string;
  domainRating?: number;
  isDofollow: boolean;
  firstSeen?: Date;
  lastSeen?: Date;
}

export interface BacklinkProfile {
  domain: string;
  totalBacklinks: number;
  uniqueDomains: number;
  dofollowPercent: number;
  nofollowPercent: number;
  domainRating?: number;
  urlRating?: number;
  backlinks: BacklinkResult[];
  topReferringDomains: { domain: string; count: number; rating?: number }[];
  anchorTexts: { text: string; count: number }[];
  duration: number;
  sources: string[];
  message?: string;
}

/**
 * Get backlink profile for a domain
 */
export async function getBacklinkProfile(domain: string): Promise<BacklinkProfile> {
  const startTime = Date.now();
  const backlinks: BacklinkResult[] = [];
  const referringDomains = new Map<string, { count: number; rating?: number }>();
  const anchorTexts = new Map<string, number>();
  const sources: string[] = [];
  let domainRating: number | undefined;
  let urlRating: number | undefined;
  let totalBacklinks = 0;
  let uniqueDomains = 0;
  let dofollowPercent = 0;
  
  logger.info(`Fetching backlinks for: ${domain}`);
  
  // Track if any API was successfully used
  let apiUsed = false;

  // 1. Try Ahrefs API if configured (PRIORITY)
  try {
    const ahrefsToken = await getAppSetting('AHREFS_API_TOKEN');
    logger.debug(`Ahrefs API token check`, {
      keyExists: ahrefsToken ? 'YES' : 'NO',
      hasValue: ahrefsToken?.value ? `YES (length: ${ahrefsToken.value.length})` : 'NO'
    });

    if (ahrefsToken?.value && ahrefsToken.value.trim().length > 0) {
      logger.info('Using Ahrefs API v3 (configured)...');
      const ahrefsResults = await fetchAhrefsApi(domain, ahrefsToken.value);
      logger.info(`Ahrefs API returned`, {
        backlinks: ahrefsResults.backlinks.length,
        domainRating: ahrefsResults.domainRating,
        totalBacklinks: ahrefsResults.totalBacklinks
      });
      
      // Use API results even if backlinks array is empty (API might return metrics only)
      apiUsed = true;
      sources.push('Ahrefs API');
      domainRating = ahrefsResults.domainRating;
      totalBacklinks = ahrefsResults.totalBacklinks;
      uniqueDomains = ahrefsResults.uniqueDomains;
      dofollowPercent = ahrefsResults.dofollowPercent;
      
      for (const bl of ahrefsResults.backlinks) {
        backlinks.push(bl);
        trackBacklink(bl, referringDomains, anchorTexts);
      }
    }
  } catch (error: any) {
    logger.error(`Ahrefs API error`, error);
  }

  // 2. Try Majestic API if configured (and no API used yet)
  if (!apiUsed) {
    try {
      const majesticToken = await getAppSetting('MAJESTIC_API_TOKEN');
      logger.debug(`Majestic API token configured: ${majesticToken?.value ? 'YES' : 'NO'}`);

      if (majesticToken?.value && majesticToken.value.trim().length > 0) {
        logger.info('Using Majestic API (configured)...');
        const majesticResults = await fetchMajesticApi(domain, majesticToken.value);
        logger.info(`Majestic API returned: ${majesticResults.backlinks.length} backlinks`);
        
        apiUsed = true;
        sources.push('Majestic API');
        domainRating = majesticResults.trustFlow;
        totalBacklinks = majesticResults.totalBacklinks;
        uniqueDomains = majesticResults.uniqueDomains;
        
        for (const bl of majesticResults.backlinks) {
          backlinks.push(bl);
          trackBacklink(bl, referringDomains, anchorTexts);
        }
      }
    } catch (error: any) {
      logger.error(`Majestic API error`, error);
    }
  }

  // 3. Try Moz API if configured (and no API used yet)
  if (!apiUsed) {
    try {
      const mozToken = await getAppSetting('MOZ_API_TOKEN');
      logger.debug(`Moz API token configured: ${mozToken?.value ? 'YES' : 'NO'}`);

      if (mozToken?.value && mozToken.value.trim().length > 0) {
        logger.info('Using Moz API (configured)...');
        const mozResults = await fetchMozBacklinks(domain, mozToken.value);
        logger.info(`Moz API returned: ${mozResults.backlinks.length} backlinks`);
        
        apiUsed = true;
        sources.push('Moz Link Explorer');
        domainRating = mozResults.domainAuthority;
        
        for (const bl of mozResults.backlinks) {
          backlinks.push(bl);
          trackBacklink(bl, referringDomains, anchorTexts);
        }
      }
    } catch (error: any) {
      logger.error(`Moz API error`, error);
    }
  }

  // 4. Scrape Ahrefs Free Backlink Checker ONLY if no API was used
  if (!apiUsed) {
    try {
      logger.info('No API configured, falling back to Ahrefs Free Backlink Checker scraping...');
      const ahrefsResults = await scrapeAhrefsFreeChecker(domain);
      logger.info(`Scraper returned: ${ahrefsResults.backlinks.length} backlinks`);
      
      if (ahrefsResults.backlinks.length > 0 || ahrefsResults.totalBacklinks > 0) {
        sources.push('Ahrefs Free Checker');
        domainRating = ahrefsResults.domainRating;
        urlRating = ahrefsResults.urlRating;
        totalBacklinks = ahrefsResults.totalBacklinks;
        uniqueDomains = ahrefsResults.uniqueDomains;
        dofollowPercent = ahrefsResults.dofollowPercent;
        
        for (const bl of ahrefsResults.backlinks) {
          backlinks.push(bl);
          trackBacklink(bl, referringDomains, anchorTexts);
        }
      }
    } catch (error: any) {
      logger.error(`Ahrefs scraping error`, error);
    }
  } else {
    logger.debug('API was used, skipping scraper fallback');
  }

  // Calculate statistics if not already set
  if (totalBacklinks === 0) {
    totalBacklinks = backlinks.length;
  }
  if (uniqueDomains === 0) {
    uniqueDomains = referringDomains.size;
  }
  
  const dofollowCount = backlinks.filter(b => b.isDofollow).length;
  const totalCount = backlinks.length || 1;
  if (dofollowPercent === 0) {
    dofollowPercent = Math.round((dofollowCount / totalCount) * 100);
  }
  
  // Sort referring domains by count
  const topReferringDomains = Array.from(referringDomains.entries())
    .map(([domain, data]) => ({ domain, ...data }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  // Sort anchor texts by count
  const topAnchorTexts = Array.from(anchorTexts.entries())
    .map(([text, count]) => ({ text, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  const duration = Date.now() - startTime;

  if (sources.length === 0) {
    logger.warn(`No backlink data retrieved for ${domain}. Configure API keys (Ahrefs, Majestic, or Moz) in Settings for reliable data.`);
  } else {
    logger.info(`Found ${backlinks.length} backlinks from ${sources.join(', ')} in ${duration}ms`);
  }

  return {
    domain,
    totalBacklinks,
    uniqueDomains,
    dofollowPercent,
    nofollowPercent: 100 - dofollowPercent,
    domainRating,
    urlRating,
    backlinks: backlinks.slice(0, 100),
    topReferringDomains,
    anchorTexts: topAnchorTexts,
    duration,
    sources,
    // Include a message if no data was retrieved
    message: sources.length === 0
      ? 'No backlink data available. The Ahrefs free scraper may be blocked by Cloudflare. Configure API keys in Settings for reliable results.'
      : undefined,
  };
}

/**
 * Track backlink in maps
 */
function trackBacklink(
  bl: BacklinkResult,
  referringDomains: Map<string, { count: number; rating?: number }>,
  anchorTexts: Map<string, number>
) {
  const refDomain = extractDomain(bl.sourceUrl);
  if (refDomain) {
    const existing = referringDomains.get(refDomain) || { count: 0 };
    referringDomains.set(refDomain, { 
      count: existing.count + 1, 
      rating: bl.domainRating || existing.rating 
    });
  }
  
  if (bl.anchorText && bl.anchorText.trim()) {
    anchorTexts.set(bl.anchorText, (anchorTexts.get(bl.anchorText) || 0) + 1);
  }
}

/**
 * Scrape Ahrefs Free Backlink Checker using puppeteer-extra with stealth plugin
 *
 * NOTE: Ahrefs uses Cloudflare Turnstile which requires human verification
 * before EACH backlink check request. This makes automated scraping very difficult.
 *
 * For reliable backlink data, consider:
 * 1. Ahrefs API ($99+/month) - Most reliable
 * 2. Majestic API - Alternative backlink source
 * 3. Moz API - For Domain Authority metrics
 * 4. Third-party scraping services (ScrapingBee, Browserless.io)
 *
 * This scraper uses puppeteer-extra stealth plugin to attempt to bypass Cloudflare
 * but may not always succeed.
 */
async function scrapeAhrefsFreeChecker(domain: string): Promise<{
  backlinks: BacklinkResult[];
  domainRating?: number;
  urlRating?: number;
  totalBacklinks: number;
  uniqueDomains: number;
  dofollowPercent: number;
}> {
  const results: BacklinkResult[] = [];
  let domainRating: number | undefined;
  let urlRating: number | undefined;
  let totalBacklinks = 0;
  let uniqueDomains = 0;
  let dofollowPercent = 0;

  let page: Page | null = null;

  try {
    logger.debug('Launching stealth browser...');

    // Create stealth page using puppeteer-extra with stealth plugin
    page = await createStealthPage({
      headless: true,
      timeout: 90000,
    });

    // Navigate to Ahrefs free backlink checker
    const url = `https://ahrefs.com/backlink-checker/?input=${encodeURIComponent(domain)}&mode=subdomains`;
    logger.debug(`Navigating to: ${url}`);

    // Navigate with stealth measures
    await stealthNavigate(page, url, {
      waitUntil: 'networkidle2',
      humanDelay: true,
    });

    // Wait for Cloudflare challenge to complete (if any)
    logger.debug('Waiting for Cloudflare challenge...');
    await page.waitForTimeout(8000);

    // Human-like scrolling
    await humanScroll(page);

    // Check for Cloudflare challenge page
    const pageContent = await page.content();
    if (pageContent.includes('Checking your browser') ||
        pageContent.includes('cf-browser-verification') ||
        pageContent.includes('Just a moment')) {
      logger.debug('Cloudflare challenge detected, waiting longer...');
      await page.waitForTimeout(10000);
      await humanScroll(page);
    }

    // Wait for the actual content to load
    logger.debug('Waiting for content to load...');
    try {
      await page.waitForSelector('::-p-text(Domain Rating)', { timeout: 30000 });
    } catch {
      logger.warn('Timeout waiting for Domain Rating text');
    }

    // Additional wait for dynamic content
    await page.waitForTimeout(3000);

    // Get page content for debugging
    const finalContent = await page.content();
    logger.debug(`Page loaded, content length: ${finalContent.length}`);

    // Check if we're still blocked
    if (finalContent.includes('Access denied') ||
        finalContent.includes('blocked') ||
        finalContent.includes('captcha') ||
        finalContent.length < 5000) {
      logger.warn('Still blocked or page not loaded properly');
      return { backlinks: results, domainRating, urlRating, totalBacklinks, uniqueDomains, dofollowPercent };
    }

    // Extract metrics using multiple strategies
    logger.debug('Extracting metrics...');

    // Strategy 1: Look for specific text patterns in the page
    const pageText = await page.$eval('body', (el: Element) => el.textContent || '').catch(() => '');

    // Extract Domain Rating
    const drMatch = pageText.match(/Domain Rating[^\d]*(\d+\.?\d*)/i);
    if (drMatch) {
      domainRating = parseFloat(drMatch[1]);
      logger.debug(`Domain Rating: ${domainRating}`);
    }

    // Extract Backlinks count
    const blMatch = pageText.match(/Backlinks[^\d]*(\d[\d,]*)/i);
    if (blMatch) {
      totalBacklinks = parseInt(blMatch[1].replace(/,/g, ''));
      logger.debug(`Total Backlinks: ${totalBacklinks}`);
    }

    // Extract Linking websites
    const lwMatch = pageText.match(/Linking websites[^\d]*(\d[\d,]*)/i);
    if (lwMatch) {
      uniqueDomains = parseInt(lwMatch[1].replace(/,/g, ''));
      logger.debug(`Linking Websites: ${uniqueDomains}`);
    }

    // Extract dofollow percentage
    const dfMatch = pageText.match(/(\d+)%\s*dofollow/i);
    if (dfMatch) {
      dofollowPercent = parseInt(dfMatch[1]);
      logger.debug(`Dofollow: ${dofollowPercent}%`);
    }

    // Strategy 2: Extract backlinks from table rows
    logger.debug('Extracting backlinks table...');

    // Scroll down to load more content
    await page.evaluate(() => window.scrollBy(0, 500));
    await page.waitForTimeout(1000);

    // Try multiple table selectors
    const tableSelectors = [
      'table tbody tr',
      '[class*="BacklinkRow"]',
      '[class*="backlink-row"]',
      '[class*="TableRow"]',
      'tr[class*="Row"]',
    ];

    for (const selector of tableSelectors) {
      const rows = await page.$$(selector);
      if (rows.length > 0) {
        logger.debug(`Found ${rows.length} rows with selector: ${selector}`);

        for (const row of rows.slice(0, 100)) {
          try {
            const rowText = await row.evaluate((el: Element) => el.textContent || '');

            // Skip header rows and empty rows
            if (rowText.includes('Referring page') ||
                rowText.includes('Anchor and target') ||
                rowText.trim().length < 10) continue;

            // Extract DR from row
            let dr: number | undefined;
            const rowDrMatch = rowText.match(/^(\d+)/);
            if (rowDrMatch) {
              dr = parseInt(rowDrMatch[1]);
            }

            // Extract links from row
            const links = await row.$$('a[href^="http"]');

            for (const link of links) {
              const href = await link.evaluate((el: Element) => el.getAttribute('href') || '');
              const text = await link.evaluate((el: Element) => el.textContent || '');

              if (href && !href.includes('ahrefs.com') && !href.includes(domain)) {
                results.push({
                  sourceUrl: href,
                  sourceTitle: text?.trim() || undefined,
                  targetUrl: `https://${domain}`,
                  domainRating: dr,
                  isDofollow: true,
                });
              }
            }
          } catch {
            // Skip rows that can't be parsed
          }
        }

        if (results.length > 0) break;
      }
    }

    // Strategy 3: Extract all external links as fallback
    if (results.length === 0) {
      logger.debug('Trying fallback link extraction...');

      const allLinks = await page.$$('a[href^="http"]');
      const seenUrls = new Set<string>();

      for (const link of allLinks) {
        try {
          const href = await link.evaluate((el: Element) => el.getAttribute('href') || '');
          const text = await link.evaluate((el: Element) => el.textContent || '');

          if (href && text &&
              !href.includes('ahrefs.com') &&
              !href.includes(domain) &&
              !href.includes('google.com') &&
              !href.includes('facebook.com') &&
              !href.includes('twitter.com') &&
              !href.includes('linkedin.com') &&
              !seenUrls.has(href) &&
              text.trim().length > 0) {
            seenUrls.add(href);
            results.push({
              sourceUrl: href,
              sourceTitle: text.trim(),
              targetUrl: `https://${domain}`,
              isDofollow: true,
            });
          }
        } catch {}
      }
    }

    logger.debug(`Extracted ${results.length} backlinks`);

  } catch (error: any) {
    logger.error(`Scraper error`, error);
  } finally {
    if (page) {
      await closePage(page);
    }
  }

  return {
    backlinks: results,
    domainRating,
    urlRating,
    totalBacklinks,
    uniqueDomains,
    dofollowPercent,
  };
}

/**
 * Fetch backlinks from Ahrefs API v3
 * 
 * API Documentation: https://docs.ahrefs.com/docs/api/v3/
 * Base URL: https://api.ahrefs.com/v3/site-explorer
 * 
 * Endpoints used:
 * - /domain-rating - Get domain rating
 * - /backlinks-stats - Get backlink statistics
 * - /all-backlinks - Get list of backlinks
 */
async function fetchAhrefsApi(domain: string, apiToken: string): Promise<{
  backlinks: BacklinkResult[];
  domainRating?: number;
  totalBacklinks: number;
  uniqueDomains: number;
  dofollowPercent: number;
}> {
  const results: BacklinkResult[] = [];
  let domainRating: number | undefined;
  let totalBacklinks = 0;
  let uniqueDomains = 0;
  let dofollowPercent = 0;
  
  const baseUrl = 'https://api.ahrefs.com/v3/site-explorer';
  const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD format
  
  const headers = {
    'Authorization': `Bearer ${apiToken}`,
    'Accept': 'application/json',
  };

  try {
    // 1. Get Domain Rating
    logger.debug('Fetching domain rating from Ahrefs API v3...');
    const drResponse = await fetch(
      `${baseUrl}/domain-rating?target=${encodeURIComponent(domain)}&date=${today}`,
      { headers }
    );

    if (drResponse.ok) {
      const drData = await drResponse.json() as any;
      domainRating = drData.domain_rating?.domain_rating;
      logger.debug(`Domain Rating: ${domainRating}`);
    } else {
      const errorText = await drResponse.text();
      logger.warn(`Domain rating error: ${drResponse.status}`, { error: errorText });
    }

    // 2. Get Backlinks Stats
    logger.debug('Fetching backlinks stats from Ahrefs API v3...');
    const statsResponse = await fetch(
      `${baseUrl}/backlinks-stats?target=${encodeURIComponent(domain)}&mode=subdomains&date=${today}`,
      { headers }
    );

    if (statsResponse.ok) {
      const statsData = await statsResponse.json() as any;
      totalBacklinks = statsData.metrics?.live || 0;
      uniqueDomains = statsData.metrics?.live_refdomains || 0;
      logger.debug(`Backlinks: ${totalBacklinks}, Referring Domains: ${uniqueDomains}`);
    } else {
      const errorText = await statsResponse.text();
      logger.warn(`Backlinks stats error: ${statsResponse.status}`, { error: errorText });
    }

    // 3. Get All Backlinks (list of actual backlinks)
    logger.debug('Fetching backlinks list from Ahrefs API v3...');
    const selectColumns = 'url_from,url_to,anchor,domain_rating_source,is_dofollow,first_seen_link,title';
    const backlinksResponse = await fetch(
      `${baseUrl}/all-backlinks?target=${encodeURIComponent(domain)}&mode=subdomains&select=${selectColumns}&limit=100&history=live`,
      { headers }
    );

    if (backlinksResponse.ok) {
      const backlinksData = await backlinksResponse.json() as any;

      let dofollowCount = 0;
      if (backlinksData.backlinks && Array.isArray(backlinksData.backlinks)) {
        for (const bl of backlinksData.backlinks) {
          const isDofollow = bl.is_dofollow === true;
          if (isDofollow) dofollowCount++;

          results.push({
            sourceUrl: bl.url_from,
            sourceTitle: bl.title,
            targetUrl: bl.url_to,
            anchorText: bl.anchor,
            domainRating: bl.domain_rating_source,
            isDofollow,
            firstSeen: bl.first_seen_link ? new Date(bl.first_seen_link) : undefined,
          });
        }

        // Calculate dofollow percentage from actual backlinks
        if (results.length > 0) {
          dofollowPercent = Math.round((dofollowCount / results.length) * 100);
        }

        logger.info(`Retrieved ${results.length} backlinks, ${dofollowPercent}% dofollow`);
      }
    } else {
      const errorText = await backlinksResponse.text();
      logger.warn(`Backlinks list error: ${backlinksResponse.status}`, { error: errorText });
    }

  } catch (error: any) {
    logger.error(`Ahrefs API v3 error`, error);
    throw error; // Re-throw to be caught by caller
  }

  return { backlinks: results, domainRating, totalBacklinks, uniqueDomains, dofollowPercent };
}

/**
 * Fetch backlinks from Majestic API
 */
async function fetchMajesticApi(domain: string, apiToken: string): Promise<{
  backlinks: BacklinkResult[];
  trustFlow?: number;
  citationFlow?: number;
  totalBacklinks: number;
  uniqueDomains: number;
}> {
  const results: BacklinkResult[] = [];
  let trustFlow: number | undefined;
  let citationFlow: number | undefined;
  let totalBacklinks = 0;
  let uniqueDomains = 0;
  
  try {
    // Majestic API - Get backlinks
    const response = await fetch(`https://api.majestic.com/api/json?app_api_key=${apiToken}&cmd=GetBackLinkData&item=${domain}&Count=100&datasource=fresh`, {
      headers: {
        'Accept': 'application/json',
      },
    });

    if (response.ok) {
      const data = await response.json() as any;
      
      if (data.DataTables?.BackLinks?.Data) {
        trustFlow = data.DataTables.BackLinks.Data[0]?.TargetTrustFlow;
        citationFlow = data.DataTables.BackLinks.Data[0]?.TargetCitationFlow;
        totalBacklinks = data.DataTables.BackLinks.Headers?.TotalBackLinks || 0;
        uniqueDomains = data.DataTables.BackLinks.Headers?.TotalRefDomains || 0;
        
        for (const bl of data.DataTables.BackLinks.Data) {
          results.push({
            sourceUrl: bl.SourceURL,
            sourceTitle: bl.SourceTitle,
            targetUrl: bl.TargetURL,
            anchorText: bl.AnchorText,
            domainRating: bl.SourceTrustFlow,
            isDofollow: bl.FlagNoFollow !== 1,
            firstSeen: bl.FirstIndexedDate ? new Date(bl.FirstIndexedDate) : undefined,
          });
        }
      }
    }
  } catch (error: any) {
    logger.error(`Majestic API error`, error);
  }

  return { backlinks: results, trustFlow, citationFlow, totalBacklinks, uniqueDomains };
}

/**
 * Fetch backlinks from Moz API
 */
async function fetchMozBacklinks(domain: string, apiToken: string): Promise<{ backlinks: BacklinkResult[]; domainAuthority?: number }> {
  const results: BacklinkResult[] = [];
  let domainAuthority: number | undefined;
  
  try {
    const response = await fetch('https://lsapi.seomoz.com/v2/links', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${apiToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        target: domain,
        target_scope: 'root_domain',
        limit: 50,
      }),
    });

    if (response.ok) {
      const data = await response.json() as any;
      domainAuthority = data.target?.domain_authority;
      
      if (data.results) {
        for (const link of data.results) {
          results.push({
            sourceUrl: link.source?.page || link.source_page,
            targetUrl: link.target?.page || `https://${domain}`,
            anchorText: link.anchor_text,
            domainRating: link.source?.domain_authority,
            isDofollow: !link.nofollow,
            firstSeen: link.first_seen ? new Date(link.first_seen) : undefined,
          });
        }
      }
    }
  } catch (error: any) {
    logger.error(`Moz Links API error`, error);
  }

  return { backlinks: results, domainAuthority };
}

/**
 * Extract domain from URL
 */
function extractDomain(url: string): string | null {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname.replace(/^www\./, '');
  } catch {
    const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^\/]+)/);
    return match ? match[1] : null;
  }
}

/**
 * Estimate domain rating based on various factors
 */
export function estimateDomainRating(backlinksCount: number, uniqueDomains: number): number {
  const score = Math.log10(backlinksCount + 1) * 10 + Math.log10(uniqueDomains + 1) * 15;
  return Math.min(Math.round(score), 100);
}
