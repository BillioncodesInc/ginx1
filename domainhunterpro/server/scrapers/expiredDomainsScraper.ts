import { chromium, Browser, Page } from 'playwright';
import { insertDomainWithMetrics, getScoreBreakdown } from '../db';
import { batchGetMozMetrics } from './mozApi';
import { batchSecurityCheck, securityResultToSpamScore, hasCleanSecurityHistory } from './securityChecker';
import { sendBatchDomainAlert, shouldSendAlert, DomainAlert } from '../alerts/emailAlerts';
import { createLogger } from '../_core/apiWrapper';
import {
  loginToExpiredDomains,
  hasExpiredDomainsCredentials,
  getCachedSession,
} from '../_core/expiredDomainsAuth';

const logger = createLogger('Scraper');

interface ScrapedDomain {
  domainName: string;
  tld: string;
  backlinks: number;
  domainPop: number;
  birthYear: number | null;          // Archive birth year (ABY)
  waybackYear?: number | null;       // Whois birth year (WBY)
  archiveSnapshots: number;          // Archive entries count (ACR)
  trustFlow: number;
  citationFlow: number;
  status: 'available' | 'registered' | 'pending';
  addDate?: string | null;
  regLength?: number;
  length?: number;
  // New fields from ExpiredDomains inspection
  majesticGlobalRank?: number;       // MMGR - Majestic Million Global Rank
  dmoz?: boolean;                    // Dmoz listing
  relatedDomains?: number;           // RDT - Related domains count
  wikipediaLinks?: number;           // WPL - Wikipedia links count
  registeredTlds?: number;           // How many TLDs are already registered
}

export class ExpiredDomainsScraper {
  private browser: Browser | null = null;
  private page: Page | null = null;

  async initialize() {
    this.browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });
    this.page = await this.browser.newPage();
    
    // Set user agent to avoid detection
    await this.page.setExtraHTTPHeaders({
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    });
  }

  async scrapeDeletedDomains(maxPages: number = 3): Promise<ScrapedDomain[]> {
    if (!this.page) {
      throw new Error('Scraper not initialized. Call initialize() first.');
    }

    const domains: ScrapedDomain[] = [];

    try {
      // Check if credentials are configured and attempt login
      const hasCredentials = await hasExpiredDomainsCredentials();
      let isAuthenticated = false;

      if (hasCredentials) {
        logger.info('ExpiredDomains credentials found, attempting login...');

        // Try to restore session from cache first
        const cachedCookies = await getCachedSession();
        if (cachedCookies) {
          const context = this.page.context();
          await context.addCookies(cachedCookies);
          logger.info('Restored session from cache');
          isAuthenticated = true;
        } else {
          // Perform full login
          const cookies = await loginToExpiredDomains(this.page);
          isAuthenticated = cookies !== null;
        }

        if (!isAuthenticated) {
          logger.warn('Failed to authenticate to ExpiredDomains.net');
        }
      } else {
        logger.warn('No ExpiredDomains credentials configured.');
      }

      // Navigate to deleted domains page on member subdomain (more data available when logged in)
      const baseUrl = isAuthenticated
        ? 'https://member.expireddomains.net/domains/combinedexpired/'
        : 'https://www.expireddomains.net/deleted-domains/';

      logger.info(`Navigating to ${baseUrl}...`);
      await this.page.goto(baseUrl, {
        waitUntil: 'networkidle',
        timeout: 60000,
      });

      // Check if redirected to login page
      let currentUrl = this.page.url();
      if (currentUrl.includes('/login/')) {
        logger.warn('Redirected to login page - need to authenticate');

        const cookies = await loginToExpiredDomains(this.page);
        if (cookies) {
          // Navigate back to deleted domains after login
          await this.page.goto(baseUrl, {
            waitUntil: 'networkidle',
            timeout: 60000,
          });
          currentUrl = this.page.url();
          isAuthenticated = true;
        }
      }

      logger.info(`Current URL: ${currentUrl}`);

      for (let pageNum = 1; pageNum <= maxPages; pageNum++) {
        logger.info(`Scraping page ${pageNum}...`);

        // Wait for the table to load
        const tableExists = await this.page.waitForSelector('table.base1, table tbody tr', { timeout: 15000 }).catch(() => null);

        if (!tableExists) {
          logger.warn(`No results table found on page ${pageNum}`);
          break;
        }

        // Extract domain data from the table using CSS class selectors
        const pageData = await this.page.evaluate(`
          (function() {
            var data = [];
            var rows = document.querySelectorAll('tbody tr');
            if (rows.length === 0) {
              var table = document.querySelector('table.base1') || document.querySelector('table');
              if (table) rows = table.querySelectorAll('tbody tr');
            }

            for (var i = 0; i < rows.length; i++) {
              var row = rows[i];

              // Get domain name from field_domain cell
              var domainCell = row.querySelector('.field_domain') || row.querySelector('td:first-child');
              if (!domainCell) continue;

              var domainLink = domainCell.querySelector('a');
              if (!domainLink) continue;

              var domainName = (domainLink.textContent || '').trim();
              if (!domainName || domainName.length < 3) continue;

              // Helper function to get text from a cell by class or fallback to index
              function getCellText(className, fallbackIndex) {
                var cell = row.querySelector('.' + className);
                if (cell) return (cell.textContent || '').trim();
                var cells = row.querySelectorAll('td');
                if (cells.length > fallbackIndex && cells[fallbackIndex]) {
                  return (cells[fallbackIndex].textContent || '').trim();
                }
                return '';
              }

              // Helper to parse first number from text
              function parseNum(text) {
                var match = text.match(/(\\d+)/);
                return match ? parseInt(match[1]) : 0;
              }

              // Helper to parse year from text
              function parseYear(text) {
                var match = text.match(/(\\d{4})/);
                if (match) {
                  var year = parseInt(match[1]);
                  if (year >= 1990 && year <= 2030) return year;
                }
                return null;
              }

              // Helper to parse numbers with K/M suffix (e.g., "5.5 M" -> 5500000)
              function parseNumWithSuffix(text) {
                if (!text) return 0;
                var clean = text.replace(/,/g, '').trim();
                var match = clean.match(/([\\d.]+)\\s*([KMkm])?/);
                if (!match) return 0;
                var num = parseFloat(match[1]);
                var suffix = (match[2] || '').toUpperCase();
                if (suffix === 'K') return Math.round(num * 1000);
                if (suffix === 'M') return Math.round(num * 1000000);
                return Math.round(num);
              }

              // Extract data using CSS classes (primary) or column indices (fallback)
              var blText = getCellText('field_bl', 4);
              var dpText = getCellText('field_domainpop', 5);
              var wbyText = getCellText('field_creationdate', 6);
              var abyText = getCellText('field_abirth', 7);
              var acrText = getCellText('field_aentries', 8);
              var mmgrText = getCellText('field_majestic_globalrank', 9);
              var dmozText = getCellText('field_dmoz', 10);
              var regTldsText = getCellText('field_statustld_registered', 11);
              var addDateText = getCellText('field_adddate', 18);
              var relatedText = getCellText('field_related_cnobi', 19);
              var wplText = getCellText('field_wikipedia_links', 20);
              var statusText = getCellText('field_whois', 22);
              var lengthText = getCellText('field_length', 3);

              // Parse the values (with K/M suffix support)
              var blVal = parseNumWithSuffix(blText);
              var dpVal = parseNumWithSuffix(dpText);
              var acrVal = parseNumWithSuffix(acrText);
              var mmgrVal = parseNumWithSuffix(mmgrText);
              var relatedVal = parseNumWithSuffix(relatedText);
              var wplVal = parseNumWithSuffix(wplText);
              var regTldsVal = parseNum(regTldsText);
              var wbyVal = parseYear(wbyText);
              var abyVal = parseYear(abyText);
              var lengthVal = parseNum(lengthText);

              // Parse dmoz (Yes/-)
              var dmozVal = dmozText.toLowerCase().indexOf('yes') !== -1;

              // Parse add date
              var addDate = null;
              var dateMatch = addDateText.match(/(\\d{4}-\\d{2}-\\d{2})/);
              if (dateMatch) addDate = dateMatch[1];

              // Parse status
              var status = 'available';
              var statusLower = statusText.toLowerCase();
              if (statusLower.indexOf('pending') !== -1) status = 'pending';
              else if (statusLower.indexOf('registered') !== -1) status = 'registered';

              data.push({
                domainName: domainName,
                backlinks: blVal,
                domainPop: dpVal,
                waybackYear: wbyVal,
                birthYear: abyVal,
                archiveSnapshots: acrVal,
                length: lengthVal,
                status: status,
                addDate: addDate,
                majesticGlobalRank: mmgrVal,
                dmoz: dmozVal,
                relatedDomains: relatedVal,
                wikipediaLinks: wplVal,
                registeredTlds: regTldsVal
              });
            }

            return data;
          })()
        `) as any[];

        // Process each domain
        for (const domain of pageData) {
          const parts = domain.domainName.split('.');
          const tld = parts.length > 1 ? parts[parts.length - 1] : 'com';
          const domainWithoutTld = parts.slice(0, -1).join('.');

          // Estimate Trust Flow and Citation Flow based on backlinks and Majestic rank
          // If domain has a Majestic rank, it's likely more authoritative
          let trustFlow = Math.min(Math.floor(domain.backlinks / 5), 100);
          let citationFlow = Math.min(Math.floor(domain.backlinks / 4), 100);

          // Boost TF/CF if domain has Majestic Million rank (lower rank = better)
          if (domain.majesticGlobalRank > 0 && domain.majesticGlobalRank < 1000000) {
            const rankBoost = Math.floor((1000000 - domain.majesticGlobalRank) / 20000);
            trustFlow = Math.min(trustFlow + rankBoost, 100);
            citationFlow = Math.min(citationFlow + rankBoost, 100);
          }

          domains.push({
            domainName: domain.domainName,
            tld,
            backlinks: domain.backlinks,
            domainPop: domain.domainPop,
            birthYear: domain.birthYear,
            waybackYear: domain.waybackYear,
            archiveSnapshots: domain.archiveSnapshots,
            trustFlow,
            citationFlow,
            status: domain.status || 'available',
            addDate: domain.addDate,
            length: domain.length || domainWithoutTld.length,
            majesticGlobalRank: domain.majesticGlobalRank || 0,
            dmoz: domain.dmoz || false,
            relatedDomains: domain.relatedDomains || 0,
            wikipediaLinks: domain.wikipediaLinks || 0,
            registeredTlds: domain.registeredTlds || 0,
          });
        }

        logger.info(`Scraped ${pageData.length} domains from page ${pageNum}`);

        // Try to go to next page if not the last one
        if (pageNum < maxPages) {
          try {
            // Use URL-based pagination for member subdomain
            if (isAuthenticated) {
              const nextStart = pageNum * 25;
              const nextPageUrl = `https://member.expireddomains.net/domains/combinedexpired/?start=${nextStart}#listing`;

              logger.info(`Navigating to page ${pageNum + 1}: ${nextPageUrl}`);

              await this.page.goto(nextPageUrl, {
                waitUntil: 'networkidle',
                timeout: 30000,
              });
              await this.page.waitForTimeout(2000);

              // Check if we actually got results on this page
              const hasMoreResults = await this.page.evaluate(`
                (function() {
                  return document.querySelectorAll('tbody tr').length > 0;
                })()
              `);

              if (!hasMoreResults) {
                logger.info('No more results on next page, stopping pagination');
                break;
              }
            } else {
              // Fallback to clicking Next button for public page
              const nextButton = await this.page.$('a:has-text("Next Page")');
              if (nextButton) {
                await Promise.all([
                  this.page.waitForNavigation({ waitUntil: 'networkidle', timeout: 30000 }),
                  nextButton.click(),
                ]);
                await this.page.waitForTimeout(2000);
              } else {
                logger.info('No next page button found, stopping pagination');
                break;
              }
            }
          } catch (error) {
            logger.warn('Error navigating to next page', { error: String(error) });
            break;
          }
        }
      }
    } catch (error) {
      logger.error('Error scraping expireddomains.net', error);
      throw error;
    }

    return domains;
  }

  async saveDomains(domains: ScrapedDomain[]): Promise<number> {
    let savedCount = 0;
    const highQualityDomains: DomainAlert[] = [];
    
    const domainNames = domains.map(d => d.domainName);

    // Batch fetch Moz metrics for all domains
    logger.info(`Fetching Moz metrics for ${domains.length} domains...`);
    const mozMetrics = await batchGetMozMetrics(domainNames);
    logger.info('Moz metrics fetched successfully');

    // Batch security checks for all domains
    logger.info(`Running security checks for ${domains.length} domains...`);
    const securityResults = await batchSecurityCheck(domainNames);
    logger.info('Security checks completed');
    
    for (const domain of domains) {
      const moz = mozMetrics.get(domain.domainName);
      const security = securityResults.get(domain.domainName);
      
      // Calculate spam score: combine Moz spam score with security risk score
      let finalSpamScore = moz?.spamScore || 0;
      if (security) {
        // If security checks found issues, use the higher score
        const securitySpamScore = securityResultToSpamScore(security);
        finalSpamScore = Math.max(finalSpamScore, securitySpamScore);
      }
      
      // Determine clean history based on both Moz and security checks
      const cleanHistory = security ? hasCleanSecurityHistory(security) : true;
      
      try {
        await insertDomainWithMetrics(
          {
            domainName: domain.domainName,
            tld: domain.tld,
            status: domain.status,
            birthYear: domain.birthYear,
            droppedDate: new Date(),
          },
          {
            backlinksCount: domain.backlinks,
            domainPop: domain.domainPop,
            trustFlow: domain.trustFlow,
            citationFlow: domain.citationFlow,
            domainAuthority: moz?.domainAuthority || 0,
            pageAuthority: moz?.pageAuthority || 0,
            archiveSnapshots: domain.archiveSnapshots,
            spamScore: finalSpamScore,
            isDictionaryWord: false, // Would need dictionary check
            hasCleanHistory: cleanHistory,
            // New metrics from ExpiredDomains.net
            majesticGlobalRank: domain.majesticGlobalRank || 0,
            inDmoz: domain.dmoz || false,
            wikipediaLinks: domain.wikipediaLinks || 0,
            relatedDomains: domain.relatedDomains || 0,
            registeredTlds: domain.registeredTlds || 0,
          }
        );
        
        // Calculate quality score for alert check using the centralized scoring function
        const scoreBreakdown = getScoreBreakdown({
          backlinksCount: domain.backlinks,
          domainPop: domain.domainPop,
          trustFlow: domain.trustFlow,
          citationFlow: domain.citationFlow,
          domainAuthority: moz?.domainAuthority || 0,
          pageAuthority: moz?.pageAuthority || 0,
          archiveSnapshots: domain.archiveSnapshots,
          spamScore: finalSpamScore,
          isDictionaryWord: false,
          hasCleanHistory: cleanHistory,
          birthYear: domain.birthYear,
          // New metrics from ExpiredDomains.net
          majesticGlobalRank: domain.majesticGlobalRank || 0,
          inDmoz: domain.dmoz || false,
          wikipediaLinks: domain.wikipediaLinks || 0,
        });
        const qualityScore = scoreBreakdown.total;
        const currentYear = new Date().getFullYear();
        const age = domain.birthYear ? currentYear - domain.birthYear : null;
        
        // Check if domain qualifies for alert
        if (shouldSendAlert(qualityScore)) {
          highQualityDomains.push({
            domainName: domain.domainName,
            qualityScore,
            domainAuthority: moz?.domainAuthority || 0,
            pageAuthority: moz?.pageAuthority || 0,
            backlinks: domain.backlinks,
            trustFlow: domain.trustFlow,
            citationFlow: domain.citationFlow,
            age,
          });
        }
        savedCount++;
      } catch (error: any) {
        // Skip duplicates
        if (error.message?.includes('Duplicate entry') || error.message?.includes('UNIQUE constraint')) {
          logger.info(`Skipping duplicate domain: ${domain.domainName}`);
        } else {
          logger.error(`Error saving domain ${domain.domainName}`, error);
        }
      }
    }

    // Send batch email alert for high-quality domains
    if (highQualityDomains.length > 0) {
      logger.info(`Found ${highQualityDomains.length} high-quality domains, sending alert...`);
      await sendBatchDomainAlert(highQualityDomains);
    }
    
    return savedCount;
  }

  async close() {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      this.page = null;
    }
  }

  async scrapeAndSave(maxPages: number = 3): Promise<{ scraped: number; saved: number }> {
    try {
      logger.info('Initializing browser...');
      await this.initialize();
      logger.info('Browser initialized, starting scrape...');
      const domains = await this.scrapeDeletedDomains(maxPages);
      logger.info(`Scraped ${domains.length} domains, saving to database...`);

      if (domains.length === 0) {
        logger.warn('No domains found - site may be blocking or structure changed');
        return { scraped: 0, saved: 0 };
      }

      const saved = await this.saveDomains(domains);
      logger.info(`Saved ${saved} domains to database`);

      return {
        scraped: domains.length,
        saved,
      };
    } catch (error: any) {
      logger.error('Error during scrape', error);
      throw error;
    } finally {
      logger.info('Closing browser...');
      await this.close();
    }
  }
}

// Standalone function for easy testing
export async function scrapeExpiredDomains(maxPages: number = 3) {
  const scraper = new ExpiredDomainsScraper();
  return await scraper.scrapeAndSave(maxPages);
}

/**
 * Interface for enriched domain results returned by keyword search
 */
export interface EnrichedDomainResult {
  domain: {
    id: number;
    domainName: string;
    tld: string;
    status: 'available' | 'registered' | 'pending';
    birthYear: number | null;
    waybackYear: number | null;
    droppedDate: Date | null;
    addDate: string | null;
    length: number;
  };
  metrics: {
    qualityScore: number;
    domainAuthority: number;
    pageAuthority: number;
    backlinksCount: number;
    trustFlow: number;
    citationFlow: number;
    domainPop: number;
    archiveSnapshots: number;
    spamScore: number;
    regLength: number;
    // New metrics from ExpiredDomains.net
    majesticGlobalRank?: number;
    inDmoz?: boolean;
    wikipediaLinks?: number;
    relatedDomains?: number;
    registeredTlds?: number;
  };
}

/**
 * Options for keyword search scraping
 */
export interface ScrapeByKeywordOptions {
  /** AbortSignal for cancellation support */
  signal?: AbortSignal;
  /** Callback to report partial results as pages are scraped */
  onProgress?: (results: EnrichedDomainResult[], page: number, totalPages: number) => Promise<void>;
}

/**
 * Scrape domains by keyword - performs live scraping and returns enriched results
 * This is used by the search bar for on-demand domain discovery
 */
export async function scrapeByKeyword(
  keyword: string,
  maxPages: number = 1,
  options?: ScrapeByKeywordOptions
): Promise<EnrichedDomainResult[]> {
  const scraper = new ExpiredDomainsScraper();
  const results: EnrichedDomainResult[] = [];
  const { signal, onProgress } = options || {};

  try {
    // Check if already aborted before starting
    if (signal?.aborted) {
      throw new Error('Search cancelled');
    }

    logger.info(`Starting keyword search for: "${keyword}"`);
    await scraper.initialize();

    // Check abort after initialization
    if (signal?.aborted) {
      throw new Error('Search cancelled');
    }

    if (!scraper['page']) {
      throw new Error('Scraper not initialized');
    }

    // Check if credentials are configured and attempt login
    const hasCredentials = await hasExpiredDomainsCredentials();
    let isAuthenticated = false;

    if (hasCredentials) {
      logger.info('ExpiredDomains credentials found, attempting login...');

      // Try to restore session from cache first
      const cachedCookies = await getCachedSession();
      if (cachedCookies) {
        const context = scraper['page'].context();
        await context.addCookies(cachedCookies);
        logger.info('Restored session from cache');
        isAuthenticated = true;
      } else {
        // Perform full login
        const cookies = await loginToExpiredDomains(scraper['page']);
        isAuthenticated = cookies !== null;
      }

      if (!isAuthenticated) {
        logger.warn('Failed to authenticate to ExpiredDomains.net, search results may be limited');
      }
    } else {
      logger.warn('No ExpiredDomains credentials configured. Keyword search requires login.');
      logger.warn('Configure credentials in Settings to enable keyword-based domain search.');
    }

    // Check abort after authentication
    if (signal?.aborted) {
      throw new Error('Search cancelled');
    }

    // Navigate directly to the search results URL on member subdomain
    // Format: https://member.expireddomains.net/domain-name-search/?q=KEYWORD&searchinit=1
    const searchUrl = `https://member.expireddomains.net/domain-name-search/?q=${encodeURIComponent(keyword)}&searchinit=1`;

    logger.info(`Navigating to search URL: ${searchUrl}`);

    await scraper['page'].goto(searchUrl, {
      waitUntil: 'networkidle',
      timeout: 60000,
    });

    // Log current page state for debugging
    let currentUrl = scraper['page'].url();
    logger.info(`Current URL after navigation: ${currentUrl}`);

    // Check if we were redirected to login page
    if (currentUrl.includes('/login/')) {
      logger.warn('Redirected to login page - need to authenticate');

      // Perform login
      const cookies = await loginToExpiredDomains(scraper['page']);
      if (!cookies) {
        throw new Error('Failed to authenticate. Please check your ExpiredDomains credentials in Settings.');
      }

      // After login, navigate back to search URL
      logger.info(`Re-navigating to search URL after login: ${searchUrl}`);
      await scraper['page'].goto(searchUrl, {
        waitUntil: 'networkidle',
        timeout: 60000,
      });

      currentUrl = scraper['page'].url();
      logger.info(`URL after re-navigation: ${currentUrl}`);
    }

    // Check abort after navigation
    if (signal?.aborted) {
      throw new Error('Search cancelled');
    }

    // Give the page time to fully render
    await scraper['page'].waitForTimeout(2000);

    // Check page state
    const pageState = await scraper['page'].evaluate(`
      (function() {
        var html = document.documentElement.innerHTML;
        var hasTable = document.querySelector('table.base1') !== null ||
                       document.querySelectorAll('tbody tr').length > 0;
        var noResults = html.indexOf('No domains found') !== -1 ||
                       html.indexOf('no matching') !== -1 ||
                       html.indexOf('0 Deleted') !== -1 ||
                       html.indexOf('Nothing found') !== -1;
        var needsLogin = document.title.toLowerCase().indexOf('login') !== -1 ||
                        html.indexOf('Please login') !== -1 ||
                        html.indexOf('Login required') !== -1;
        var rowCount = document.querySelectorAll('tbody tr').length;
        return {
          hasTable: hasTable,
          noResults: noResults,
          needsLogin: needsLogin,
          title: document.title,
          rowCount: rowCount,
          url: window.location.href
        };
      })()
    `) as { hasTable: boolean; noResults: boolean; needsLogin: boolean; title: string; rowCount: number; url: string };

    logger.info(`Page state: hasTable=${pageState.hasTable}, noResults=${pageState.noResults}, rowCount=${pageState.rowCount}, title="${pageState.title}"`);

    if (pageState.needsLogin) {
      throw new Error('ExpiredDomains requires login for this search. Please check your credentials.');
    }

    if (pageState.noResults && pageState.rowCount === 0) {
      logger.info(`No results found for keyword "${keyword}"`);
      return [];
    }

    const domains: ScrapedDomain[] = [];

    for (let pageNum = 1; pageNum <= maxPages; pageNum++) {
      // Check abort at start of each page
      if (signal?.aborted) {
        logger.info('Search cancelled by user');
        break;
      }

      logger.info(`Scraping page ${pageNum} for keyword "${keyword}"...`);

      // Wait for the table to load (use more specific selector)
      const tableExists = await scraper['page'].waitForSelector('table.base1, table tbody tr', { timeout: 15000 }).catch(() => null);

      if (!tableExists) {
        logger.warn(`No results table found on page ${pageNum}`);
        break;
      }

      // Extract domain data from the table using CSS class selectors
      // ExpiredDomains.net uses field_* classes for each column:
      // field_domain, field_length, field_bl, field_domainpop, field_creationdate,
      // field_abirth, field_aentries, field_adddate, field_whois2, etc.
      const pageData = await scraper['page'].evaluate(`
        (function() {
          var data = [];

          // Find rows in the domain listing table
          var rows = document.querySelectorAll('tbody tr');
          if (rows.length === 0) {
            // Fallback: try to find table with domain links
            var table = document.querySelector('table.base1') || document.querySelector('table');
            if (table) rows = table.querySelectorAll('tbody tr');
          }

          for (var i = 0; i < rows.length; i++) {
            var row = rows[i];

            // Get domain name from field_domain cell
            var domainCell = row.querySelector('.field_domain') || row.querySelector('td:first-child');
            if (!domainCell) continue;

            var domainLink = domainCell.querySelector('a');
            if (!domainLink) continue;

            var domainName = (domainLink.textContent || '').trim();
            if (!domainName || domainName.length < 3) continue;

            // Helper function to get text from a cell by class or fallback to index
            function getCellText(className, fallbackIndex) {
              var cell = row.querySelector('.' + className);
              if (cell) return (cell.textContent || '').trim();
              var cells = row.querySelectorAll('td');
              if (cells.length > fallbackIndex && cells[fallbackIndex]) {
                return (cells[fallbackIndex].textContent || '').trim();
              }
              return '';
            }

            // Helper to parse first number from text
            function parseNum(text) {
              var match = text.match(/(\\d+)/);
              return match ? parseInt(match[1]) : 0;
            }

            // Helper to parse year from text
            function parseYear(text) {
              var match = text.match(/(\\d{4})/);
              if (match) {
                var year = parseInt(match[1]);
                if (year >= 1990 && year <= 2030) return year;
              }
              return null;
            }

            // Helper to parse numbers with K/M suffix (e.g., "5.5 M" -> 5500000)
            function parseNumWithSuffix(text) {
              if (!text) return 0;
              var clean = text.replace(/,/g, '').trim();
              var match = clean.match(/([\\d.]+)\\s*([KMkm])?/);
              if (!match) return 0;
              var num = parseFloat(match[1]);
              var suffix = (match[2] || '').toUpperCase();
              if (suffix === 'K') return Math.round(num * 1000);
              if (suffix === 'M') return Math.round(num * 1000000);
              return Math.round(num);
            }

            // Extract data using CSS classes (primary) or column indices (fallback)
            var blText = getCellText('field_bl', 4);
            var dpText = getCellText('field_domainpop', 5);
            var wbyText = getCellText('field_creationdate', 6);  // Whois birth year
            var abyText = getCellText('field_abirth', 7);        // Archive birth year
            var acrText = getCellText('field_aentries', 8);      // Archive count
            var mmgrText = getCellText('field_majestic_globalrank', 9);  // Majestic Million Rank
            var dmozText = getCellText('field_dmoz', 10);        // DMOZ listing
            var regTldsText = getCellText('field_statustld_registered', 11);  // Registered TLDs
            var addDateText = getCellText('field_adddate', 18);  // Add/dropped date
            var relatedText = getCellText('field_related_cnobi', 19);  // Related domains
            var wplText = getCellText('field_wikipedia_links', 20);    // Wikipedia links
            var statusText = getCellText('field_whois', 22);    // Status
            var lengthText = getCellText('field_length', 3);     // Domain length

            // Parse the values (with K/M suffix support)
            var blVal = parseNumWithSuffix(blText);
            var dpVal = parseNumWithSuffix(dpText);
            var acrVal = parseNumWithSuffix(acrText);
            var mmgrVal = parseNumWithSuffix(mmgrText);
            var relatedVal = parseNumWithSuffix(relatedText);
            var wplVal = parseNumWithSuffix(wplText);
            var regTldsVal = parseNum(regTldsText);
            var wbyVal = parseYear(wbyText);
            var abyVal = parseYear(abyText);
            var lengthVal = parseNum(lengthText);

            // Parse dmoz (Yes/-)
            var dmozVal = dmozText.toLowerCase().indexOf('yes') !== -1;

            // Parse add date (format: YYYY-MM-DD)
            var addDate = null;
            var dateMatch = addDateText.match(/(\\d{4}-\\d{2}-\\d{2})/);
            if (dateMatch) addDate = dateMatch[1];

            // Parse status
            var status = 'available';
            var statusLower = statusText.toLowerCase();
            if (statusLower.indexOf('pending') !== -1) status = 'pending';
            else if (statusLower.indexOf('registered') !== -1) status = 'registered';

            data.push({
              domainName: domainName,
              backlinks: blVal,
              domainPop: dpVal,
              waybackYear: wbyVal,
              birthYear: abyVal,
              archiveSnapshots: acrVal,
              length: lengthVal,
              status: status,
              addDate: addDate,
              majesticGlobalRank: mmgrVal,
              dmoz: dmozVal,
              relatedDomains: relatedVal,
              wikipediaLinks: wplVal,
              registeredTlds: regTldsVal
            });
          }

          return data;
        })()
      `) as any[];

      // Process each domain
      for (const domain of pageData) {
        const parts = domain.domainName.split('.');
        const tld = parts.length > 1 ? parts[parts.length - 1] : 'com';
        const domainWithoutTld = parts.slice(0, -1).join('.');

        // Estimate Trust Flow and Citation Flow based on backlinks and Majestic rank
        let trustFlow = Math.min(Math.floor(domain.backlinks / 5), 100);
        let citationFlow = Math.min(Math.floor(domain.backlinks / 4), 100);

        // Boost TF/CF if domain has Majestic Million rank (lower rank = better)
        if (domain.majesticGlobalRank > 0 && domain.majesticGlobalRank < 1000000) {
          const rankBoost = Math.floor((1000000 - domain.majesticGlobalRank) / 20000);
          trustFlow = Math.min(trustFlow + rankBoost, 100);
          citationFlow = Math.min(citationFlow + rankBoost, 100);
        }

        domains.push({
          domainName: domain.domainName,
          tld,
          backlinks: domain.backlinks,
          domainPop: domain.domainPop,
          birthYear: domain.birthYear,
          waybackYear: domain.waybackYear,
          archiveSnapshots: domain.archiveSnapshots,
          trustFlow,
          citationFlow,
          status: domain.status || 'available',
          addDate: domain.addDate,
          regLength: domain.regLength || 0,
          length: domain.length || domainWithoutTld.length,
          majesticGlobalRank: domain.majesticGlobalRank || 0,
          dmoz: domain.dmoz || false,
          relatedDomains: domain.relatedDomains || 0,
          wikipediaLinks: domain.wikipediaLinks || 0,
          registeredTlds: domain.registeredTlds || 0,
        });
      }

      logger.info(`Found ${pageData.length} domains on page ${pageNum}`);

      // Check abort after page processing
      if (signal?.aborted) {
        logger.info('Search cancelled by user after page processing');
        break;
      }

      // Try to go to next page if not the last one
      if (pageNum < maxPages) {
        try {
          // ExpiredDomains uses start=25, start=50, etc. for pagination (25 results per page)
          const nextStart = pageNum * 25;
          const nextPageUrl = `https://member.expireddomains.net/domain-name-search/?start=${nextStart}&q=${encodeURIComponent(keyword)}#listing`;

          logger.info(`Navigating to page ${pageNum + 1}: ${nextPageUrl}`);

          await scraper['page'].goto(nextPageUrl, {
            waitUntil: 'networkidle',
            timeout: 30000,
          });
          await scraper['page'].waitForTimeout(2000);

          // Check if we actually got results on this page
          const hasMoreResults = await scraper['page'].evaluate(`
            (function() {
              return document.querySelectorAll('tbody tr').length > 0;
            })()
          `);

          if (!hasMoreResults) {
            logger.info('No more results on next page, stopping pagination');
            break;
          }
        } catch (error) {
          logger.warn('Error navigating to next page', { error: String(error) });
          break;
        }
      }
    }

    if (domains.length === 0) {
      logger.info(`No domains found for keyword "${keyword}"`);
      return [];
    }

    // Check abort before enrichment (most expensive step)
    if (signal?.aborted) {
      logger.info('Search cancelled before enrichment');
      // Return partial results without enrichment
      return domains.map((d, i) => ({
        domain: {
          id: i,
          domainName: d.domainName,
          tld: d.tld,
          status: d.status,
          birthYear: d.birthYear,
          waybackYear: d.waybackYear || null,
          droppedDate: d.addDate ? new Date(d.addDate) : new Date(),
          addDate: d.addDate || null,
          length: d.length || d.domainName.split('.')[0].length,
        },
        metrics: {
          qualityScore: 0,
          domainAuthority: 0,
          pageAuthority: 0,
          backlinksCount: d.backlinks,
          trustFlow: d.trustFlow,
          citationFlow: d.citationFlow,
          domainPop: d.domainPop,
          archiveSnapshots: d.archiveSnapshots,
          spamScore: 0,
          regLength: d.regLength || 0,
        },
      }));
    }

    // Enrich domains with Moz metrics and security data
    logger.info(`Enriching ${domains.length} domains with metrics...`);
    const domainNames = domains.map(d => d.domainName);

    // Batch fetch Moz metrics
    const mozMetrics = await batchGetMozMetrics(domainNames);

    // Batch security checks
    const securityResults = await batchSecurityCheck(domainNames);

    // Build enriched results
    for (let i = 0; i < domains.length; i++) {
      const domain = domains[i];
      const moz = mozMetrics.get(domain.domainName);
      const security = securityResults.get(domain.domainName);

      // Calculate spam score
      let finalSpamScore = moz?.spamScore || 0;
      if (security) {
        const securitySpamScore = securityResultToSpamScore(security);
        finalSpamScore = Math.max(finalSpamScore, securitySpamScore);
      }

      const cleanHistory = security ? hasCleanSecurityHistory(security) : true;

      // Calculate quality score
      const scoreBreakdown = getScoreBreakdown({
        backlinksCount: domain.backlinks,
        domainPop: domain.domainPop,
        trustFlow: domain.trustFlow,
        citationFlow: domain.citationFlow,
        domainAuthority: moz?.domainAuthority || 0,
        pageAuthority: moz?.pageAuthority || 0,
        archiveSnapshots: domain.archiveSnapshots,
        spamScore: finalSpamScore,
        isDictionaryWord: false,
        hasCleanHistory: cleanHistory,
        birthYear: domain.birthYear,
        // New metrics from ExpiredDomains.net
        majesticGlobalRank: domain.majesticGlobalRank || 0,
        inDmoz: domain.dmoz || false,
        wikipediaLinks: domain.wikipediaLinks || 0,
      });

      results.push({
        domain: {
          id: i, // Temporary ID for frontend
          domainName: domain.domainName,
          tld: domain.tld,
          status: domain.status,
          birthYear: domain.birthYear,
          waybackYear: domain.waybackYear || null,
          droppedDate: domain.addDate ? new Date(domain.addDate) : new Date(),
          addDate: domain.addDate || null,
          length: domain.length || domain.domainName.split('.')[0].length,
        },
        metrics: {
          qualityScore: scoreBreakdown.total,
          domainAuthority: moz?.domainAuthority || 0,
          pageAuthority: moz?.pageAuthority || 0,
          backlinksCount: domain.backlinks,
          trustFlow: domain.trustFlow,
          citationFlow: domain.citationFlow,
          domainPop: domain.domainPop,
          archiveSnapshots: domain.archiveSnapshots,
          spamScore: finalSpamScore,
          regLength: domain.regLength || 0,
          // New metrics from ExpiredDomains.net
          majesticGlobalRank: domain.majesticGlobalRank || 0,
          inDmoz: domain.dmoz || false,
          wikipediaLinks: domain.wikipediaLinks || 0,
          relatedDomains: domain.relatedDomains || 0,
          registeredTlds: domain.registeredTlds || 0,
        },
      });
    }

    // Sort by quality score descending
    results.sort((a, b) => b.metrics.qualityScore - a.metrics.qualityScore);

    // Report final progress
    if (onProgress) {
      try {
        await onProgress(results, maxPages, maxPages);
      } catch (e) {
        logger.warn('Error in progress callback', { error: String(e) });
      }
    }

    logger.info(`Returning ${results.length} enriched domains for keyword "${keyword}"`);
    return results;

  } catch (error: any) {
    logger.error(`Error scraping for keyword "${keyword}"`, error);
    throw error;
  } finally {
    await scraper.close();
  }
}

