import cron, { ScheduledTask } from 'node-cron';
import { scrapeExpiredDomains } from '../scrapers/expiredDomainsScraper';

let isScrapingRunning = false;
let scheduledTask: ScheduledTask | null = null;
let currentSchedule = '0 2 * * *'; // Default: 2:00 AM daily

let lastScrapingResult: {
  timestamp: Date;
  scraped: number;
  saved: number;
  success: boolean;
  message: string;
} | null = null;

/**
 * What runs automatically at the scheduled time:
 * 
 * 1. Scrapes expireddomains.net for deleted/expired domains (3 pages by default)
 * 2. For each domain found:
 *    - Extracts basic metrics (backlinks, domain pop, birth year, archive snapshots)
 *    - Fetches MOZ metrics (Domain Authority, Page Authority, Spam Score) if API key configured
 *    - Runs security checks:
 *      a. DNS Blacklists (SURBL, URIBL, Barracuda) - always runs
 *      b. Spamhaus DBL/ZEN - if DQS key configured
 *      c. Google Safe Browsing - if API key configured
 *      d. VirusTotal - if API key configured
 *    - Calculates quality score (0-100)
 *    - Saves to database
 * 3. Sends email alerts for high-quality domains (if email configured)
 */
async function runScrapingJob() {
  if (isScrapingRunning) {
    console.log('[Scraping Job] Already running, skipping...');
    return;
  }

  isScrapingRunning = true;
  console.log('[Scraping Job] Starting automated scraping...');
  console.log('[Scraping Job] This will:');
  console.log('  1. Scrape expireddomains.net (3 pages)');
  console.log('  2. Fetch MOZ metrics (if API key configured)');
  console.log('  3. Run security checks (DNS blacklists + configured APIs)');
  console.log('  4. Calculate quality scores');
  console.log('  5. Save new domains to database');

  try {
    const result = await scrapeExpiredDomains(3); // Scrape 3 pages
    
    lastScrapingResult = {
      timestamp: new Date(),
      scraped: result.scraped,
      saved: result.saved,
      success: true,
      message: `Successfully scraped ${result.scraped} domains, saved ${result.saved} new domains`,
    };

    console.log(`[Scraping Job] ${lastScrapingResult.message}`);
  } catch (error: any) {
    lastScrapingResult = {
      timestamp: new Date(),
      scraped: 0,
      saved: 0,
      success: false,
      message: `Scraping failed: ${error.message}`,
    };

    console.error('[Scraping Job] Error:', error);
  } finally {
    isScrapingRunning = false;
  }
}

/**
 * Parse hour and minute from cron expression
 */
function parseCronTime(cronExpr: string): { hour: number; minute: number } {
  const parts = cronExpr.split(' ');
  return {
    minute: parseInt(parts[0]) || 0,
    hour: parseInt(parts[1]) || 2,
  };
}

/**
 * Create cron expression from hour and minute
 */
function createCronExpression(hour: number, minute: number): string {
  return `${minute} ${hour} * * *`;
}

/**
 * Initialize scraping scheduler with configurable time
 */
export function initializeScrapingScheduler(hour: number = 2, minute: number = 0) {
  // Stop existing task if any
  if (scheduledTask) {
    scheduledTask.stop();
  }

  currentSchedule = createCronExpression(hour, minute);
  
  scheduledTask = cron.schedule(currentSchedule, async () => {
    const time = `${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}`;
    console.log(`[Scraping Scheduler] Triggered at ${time}`);
    await runScrapingJob();
  });

  const time = `${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}`;
  console.log(`[Scraping Scheduler] Initialized - will run daily at ${time}`);
}

/**
 * Update schedule time
 */
export function updateScheduleTime(hour: number, minute: number) {
  if (hour < 0 || hour > 23 || minute < 0 || minute > 59) {
    throw new Error('Invalid time: hour must be 0-23, minute must be 0-59');
  }
  
  initializeScrapingScheduler(hour, minute);
  return { hour, minute };
}

/**
 * Get current schedule
 */
export function getCurrentSchedule(): { hour: number; minute: number; cronExpression: string } {
  const { hour, minute } = parseCronTime(currentSchedule);
  return { hour, minute, cronExpression: currentSchedule };
}

/**
 * Get last scraping result
 */
export function getLastScrapingResult() {
  return lastScrapingResult;
}

/**
 * Check if scraping is currently running
 */
export function isScrapingActive() {
  return isScrapingRunning;
}

/**
 * Manually trigger scraping job
 */
export async function triggerManualScraping(maxPages: number = 3) {
  if (isScrapingRunning) {
    throw new Error('Scraping is already in progress');
  }

  isScrapingRunning = true;
  
  try {
    const result = await scrapeExpiredDomains(maxPages);
    
    lastScrapingResult = {
      timestamp: new Date(),
      scraped: result.scraped,
      saved: result.saved,
      success: true,
      message: `Successfully scraped ${result.scraped} domains, saved ${result.saved} new domains`,
    };

    return lastScrapingResult;
  } catch (error: any) {
    lastScrapingResult = {
      timestamp: new Date(),
      scraped: 0,
      saved: 0,
      success: false,
      message: `Scraping failed: ${error.message}`,
    };

    throw error;
  } finally {
    isScrapingRunning = false;
  }
}

/**
 * Get description of what runs automatically
 */
export function getScheduledJobDescription(): string[] {
  return [
    'Scrapes expireddomains.net for newly deleted/expired domains',
    'Fetches MOZ metrics (DA, PA, Spam Score) - requires MOZ API key',
    'Runs DNS blacklist checks (SURBL, URIBL, Barracuda) - always active',
    'Runs Spamhaus checks (DBL, ZEN, ZRD) - requires free DQS key',
    'Runs Google Safe Browsing check - requires free API key',
    'Runs VirusTotal reputation check - requires free API key',
    'Calculates quality score (0-100) for each domain',
    'Saves new domains to database (skips duplicates)',
    'Sends email alerts for high-quality domains (if configured)',
  ];
}
