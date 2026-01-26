/**
 * Stealth browser utility using puppeteer-extra
 * Bypasses common anti-bot detection mechanisms
 */

import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import type { Browser, Page, LaunchOptions } from 'puppeteer';

// Re-export types for consumers
export type { Page, Browser };

// Add stealth plugin to puppeteer
puppeteer.use(StealthPlugin());

let browserInstance: Browser | null = null;

export interface StealthBrowserOptions {
  headless?: boolean;
  proxy?: string;
  timeout?: number;
  userAgent?: string;
}

const DEFAULT_USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
];

/**
 * Get a random user agent
 */
function getRandomUserAgent(): string {
  return DEFAULT_USER_AGENTS[Math.floor(Math.random() * DEFAULT_USER_AGENTS.length)];
}

/**
 * Launch or get existing stealth browser instance
 */
export async function getStealthBrowser(options: StealthBrowserOptions = {}): Promise<Browser> {
  if (browserInstance && browserInstance.isConnected()) {
    return browserInstance;
  }

  const launchOptions: LaunchOptions = {
    headless: options.headless !== false,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-accelerated-2d-canvas',
      '--disable-gpu',
      '--window-size=1920,1080',
      '--disable-blink-features=AutomationControlled',
    ],
  };

  if (options.proxy) {
    launchOptions.args?.push(`--proxy-server=${options.proxy}`);
  }

  browserInstance = await puppeteer.launch(launchOptions);
  return browserInstance;
}

/**
 * Create a new stealth page with anti-detection measures
 */
export async function createStealthPage(options: StealthBrowserOptions = {}): Promise<Page> {
  const browser = await getStealthBrowser(options);
  const page = await browser.newPage();

  // Set random viewport
  await page.setViewport({
    width: 1920 + Math.floor(Math.random() * 100),
    height: 1080 + Math.floor(Math.random() * 100),
  });

  // Set user agent
  const userAgent = options.userAgent || getRandomUserAgent();
  await page.setUserAgent(userAgent);

  // Set extra HTTP headers
  await page.setExtraHTTPHeaders({
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
  });

  // Override navigator properties
  await page.evaluateOnNewDocument(() => {
    // Override webdriver property
    Object.defineProperty(navigator, 'webdriver', { get: () => false });

    // Override plugins
    Object.defineProperty(navigator, 'plugins', {
      get: () => [
        { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
        { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
        { name: 'Native Client', filename: 'internal-nacl-plugin' },
      ],
    });

    // Override languages
    Object.defineProperty(navigator, 'languages', {
      get: () => ['en-US', 'en'],
    });

    // Override chrome property
    (window as any).chrome = {
      runtime: {},
      loadTimes: function () {},
      csi: function () {},
      app: {},
    };
  });

  // Set default timeout
  page.setDefaultTimeout(options.timeout || 30000);
  page.setDefaultNavigationTimeout(options.timeout || 30000);

  return page;
}

/**
 * Navigate to a URL with stealth measures and wait for content
 */
export async function stealthNavigate(
  page: Page,
  url: string,
  options: {
    waitUntil?: 'load' | 'domcontentloaded' | 'networkidle0' | 'networkidle2';
    waitForSelector?: string;
    humanDelay?: boolean;
  } = {}
): Promise<void> {
  const { waitUntil = 'networkidle2', waitForSelector, humanDelay = true } = options;

  // Random delay before navigation to appear more human
  if (humanDelay) {
    await page.evaluate(() => new Promise((r) => setTimeout(r, Math.random() * 2000 + 500)));
  }

  await page.goto(url, { waitUntil });

  if (waitForSelector) {
    await page.waitForSelector(waitForSelector, { timeout: 10000 });
  }

  // Random delay after navigation
  if (humanDelay) {
    await page.evaluate(() => new Promise((r) => setTimeout(r, Math.random() * 1000 + 500)));
  }
}

/**
 * Scroll page like a human
 */
export async function humanScroll(page: Page): Promise<void> {
  await page.evaluate(async () => {
    await new Promise<void>((resolve) => {
      let totalHeight = 0;
      const distance = 100 + Math.random() * 100;
      const timer = setInterval(() => {
        window.scrollBy(0, distance);
        totalHeight += distance;

        if (totalHeight >= document.body.scrollHeight * 0.7) {
          clearInterval(timer);
          resolve();
        }
      }, 100 + Math.random() * 200);
    });
  });
}

/**
 * Extract text content from page
 */
export async function extractPageContent(page: Page): Promise<string> {
  return page.evaluate(() => document.body.innerText);
}

/**
 * Extract HTML content from page
 */
export async function extractPageHtml(page: Page): Promise<string> {
  return page.content();
}

/**
 * Close a page safely
 */
export async function closePage(page: Page): Promise<void> {
  try {
    if (!page.isClosed()) {
      await page.close();
    }
  } catch {
    // Page may already be closed
  }
}

/**
 * Close the browser instance
 */
export async function closeBrowser(): Promise<void> {
  if (browserInstance) {
    try {
      await browserInstance.close();
    } catch {
      // Browser may already be closed
    }
    browserInstance = null;
  }
}

/**
 * Execute a scraping operation with stealth browser
 */
export async function withStealthBrowser<T>(
  url: string,
  operation: (page: Page) => Promise<T>,
  options: StealthBrowserOptions = {}
): Promise<T> {
  const page = await createStealthPage(options);

  try {
    await stealthNavigate(page, url);
    return await operation(page);
  } finally {
    await closePage(page);
  }
}

// Cleanup on process exit
process.on('exit', () => {
  if (browserInstance) {
    browserInstance.close().catch(() => {});
  }
});

process.on('SIGINT', async () => {
  await closeBrowser();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await closeBrowser();
  process.exit(0);
});
