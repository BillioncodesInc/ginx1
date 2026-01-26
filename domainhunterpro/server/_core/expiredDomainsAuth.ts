/**
 * ExpiredDomains.net Authentication Module
 *
 * Handles login and session management for ExpiredDomains.net
 * Required for keyword-based domain search functionality.
 */

import { getAppSetting, setAppSetting } from "../db";
import { createLogger } from "./apiWrapper";

const logger = createLogger('ExpiredDomainsAuth');

// Session storage
interface SessionData {
  cookies: Array<{
    name: string;
    value: string;
    domain: string;
    path: string;
    expires?: number;
    httpOnly?: boolean;
    secure?: boolean;
  }>;
  expiresAt: number;
  username: string;
}

let cachedSession: SessionData | null = null;

// Session expires after 23 hours (cookies typically last 24h)
const SESSION_TTL_MS = 23 * 60 * 60 * 1000;

/**
 * Get stored ExpiredDomains credentials
 */
export async function getExpiredDomainsCredentials(): Promise<{ username: string; password: string } | null> {
  const usernameRecord = await getAppSetting('EXPIRED_DOMAINS_USERNAME');
  const passwordRecord = await getAppSetting('EXPIRED_DOMAINS_PASSWORD');

  const username = usernameRecord?.value;
  const password = passwordRecord?.value;

  if (!username || !password) {
    return null;
  }

  return { username, password };
}

/**
 * Check if credentials are configured
 */
export async function hasExpiredDomainsCredentials(): Promise<boolean> {
  const creds = await getExpiredDomainsCredentials();
  return creds !== null;
}

/**
 * Save ExpiredDomains credentials
 */
export async function saveExpiredDomainsCredentials(username: string, password: string): Promise<void> {
  await setAppSetting('EXPIRED_DOMAINS_USERNAME', username, 'ExpiredDomains.net username', false);
  await setAppSetting('EXPIRED_DOMAINS_PASSWORD', password, 'ExpiredDomains.net password', true);

  // Clear cached session when credentials change
  cachedSession = null;
  await setAppSetting('EXPIRED_DOMAINS_SESSION', null, 'ExpiredDomains.net session cookies', true);

  logger.info('ExpiredDomains credentials saved');
}

/**
 * Get cached session cookies if still valid
 */
export async function getCachedSession(): Promise<SessionData['cookies'] | null> {
  // Check memory cache first
  if (cachedSession && Date.now() < cachedSession.expiresAt) {
    logger.debug('Using memory-cached session');
    return cachedSession.cookies;
  }

  // Check database cache
  const storedSessionRecord = await getAppSetting('EXPIRED_DOMAINS_SESSION');
  const storedSession = storedSessionRecord?.value;
  if (storedSession) {
    try {
      const session: SessionData = JSON.parse(storedSession);
      if (Date.now() < session.expiresAt) {
        cachedSession = session;
        logger.debug('Using database-cached session');
        return session.cookies;
      }
    } catch {
      // Invalid stored session
    }
  }

  return null;
}

/**
 * Store session cookies
 */
export async function storeSession(cookies: SessionData['cookies'], username: string): Promise<void> {
  const session: SessionData = {
    cookies,
    expiresAt: Date.now() + SESSION_TTL_MS,
    username,
  };

  cachedSession = session;
  await setAppSetting('EXPIRED_DOMAINS_SESSION', JSON.stringify(session), 'ExpiredDomains.net session cookies', true);

  logger.info('ExpiredDomains session stored');
}

/**
 * Clear stored session
 */
export async function clearSession(): Promise<void> {
  cachedSession = null;
  await setAppSetting('EXPIRED_DOMAINS_SESSION', null, 'ExpiredDomains.net session cookies', true);
  logger.info('ExpiredDomains session cleared');
}

/**
 * Login to ExpiredDomains.net using Playwright
 * Returns cookies on success, null on failure
 */
export async function loginToExpiredDomains(
  page: any, // Playwright Page
  credentials?: { username: string; password: string }
): Promise<SessionData['cookies'] | null> {
  // Get credentials if not provided
  const creds = credentials || await getExpiredDomainsCredentials();
  if (!creds) {
    logger.warn('No ExpiredDomains credentials configured');
    return null;
  }

  // Check for cached session first
  const cachedCookies = await getCachedSession();
  if (cachedCookies) {
    // Set cookies on the page
    const context = page.context();
    await context.addCookies(cachedCookies);

    // Verify session is still valid by navigating
    await page.goto('https://www.expireddomains.net/', { waitUntil: 'networkidle', timeout: 30000 });

    // Check if we're logged in by looking for username in the page
    const isLoggedIn = await page.evaluate(`
      (function() {
        var html = document.documentElement.innerHTML;
        return html.indexOf('${creds.username}') !== -1 ||
               html.indexOf('Logout') !== -1 ||
               html.indexOf('logout') !== -1;
      })()
    `);

    if (isLoggedIn) {
      logger.info('Session restored from cache');
      return cachedCookies;
    }

    logger.info('Cached session expired, logging in again');
    await clearSession();
  }

  try {
    logger.info(`Logging in to ExpiredDomains.net as ${creds.username}...`);

    // Navigate to login page
    await page.goto('https://www.expireddomains.net/login/', {
      waitUntil: 'networkidle',
      timeout: 30000,
    });

    // Fill in the login form using specific selectors
    await page.fill('#inputLogin', creds.username);
    await page.fill('#inputPassword', creds.password);

    // Check "Remember me" for longer session
    const rememberCheckbox = await page.$('#rememberme');
    if (rememberCheckbox) {
      await rememberCheckbox.check();
    }

    // Submit the login form specifically (not the search form)
    const loginButton = await page.$('form.form-horizontal button[type="submit"]');
    if (loginButton) {
      await loginButton.click();
    } else {
      // Fallback: submit form directly
      await page.evaluate(`
        (function() {
          var form = document.querySelector('form.form-horizontal');
          if (form) form.submit();
        })()
      `);
    }

    // Wait for navigation - login redirects through member.expireddomains.net/auth/
    // This can timeout due to multiple redirects, which is fine
    await page.waitForNavigation({ waitUntil: 'networkidle', timeout: 30000 }).catch(() => {
      // Navigation might timeout due to multiple redirects
    });

    // Wait for all redirects to complete
    await page.waitForTimeout(3000);

    // Check if login was successful
    const currentUrl = page.url();
    const pageContent = await page.content();

    logger.debug(`Post-login URL: ${currentUrl}`);

    // Check for login errors on the page
    if (pageContent.includes('Login failed') ||
        pageContent.includes('Invalid username') ||
        pageContent.includes('Invalid password') ||
        pageContent.includes('Wrong credentials') ||
        pageContent.includes('incorrect')) {
      logger.error('Login failed: Invalid credentials');
      return null;
    }

    // Success indicators: redirected to member subdomain, or has logout link
    const isLoggedIn = currentUrl.includes('member.expireddomains.net') ||
                       pageContent.includes('Logout') ||
                       pageContent.includes('logout') ||
                       pageContent.includes(creds.username);

    if (!isLoggedIn && currentUrl.includes('/login/')) {
      logger.error('Login failed: Still on login page');
      return null;
    }

    // Get all cookies from the browser context
    const context = page.context();
    const cookies = await context.cookies();

    // Filter for ExpiredDomains cookies (includes both www and member subdomains)
    const edCookies = cookies.filter((c: any) =>
      c.domain.includes('expireddomains.net')
    );

    // Check for essential session cookies
    const hasSessionCookie = edCookies.some((c: any) =>
      c.name === 'ExpiredDomainssessid' || c.name === 'reme'
    );

    if (!hasSessionCookie) {
      logger.error('Login failed: No session cookies received');
      return null;
    }

    // Store the session
    await storeSession(edCookies, creds.username);

    logger.info(`Successfully logged in to ExpiredDomains.net (${edCookies.length} cookies)`);
    return edCookies;

  } catch (error: any) {
    logger.error('Login error', { error: error.message });
    return null;
  }
}

/**
 * Ensure page is authenticated before making requests
 * Returns true if authenticated, false otherwise
 */
export async function ensureAuthenticated(page: any): Promise<boolean> {
  const cookies = await loginToExpiredDomains(page);
  return cookies !== null;
}
