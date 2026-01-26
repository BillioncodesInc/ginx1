import { and, desc, eq, gte, like, lte, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/better-sqlite3";
import Database from "better-sqlite3";
import { 
  domains, 
  domainMetrics, 
  domainHistory, 
  searchHistory, 
  userFavorites,
  appSettings,
  scrapingJobs,
  InsertDomain,
  InsertDomainMetric,
  InsertUser, 
  users,
  Domain,
  DomainMetric
} from "../drizzle/schema";
import { ENV } from './_core/env';
import path from "path";
import fs from "fs";

// Database file path
const DB_PATH = path.join(process.cwd(), "data", "domain-hunter.db");

// Ensure data directory exists
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Create SQLite database connection
const sqlite = new Database(DB_PATH);
const db = drizzle(sqlite);

// Initialize database tables
function initializeDatabase() {
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      openId TEXT NOT NULL UNIQUE,
      name TEXT,
      email TEXT,
      loginMethod TEXT,
      role TEXT DEFAULT 'user' NOT NULL,
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      updatedAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      lastSignedIn INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );

    CREATE TABLE IF NOT EXISTS domains (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domainName TEXT NOT NULL UNIQUE,
      tld TEXT NOT NULL,
      status TEXT DEFAULT 'available' NOT NULL,
      droppedDate INTEGER,
      birthYear INTEGER,
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      updatedAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );

    CREATE TABLE IF NOT EXISTS domainMetrics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domainId INTEGER NOT NULL,
      backlinksCount INTEGER DEFAULT 0 NOT NULL,
      domainPop INTEGER DEFAULT 0 NOT NULL,
      trustFlow INTEGER DEFAULT 0 NOT NULL,
      citationFlow INTEGER DEFAULT 0 NOT NULL,
      domainAuthority INTEGER DEFAULT 0 NOT NULL,
      pageAuthority INTEGER DEFAULT 0 NOT NULL,
      archiveSnapshots INTEGER DEFAULT 0 NOT NULL,
      spamScore INTEGER DEFAULT 0 NOT NULL,
      qualityScore INTEGER DEFAULT 0 NOT NULL,
      isDictionaryWord INTEGER DEFAULT 0 NOT NULL,
      hasCleanHistory INTEGER DEFAULT 1 NOT NULL,
      majesticGlobalRank INTEGER DEFAULT 0 NOT NULL,
      inDmoz INTEGER DEFAULT 0 NOT NULL,
      wikipediaLinks INTEGER DEFAULT 0 NOT NULL,
      relatedDomains INTEGER DEFAULT 0 NOT NULL,
      registeredTlds INTEGER DEFAULT 0 NOT NULL,
      lastChecked INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      FOREIGN KEY (domainId) REFERENCES domains(id)
    );

    CREATE TABLE IF NOT EXISTS domainHistory (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domainId INTEGER NOT NULL,
      snapshotDate INTEGER NOT NULL,
      contentType TEXT,
      screenshotUrl TEXT,
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      FOREIGN KEY (domainId) REFERENCES domains(id)
    );

    CREATE TABLE IF NOT EXISTS searchHistory (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER,
      searchQuery TEXT,
      filtersApplied TEXT,
      resultsCount INTEGER DEFAULT 0 NOT NULL,
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );

    CREATE TABLE IF NOT EXISTS userFavorites (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      domainId INTEGER NOT NULL,
      notes TEXT,
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      FOREIGN KEY (domainId) REFERENCES domains(id)
    );

    CREATE TABLE IF NOT EXISTS scrapingJobs (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      status TEXT DEFAULT 'pending' NOT NULL,
      startTime INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      endTime INTEGER,
      domainsFound INTEGER DEFAULT 0 NOT NULL,
      domainsSaved INTEGER DEFAULT 0 NOT NULL,
      logs TEXT,
      results TEXT,
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      updatedAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );

    CREATE TABLE IF NOT EXISTS appSettings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT NOT NULL UNIQUE,
      value TEXT,
      description TEXT,
      isSecret INTEGER DEFAULT 0 NOT NULL,
      createdAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      updatedAt INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );

    CREATE INDEX IF NOT EXISTS idx_domains_domainName ON domains(domainName);
    CREATE INDEX IF NOT EXISTS idx_domainMetrics_domainId ON domainMetrics(domainId);
    CREATE INDEX IF NOT EXISTS idx_domainMetrics_qualityScore ON domainMetrics(qualityScore);
  `);
  console.log("[Database] SQLite database initialized at:", DB_PATH);
}

// Initialize on startup
initializeDatabase();

export async function getDb() {
  return db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }

  try {
    const existing = await db.select().from(users).where(eq(users.openId, user.openId)).limit(1);
    
    if (existing.length > 0) {
      await db.update(users)
        .set({
          name: user.name ?? existing[0].name,
          email: user.email ?? existing[0].email,
          loginMethod: user.loginMethod ?? existing[0].loginMethod,
          lastSignedIn: new Date(),
          updatedAt: new Date(),
        })
        .where(eq(users.openId, user.openId));
    } else {
      await db.insert(users).values({
        openId: user.openId,
        name: user.name,
        email: user.email,
        loginMethod: user.loginMethod,
        role: user.openId === ENV.ownerOpenId ? 'admin' : 'user',
        lastSignedIn: new Date(),
      });
    }
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}

export async function getUserByOpenId(openId: string) {
  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);
  return result.length > 0 ? result[0] : undefined;
}

/**
 * Calculate quality score based on domain metrics
 *
 * SCORING BREAKDOWN (100 points max):
 *
 * 1. AUTHORITY METRICS (40 points max)
 *    - Domain Authority (DA): 0-18 points
 *    - Trust Flow (TF): 0-10 points
 *    - Citation Flow (CF): 0-7 points
 *    - TF/CF Ratio Bonus: 0-5 points (healthy ratio = TF >= CF * 0.8)
 *
 * 2. BACKLINK PROFILE (20 points max)
 *    - Backlinks Count: 0-10 points (logarithmic scale)
 *    - Domain Pop (unique referring domains): 0-10 points (logarithmic scale)
 *
 * 3. DOMAIN AGE & HISTORY (20 points max)
 *    - Domain Age: 0-12 points (older = better, max at 15+ years)
 *    - Archive Snapshots: 0-8 points (more history = better)
 *
 * 4. QUALITY BONUSES (20 points max)
 *    - Dictionary Word: +4 points
 *    - Clean History: +4 points
 *    - Page Authority: 0-4 points
 *    - Majestic Top Million: 0-4 points (ranked in Majestic Million)
 *    - DMOZ Listed: +2 points
 *    - Wikipedia Links: 0-2 points
 *
 * 5. PENALTIES (up to -25 points)
 *    - High Spam Score: -5 to -15 points
 *    - Bad TF/CF Ratio: -5 points (TF < CF * 0.3 = spammy links)
 *    - No History: -5 points (no archive snapshots)
 */
function calculateQualityScore(metrics: {
  backlinksCount: number;
  domainPop?: number;
  trustFlow: number;
  citationFlow: number;
  domainAuthority: number;
  pageAuthority: number;
  archiveSnapshots: number;
  spamScore?: number;
  isDictionaryWord: boolean;
  hasCleanHistory: boolean;
  birthYear?: number | null;
  // New metrics from ExpiredDomains.net
  majesticGlobalRank?: number;
  inDmoz?: boolean;
  wikipediaLinks?: number;
}): number {
  const currentYear = new Date().getFullYear();
  const ageYears = metrics.birthYear ? currentYear - metrics.birthYear : 0;
  
  // ============================================
  // 1. AUTHORITY METRICS (40 points max)
  // ============================================
  
  // Domain Authority (0-20 points)
  // DA is the most important metric - logarithmic scale to reward higher DA more
  let daScore = 0;
  if (metrics.domainAuthority > 0) {
    if (metrics.domainAuthority >= 60) {
      daScore = 20; // Excellent DA
    } else if (metrics.domainAuthority >= 40) {
      daScore = 15 + ((metrics.domainAuthority - 40) / 20) * 5; // 15-20 points
    } else if (metrics.domainAuthority >= 20) {
      daScore = 8 + ((metrics.domainAuthority - 20) / 20) * 7; // 8-15 points
    } else {
      daScore = (metrics.domainAuthority / 20) * 8; // 0-8 points
    }
  }
  
  // Trust Flow (0-12 points)
  // TF indicates quality of backlinks
  let tfScore = 0;
  if (metrics.trustFlow > 0) {
    if (metrics.trustFlow >= 40) {
      tfScore = 12; // Excellent TF
    } else if (metrics.trustFlow >= 20) {
      tfScore = 6 + ((metrics.trustFlow - 20) / 20) * 6; // 6-12 points
    } else {
      tfScore = (metrics.trustFlow / 20) * 6; // 0-6 points
    }
  }
  
  // Citation Flow (0-8 points)
  // CF indicates quantity of backlinks
  let cfScore = 0;
  if (metrics.citationFlow > 0) {
    if (metrics.citationFlow >= 40) {
      cfScore = 8;
    } else if (metrics.citationFlow >= 20) {
      cfScore = 4 + ((metrics.citationFlow - 20) / 20) * 4;
    } else {
      cfScore = (metrics.citationFlow / 20) * 4;
    }
  }
  
  // TF/CF Ratio Bonus (0-5 points)
  // Healthy ratio: TF should be close to or higher than CF
  // Spammy domains have high CF but low TF
  let tfCfRatioBonus = 0;
  if (metrics.citationFlow > 0 && metrics.trustFlow > 0) {
    const ratio = metrics.trustFlow / metrics.citationFlow;
    if (ratio >= 1.0) {
      tfCfRatioBonus = 5; // Excellent - TF >= CF
    } else if (ratio >= 0.8) {
      tfCfRatioBonus = 4; // Good
    } else if (ratio >= 0.6) {
      tfCfRatioBonus = 2; // Acceptable
    } else if (ratio >= 0.4) {
      tfCfRatioBonus = 1; // Marginal
    }
    // Below 0.4 = no bonus (potentially spammy)
  }
  
  const authorityScore = daScore + tfScore + cfScore + tfCfRatioBonus;
  
  // ============================================
  // 2. BACKLINK PROFILE (20 points max)
  // ============================================
  
  // Backlinks Count (0-10 points) - logarithmic scale
  // 1 backlink = ~1 point, 10 = ~3 points, 100 = ~6 points, 1000 = ~10 points
  let backlinksScore = 0;
  if (metrics.backlinksCount > 0) {
    backlinksScore = Math.min(10, Math.log10(metrics.backlinksCount + 1) * 3.33);
  }
  
  // Domain Pop / Referring Domains (0-10 points) - logarithmic scale
  // More unique referring domains = more valuable
  let domainPopScore = 0;
  const domainPop = metrics.domainPop ?? Math.min(metrics.backlinksCount, 50); // Estimate if not provided
  if (domainPop > 0) {
    domainPopScore = Math.min(10, Math.log10(domainPop + 1) * 4);
  }
  
  const backlinkScore = backlinksScore + domainPopScore;
  
  // ============================================
  // 3. DOMAIN AGE & HISTORY (20 points max)
  // ============================================
  
  // Domain Age (0-12 points)
  // Older domains are more valuable, max benefit at 15+ years
  let ageScore = 0;
  if (ageYears > 0) {
    if (ageYears >= 15) {
      ageScore = 12; // Very old domain
    } else if (ageYears >= 10) {
      ageScore = 9 + ((ageYears - 10) / 5) * 3; // 9-12 points
    } else if (ageYears >= 5) {
      ageScore = 5 + ((ageYears - 5) / 5) * 4; // 5-9 points
    } else {
      ageScore = (ageYears / 5) * 5; // 0-5 points
    }
  }
  
  // Archive Snapshots (0-8 points)
  // More snapshots = more established history
  let archiveScore = 0;
  if (metrics.archiveSnapshots > 0) {
    if (metrics.archiveSnapshots >= 100) {
      archiveScore = 8;
    } else if (metrics.archiveSnapshots >= 50) {
      archiveScore = 6 + ((metrics.archiveSnapshots - 50) / 50) * 2;
    } else if (metrics.archiveSnapshots >= 20) {
      archiveScore = 3 + ((metrics.archiveSnapshots - 20) / 30) * 3;
    } else {
      archiveScore = (metrics.archiveSnapshots / 20) * 3;
    }
  }
  
  const historyScore = ageScore + archiveScore;
  
  // ============================================
  // 4. QUALITY BONUSES (20 points max)
  // ============================================

  // Dictionary Word Bonus (+4 points)
  // Short, memorable domain names are more valuable
  const dictionaryBonus = metrics.isDictionaryWord ? 4 : 0;

  // Clean History Bonus (+4 points)
  // No spam/malware history
  const cleanHistoryBonus = metrics.hasCleanHistory ? 4 : 0;

  // Page Authority (0-4 points)
  let paScore = 0;
  if (metrics.pageAuthority > 0) {
    paScore = Math.min(4, (metrics.pageAuthority / 100) * 4);
  }

  // Majestic Million Rank Bonus (0-4 points)
  // Being ranked in Majestic Million indicates established authority
  let majesticBonus = 0;
  const majesticRank = metrics.majesticGlobalRank ?? 0;
  if (majesticRank > 0 && majesticRank < 1000000) {
    if (majesticRank < 100000) {
      majesticBonus = 4; // Top 100K = excellent
    } else if (majesticRank < 500000) {
      majesticBonus = 3; // Top 500K = very good
    } else {
      majesticBonus = 2; // In Majestic Million = good
    }
  }

  // DMOZ Directory Listing Bonus (+2 points)
  // Being listed in DMOZ was a strong quality signal
  const dmozBonus = metrics.inDmoz ? 2 : 0;

  // Wikipedia Links Bonus (0-2 points)
  // Links from Wikipedia indicate notable, authoritative domains
  let wikiBonus = 0;
  const wikiLinks = metrics.wikipediaLinks ?? 0;
  if (wikiLinks > 0) {
    wikiBonus = Math.min(2, wikiLinks); // 1 point per link, max 2
  }

  const bonusScore = dictionaryBonus + cleanHistoryBonus + paScore + majesticBonus + dmozBonus + wikiBonus;
  
  // ============================================
  // 5. PENALTIES (up to -25 points)
  // ============================================
  
  let penalties = 0;
  
  // Spam Score Penalty (-5 to -15 points)
  // Moz spam score: 0-17 scale, higher = more spammy
  const spamScore = metrics.spamScore ?? 0;
  if (spamScore >= 10) {
    penalties -= 15; // Very spammy
  } else if (spamScore >= 7) {
    penalties -= 10; // Moderately spammy
  } else if (spamScore >= 4) {
    penalties -= 5; // Slightly spammy
  }
  
  // Bad TF/CF Ratio Penalty (-5 points)
  // Very low TF compared to CF indicates spammy backlinks
  if (metrics.citationFlow > 10 && metrics.trustFlow > 0) {
    const ratio = metrics.trustFlow / metrics.citationFlow;
    if (ratio < 0.3) {
      penalties -= 5; // Spammy link profile
    }
  }
  
  // No History Penalty (-5 points)
  // Domains with no archive history are suspicious
  if (metrics.archiveSnapshots === 0 && ageYears > 2) {
    penalties -= 5; // Old domain but no history = suspicious
  }
  
  // Dirty History Penalty (already handled by cleanHistoryBonus = 0)
  // But add extra penalty for known bad history
  if (!metrics.hasCleanHistory) {
    penalties -= 5; // Extra penalty for bad history
  }
  
  // ============================================
  // FINAL SCORE CALCULATION
  // ============================================
  
  const rawScore = authorityScore + backlinkScore + historyScore + bonusScore + penalties;
  
  // Clamp to 0-100 range
  const finalScore = Math.max(0, Math.min(100, Math.round(rawScore)));
  
  return finalScore;
}

/**
 * Get score breakdown for a domain (for UI display)
 */
export function getScoreBreakdown(metrics: {
  backlinksCount: number;
  domainPop?: number;
  trustFlow: number;
  citationFlow: number;
  domainAuthority: number;
  pageAuthority: number;
  archiveSnapshots: number;
  spamScore?: number;
  isDictionaryWord: boolean;
  hasCleanHistory: boolean;
  birthYear?: number | null;
  // New metrics from ExpiredDomains.net
  majesticGlobalRank?: number;
  inDmoz?: boolean;
  wikipediaLinks?: number;
}): {
  total: number;
  authority: { score: number; max: number; details: string };
  backlinks: { score: number; max: number; details: string };
  history: { score: number; max: number; details: string };
  bonuses: { score: number; max: number; details: string };
  penalties: { score: number; details: string };
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
} {
  const currentYear = new Date().getFullYear();
  const ageYears = metrics.birthYear ? currentYear - metrics.birthYear : 0;
  
  // Calculate each component (simplified version of main function)
  const daScore = Math.min(20, metrics.domainAuthority >= 60 ? 20 : 
    metrics.domainAuthority >= 40 ? 15 + ((metrics.domainAuthority - 40) / 20) * 5 :
    metrics.domainAuthority >= 20 ? 8 + ((metrics.domainAuthority - 20) / 20) * 7 :
    (metrics.domainAuthority / 20) * 8);
  
  const tfScore = Math.min(12, metrics.trustFlow >= 40 ? 12 :
    metrics.trustFlow >= 20 ? 6 + ((metrics.trustFlow - 20) / 20) * 6 :
    (metrics.trustFlow / 20) * 6);
  
  const cfScore = Math.min(8, metrics.citationFlow >= 40 ? 8 :
    metrics.citationFlow >= 20 ? 4 + ((metrics.citationFlow - 20) / 20) * 4 :
    (metrics.citationFlow / 20) * 4);
  
  let tfCfRatioBonus = 0;
  if (metrics.citationFlow > 0 && metrics.trustFlow > 0) {
    const ratio = metrics.trustFlow / metrics.citationFlow;
    tfCfRatioBonus = ratio >= 1.0 ? 5 : ratio >= 0.8 ? 4 : ratio >= 0.6 ? 2 : ratio >= 0.4 ? 1 : 0;
  }
  
  const authorityTotal = Math.round(daScore + tfScore + cfScore + tfCfRatioBonus);
  
  const backlinksScore = metrics.backlinksCount > 0 ? Math.min(10, Math.log10(metrics.backlinksCount + 1) * 3.33) : 0;
  const domainPop = metrics.domainPop ?? Math.min(metrics.backlinksCount, 50);
  const domainPopScore = domainPop > 0 ? Math.min(10, Math.log10(domainPop + 1) * 4) : 0;
  const backlinksTotal = Math.round(backlinksScore + domainPopScore);
  
  const ageScore = ageYears >= 15 ? 12 : ageYears >= 10 ? 9 + ((ageYears - 10) / 5) * 3 :
    ageYears >= 5 ? 5 + ((ageYears - 5) / 5) * 4 : (ageYears / 5) * 5;
  const archiveScore = metrics.archiveSnapshots >= 100 ? 8 :
    metrics.archiveSnapshots >= 50 ? 6 + ((metrics.archiveSnapshots - 50) / 50) * 2 :
    metrics.archiveSnapshots >= 20 ? 3 + ((metrics.archiveSnapshots - 20) / 30) * 3 :
    (metrics.archiveSnapshots / 20) * 3;
  const historyTotal = Math.round(ageScore + archiveScore);
  
  const dictionaryBonus = metrics.isDictionaryWord ? 4 : 0;
  const cleanHistoryBonus = metrics.hasCleanHistory ? 4 : 0;
  const paScore = Math.min(4, (metrics.pageAuthority / 100) * 4);

  // Majestic Million Rank Bonus (0-4 points)
  let majesticBonus = 0;
  const majesticRank = metrics.majesticGlobalRank ?? 0;
  if (majesticRank > 0 && majesticRank < 1000000) {
    if (majesticRank < 100000) majesticBonus = 4;
    else if (majesticRank < 500000) majesticBonus = 3;
    else majesticBonus = 2;
  }

  // DMOZ and Wikipedia bonuses
  const dmozBonus = metrics.inDmoz ? 2 : 0;
  const wikiBonus = Math.min(2, metrics.wikipediaLinks ?? 0);

  const bonusesTotal = Math.round(dictionaryBonus + cleanHistoryBonus + paScore + majesticBonus + dmozBonus + wikiBonus);
  
  let penalties = 0;
  const spamScore = metrics.spamScore ?? 0;
  if (spamScore >= 10) penalties -= 15;
  else if (spamScore >= 7) penalties -= 10;
  else if (spamScore >= 4) penalties -= 5;
  
  if (metrics.citationFlow > 10 && metrics.trustFlow > 0 && (metrics.trustFlow / metrics.citationFlow) < 0.3) {
    penalties -= 5;
  }
  if (metrics.archiveSnapshots === 0 && ageYears > 2) penalties -= 5;
  if (!metrics.hasCleanHistory) penalties -= 5;
  
  const total = Math.max(0, Math.min(100, authorityTotal + backlinksTotal + historyTotal + bonusesTotal + penalties));
  
  // Determine grade
  let grade: 'A' | 'B' | 'C' | 'D' | 'F';
  if (total >= 80) grade = 'A';
  else if (total >= 60) grade = 'B';
  else if (total >= 40) grade = 'C';
  else if (total >= 20) grade = 'D';
  else grade = 'F';
  
  return {
    total,
    authority: {
      score: authorityTotal,
      max: 45,
      details: `DA: ${metrics.domainAuthority}, TF: ${metrics.trustFlow}, CF: ${metrics.citationFlow}`
    },
    backlinks: {
      score: backlinksTotal,
      max: 20,
      details: `${metrics.backlinksCount.toLocaleString()} backlinks, ${domainPop.toLocaleString()} referring domains`
    },
    history: {
      score: historyTotal,
      max: 20,
      details: `${ageYears} years old, ${metrics.archiveSnapshots} archive snapshots`
    },
    bonuses: {
      score: bonusesTotal,
      max: 20,
      details: [
        metrics.isDictionaryWord ? 'Dictionary word (+4)' : null,
        metrics.hasCleanHistory ? 'Clean history (+4)' : null,
        metrics.pageAuthority > 0 ? `PA: ${metrics.pageAuthority}` : null,
        majesticBonus > 0 ? `Majestic Top ${majesticRank < 100000 ? '100K' : majesticRank < 500000 ? '500K' : '1M'} (+${majesticBonus})` : null,
        metrics.inDmoz ? 'DMOZ listed (+2)' : null,
        (metrics.wikipediaLinks ?? 0) > 0 ? `Wikipedia links: ${metrics.wikipediaLinks} (+${wikiBonus})` : null
      ].filter(Boolean).join(', ') || 'None'
    },
    penalties: {
      score: penalties,
      details: penalties < 0 ? [
        spamScore >= 4 ? `Spam score: ${spamScore}` : null,
        !metrics.hasCleanHistory ? 'Bad history' : null,
        metrics.archiveSnapshots === 0 && ageYears > 2 ? 'No archive history' : null
      ].filter(Boolean).join(', ') : 'None'
    },
    grade
  };
}

/**
 * Insert domain with metrics in a single transaction
 */
export async function insertDomainWithMetrics(
  domainData: InsertDomain,
  metricsData: Omit<InsertDomainMetric, 'domainId' | 'qualityScore' | 'lastChecked'>
): Promise<number> {
  // Check if domain already exists
  const existing = await db.select().from(domains).where(eq(domains.domainName, domainData.domainName)).limit(1);
  if (existing.length > 0) {
    return existing[0].id;
  }

  // Insert domain
  const insertedDomain = await db.insert(domains).values(domainData).returning({ id: domains.id });
  const domainId = insertedDomain[0].id;

  // Calculate quality score with all available metrics
  const qualityScore = calculateQualityScore({
    backlinksCount: metricsData.backlinksCount ?? 0,
    domainPop: metricsData.domainPop ?? 0,
    trustFlow: metricsData.trustFlow ?? 0,
    citationFlow: metricsData.citationFlow ?? 0,
    domainAuthority: metricsData.domainAuthority ?? 0,
    pageAuthority: metricsData.pageAuthority ?? 0,
    archiveSnapshots: metricsData.archiveSnapshots ?? 0,
    spamScore: metricsData.spamScore ?? 0,
    isDictionaryWord: metricsData.isDictionaryWord ?? false,
    hasCleanHistory: metricsData.hasCleanHistory ?? true,
    birthYear: domainData.birthYear,
  });

  // Insert metrics
  await db.insert(domainMetrics).values({
    domainId,
    ...metricsData,
    qualityScore,
    lastChecked: new Date(),
  });

  return domainId;
}

export interface DomainWithMetrics {
  domain: Domain;
  metrics: DomainMetric;
}

/**
 * Search domains with filters
 */
export async function searchDomains(filters: {
  keyword?: string;
  minBacklinks?: number;
  maxBacklinks?: number;
  minTrustFlow?: number;
  minCitationFlow?: number;
  minAge?: number;
  minArchiveSnapshots?: number;
  tlds?: string[];
  dictionaryOnly?: boolean;
  limit?: number;
  offset?: number;
}): Promise<DomainWithMetrics[]> {
  const conditions = [];

  if (filters.keyword) {
    conditions.push(like(domains.domainName, `%${filters.keyword}%`));
  }

  if (filters.minAge !== undefined && filters.minAge > 0) {
    const currentYear = new Date().getFullYear();
    const maxBirthYear = currentYear - filters.minAge;
    conditions.push(lte(domains.birthYear, maxBirthYear));
  }

  if (filters.minBacklinks !== undefined) {
    conditions.push(gte(domainMetrics.backlinksCount, filters.minBacklinks));
  }

  if (filters.maxBacklinks !== undefined) {
    conditions.push(lte(domainMetrics.backlinksCount, filters.maxBacklinks));
  }

  if (filters.minTrustFlow !== undefined) {
    conditions.push(gte(domainMetrics.trustFlow, filters.minTrustFlow));
  }

  if (filters.minCitationFlow !== undefined) {
    conditions.push(gte(domainMetrics.citationFlow, filters.minCitationFlow));
  }

  if (filters.minArchiveSnapshots !== undefined) {
    conditions.push(gte(domainMetrics.archiveSnapshots, filters.minArchiveSnapshots));
  }

  if (filters.dictionaryOnly) {
    conditions.push(eq(domainMetrics.isDictionaryWord, true));
  }

  const limit = filters.limit || 100;
  const offset = filters.offset || 0;

  const results = await db
    .select({
      domain: domains,
      metrics: domainMetrics,
    })
    .from(domains)
    .innerJoin(domainMetrics, eq(domains.id, domainMetrics.domainId))
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .orderBy(desc(domainMetrics.qualityScore))
    .limit(limit)
    .offset(offset);

  return results as DomainWithMetrics[];
}

/**
 * Get domain by ID with metrics
 */
export async function getDomainById(id: number): Promise<DomainWithMetrics | null> {
  const result = await db
    .select({
      domain: domains,
      metrics: domainMetrics,
    })
    .from(domains)
    .innerJoin(domainMetrics, eq(domains.id, domainMetrics.domainId))
    .where(eq(domains.id, id))
    .limit(1);

  return result.length > 0 ? result[0] as DomainWithMetrics : null;
}

/**
 * Get domain by name with metrics
 */
export async function getDomainByName(domainName: string): Promise<DomainWithMetrics | null> {
  const result = await db
    .select({
      domain: domains,
      metrics: domainMetrics,
    })
    .from(domains)
    .innerJoin(domainMetrics, eq(domains.id, domainMetrics.domainId))
    .where(eq(domains.domainName, domainName))
    .limit(1);

  return result.length > 0 ? result[0] as DomainWithMetrics : null;
}

/**
 * Get domain history
 */
export async function getDomainHistory(domainId: number) {
  return await db
    .select()
    .from(domainHistory)
    .where(eq(domainHistory.domainId, domainId))
    .orderBy(desc(domainHistory.createdAt));
}

/**
 * Quick find high-quality domains
 * Returns domains sorted by quality score (highest first)
 * No strict filters - just returns the best domains we have
 */
export async function getQuickFindDomains(limit: number = 100): Promise<DomainWithMetrics[]> {
  // Simply return the top domains by quality score
  // This gives users immediate results without strict filtering
  const results = await db
    .select({
      domain: domains,
      metrics: domainMetrics,
    })
    .from(domains)
    .innerJoin(domainMetrics, eq(domains.id, domainMetrics.domainId))
    .orderBy(desc(domainMetrics.qualityScore))
    .limit(limit);

  return results as DomainWithMetrics[];
}

/**
 * Save search history
 */
export async function saveSearchHistory(data: {
  userId: number;
  searchQuery: string | null;
  filtersApplied: any;
  resultsCount: number;
}) {
  await db.insert(searchHistory).values({
    userId: data.userId,
    searchQuery: data.searchQuery,
    filtersApplied: JSON.stringify(data.filtersApplied),
    resultsCount: data.resultsCount,
  });
}

/**
 * Get user favorites
 */
export async function getUserFavorites(userId: number) {
  return await db
    .select({
      favorite: userFavorites,
      domain: domains,
      metrics: domainMetrics,
    })
    .from(userFavorites)
    .innerJoin(domains, eq(userFavorites.domainId, domains.id))
    .innerJoin(domainMetrics, eq(domains.id, domainMetrics.domainId))
    .where(eq(userFavorites.userId, userId))
    .orderBy(desc(userFavorites.createdAt));
}

/**
 * Add domain to favorites
 */
export async function addToFavorites(data: {
  userId: number;
  domainId: number;
  notes: string | null;
}) {
  await db.insert(userFavorites).values({
    userId: data.userId,
    domainId: data.domainId,
    notes: data.notes,
  });
}

/**
 * Remove domain from favorites
 */
export async function removeFromFavorites(favoriteId: number) {
  await db.delete(userFavorites).where(eq(userFavorites.id, favoriteId));
}

/**
 * Get app setting by key
 */
export async function getAppSetting(key: string) {
  const result = await db
    .select()
    .from(appSettings)
    .where(eq(appSettings.key, key))
    .limit(1);

  return result.length > 0 ? result[0] : null;
}

/**
 * Get all app settings
 */
export async function getAllAppSettings() {
  return await db.select().from(appSettings);
}

/**
 * Set app setting
 */
export async function setAppSetting(key: string, value: string | null, description?: string, isSecret?: boolean) {
  const existing = await db.select().from(appSettings).where(eq(appSettings.key, key)).limit(1);
  
  if (existing.length > 0) {
    await db.update(appSettings)
      .set({
        value,
        description,
        isSecret: isSecret ?? false,
        updatedAt: new Date(),
      })
      .where(eq(appSettings.key, key));
  } else {
    await db.insert(appSettings).values({
      key,
      value,
      description,
      isSecret: isSecret ?? false,
    });
  }
}

/**
 * Delete app setting
 */
export async function deleteAppSetting(key: string) {
  await db.delete(appSettings).where(eq(appSettings.key, key));
}

/**
 * Get total domain count
 */
export async function getTotalDomainCount() {
  const result = await db.select({ count: sql<number>`count(*)` }).from(domains);
  return result[0]?.count ?? 0;
}

/**
 * Get high quality domain count (score > 75)
 */
export async function getHighQualityDomainCount() {
  const result = await db
    .select({ count: sql<number>`count(*)` })
    .from(domainMetrics)
    .where(gte(domainMetrics.qualityScore, 75));
  return result[0]?.count ?? 0;
}

/**
 * Get average trust flow
 */
export async function getAverageTrustFlow() {
  const result = await db
    .select({ avg: sql<number>`AVG(trustFlow)` })
    .from(domainMetrics);
  return Math.round(result[0]?.avg ?? 0);
}

// Export the db instance for use in other modules
export { db };
