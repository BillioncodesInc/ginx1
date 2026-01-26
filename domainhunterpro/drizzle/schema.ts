import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

/**
 * Core user table backing auth flow.
 */
export const users = sqliteTable("users", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  openId: text("openId").notNull().unique(),
  name: text("name"),
  email: text("email"),
  loginMethod: text("loginMethod"),
  role: text("role", { enum: ["user", "admin"] }).default("user").notNull(),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().$defaultFn(() => new Date()),
  updatedAt: integer("updatedAt", { mode: "timestamp" }).notNull().$defaultFn(() => new Date()),
  lastSignedIn: integer("lastSignedIn", { mode: "timestamp" }).notNull().$defaultFn(() => new Date()),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

/**
 * Domains table - stores basic domain information
 */
export const domains = sqliteTable("domains", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  domainName: text("domainName").notNull().unique(),
  tld: text("tld").notNull(),
  status: text("status", { enum: ["available", "registered", "pending"] }).default("available").notNull(),
  droppedDate: integer("droppedDate", { mode: "timestamp" }),
  birthYear: integer("birthYear"),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().$defaultFn(() => new Date()),
  updatedAt: integer("updatedAt", { mode: "timestamp" }).notNull().$defaultFn(() => new Date()),
});

export type Domain = typeof domains.$inferSelect;
export type InsertDomain = typeof domains.$inferInsert;

/**
 * Domain metrics table - stores SEO and authority metrics
 */
export const domainMetrics = sqliteTable("domainMetrics", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  domainId: integer("domainId").notNull(),
  backlinksCount: integer("backlinksCount").default(0).notNull(),
  domainPop: integer("domainPop").default(0).notNull(),
  trustFlow: integer("trustFlow").default(0).notNull(),
  citationFlow: integer("citationFlow").default(0).notNull(),
  domainAuthority: integer("domainAuthority").default(0).notNull(),
  pageAuthority: integer("pageAuthority").default(0).notNull(),
  archiveSnapshots: integer("archiveSnapshots").default(0).notNull(),
  spamScore: integer("spamScore").default(0).notNull(),
  qualityScore: integer("qualityScore").default(0).notNull(),
  isDictionaryWord: integer("isDictionaryWord", { mode: "boolean" }).default(false).notNull(),
  hasCleanHistory: integer("hasCleanHistory", { mode: "boolean" }).default(true).notNull(),
  // New metrics from ExpiredDomains.net
  majesticGlobalRank: integer("majesticGlobalRank").default(0).notNull(), // Majestic Million Global Rank (lower = better)
  inDmoz: integer("inDmoz", { mode: "boolean" }).default(false).notNull(), // Listed in DMOZ directory
  wikipediaLinks: integer("wikipediaLinks").default(0).notNull(), // Number of Wikipedia links
  relatedDomains: integer("relatedDomains").default(0).notNull(), // Related domains count
  registeredTlds: integer("registeredTlds").default(0).notNull(), // How many other TLDs are registered
  lastChecked: integer("lastChecked", { mode: "timestamp" }).notNull().$defaultFn(() => new Date()),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().$defaultFn(() => new Date()),
});

export type DomainMetric = typeof domainMetrics.$inferSelect;
export type InsertDomainMetric = typeof domainMetrics.$inferInsert;

/**
 * Domain history table - stores historical snapshots
 */
export const domainHistory = sqliteTable("domainHistory", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  domainId: integer("domainId").notNull(),
  snapshotDate: integer("snapshotDate", { mode: "timestamp" }).notNull(),
  contentType: text("contentType"),
  screenshotUrl: text("screenshotUrl"),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().$defaultFn(() => new Date()),
});

export type DomainHistoryRecord = typeof domainHistory.$inferSelect;
export type InsertDomainHistory = typeof domainHistory.$inferInsert;

/**
 * Search history table - tracks user searches
 */
export const searchHistory = sqliteTable("searchHistory", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  userId: integer("userId"),
  searchQuery: text("searchQuery"),
  filtersApplied: text("filtersApplied"), // JSON stored as text
  resultsCount: integer("resultsCount").default(0).notNull(),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().$defaultFn(() => new Date()),
});

export type SearchHistory = typeof searchHistory.$inferSelect;
export type InsertSearchHistory = typeof searchHistory.$inferInsert;

/**
 * User favorites table - stores favorited domains
 */
export const userFavorites = sqliteTable("userFavorites", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  userId: integer("userId").notNull(),
  domainId: integer("domainId").notNull(),
  notes: text("notes"),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().$defaultFn(() => new Date()),
});

export type UserFavorite = typeof userFavorites.$inferSelect;
export type InsertUserFavorite = typeof userFavorites.$inferInsert;

/**
 * Scraping jobs table - tracks background scraping tasks
 */
export const scrapingJobs = sqliteTable("scrapingJobs", {
  id: text("id").primaryKey(), // UUID
  name: text("name").notNull(),
  status: text("status", { enum: ["pending", "running", "completed", "failed"] }).default("pending").notNull(),
  startTime: integer("startTime", { mode: "timestamp" }).notNull().$defaultFn(() => new Date()),
  endTime: integer("endTime", { mode: "timestamp" }),
  domainsFound: integer("domainsFound").default(0).notNull(),
  domainsSaved: integer("domainsSaved").default(0).notNull(),
  logs: text("logs"), // JSON stored as text
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().$defaultFn(() => new Date()),
  updatedAt: integer("updatedAt", { mode: "timestamp" }).notNull().$defaultFn(() => new Date()),
});

export type ScrapingJob = typeof scrapingJobs.$inferSelect;
export type InsertScrapingJob = typeof scrapingJobs.$inferInsert;

/**
 * App settings table - stores application configuration
 */
export const appSettings = sqliteTable("appSettings", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  key: text("key").notNull().unique(),
  value: text("value"),
  description: text("description"),
  isSecret: integer("isSecret", { mode: "boolean" }).default(false).notNull(),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull().$defaultFn(() => new Date()),
  updatedAt: integer("updatedAt", { mode: "timestamp" }).notNull().$defaultFn(() => new Date()),
});

export type AppSetting = typeof appSettings.$inferSelect;
export type InsertAppSetting = typeof appSettings.$inferInsert;
