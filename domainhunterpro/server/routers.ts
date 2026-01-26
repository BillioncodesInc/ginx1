import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, protectedProcedure, router } from "./_core/trpc";
import { z } from "zod";
import {
  searchDomains,
  getDomainById,
  getDomainByName,
  getDomainHistory,
  getUserFavorites,
  addToFavorites,
  removeFromFavorites,
  getQuickFindDomains,
  saveSearchHistory,
  getAppSetting,
  getAllAppSettings,
  setAppSetting,
  deleteAppSetting,
  getTotalDomainCount,
  getHighQualityDomainCount,
  getAverageTrustFlow,
  getScoreBreakdown,
  insertDomainWithMetrics,
} from "./db";
import { scrapeExpiredDomains } from "./scrapers/expiredDomainsScraper";
import { checkDomainWhois } from "./scrapers/whoisChecker";
import { getArchiveData } from "./scrapers/archiveChecker";
import { getCachedSearch, setCachedSearch, clearExpiredCache } from "./_core/searchCache";

// Track active search jobs for cancellation
const activeSearchJobs = new Map<string, AbortController>();

// Cleanup expired cache periodically (every 5 minutes)
setInterval(() => {
  clearExpiredCache();
}, 5 * 60 * 1000);

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return {
        success: true,
      } as const;
    }),
  }),

  domains: router({
    // Live search - scrapes expireddomains.net for the keyword
    search: publicProcedure
      .input(
        z.object({
          keyword: z.string()
            .min(2, "Search term must be at least 2 characters")
            .max(63, "Search term is too long (max 63 characters)")
            .regex(/^[a-zA-Z0-9-]+$/, "Only letters, numbers, and hyphens are allowed")
            .transform(s => s.toLowerCase().trim()),
          maxPages: z.number().min(1).max(3).default(1),
          forceRefresh: z.boolean().default(false),
          searchId: z.string().optional(), // For cancellation tracking
        })
      )
      .mutation(async ({ input, ctx }) => {
        const { scrapeByKeyword } = await import("./scrapers/expiredDomainsScraper");
        const searchId = input.searchId || crypto.randomUUID();

        // Check cache first (unless force refresh)
        if (!input.forceRefresh) {
          const cached = getCachedSearch(input.keyword, input.maxPages);
          if (cached) {
            // Save search history even for cached results
            if (ctx.user) {
              await saveSearchHistory({
                userId: ctx.user.id,
                searchQuery: input.keyword,
                filtersApplied: { keyword: input.keyword, maxPages: input.maxPages, cached: true },
                resultsCount: cached.length,
              });
            }
            return { searchId, results: cached, fromCache: true };
          }
        }

        // Create abort controller for cancellation
        const abortController = new AbortController();
        activeSearchJobs.set(searchId, abortController);

        try {
          // Perform live scraping for the keyword
          const results = await scrapeByKeyword(input.keyword, input.maxPages, {
            signal: abortController.signal,
          });

          // Save results to database so they can be looked up by name
          for (const result of results) {
            try {
              await insertDomainWithMetrics(
                {
                  domainName: result.domain.domainName,
                  tld: result.domain.tld,
                  status: result.domain.status as 'available' | 'registered' | 'pending',
                  birthYear: result.domain.birthYear,
                  droppedDate: result.domain.droppedDate ? new Date(result.domain.droppedDate) : null,
                },
                {
                  backlinksCount: result.metrics.backlinksCount,
                  domainPop: result.metrics.domainPop,
                  trustFlow: result.metrics.trustFlow,
                  citationFlow: result.metrics.citationFlow,
                  domainAuthority: result.metrics.domainAuthority,
                  pageAuthority: result.metrics.pageAuthority,
                  archiveSnapshots: result.metrics.archiveSnapshots,
                  spamScore: result.metrics.spamScore,
                  isDictionaryWord: false,
                  hasCleanHistory: true,
                  majesticGlobalRank: result.metrics.majesticGlobalRank || 0,
                  inDmoz: result.metrics.inDmoz || false,
                  wikipediaLinks: result.metrics.wikipediaLinks || 0,
                  relatedDomains: result.metrics.relatedDomains || 0,
                  registeredTlds: result.metrics.registeredTlds || 0,
                }
              );
            } catch (err) {
              // Domain may already exist, continue
            }
          }

          // Cache the results
          setCachedSearch(input.keyword, input.maxPages, results);

          // Save search history if user is authenticated
          if (ctx.user) {
            await saveSearchHistory({
              userId: ctx.user.id,
              searchQuery: input.keyword,
              filtersApplied: { keyword: input.keyword, maxPages: input.maxPages },
              resultsCount: results.length,
            });
          }

          return { searchId, results, fromCache: false };
        } finally {
          activeSearchJobs.delete(searchId);
        }
      }),

    // Cancel an active search
    cancelSearch: publicProcedure
      .input(z.object({ searchId: z.string() }))
      .mutation(({ input }) => {
        const controller = activeSearchJobs.get(input.searchId);
        if (controller) {
          controller.abort();
          activeSearchJobs.delete(input.searchId);
          return { success: true, message: 'Search cancelled' };
        }
        return { success: false, message: 'Search not found or already completed' };
      }),

    quickFind: publicProcedure
      .input(z.object({ limit: z.number().optional() }))
      .query(async ({ input }) => {
        return await getQuickFindDomains(input.limit);
      }),

    getById: publicProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return await getDomainById(input.id);
      }),

    getByName: publicProcedure
      .input(z.object({ name: z.string() }))
      .query(async ({ input }) => {
        return await getDomainByName(input.name);
      }),

    getHistory: publicProcedure
      .input(z.object({ domainId: z.number() }))
      .query(async ({ input }) => {
        return await getDomainHistory(input.domainId);
      }),

    // Get scraping jobs
    getJobs: publicProcedure
      .input(z.object({ limit: z.number().optional() }))
      .query(async ({ input }) => {
        const { getScrapingJobs, cleanupStaleJobs } = await import("./jobs/jobManager");
        // Clean up stale jobs first
        await cleanupStaleJobs();
        return await getScrapingJobs(input.limit);
      }),

    // Stop a running job
    stopJob: publicProcedure
      .input(z.object({ jobId: z.string() }))
      .mutation(async ({ input }) => {
        const { stopJob } = await import("./jobs/jobManager");
        const success = await stopJob(input.jobId);
        return { success, message: success ? 'Job stopped' : 'Job not found or already stopped' };
      }),

    // Delete a job
    deleteJob: publicProcedure
      .input(z.object({ jobId: z.string() }))
      .mutation(async ({ input }) => {
        const { deleteJob } = await import("./jobs/jobManager");
        const success = await deleteJob(input.jobId);
        return { success, message: success ? 'Job deleted' : 'Job not found' };
      }),

    // New scraping endpoint
    scrape: publicProcedure
      .input(z.object({ maxPages: z.number().min(1).max(10).default(3) }))
      .mutation(async ({ input }) => {
        const { createScrapingJob, updateScrapingJob, addJobLog, saveJobResults } = await import("./jobs/jobManager");
        const jobId = await createScrapingJob("MANUAL_SCRAPE");
        
        try {
          await updateScrapingJob(jobId, { status: "running" });
          await addJobLog(jobId, `Starting scrape of ${input.maxPages} pages`);
          
          const result = await scrapeExpiredDomains(input.maxPages);
          
          // Fetch the recently saved domains to include in results
          const recentDomains = await searchDomains({ limit: result.saved || 50 });
          const jobResults = recentDomains.map(d => ({
            domainName: d.domain.domainName,
            tld: d.domain.tld,
            birthYear: d.domain.birthYear ?? undefined,
            backlinksCount: d.metrics.backlinksCount,
            domainAuthority: d.metrics.domainAuthority,
            trustFlow: d.metrics.trustFlow,
            qualityScore: d.metrics.qualityScore,
          }));
          
          // Save results to job
          await saveJobResults(jobId, jobResults);
          
          await updateScrapingJob(jobId, { 
            status: "completed",
            endTime: new Date(),
            domainsFound: result.scraped,
            domainsSaved: result.saved
          });
          await addJobLog(jobId, `Completed: Scraped ${result.scraped}, Saved ${result.saved}`);

          return {
            success: true,
            jobId,
            scraped: result.scraped,
            saved: result.saved,
            message: `Successfully scraped ${result.scraped} domains, saved ${result.saved} new domains`,
          };
        } catch (error: any) {
          console.error('Scraping error:', error);
          await updateScrapingJob(jobId, { 
            status: "failed",
            endTime: new Date()
          });
          await addJobLog(jobId, `Error: ${error.message}`);
          
          return {
            success: false,
            jobId,
            scraped: 0,
            saved: 0,
            message: `Scraping failed: ${error.message}`,
          };
        }
      }),

    // Check domain availability
    checkAvailability: publicProcedure
      .input(z.object({ domain: z.string() }))
      .query(async ({ input }) => {
        const whoisData = await checkDomainWhois(input.domain);
        return whoisData;
      }),

    // Get archive data
    getArchiveInfo: publicProcedure
      .input(z.object({ domain: z.string() }))
      .query(async ({ input }) => {
        const archiveData = await getArchiveData(input.domain);
        return archiveData;
      }),

    // Discover subdomains for a domain
    discoverSubdomains: publicProcedure
      .input(z.object({ 
        domain: z.string(),
        useDnsEnum: z.boolean().optional().default(true),
        useExternalApis: z.boolean().optional().default(true),
        useCertTransparency: z.boolean().optional().default(true),
        usePermutations: z.boolean().optional().default(true),
      }))
      .mutation(async ({ input }) => {
        const { createScrapingJob, updateScrapingJob, addJobLog } = await import("./jobs/jobManager");
        const { discoverSubdomains } = await import("./scrapers/subdomainDiscovery");
        
        const jobId = await createScrapingJob(`SUBDOMAIN_DISCOVERY: ${input.domain}`);
        
        try {
          await updateScrapingJob(jobId, { status: "running" });
          await addJobLog(jobId, `Starting subdomain discovery for ${input.domain}`);
          
          const result = await discoverSubdomains(input.domain, {
            useDnsEnum: input.useDnsEnum,
            useExternalApis: input.useExternalApis,
            useCertTransparency: input.useCertTransparency,
            usePermutations: input.usePermutations,
          });
          
          await updateScrapingJob(jobId, { 
            status: "completed",
            endTime: new Date(),
            domainsFound: result.totalFound,
            domainsSaved: result.totalFound
          });
          await addJobLog(jobId, `Completed: Found ${result.totalFound} subdomains using ${result.techniques.join(', ')}`);

          return {
            success: true,
            jobId,
            ...result,
          };
        } catch (error: any) {
          console.error('Subdomain discovery error:', error);
          await updateScrapingJob(jobId, { 
            status: "failed",
            endTime: new Date()
          });
          await addJobLog(jobId, `Error: ${error.message}`);
          
          return {
            success: false,
            jobId,
            domain: input.domain,
            subdomains: [],
            dnsRecords: { ns: [], mx: [], txt: [], cname: [] },
            totalFound: 0,
            techniques: [],
            duration: 0,
            message: `Subdomain discovery failed: ${error.message}`,
          };
        }
      }),

    // Get score breakdown for a domain
    getScoreBreakdown: publicProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const domainData = await getDomainById(input.id);
        if (!domainData) {
          return null;
        }
        
        const breakdown = getScoreBreakdown({
          backlinksCount: domainData.metrics.backlinksCount,
          domainPop: domainData.metrics.domainPop,
          trustFlow: domainData.metrics.trustFlow,
          citationFlow: domainData.metrics.citationFlow,
          domainAuthority: domainData.metrics.domainAuthority,
          pageAuthority: domainData.metrics.pageAuthority,
          archiveSnapshots: domainData.metrics.archiveSnapshots,
          spamScore: domainData.metrics.spamScore,
          isDictionaryWord: domainData.metrics.isDictionaryWord,
          hasCleanHistory: domainData.metrics.hasCleanHistory,
          birthYear: domainData.domain.birthYear,
        });
        
        return {
          domain: domainData.domain.domainName,
          ...breakdown,
        };
      }),

    // Get backlink profile for a domain
    getBacklinks: publicProcedure
      .input(z.object({ domain: z.string() }))
      .mutation(async ({ input }) => {
        const { createScrapingJob, updateScrapingJob, addJobLog } = await import("./jobs/jobManager");
        const { getBacklinkProfile } = await import("./scrapers/backlinkChecker");
        
        const jobId = await createScrapingJob(`BACKLINK_ANALYSIS: ${input.domain}`);
        
        try {
          await updateScrapingJob(jobId, { status: "running" });
          await addJobLog(jobId, `Starting backlink analysis for ${input.domain}`);
          
          const result = await getBacklinkProfile(input.domain);
          
          await updateScrapingJob(jobId, { 
            status: "completed",
            endTime: new Date(),
            domainsFound: result.totalBacklinks,
            domainsSaved: result.uniqueDomains
          });
          await addJobLog(jobId, `Completed: Found ${result.totalBacklinks} backlinks from ${result.uniqueDomains} domains`);

          return {
            success: true,
            jobId,
            ...result,
          };
        } catch (error: any) {
          console.error('Backlink analysis error:', error);
          await updateScrapingJob(jobId, { 
            status: "failed",
            endTime: new Date()
          });
          await addJobLog(jobId, `Error: ${error.message}`);
          
          return {
            success: false,
            jobId,
            domain: input.domain,
            totalBacklinks: 0,
            uniqueDomains: 0,
            dofollowPercent: 0,
            nofollowPercent: 0,
            backlinks: [],
            topReferringDomains: [],
            anchorTexts: [],
            duration: 0,
            message: `Backlink analysis failed: ${error.message}`,
          };
        }
      }),
  }),

  favorites: router({
    list: protectedProcedure.query(async ({ ctx }) => {
      return await getUserFavorites(ctx.user.id);
    }),

    add: protectedProcedure
      .input(
        z.object({
          domainId: z.number(),
          notes: z.string().optional(),
        })
      )
      .mutation(async ({ input, ctx }) => {
        await addToFavorites({
          userId: ctx.user.id,
          domainId: input.domainId,
          notes: input.notes || null,
        });
        return { success: true };
      }),

    remove: protectedProcedure
      .input(z.object({ favoriteId: z.number() }))
      .mutation(async ({ input }) => {
        await removeFromFavorites(input.favoriteId);
        return { success: true };
      }),
  }),

  settings: router({
    // Get all settings (masks secret values)
    getAll: publicProcedure.query(async () => {
      const settings = await getAllAppSettings();
      return settings.map(s => ({
        ...s,
        value: s.isSecret ? (s.value ? '••••••••' : null) : s.value,
      }));
    }),

    // Get a specific setting
    get: publicProcedure
      .input(z.object({ key: z.string() }))
      .query(async ({ input }) => {
        const setting = await getAppSetting(input.key);
        if (!setting) return null;
        return {
          ...setting,
          value: setting.isSecret ? (setting.value ? '••••••••' : null) : setting.value,
        };
      }),

    // Set a setting
    set: publicProcedure
      .input(z.object({
        key: z.string(),
        value: z.string().nullable(),
        description: z.string().optional(),
        isSecret: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        await setAppSetting(input.key, input.value, input.description, input.isSecret);
        
        // If setting MOZ_API_TOKEN, also update the environment variable
        if (input.key === 'MOZ_API_TOKEN' && input.value) {
          process.env.MOZ_API_TOKEN = input.value;
        }
        
        return { success: true };
      }),

    // Delete a setting
    delete: publicProcedure
      .input(z.object({ key: z.string() }))
      .mutation(async ({ input }) => {
        await deleteAppSetting(input.key);
        return { success: true };
      }),

    // Test MOZ API connection
    testMozApi: publicProcedure.mutation(async () => {
      const { testMozApi } = await import("./scrapers/mozApi");
      const isConnected = await testMozApi();
      return { success: isConnected };
    }),

    // ExpiredDomains.net credentials management
    getExpiredDomainsStatus: publicProcedure.query(async () => {
      const {
        hasExpiredDomainsCredentials,
        getExpiredDomainsCredentials,
        getCachedSession,
      } = await import("./_core/expiredDomainsAuth");

      const hasCredentials = await hasExpiredDomainsCredentials();
      const session = await getCachedSession();
      let username = null;

      if (hasCredentials) {
        const creds = await getExpiredDomainsCredentials();
        username = creds?.username || null;
      }

      return {
        hasCredentials,
        username,
        hasActiveSession: session !== null,
      };
    }),

    saveExpiredDomainsCredentials: publicProcedure
      .input(z.object({
        username: z.string().min(1, "Username is required"),
        password: z.string().min(1, "Password is required"),
      }))
      .mutation(async ({ input }) => {
        const { saveExpiredDomainsCredentials } = await import("./_core/expiredDomainsAuth");
        await saveExpiredDomainsCredentials(input.username, input.password);
        return { success: true, message: 'ExpiredDomains credentials saved' };
      }),

    clearExpiredDomainsSession: publicProcedure.mutation(async () => {
      const { clearSession } = await import("./_core/expiredDomainsAuth");
      await clearSession();
      return { success: true, message: 'ExpiredDomains session cleared' };
    }),

    testExpiredDomainsLogin: publicProcedure.mutation(async () => {
      const { chromium } = await import('playwright');
      const {
        loginToExpiredDomains,
        getExpiredDomainsCredentials,
      } = await import("./_core/expiredDomainsAuth");

      const creds = await getExpiredDomainsCredentials();
      if (!creds) {
        return { success: false, message: 'No credentials configured' };
      }

      const browser = await chromium.launch({ headless: true });
      try {
        const page = await browser.newPage();
        const cookies = await loginToExpiredDomains(page, creds);

        if (cookies) {
          return { success: true, message: 'Successfully logged in to ExpiredDomains.net' };
        } else {
          return { success: false, message: 'Login failed - check your credentials' };
        }
      } finally {
        await browser.close();
      }
    }),
  }),

  stats: router({
    // Get dashboard stats
    getDashboardStats: publicProcedure.query(async () => {
      const { getCurrentSchedule, getLastScrapingResult } = await import("./jobs/scrapingScheduler");
      const [totalDomains, highQualityCount, avgTrustFlow] = await Promise.all([
        getTotalDomainCount(),
        getHighQualityDomainCount(),
        getAverageTrustFlow(),
      ]);

      const schedule = getCurrentSchedule();
      const lastResult = getLastScrapingResult();
      const scheduleTime = `${schedule.hour.toString().padStart(2, '0')}:${schedule.minute.toString().padStart(2, '0')}`;

      return {
        totalDomains,
        highQualityCount,
        avgTrustFlow,
        lastScanTime: lastResult ? new Date(lastResult.timestamp).toLocaleTimeString() : scheduleTime,
        nextScanTime: `${scheduleTime} (daily)`,
        scheduleHour: schedule.hour,
        scheduleMinute: schedule.minute,
      };
    }),
  }),

  schedule: router({
    // Get current schedule
    get: publicProcedure.query(async () => {
      const { getCurrentSchedule, getLastScrapingResult, getScheduledJobDescription } = await import("./jobs/scrapingScheduler");
      const schedule = getCurrentSchedule();
      const lastResult = getLastScrapingResult();
      const description = getScheduledJobDescription();
      
      return {
        hour: schedule.hour,
        minute: schedule.minute,
        cronExpression: schedule.cronExpression,
        lastRun: lastResult,
        description,
      };
    }),

    // Update schedule time
    update: publicProcedure
      .input(z.object({
        hour: z.number().min(0).max(23),
        minute: z.number().min(0).max(59),
      }))
      .mutation(async ({ input }) => {
        const { updateScheduleTime } = await import("./jobs/scrapingScheduler");
        const result = updateScheduleTime(input.hour, input.minute);
        
        // Also save to settings for persistence
        await setAppSetting(
          'SCRAPE_SCHEDULE_HOUR', 
          input.hour.toString(), 
          'Hour for daily scraping (0-23)', 
          false
        );
        await setAppSetting(
          'SCRAPE_SCHEDULE_MINUTE', 
          input.minute.toString(), 
          'Minute for daily scraping (0-59)', 
          false
        );
        
        return {
          success: true,
          hour: result.hour,
          minute: result.minute,
          message: `Schedule updated to ${result.hour.toString().padStart(2, '0')}:${result.minute.toString().padStart(2, '0')} daily`,
        };
      }),
  }),
});

export type AppRouter = typeof appRouter;
