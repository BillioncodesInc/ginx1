import { eq, desc, sql } from "drizzle-orm";
import { db } from "../db";
import { scrapingJobs, type InsertScrapingJob, type ScrapingJob } from "../../drizzle/schema";
import { nanoid } from "nanoid";

// Track active jobs that can be cancelled
const activeJobs = new Map<string, { cancel: () => void }>();

// Extended job type with results
export interface JobResult {
  domainName: string;
  tld: string;
  birthYear?: number;
  backlinksCount?: number;
  domainAuthority?: number;
  trustFlow?: number;
  qualityScore?: number;
}

export interface ScrapingJobWithResults extends ScrapingJob {
  results?: JobResult[];
}

export async function createScrapingJob(name: string = "MANUAL_SCRAPE"): Promise<string> {
  const id = nanoid();
  
  // Use raw SQL to insert with results field
  await db.run(sql`
    INSERT INTO scrapingJobs (id, name, status, startTime, logs, results, domainsFound, domainsSaved)
    VALUES (${id}, ${name}, 'pending', ${Date.now()}, ${JSON.stringify(["Job initialized"])}, ${JSON.stringify([])}, 0, 0)
  `);
  
  return id;
}

export async function updateScrapingJob(
  id: string, 
  updates: Partial<Omit<ScrapingJob, 'id' | 'createdAt'>>
) {
  const updateData: Record<string, any> = { ...updates };
  
  // Convert Date objects to timestamps for SQLite
  if (updates.endTime) {
    updateData.endTime = updates.endTime;
  }
  
  await db.update(scrapingJobs)
    .set(updateData)
    .where(eq(scrapingJobs.id, id));
}

export async function addJobLog(id: string, message: string) {
  const job = await db.select().from(scrapingJobs).where(eq(scrapingJobs.id, id)).limit(1);
  
  if (job.length > 0) {
    let currentLogs: string[] = [];
    try {
      currentLogs = job[0].logs ? JSON.parse(job[0].logs) : [];
    } catch {
      currentLogs = [];
    }
    
    await db.update(scrapingJobs)
      .set({ logs: JSON.stringify([...currentLogs, message]) })
      .where(eq(scrapingJobs.id, id));
  }
}

/**
 * Save job results (list of domains found)
 */
export async function saveJobResults(id: string, results: JobResult[]) {
  await db.run(sql`
    UPDATE scrapingJobs 
    SET results = ${JSON.stringify(results)}
    WHERE id = ${id}
  `);
}

/**
 * Add a single result to job results
 */
export async function addJobResult(id: string, result: JobResult) {
  // Get current results using db.all
  const jobData = await db.all(sql`SELECT results FROM scrapingJobs WHERE id = ${id}`);
  let currentResults: JobResult[] = [];
  
  try {
    const rows = jobData as any[];
    if (rows && rows[0]?.results) {
      currentResults = JSON.parse(rows[0].results);
    }
  } catch {
    currentResults = [];
  }
  
  // Add new result (limit to 100 to prevent huge payloads)
  currentResults.push(result);
  if (currentResults.length > 100) {
    currentResults = currentResults.slice(-100);
  }
  
  await db.run(sql`
    UPDATE scrapingJobs 
    SET results = ${JSON.stringify(currentResults)}
    WHERE id = ${id}
  `);
}

export async function getScrapingJobs(limit: number = 50): Promise<ScrapingJobWithResults[]> {
  // Use raw SQL to get results field
  const rawJobs = await db.all(sql`
    SELECT id, name, status, startTime, endTime, domainsFound, domainsSaved, logs, results, createdAt, updatedAt
    FROM scrapingJobs 
    ORDER BY startTime DESC 
    LIMIT ${limit}
  `);
  
  // Parse logs and results from JSON string
  return (rawJobs as any[]).map(job => ({
    ...job,
    startTime: job.startTime ? new Date(job.startTime) : null,
    endTime: job.endTime ? new Date(job.endTime) : null,
    createdAt: job.createdAt ? new Date(job.createdAt) : null,
    updatedAt: job.updatedAt ? new Date(job.updatedAt) : null,
    logs: job.logs ? JSON.parse(job.logs) : [],
    results: job.results ? JSON.parse(job.results) : [],
  })) as ScrapingJobWithResults[];
}

export async function getJobById(id: string): Promise<ScrapingJobWithResults | null> {
  const rawJobs = await db.all(sql`
    SELECT id, name, status, startTime, endTime, domainsFound, domainsSaved, logs, results, createdAt, updatedAt
    FROM scrapingJobs 
    WHERE id = ${id}
    LIMIT 1
  `);
  
  if (!rawJobs || (rawJobs as any[]).length === 0) return null;
  
  const job = (rawJobs as any[])[0];
  return {
    ...job,
    startTime: job.startTime ? new Date(job.startTime) : null,
    endTime: job.endTime ? new Date(job.endTime) : null,
    createdAt: job.createdAt ? new Date(job.createdAt) : null,
    updatedAt: job.updatedAt ? new Date(job.updatedAt) : null,
    logs: job.logs ? JSON.parse(job.logs) : [],
    results: job.results ? JSON.parse(job.results) : [],
  } as ScrapingJobWithResults;
}

/**
 * Stop a running job
 */
export async function stopJob(id: string): Promise<boolean> {
  const job = await getJobById(id);
  if (!job) return false;
  
  // If job is running, try to cancel it
  if (job.status === 'running' || job.status === 'pending') {
    const activeJob = activeJobs.get(id);
    if (activeJob) {
      activeJob.cancel();
      activeJobs.delete(id);
    }
    
    await updateScrapingJob(id, {
      status: 'failed',
      endTime: new Date(),
    });
    await addJobLog(id, 'Job stopped by user');
    return true;
  }
  
  return false;
}

/**
 * Delete a job from the database
 */
export async function deleteJob(id: string): Promise<boolean> {
  const job = await getJobById(id);
  if (!job) return false;
  
  // Stop if running
  if (job.status === 'running' || job.status === 'pending') {
    await stopJob(id);
  }
  
  await db.delete(scrapingJobs).where(eq(scrapingJobs.id, id));
  return true;
}

/**
 * Register an active job that can be cancelled
 */
export function registerActiveJob(id: string, cancelFn: () => void) {
  activeJobs.set(id, { cancel: cancelFn });
}

/**
 * Unregister an active job
 */
export function unregisterActiveJob(id: string) {
  activeJobs.delete(id);
}

/**
 * Check if a job should be cancelled
 */
export function isJobCancelled(id: string): boolean {
  return !activeJobs.has(id);
}

/**
 * Mark stale running jobs as failed (jobs running for more than 10 minutes)
 */
export async function cleanupStaleJobs(): Promise<number> {
  const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
  
  const staleJobs = await db.select()
    .from(scrapingJobs)
    .where(eq(scrapingJobs.status, 'running'));
  
  let cleaned = 0;
  for (const job of staleJobs) {
    if (job.startTime && new Date(job.startTime) < tenMinutesAgo) {
      await updateScrapingJob(job.id, {
        status: 'failed',
        endTime: new Date(),
      });
      await addJobLog(job.id, 'Job timed out after 10 minutes');
      activeJobs.delete(job.id);
      cleaned++;
    }
  }
  
  return cleaned;
}
