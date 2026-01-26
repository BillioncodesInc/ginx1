import { drizzle } from "drizzle-orm/mysql2";
import * as schema from "./drizzle/schema.js";

const sampleDomains = [
  { name: "techblog", tld: "com", birthYear: 2010, backlinks: 145, trustFlow: 42, citationFlow: 38, archiveSnapshots: 89, isDictionary: true },
  { name: "marketpro", tld: "net", birthYear: 2008, backlinks: 230, trustFlow: 55, citationFlow: 52, archiveSnapshots: 124, isDictionary: true },
  { name: "digitalwave", tld: "com", birthYear: 2012, backlinks: 89, trustFlow: 35, citationFlow: 30, archiveSnapshots: 67, isDictionary: true },
  { name: "cloudventure", tld: "io", birthYear: 2015, backlinks: 67, trustFlow: 28, citationFlow: 25, archiveSnapshots: 45, isDictionary: true },
  { name: "webmaster", tld: "org", birthYear: 2005, backlinks: 312, trustFlow: 68, citationFlow: 65, archiveSnapshots: 156, isDictionary: true },
  { name: "startupkit", tld: "com", birthYear: 2014, backlinks: 98, trustFlow: 38, citationFlow: 35, archiveSnapshots: 52, isDictionary: true },
  { name: "biztools", tld: "net", birthYear: 2009, backlinks: 178, trustFlow: 48, citationFlow: 45, archiveSnapshots: 98, isDictionary: true },
  { name: "devhub", tld: "com", birthYear: 2011, backlinks: 156, trustFlow: 45, citationFlow: 42, archiveSnapshots: 78, isDictionary: true },
  { name: "socialnet", tld: "com", birthYear: 2007, backlinks: 289, trustFlow: 62, citationFlow: 58, archiveSnapshots: 134, isDictionary: true },
  { name: "dataforge", tld: "io", birthYear: 2016, backlinks: 54, trustFlow: 25, citationFlow: 22, archiveSnapshots: 38, isDictionary: true },
  { name: "appstore", tld: "net", birthYear: 2006, backlinks: 267, trustFlow: 58, citationFlow: 55, archiveSnapshots: 145, isDictionary: true },
  { name: "codebase", tld: "com", birthYear: 2013, backlinks: 112, trustFlow: 40, citationFlow: 37, archiveSnapshots: 61, isDictionary: true },
  { name: "netcraft", tld: "org", birthYear: 2004, backlinks: 345, trustFlow: 72, citationFlow: 68, archiveSnapshots: 178, isDictionary: true },
  { name: "webforge", tld: "com", birthYear: 2010, backlinks: 134, trustFlow: 43, citationFlow: 40, archiveSnapshots: 72, isDictionary: true },
  { name: "techstack", tld: "io", birthYear: 2017, backlinks: 45, trustFlow: 22, citationFlow: 20, archiveSnapshots: 29, isDictionary: true },
  { name: "marketplace", tld: "com", birthYear: 2008, backlinks: 298, trustFlow: 65, citationFlow: 62, archiveSnapshots: 142, isDictionary: true },
  { name: "innovate", tld: "net", birthYear: 2011, backlinks: 123, trustFlow: 41, citationFlow: 38, archiveSnapshots: 68, isDictionary: true },
  { name: "growthlab", tld: "com", birthYear: 2014, backlinks: 87, trustFlow: 36, citationFlow: 33, archiveSnapshots: 49, isDictionary: true },
  { name: "smarttools", tld: "org", birthYear: 2009, backlinks: 189, trustFlow: 50, citationFlow: 47, archiveSnapshots: 102, isDictionary: true },
  { name: "futuretech", tld: "com", birthYear: 2012, backlinks: 145, trustFlow: 44, citationFlow: 41, archiveSnapshots: 75, isDictionary: true },
  { name: "digitalspace", tld: "net", birthYear: 2010, backlinks: 167, trustFlow: 46, citationFlow: 43, archiveSnapshots: 85, isDictionary: true },
  { name: "webcraft", tld: "com", birthYear: 2007, backlinks: 234, trustFlow: 56, citationFlow: 53, archiveSnapshots: 128, isDictionary: true },
  { name: "techwise", tld: "io", birthYear: 2016, backlinks: 62, trustFlow: 27, citationFlow: 24, archiveSnapshots: 41, isDictionary: true },
  { name: "netpower", tld: "com", birthYear: 2006, backlinks: 278, trustFlow: 60, citationFlow: 57, archiveSnapshots: 138, isDictionary: true },
  { name: "cloudbase", tld: "net", birthYear: 2013, backlinks: 98, trustFlow: 37, citationFlow: 34, archiveSnapshots: 56, isDictionary: true },
  { name: "applab", tld: "com", birthYear: 2011, backlinks: 156, trustFlow: 45, citationFlow: 42, archiveSnapshots: 79, isDictionary: true },
  { name: "webzone", tld: "org", birthYear: 2005, backlinks: 312, trustFlow: 67, citationFlow: 64, archiveSnapshots: 152, isDictionary: true },
  { name: "techport", tld: "com", birthYear: 2009, backlinks: 189, trustFlow: 49, citationFlow: 46, archiveSnapshots: 95, isDictionary: true },
  { name: "datastream", tld: "io", birthYear: 2015, backlinks: 73, trustFlow: 30, citationFlow: 27, archiveSnapshots: 47, isDictionary: true },
  { name: "netbridge", tld: "com", birthYear: 2008, backlinks: 245, trustFlow: 57, citationFlow: 54, archiveSnapshots: 131, isDictionary: true },
];

function calculateQualityScore(metrics) {
  const currentYear = new Date().getFullYear();
  const ageYears = currentYear - metrics.birthYear;
  
  const backlinksScore = (Math.min(metrics.backlinks, 100) / 100) * 20;
  const trustFlowScore = (metrics.trustFlow / 100) * 25;
  const citationFlowScore = (metrics.citationFlow / 100) * 15;
  const ageScore = (Math.min(ageYears, 20) / 20) * 20;
  const archiveScore = (Math.min(metrics.archiveSnapshots, 100) / 100) * 10;
  const dictionaryBonus = metrics.isDictionary ? 5 : 0;
  const cleanHistoryBonus = 5;

  return Math.round(
    backlinksScore + 
    trustFlowScore + 
    citationFlowScore + 
    ageScore + 
    archiveScore + 
    dictionaryBonus + 
    cleanHistoryBonus
  );
}

async function seed() {
  if (!process.env.DATABASE_URL) {
    console.error("DATABASE_URL not set");
    process.exit(1);
  }

  const db = drizzle(process.env.DATABASE_URL);

  console.log("Seeding domains...");

  for (const domain of sampleDomains) {
    try {
      const domainName = `${domain.name}.${domain.tld}`;
      
      // Insert domain
      const [insertedDomain] = await db.insert(schema.domains).values({
        domainName,
        tld: domain.tld,
        status: "available",
        birthYear: domain.birthYear,
        droppedDate: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000), // Random date within last 30 days
      });

      const domainId = Number(insertedDomain.insertId);

      // Calculate quality score
      const qualityScore = calculateQualityScore(domain);

      // Insert metrics
      await db.insert(schema.domainMetrics).values({
        domainId,
        backlinksCount: domain.backlinks,
        domainPop: Math.floor(domain.backlinks * 0.6),
        trustFlow: domain.trustFlow,
        citationFlow: domain.citationFlow,
        domainAuthority: Math.floor((domain.trustFlow + domain.citationFlow) / 2),
        archiveSnapshots: domain.archiveSnapshots,
        spamScore: Math.floor(Math.random() * 10),
        qualityScore,
        isDictionaryWord: domain.isDictionary,
        hasCleanHistory: true,
      });

      console.log(`✓ Added ${domainName} (Quality Score: ${qualityScore})`);
    } catch (error) {
      console.error(`✗ Failed to add ${domain.name}.${domain.tld}:`, error.message);
    }
  }

  console.log("\nSeeding complete!");
  process.exit(0);
}

seed().catch((error) => {
  console.error("Seed failed:", error);
  process.exit(1);
});
