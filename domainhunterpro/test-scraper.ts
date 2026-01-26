/**
 * Test script for the expired domains scraper
 * Run with: npx tsx test-scraper.ts
 */

import { scrapeExpiredDomains } from './server/scrapers/expiredDomainsScraper';

async function main() {
  console.log('Starting scraper test...');
  console.log('This will scrape 1 page from expireddomains.net\n');
  
  try {
    const result = await scrapeExpiredDomains(1);
    console.log('\n=== Result ===');
    console.log('Scraped:', result.scraped);
    console.log('Saved:', result.saved);
  } catch (error: any) {
    console.error('\n=== Error ===');
    console.error('Message:', error.message);
    console.error('Stack:', error.stack);
  }
}

main();
