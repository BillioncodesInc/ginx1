/**
 * Test script for security checker APIs
 * Run with: npx tsx server/scrapers/securityChecker.test.ts
 */

import { 
  checkGoogleSafeBrowsing, 
  checkSpamhaus, 
  checkVirusTotal,
  performSecurityCheck 
} from './securityChecker';

const TEST_DOMAINS = [
  'google.com',      // Known safe domain
  'example.com',     // Known safe domain
  'malware.testing.google.test', // Google's test URL (may trigger Safe Browsing)
];

async function testDNSBlacklists() {
  console.log('\n=== Testing DNS Blacklist Checks ===\n');
  
  for (const domain of TEST_DOMAINS.slice(0, 2)) {
    console.log(`Testing: ${domain}`);
    const result = await checkSpamhaus(domain);
    console.log('  Checked:', result.checked);
    console.log('  Is Listed:', result.isListed);
    console.log('  Lists:', result.lists.length > 0 ? result.lists.join(', ') : 'None');
    console.log('');
  }
  
  // Check if Spamhaus DQS key is configured
  if (!process.env.SPAMHAUS_DQS_KEY) {
    console.log('⚠️  SPAMHAUS_DQS_KEY not configured - Spamhaus DBL/ZEN checks skipped');
    console.log('   Get free key at: https://www.spamhaus.org/free-trial/sign-up-for-a-free-data-query-service-account\n');
  } else {
    console.log('✓ SPAMHAUS_DQS_KEY configured - Full Spamhaus checks enabled\n');
  }
}

async function testGoogleSafeBrowsing() {
  console.log('\n=== Testing Google Safe Browsing API ===\n');
  
  if (!process.env.GOOGLE_SAFE_BROWSING_API_KEY) {
    console.log('⚠️  GOOGLE_SAFE_BROWSING_API_KEY not configured');
    console.log('   Get free key at: https://console.cloud.google.com (enable Safe Browsing API)');
    console.log('   Free tier: 10,000 requests/day\n');
    
    // Test anyway to show the response
    const result = await checkGoogleSafeBrowsing('google.com');
    console.log('Result without API key:');
    console.log('  Checked:', result.checked);
    console.log('  Is Safe:', result.isSafe);
    console.log('');
    return;
  }
  
  console.log('✓ GOOGLE_SAFE_BROWSING_API_KEY configured\n');
  
  for (const domain of TEST_DOMAINS.slice(0, 2)) {
    console.log(`Testing: ${domain}`);
    const result = await checkGoogleSafeBrowsing(domain);
    console.log('  Checked:', result.checked);
    console.log('  Is Safe:', result.isSafe);
    console.log('  Threats:', result.threats.length > 0 ? result.threats.join(', ') : 'None');
    console.log('');
  }
}

async function testVirusTotal() {
  console.log('\n=== Testing VirusTotal API ===\n');
  
  if (!process.env.VIRUSTOTAL_API_KEY) {
    console.log('⚠️  VIRUSTOTAL_API_KEY not configured');
    console.log('   Get free key at: https://www.virustotal.com/gui/join-us');
    console.log('   Free tier: 500 requests/day, 4 requests/minute\n');
    
    // Test anyway to show the response
    const result = await checkVirusTotal('google.com');
    console.log('Result without API key:');
    console.log('  Checked:', result.checked);
    console.log('');
    return;
  }
  
  console.log('✓ VIRUSTOTAL_API_KEY configured\n');
  
  for (const domain of TEST_DOMAINS.slice(0, 2)) {
    console.log(`Testing: ${domain}`);
    const result = await checkVirusTotal(domain);
    console.log('  Checked:', result.checked);
    console.log('  Malicious:', result.malicious);
    console.log('  Suspicious:', result.suspicious);
    console.log('  Harmless:', result.harmless);
    console.log('  Undetected:', result.undetected);
    console.log('');
  }
}

async function testFullSecurityCheck() {
  console.log('\n=== Testing Full Security Check ===\n');
  
  const domain = 'google.com';
  console.log(`Running comprehensive security check on: ${domain}\n`);
  
  const result = await performSecurityCheck(domain);
  
  console.log('Results:');
  console.log('  Safe Browsing:');
  console.log('    - Checked:', result.safeBrowsing.checked);
  console.log('    - Is Safe:', result.safeBrowsing.isSafe);
  console.log('    - Threats:', result.safeBrowsing.threats.length > 0 ? result.safeBrowsing.threats.join(', ') : 'None');
  
  console.log('  DNS Blacklists:');
  console.log('    - Checked:', result.spamhaus.checked);
  console.log('    - Is Listed:', result.spamhaus.isListed);
  console.log('    - Lists:', result.spamhaus.lists.length > 0 ? result.spamhaus.lists.join(', ') : 'None');
  
  console.log('  VirusTotal:');
  console.log('    - Checked:', result.virusTotal.checked);
  console.log('    - Malicious:', result.virusTotal.malicious);
  console.log('    - Suspicious:', result.virusTotal.suspicious);
  
  console.log('\n  Overall Assessment:');
  console.log('    - Risk Level:', result.overallRisk);
  console.log('    - Risk Score:', result.riskScore, '/ 100');
}

async function main() {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║         Security Checker API Test Suite                    ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  
  console.log('\nEnvironment Variables Status:');
  console.log('  SPAMHAUS_DQS_KEY:', process.env.SPAMHAUS_DQS_KEY ? '✓ Set' : '✗ Not set');
  console.log('  GOOGLE_SAFE_BROWSING_API_KEY:', process.env.GOOGLE_SAFE_BROWSING_API_KEY ? '✓ Set' : '✗ Not set');
  console.log('  VIRUSTOTAL_API_KEY:', process.env.VIRUSTOTAL_API_KEY ? '✓ Set' : '✗ Not set');
  
  try {
    await testDNSBlacklists();
    await testGoogleSafeBrowsing();
    await testVirusTotal();
    await testFullSecurityCheck();
    
    console.log('\n╔════════════════════════════════════════════════════════════╗');
    console.log('║                    Test Complete!                          ║');
    console.log('╚════════════════════════════════════════════════════════════╝\n');
    
    console.log('Summary:');
    console.log('- DNS Blacklists (SURBL, URIBL, Barracuda) work without API keys');
    console.log('- Spamhaus DBL/ZEN requires free DQS key');
    console.log('- Google Safe Browsing requires free API key');
    console.log('- VirusTotal requires free API key');
    console.log('\nAll APIs gracefully handle missing keys and return checked: false');
    
  } catch (error) {
    console.error('\n❌ Test failed with error:', error);
    process.exit(1);
  }
}

main();
