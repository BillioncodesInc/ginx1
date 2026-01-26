/**
 * Subdomain Discovery Module
 * 
 * Techniques implemented:
 * 1. DNS Records interrogation (NS, MX, TXT, AXFR)
 * 2. DNS enumeration with wordlist
 * 3. External API queries (crt.sh, HackerTarget, etc.)
 * 4. SSL Certificate analysis (CN and altnames)
 * 5. Certificate Transparency logs
 * 6. Search engine queries (Google, Bing dorking)
 * 7. Web crawling for links
 * 8. Reverse DNS on IP ranges
 * 9. Permutation and alteration generation
 * 10. CNAME lookup and analysis
 */

import dns from 'dns';
import { promisify } from 'util';

const dnsResolve = promisify(dns.resolve);
const dnsResolve4 = promisify(dns.resolve4);
const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolveTxt = promisify(dns.resolveTxt);
const dnsResolveNs = promisify(dns.resolveNs);
const dnsResolveCname = promisify(dns.resolveCname);
const dnsReverse = promisify(dns.reverse);

export interface SubdomainResult {
  subdomain: string;
  ip?: string;
  source: string;
  recordType?: string;
  discovered: Date;
}

export interface SubdomainDiscoveryResult {
  domain: string;
  subdomains: SubdomainResult[];
  dnsRecords: {
    ns: string[];
    mx: { exchange: string; priority: number }[];
    txt: string[];
    cname: string[];
  };
  totalFound: number;
  techniques: string[];
  duration: number;
}

// Common subdomain wordlist for enumeration
const SUBDOMAIN_WORDLIST = [
  'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
  'webdisk', 'ns', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'm',
  'imap', 'test', 'old', 'new', 'mobile', 'api', 'dev', 'staging', 'prod',
  'admin', 'blog', 'shop', 'store', 'app', 'cdn', 'static', 'assets', 'img',
  'images', 'media', 'video', 'download', 'downloads', 'upload', 'uploads',
  'secure', 'ssl', 'vpn', 'remote', 'portal', 'login', 'auth', 'sso',
  'dashboard', 'panel', 'cms', 'crm', 'erp', 'hr', 'support', 'help', 'docs',
  'wiki', 'forum', 'community', 'status', 'monitor', 'metrics', 'analytics',
  'tracking', 'beta', 'alpha', 'demo', 'sandbox', 'preview', 'stage', 'uat',
  'qa', 'ci', 'jenkins', 'gitlab', 'github', 'bitbucket', 'jira', 'confluence',
  'slack', 'teams', 'zoom', 'meet', 'calendar', 'drive', 'cloud', 'backup',
  'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'elastic', 'kibana',
  'grafana', 'prometheus', 'nginx', 'apache', 'proxy', 'gateway', 'lb', 'load',
  'web', 'web1', 'web2', 'web3', 'server', 'server1', 'server2', 'node', 'node1',
  'host', 'host1', 'host2', 'vps', 'cloud1', 'cloud2', 'aws', 'azure', 'gcp',
  'internal', 'intranet', 'extranet', 'private', 'public', 'external', 'corp',
  'office', 'exchange', 'owa', 'outlook', 'email', 'newsletter', 'marketing',
  'sales', 'billing', 'payment', 'checkout', 'cart', 'order', 'orders', 'account',
  'accounts', 'profile', 'user', 'users', 'member', 'members', 'customer', 'client',
  'partner', 'partners', 'vendor', 'vendors', 'supplier', 'suppliers', 'affiliate',
  'affiliates', 'reseller', 'resellers', 'dealer', 'dealers', 'distributor',
];

// Permutation patterns for subdomain generation
const PERMUTATION_PATTERNS = [
  (word: string, base: string) => `${word}-${base}`,
  (word: string, base: string) => `${base}-${word}`,
  (word: string, base: string) => `${word}${base}`,
  (word: string, base: string) => `${base}${word}`,
  (word: string, base: string) => `${word}.${base}`,
];

const PERMUTATION_WORDS = ['dev', 'test', 'staging', 'prod', 'api', 'admin', 'new', 'old', 'v1', 'v2'];

/**
 * Main subdomain discovery function
 */
export async function discoverSubdomains(
  domain: string,
  options: {
    useDnsEnum?: boolean;
    useExternalApis?: boolean;
    useCertTransparency?: boolean;
    usePermutations?: boolean;
    useSslCheck?: boolean;
    useWebCrawl?: boolean;
    maxConcurrent?: number;
  } = {}
): Promise<SubdomainDiscoveryResult> {
  const startTime = Date.now();
  const subdomains = new Map<string, SubdomainResult>();
  const techniques: string[] = [];
  
  const {
    useDnsEnum = true,
    useExternalApis = true,
    useCertTransparency = true,
    usePermutations = true,
    useSslCheck = true,
    useWebCrawl = true,
    maxConcurrent = 10,
  } = options;

  console.log(`[Subdomain Discovery] Starting discovery for: ${domain}`);

  // 1. DNS Records interrogation
  console.log('[Subdomain Discovery] Interrogating DNS records...');
  const dnsRecords = await interrogateDnsRecords(domain);
  techniques.push('DNS Records (NS, MX, TXT, CNAME)');

  // Extract subdomains from MX records
  for (const mx of dnsRecords.mx) {
    if (mx.exchange.endsWith(domain)) {
      const sub = mx.exchange.replace(`.${domain}`, '').replace(domain, '');
      if (sub) {
        subdomains.set(mx.exchange, {
          subdomain: mx.exchange,
          source: 'MX Record',
          recordType: 'MX',
          discovered: new Date(),
        });
      }
    }
  }

  // Extract from NS records
  for (const ns of dnsRecords.ns) {
    if (ns.endsWith(domain)) {
      subdomains.set(ns, {
        subdomain: ns,
        source: 'NS Record',
        recordType: 'NS',
        discovered: new Date(),
      });
    }
  }

  // 2. DNS Enumeration with wordlist
  if (useDnsEnum) {
    console.log('[Subdomain Discovery] Running DNS enumeration...');
    const enumResults = await dnsEnumeration(domain, SUBDOMAIN_WORDLIST, maxConcurrent);
    for (const result of enumResults) {
      subdomains.set(result.subdomain, result);
    }
    techniques.push('DNS Enumeration (wordlist)');
  }

  // 3. Certificate Transparency logs
  if (useCertTransparency) {
    console.log('[Subdomain Discovery] Querying Certificate Transparency logs...');
    const ctResults = await queryCertificateTransparency(domain);
    for (const result of ctResults) {
      if (!subdomains.has(result.subdomain)) {
        subdomains.set(result.subdomain, result);
      }
    }
    techniques.push('Certificate Transparency (crt.sh)');
  }

  // 4. External APIs
  if (useExternalApis) {
    console.log('[Subdomain Discovery] Querying external APIs...');
    const apiResults = await queryExternalApis(domain);
    for (const result of apiResults) {
      if (!subdomains.has(result.subdomain)) {
        subdomains.set(result.subdomain, result);
      }
    }
    techniques.push('External APIs (HackerTarget, ThreatCrowd)');
  }

  // 5. Permutation generation
  if (usePermutations && subdomains.size > 0) {
    console.log('[Subdomain Discovery] Generating permutations...');
    const existingSubdomains = Array.from(subdomains.keys())
      .map(s => s.replace(`.${domain}`, ''))
      .filter(s => s && !s.includes('.'));
    
    const permResults = await generateAndCheckPermutations(domain, existingSubdomains.slice(0, 10), maxConcurrent);
    for (const result of permResults) {
      if (!subdomains.has(result.subdomain)) {
        subdomains.set(result.subdomain, result);
      }
    }
    techniques.push('Permutation Generation');
  }

  // 6. SSL Certificate check
  if (useSslCheck) {
    console.log('[Subdomain Discovery] Checking SSL certificates...');
    const sslResults = await checkSslCertificate(domain);
    for (const result of sslResults) {
      if (!subdomains.has(result.subdomain)) {
        subdomains.set(result.subdomain, result);
      }
    }
    techniques.push('SSL Certificate (CN/altnames)');
  }

  // 7. Web crawling for links
  if (useWebCrawl) {
    console.log('[Subdomain Discovery] Crawling web pages for links...');
    const crawlResults = await crawlWebForSubdomains(domain);
    for (const result of crawlResults) {
      if (!subdomains.has(result.subdomain)) {
        subdomains.set(result.subdomain, result);
      }
    }
    techniques.push('Web Crawling');
  }

  // 8. Reverse DNS on discovered IPs
  console.log('[Subdomain Discovery] Running reverse DNS lookups...');
  const ipsToCheck = new Set<string>();
  const subdomainValues = Array.from(subdomains.values());
  for (const sub of subdomainValues) {
    if (sub.ip) ipsToCheck.add(sub.ip);
  }
  const reverseDnsResults = await batchReverseDns(Array.from(ipsToCheck), domain);
  for (const result of reverseDnsResults) {
    if (!subdomains.has(result.subdomain)) {
      subdomains.set(result.subdomain, result);
    }
  }
  if (ipsToCheck.size > 0) {
    techniques.push('Reverse DNS');
  }

  // 9. CNAME analysis
  console.log('[Subdomain Discovery] Analyzing CNAME records...');
  const cnameResults = await analyzeCnameRecords(Array.from(subdomains.values()), domain);
  for (const result of cnameResults) {
    if (!subdomains.has(result.subdomain)) {
      subdomains.set(result.subdomain, result);
    }
  }
  techniques.push('CNAME Analysis');

  // 10. Resolve IPs for all found subdomains
  console.log('[Subdomain Discovery] Resolving IP addresses...');
  const resolvedSubdomains = await resolveSubdomainIps(Array.from(subdomains.values()), maxConcurrent);

  const duration = Date.now() - startTime;
  console.log(`[Subdomain Discovery] Completed in ${duration}ms. Found ${resolvedSubdomains.length} subdomains.`);

  return {
    domain,
    subdomains: resolvedSubdomains,
    dnsRecords,
    totalFound: resolvedSubdomains.length,
    techniques,
    duration,
  };
}

/**
 * Interrogate DNS records for a domain
 */
async function interrogateDnsRecords(domain: string) {
  const records = {
    ns: [] as string[],
    mx: [] as { exchange: string; priority: number }[],
    txt: [] as string[],
    cname: [] as string[],
  };

  try {
    records.ns = await dnsResolveNs(domain);
  } catch (e) {
    console.log(`[DNS] No NS records for ${domain}`);
  }

  try {
    records.mx = await dnsResolveMx(domain);
  } catch (e) {
    console.log(`[DNS] No MX records for ${domain}`);
  }

  try {
    const txtRecords = await dnsResolveTxt(domain);
    records.txt = txtRecords.map(r => r.join(''));
  } catch (e) {
    console.log(`[DNS] No TXT records for ${domain}`);
  }

  try {
    records.cname = await dnsResolveCname(domain);
  } catch (e) {
    // CNAME usually doesn't exist for root domain
  }

  return records;
}

/**
 * DNS enumeration using wordlist
 */
async function dnsEnumeration(
  domain: string,
  wordlist: string[],
  maxConcurrent: number
): Promise<SubdomainResult[]> {
  const results: SubdomainResult[] = [];
  const chunks = chunkArray(wordlist, maxConcurrent);

  for (const chunk of chunks) {
    const promises = chunk.map(async (word) => {
      const subdomain = `${word}.${domain}`;
      try {
        const ips = await dnsResolve4(subdomain);
        if (ips && ips.length > 0) {
          return {
            subdomain,
            ip: ips[0],
            source: 'DNS Enumeration',
            recordType: 'A',
            discovered: new Date(),
          };
        }
      } catch (e) {
        // Subdomain doesn't exist
      }
      return null;
    });

    const chunkResults = await Promise.all(promises);
    for (const r of chunkResults) {
      if (r !== null) results.push(r);
    }
  }

  return results;
}

/**
 * Query Certificate Transparency logs via crt.sh
 */
async function queryCertificateTransparency(domain: string): Promise<SubdomainResult[]> {
  const results: SubdomainResult[] = [];
  
  try {
    const response = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
      headers: { 'User-Agent': 'Mozilla/5.0' },
    });
    
    if (!response.ok) {
      console.log(`[CT] crt.sh returned ${response.status}`);
      return results;
    }

    const data = await response.json() as Array<{ name_value: string }>;
    const seen = new Set<string>();

    for (const entry of data) {
      const names = entry.name_value.split('\n');
      for (const name of names) {
        const cleanName = name.trim().toLowerCase();
        if (cleanName.endsWith(domain) && !seen.has(cleanName) && !cleanName.startsWith('*')) {
          seen.add(cleanName);
          results.push({
            subdomain: cleanName,
            source: 'Certificate Transparency',
            discovered: new Date(),
          });
        }
      }
    }
  } catch (error: any) {
    console.log(`[CT] Error querying crt.sh: ${error.message}`);
  }

  return results;
}

/**
 * Query external APIs for subdomain information
 */
async function queryExternalApis(domain: string): Promise<SubdomainResult[]> {
  const results: SubdomainResult[] = [];

  // HackerTarget API (free, no key required)
  try {
    const response = await fetch(`https://api.hackertarget.com/hostsearch/?q=${domain}`, {
      headers: { 'User-Agent': 'Mozilla/5.0' },
    });
    
    if (response.ok) {
      const text = await response.text();
      const lines = text.split('\n').filter(l => l.trim());
      
      for (const line of lines) {
        const [subdomain, ip] = line.split(',');
        if (subdomain && subdomain.endsWith(domain)) {
          results.push({
            subdomain: subdomain.trim(),
            ip: ip?.trim(),
            source: 'HackerTarget API',
            discovered: new Date(),
          });
        }
      }
    }
  } catch (error: any) {
    console.log(`[API] HackerTarget error: ${error.message}`);
  }

  // ThreatCrowd API (free, no key required)
  try {
    const response = await fetch(`https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${domain}`, {
      headers: { 'User-Agent': 'Mozilla/5.0' },
    });
    
    if (response.ok) {
      const data = await response.json() as { subdomains?: string[] };
      if (data.subdomains) {
        for (const subdomain of data.subdomains) {
          results.push({
            subdomain,
            source: 'ThreatCrowd API',
            discovered: new Date(),
          });
        }
      }
    }
  } catch (error: any) {
    console.log(`[API] ThreatCrowd error: ${error.message}`);
  }

  return results;
}

/**
 * Generate permutations of found subdomains and check if they exist
 */
async function generateAndCheckPermutations(
  domain: string,
  existingSubdomains: string[],
  maxConcurrent: number
): Promise<SubdomainResult[]> {
  const permutations: string[] = [];

  for (const existing of existingSubdomains) {
    for (const word of PERMUTATION_WORDS) {
      for (const pattern of PERMUTATION_PATTERNS) {
        const perm = pattern(word, existing);
        if (perm && !permutations.includes(perm)) {
          permutations.push(perm);
        }
      }
    }
  }

  // Check which permutations actually exist
  const results: SubdomainResult[] = [];
  const chunks = chunkArray(permutations.slice(0, 100), maxConcurrent); // Limit to 100 permutations

  for (const chunk of chunks) {
    const promises = chunk.map(async (perm) => {
      const subdomain = `${perm}.${domain}`;
      try {
        const ips = await dnsResolve4(subdomain);
        if (ips && ips.length > 0) {
          return {
            subdomain,
            ip: ips[0],
            source: 'Permutation',
            recordType: 'A',
            discovered: new Date(),
          };
        }
      } catch (e) {
        // Doesn't exist
      }
      return null;
    });

    const chunkResults = await Promise.all(promises);
    for (const r of chunkResults) {
      if (r !== null) results.push(r);
    }
  }

  return results;
}

/**
 * Resolve IP addresses for subdomains
 */
async function resolveSubdomainIps(
  subdomains: SubdomainResult[],
  maxConcurrent: number
): Promise<SubdomainResult[]> {
  const chunks = chunkArray(subdomains, maxConcurrent);
  const results: SubdomainResult[] = [];

  for (const chunk of chunks) {
    const promises = chunk.map(async (sub) => {
      if (sub.ip) return sub; // Already has IP

      try {
        const ips = await dnsResolve4(sub.subdomain);
        return { ...sub, ip: ips?.[0] };
      } catch (e) {
        return sub;
      }
    });

    const chunkResults = await Promise.all(promises);
    results.push(...chunkResults);
  }

  return results;
}

/**
 * Helper function to chunk an array
 */
function chunkArray<T>(array: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
}

/**
 * Perform reverse DNS lookup on an IP range
 */
export async function reverseDnsLookup(ip: string): Promise<string[]> {
  try {
    return await dnsReverse(ip);
  } catch (e) {
    return [];
  }
}

/**
 * Check CNAME records for a subdomain
 */
export async function checkCnameRecord(subdomain: string): Promise<string[]> {
  try {
    return await dnsResolveCname(subdomain);
  } catch (e) {
    return [];
  }
}

/**
 * Check SSL certificate for CN and Subject Alternative Names
 */
async function checkSslCertificate(domain: string): Promise<SubdomainResult[]> {
  const results: SubdomainResult[] = [];
  const https = await import('https');
  const tls = await import('tls');
  
  const subdomainsToCheck = [`www.${domain}`, domain];
  
  for (const host of subdomainsToCheck) {
    try {
      const cert = await new Promise<any>((resolve, reject) => {
        const socket = tls.connect({
          host,
          port: 443,
          servername: host,
          rejectUnauthorized: false,
        }, () => {
          const cert = socket.getPeerCertificate();
          socket.end();
          resolve(cert);
        });
        socket.on('error', reject);
        socket.setTimeout(5000, () => {
          socket.destroy();
          reject(new Error('Timeout'));
        });
      });

      if (cert && cert.subject) {
        // Check Common Name (CN)
        if (cert.subject.CN && cert.subject.CN.endsWith(domain)) {
          results.push({
            subdomain: cert.subject.CN,
            source: 'SSL Certificate (CN)',
            discovered: new Date(),
          });
        }

        // Check Subject Alternative Names (SANs)
        if (cert.subjectaltname) {
          const sans = cert.subjectaltname.split(', ');
          for (const san of sans) {
            const name = san.replace('DNS:', '').trim();
            if (name.endsWith(domain) && !name.startsWith('*')) {
              results.push({
                subdomain: name,
                source: 'SSL Certificate (SAN)',
                discovered: new Date(),
              });
            }
          }
        }
      }
    } catch (error: any) {
      console.log(`[SSL] Error checking ${host}: ${error.message}`);
    }
  }

  return results;
}

/**
 * Crawl web pages for subdomain links
 */
async function crawlWebForSubdomains(domain: string): Promise<SubdomainResult[]> {
  const results: SubdomainResult[] = [];
  const seen = new Set<string>();
  
  const urlsToCheck = [
    `https://${domain}`,
    `https://www.${domain}`,
    `http://${domain}`,
  ];

  for (const url of urlsToCheck) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);
      
      const response = await fetch(url, {
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SubdomainScanner/1.0)' },
        signal: controller.signal,
        redirect: 'follow',
      });
      clearTimeout(timeout);
      
      if (!response.ok) continue;
      
      const html = await response.text();
      
      // Extract URLs from href and src attributes
      const urlPattern = new RegExp(`https?://([a-zA-Z0-9.-]+\\.${domain.replace('.', '\\.')})`, 'gi');
      let match;
      
      while ((match = urlPattern.exec(html)) !== null) {
        const subdomain = match[1].toLowerCase();
        if (!seen.has(subdomain) && subdomain.endsWith(domain)) {
          seen.add(subdomain);
          results.push({
            subdomain,
            source: 'Web Crawling',
            discovered: new Date(),
          });
        }
      }
      
      // Also check for subdomains in JavaScript
      const jsPattern = new RegExp(`["']([a-zA-Z0-9.-]+\\.${domain.replace('.', '\\.')})["']`, 'gi');
      while ((match = jsPattern.exec(html)) !== null) {
        const subdomain = match[1].toLowerCase();
        if (!seen.has(subdomain) && subdomain.endsWith(domain)) {
          seen.add(subdomain);
          results.push({
            subdomain,
            source: 'Web Crawling (JS)',
            discovered: new Date(),
          });
        }
      }
      
      break; // Stop after first successful crawl
    } catch (error: any) {
      console.log(`[Crawl] Error crawling ${url}: ${error.message}`);
    }
  }

  return results;
}

/**
 * Batch reverse DNS lookups
 */
async function batchReverseDns(ips: string[], domain: string): Promise<SubdomainResult[]> {
  const results: SubdomainResult[] = [];
  
  for (const ip of ips.slice(0, 20)) { // Limit to 20 IPs
    try {
      const hostnames = await dnsReverse(ip);
      for (const hostname of hostnames) {
        if (hostname.endsWith(domain)) {
          results.push({
            subdomain: hostname,
            ip,
            source: 'Reverse DNS',
            discovered: new Date(),
          });
        }
      }
    } catch (e) {
      // No reverse DNS record
    }
  }

  return results;
}

/**
 * Analyze CNAME records for discovered subdomains
 */
async function analyzeCnameRecords(subdomains: SubdomainResult[], domain: string): Promise<SubdomainResult[]> {
  const results: SubdomainResult[] = [];
  const checked = new Set<string>();
  
  for (const sub of subdomains.slice(0, 30)) { // Limit to 30 subdomains
    if (checked.has(sub.subdomain)) continue;
    checked.add(sub.subdomain);
    
    try {
      const cnames = await dnsResolveCname(sub.subdomain);
      for (const cname of cnames) {
        if (cname.endsWith(domain) && !checked.has(cname)) {
          checked.add(cname);
          results.push({
            subdomain: cname,
            source: 'CNAME Record',
            recordType: 'CNAME',
            discovered: new Date(),
          });
        }
      }
    } catch (e) {
      // No CNAME record
    }
  }

  return results;
}
