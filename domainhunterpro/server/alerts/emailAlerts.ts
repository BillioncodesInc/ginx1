import { notifyOwner } from '../_core/notification';

export interface DomainAlert {
  domainName: string;
  qualityScore: number;
  domainAuthority: number;
  pageAuthority: number;
  backlinks: number;
  trustFlow: number;
  citationFlow: number;
  age: number | null;
}

/**
 * Send email alert for high-quality domain
 */
export async function sendDomainAlert(domain: DomainAlert): Promise<boolean> {
  const title = `🎯 High-Quality Domain Found: ${domain.domainName}`;
  
  const content = `
A new high-quality expired domain has been discovered:

**Domain:** ${domain.domainName}
**Quality Score:** ${domain.qualityScore}/100

**Moz Metrics:**
- Domain Authority: ${domain.domainAuthority}
- Page Authority: ${domain.pageAuthority}

**SEO Metrics:**
- Backlinks: ${domain.backlinks}
- Trust Flow: ${domain.trustFlow}
- Citation Flow: ${domain.citationFlow}
- Domain Age: ${domain.age ? `${domain.age} years` : 'Unknown'}

This domain meets your high-quality criteria (score > 80).

**Next Steps:**
1. Review the domain in Domain Hunter Pro
2. Check availability and purchase if interested
3. Analyze backlink profile and historical content
  `.trim();

  try {
    const success = await notifyOwner({ title, content });
    if (success) {
      console.log(`[Email Alert] Sent alert for ${domain.domainName}`);
    } else {
      console.warn(`[Email Alert] Failed to send alert for ${domain.domainName}`);
    }
    return success;
  } catch (error) {
    console.error(`[Email Alert] Error sending alert for ${domain.domainName}:`, error);
    return false;
  }
}

/**
 * Send batch alert for multiple high-quality domains
 */
export async function sendBatchDomainAlert(domains: DomainAlert[]): Promise<boolean> {
  if (domains.length === 0) {
    return true;
  }

  const title = `🎯 ${domains.length} High-Quality Domains Found`;
  
  const domainList = domains
    .map((d, i) => `${i + 1}. **${d.domainName}** (Score: ${d.qualityScore}/100, DA: ${d.domainAuthority}, PA: ${d.pageAuthority})`)
    .join('\n');

  const content = `
${domains.length} new high-quality expired domains have been discovered:

${domainList}

All domains meet your high-quality criteria (score > 80).

**Next Steps:**
1. Review these domains in Domain Hunter Pro
2. Check availability and prioritize by score
3. Analyze backlink profiles before purchasing
  `.trim();

  try {
    const success = await notifyOwner({ title, content });
    if (success) {
      console.log(`[Email Alert] Sent batch alert for ${domains.length} domains`);
    } else {
      console.warn(`[Email Alert] Failed to send batch alert`);
    }
    return success;
  } catch (error) {
    console.error(`[Email Alert] Error sending batch alert:`, error);
    return false;
  }
}

/**
 * Check if domain qualifies for alert (score > 80)
 */
export function shouldSendAlert(qualityScore: number): boolean {
  return qualityScore > 80;
}
