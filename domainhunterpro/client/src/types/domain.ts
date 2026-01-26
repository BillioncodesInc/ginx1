/**
 * Shared domain-related types for client components
 * Consolidates duplicate type definitions from MangoTree components
 */

/**
 * Domain result interface used across visualization components
 */
export interface DomainResult {
  domain: {
    id: number;
    domainName: string;
    tld: string;
    birthYear: number | null;
  };
  metrics: {
    backlinksCount: number;
    trustFlow: number;
    citationFlow: number;
    domainAuthority: number;
    pageAuthority: number;
    qualityScore: number;
  };
}

/**
 * Quality score thresholds
 */
export const QUALITY_THRESHOLDS = {
  EXCELLENT: 75,
  GOOD: 60,
  FAIR: 45,
} as const;

/**
 * Get quality level based on score
 */
export function getQualityLevel(score: number): 'excellent' | 'good' | 'fair' | 'poor' {
  if (score >= QUALITY_THRESHOLDS.EXCELLENT) return 'excellent';
  if (score >= QUALITY_THRESHOLDS.GOOD) return 'good';
  if (score >= QUALITY_THRESHOLDS.FAIR) return 'fair';
  return 'poor';
}

/**
 * Calculate domain age from birth year
 */
export function getDomainAge(birthYear: number | null): number | null {
  if (!birthYear) return null;
  return new Date().getFullYear() - birthYear;
}

/**
 * Format domain age for display
 */
export function formatDomainAge(birthYear: number | null): string {
  const age = getDomainAge(birthYear);
  if (age === null) return '—';
  return `${age}y`;
}
