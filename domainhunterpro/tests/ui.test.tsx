import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MangoTree } from '../client/src/components/MangoTree';
import { ScrapingJobsTable } from '../client/src/components/ScrapingJobsTable';

// Mock wouter
vi.mock('wouter', () => ({
  useLocation: () => ['/', vi.fn()],
}));

describe('MangoTree Component', () => {
  const mockDomains = [
    {
      domain: { id: 1, domainName: 'test1.com', tld: 'com', birthYear: 2000 },
      metrics: { backlinksCount: 100, trustFlow: 20, qualityScore: 85 }
    },
    {
      domain: { id: 2, domainName: 'test2.com', tld: 'com', birthYear: 2010 },
      metrics: { backlinksCount: 50, trustFlow: 10, qualityScore: 50 }
    }
  ];

  it('renders without crashing', () => {
    render(<MangoTree domains={mockDomains} />);
    expect(screen.getByText('ROOT')).toBeDefined();
  });

  it('renders correct number of nodes', () => {
    const { container } = render(<MangoTree domains={mockDomains} />);
    // 1 root node + 2 domain nodes = 3 circles (but root is separate)
    // We look for the domain nodes which are in groups
    const nodes = container.querySelectorAll('g');
    expect(nodes.length).toBe(2);
  });
});

describe('ScrapingJobsTable Component', () => {
  const mockJobs = [
    {
      id: 'job-1234567890',
      name: 'TEST_JOB',
      status: 'completed' as const,
      startTime: new Date(),
      domainsFound: 10,
      domainsSaved: 5,
      logs: ['Log 1', 'Log 2']
    }
  ];

  it('renders job details correctly', () => {
    render(<ScrapingJobsTable jobs={mockJobs} />);
    expect(screen.getByText('job-12345678...')).toBeDefined();
    expect(screen.getByText('TEST_JOB')).toBeDefined();
    expect(screen.getByText('ok')).toBeDefined();
  });

  it('renders empty state when no jobs', () => {
    render(<ScrapingJobsTable jobs={[]} />);
    expect(screen.getByText('No scraping jobs recorded')).toBeDefined();
  });
});
