import { describe, expect, it } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

function createTestContext(): TrpcContext {
  return {
    user: undefined,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: () => {},
    } as TrpcContext["res"],
  };
}

describe("domains.scrape", () => {
  it("should have scrape endpoint available", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    // Just verify the endpoint exists and returns proper structure
    // We won't actually run scraping in tests to avoid external dependencies
    expect(caller.domains.scrape).toBeDefined();
  });
});

describe("domains.checkAvailability", () => {
  it("should return whois data structure", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    // Test with a known domain
    const result = await caller.domains.checkAvailability({ 
      domain: "example.com" 
    });

    expect(result).toBeDefined();
    expect(result.domainName).toBe("example.com");
    expect(typeof result.isAvailable).toBe("boolean");
  });
});

describe("domains.getArchiveInfo", () => {
  it("should return archive data structure", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    // Test with a known domain
    const result = await caller.domains.getArchiveInfo({ 
      domain: "example.com" 
    });

    expect(result).toBeDefined();
    expect(result.domainName).toBe("example.com");
    expect(typeof result.snapshotCount).toBe("number");
  }, { timeout: 20000 }); // Increase timeout for external API

  it("should handle domains with no archive data", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    // Test with a likely non-existent domain
    const result = await caller.domains.getArchiveInfo({ 
      domain: "nonexistent-domain-12345.xyz" 
    });

    expect(result).toBeDefined();
    expect(result.snapshotCount).toBeGreaterThanOrEqual(0);
  }, { timeout: 20000 }); // Increase timeout for external API
});

describe("integration: scraped domains", () => {
  it("should be able to search scraped domains", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    // Search for any domains
    const result = await caller.domains.search({ limit: 10 });

    expect(Array.isArray(result)).toBe(true);
    // Should have domains from either sample data or scraping
    expect(result.length).toBeGreaterThan(0);
    
    // Verify domain structure
    if (result.length > 0) {
      const firstDomain = result[0];
      expect(firstDomain.domain).toBeDefined();
      expect(firstDomain.metrics).toBeDefined();
      expect(firstDomain.domain.domainName).toBeDefined();
      expect(typeof firstDomain.metrics.qualityScore).toBe("number");
    }
  });

  it("should return domains with valid metrics", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.domains.search({ limit: 5 });

    result.forEach((domain) => {
      // Verify all metrics are present and valid
      expect(domain.metrics.backlinksCount).toBeGreaterThanOrEqual(0);
      expect(domain.metrics.trustFlow).toBeGreaterThanOrEqual(0);
      expect(domain.metrics.trustFlow).toBeLessThanOrEqual(100);
      expect(domain.metrics.citationFlow).toBeGreaterThanOrEqual(0);
      expect(domain.metrics.citationFlow).toBeLessThanOrEqual(100);
      expect(domain.metrics.qualityScore).toBeGreaterThanOrEqual(0);
      expect(domain.metrics.qualityScore).toBeLessThanOrEqual(100);
    });
  });
});
