import { describe, expect, it } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createTestContext(authenticated: boolean = false): TrpcContext {
  const user: AuthenticatedUser | undefined = authenticated
    ? {
        id: 1,
        openId: "test-user",
        email: "test@example.com",
        name: "Test User",
        loginMethod: "manus",
        role: "user",
        createdAt: new Date(),
        updatedAt: new Date(),
        lastSignedIn: new Date(),
      }
    : undefined;

  return {
    user,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: () => {},
    } as TrpcContext["res"],
  };
}

describe("domains.search", () => {
  it("should return domains matching keyword search", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.domains.search({
      keyword: "tech",
      limit: 10,
    });

    expect(Array.isArray(result)).toBe(true);
    // Should find domains with "tech" in the name
    const hasTechDomain = result.some((r) => r.domain.domainName.includes("tech"));
    expect(hasTechDomain).toBe(true);
  });

  it("should filter by minimum backlinks", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.domains.search({
      minBacklinks: 200,
      limit: 10,
    });

    expect(Array.isArray(result)).toBe(true);
    // All results should have backlinks >= 200
    result.forEach((r) => {
      expect(r.metrics.backlinksCount).toBeGreaterThanOrEqual(200);
    });
  });

  it("should filter by minimum trust flow", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.domains.search({
      minTrustFlow: 50,
      limit: 10,
    });

    expect(Array.isArray(result)).toBe(true);
    // All results should have trust flow >= 50
    result.forEach((r) => {
      expect(r.metrics.trustFlow).toBeGreaterThanOrEqual(50);
    });
  });

  it("should filter by minimum age", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.domains.search({
      minAge: 10,
      limit: 10,
    });

    expect(Array.isArray(result)).toBe(true);
    const currentYear = new Date().getFullYear();
    // All results should be at least 10 years old
    result.forEach((r) => {
      if (r.domain.birthYear) {
        const age = currentYear - r.domain.birthYear;
        expect(age).toBeGreaterThanOrEqual(10);
      }
    });
  });

  it("should filter dictionary words only", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.domains.search({
      dictionaryOnly: true,
      limit: 10,
    });

    expect(Array.isArray(result)).toBe(true);
    // All results should be dictionary words
    result.forEach((r) => {
      expect(r.metrics.isDictionaryWord).toBe(true);
    });
  });

  it("should combine multiple filters", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.domains.search({
      minBacklinks: 100,
      minTrustFlow: 40,
      minAge: 5,
      dictionaryOnly: true,
      limit: 10,
    });

    expect(Array.isArray(result)).toBe(true);
    const currentYear = new Date().getFullYear();
    
    result.forEach((r) => {
      expect(r.metrics.backlinksCount).toBeGreaterThanOrEqual(100);
      expect(r.metrics.trustFlow).toBeGreaterThanOrEqual(40);
      expect(r.metrics.isDictionaryWord).toBe(true);
      if (r.domain.birthYear) {
        const age = currentYear - r.domain.birthYear;
        expect(age).toBeGreaterThanOrEqual(5);
      }
    });
  });
});

describe("domains.quickFind", () => {
  it("should return high-quality domains with preset filters", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.domains.quickFind({ limit: 20 });

    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
    
    // Quick find should return domains meeting quality criteria
    result.forEach((r) => {
      expect(r.metrics.backlinksCount).toBeGreaterThanOrEqual(10);
      expect(r.metrics.trustFlow).toBeGreaterThanOrEqual(5);
      expect(r.metrics.citationFlow).toBeGreaterThanOrEqual(10);
      expect(r.metrics.archiveSnapshots).toBeGreaterThanOrEqual(20);
    });
  });

  it("should respect limit parameter", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.domains.quickFind({ limit: 5 });

    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeLessThanOrEqual(5);
  });

  it("should return domains sorted by quality score", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.domains.quickFind({ limit: 10 });

    expect(Array.isArray(result)).toBe(true);
    
    // Results should be sorted by quality score descending
    for (let i = 1; i < result.length; i++) {
      expect(result[i - 1].metrics.qualityScore).toBeGreaterThanOrEqual(
        result[i].metrics.qualityScore
      );
    }
  });
});

describe("domains.getById", () => {
  it("should return domain details by ID", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    // First, get a domain from search
    const searchResult = await caller.domains.search({ limit: 1 });
    expect(searchResult.length).toBeGreaterThan(0);
    
    const domainId = searchResult[0].domain.id;
    const result = await caller.domains.getById({ id: domainId });

    expect(result).toBeDefined();
    expect(result?.domain.id).toBe(domainId);
    expect(result?.metrics).toBeDefined();
  });

  it("should return null for non-existent domain", async () => {
    const ctx = createTestContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.domains.getById({ id: 999999 });

    expect(result).toBeNull();
  });
});

describe("favorites", () => {
  it("should require authentication to add favorites", async () => {
    const ctx = createTestContext(false); // Not authenticated
    const caller = appRouter.createCaller(ctx);

    await expect(
      caller.favorites.add({ domainId: 1 })
    ).rejects.toThrow();
  });

  it("should allow authenticated users to add favorites", async () => {
    const ctx = createTestContext(true); // Authenticated
    const caller = appRouter.createCaller(ctx);

    // Get a domain first
    const searchResult = await caller.domains.search({ limit: 1 });
    expect(searchResult.length).toBeGreaterThan(0);
    
    const domainId = searchResult[0].domain.id;
    const result = await caller.favorites.add({
      domainId,
      notes: "Test favorite",
    });

    expect(result.success).toBe(true);
  });

  it("should require authentication to list favorites", async () => {
    const ctx = createTestContext(false); // Not authenticated
    const caller = appRouter.createCaller(ctx);

    await expect(caller.favorites.list()).rejects.toThrow();
  });

  it("should allow authenticated users to list favorites", async () => {
    const ctx = createTestContext(true); // Authenticated
    const caller = appRouter.createCaller(ctx);

    const result = await caller.favorites.list();

    expect(Array.isArray(result)).toBe(true);
  });
});
