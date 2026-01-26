import { describe, expect, it } from "vitest";
import { getMozMetrics, testMozApi } from "./scrapers/mozApi";

describe("Moz API Integration", () => {
  it("should have MOZ_API_TOKEN configured", () => {
    expect(process.env.MOZ_API_TOKEN).toBeDefined();
    expect(process.env.MOZ_API_TOKEN).not.toBe("");
  });

  it("should successfully fetch Moz metrics for a known domain", async () => {
    const result = await getMozMetrics("example.com");
    
    expect(result).toBeDefined();
    expect(typeof result.domainAuthority).toBe("number");
    expect(typeof result.pageAuthority).toBe("number");
    expect(typeof result.spamScore).toBe("number");
    
    // If there's an error, log it for debugging
    if (result.error) {
      console.log("Moz API Error:", result.error);
    }
    
    // The API should not return an error for a valid domain
    expect(result.error).toBeUndefined();
  }, { timeout: 20000 });

  it("should pass connectivity test", async () => {
    const isConnected = await testMozApi();
    expect(isConnected).toBe(true);
  }, { timeout: 20000 });

  it("should return valid DA/PA ranges", async () => {
    const result = await getMozMetrics("example.com");
    
    // Domain Authority should be between 0-100
    expect(result.domainAuthority).toBeGreaterThanOrEqual(0);
    expect(result.domainAuthority).toBeLessThanOrEqual(100);
    
    // Page Authority should be between 0-100
    expect(result.pageAuthority).toBeGreaterThanOrEqual(0);
    expect(result.pageAuthority).toBeLessThanOrEqual(100);
    
    // Spam Score should be between 0-100
    expect(result.spamScore).toBeGreaterThanOrEqual(0);
    expect(result.spamScore).toBeLessThanOrEqual(100);
  }, { timeout: 20000 });
});
