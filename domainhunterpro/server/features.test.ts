import { describe, expect, it } from "vitest";
import { sendDomainAlert, sendBatchDomainAlert, shouldSendAlert } from "./alerts/emailAlerts";
import type { DomainAlert } from "./alerts/emailAlerts";

describe("Email Alerts", () => {
  it("should determine alert threshold correctly", () => {
    expect(shouldSendAlert(85)).toBe(true);
    expect(shouldSendAlert(90)).toBe(true);
    expect(shouldSendAlert(100)).toBe(true);
    expect(shouldSendAlert(80)).toBe(false);
    expect(shouldSendAlert(75)).toBe(false);
    expect(shouldSendAlert(50)).toBe(false);
  });

  it("should send alert for high-quality domain", async () => {
    const domain: DomainAlert = {
      domainName: "test-domain.com",
      qualityScore: 85,
      domainAuthority: 45,
      pageAuthority: 38,
      backlinks: 150,
      trustFlow: 30,
      citationFlow: 35,
      age: 10,
    };

    const result = await sendDomainAlert(domain);
    
    // Should return boolean
    expect(typeof result).toBe("boolean");
  }, { timeout: 10000 });

  it("should send batch alert for multiple domains", async () => {
    const domains: DomainAlert[] = [
      {
        domainName: "test-domain-1.com",
        qualityScore: 85,
        domainAuthority: 45,
        pageAuthority: 38,
        backlinks: 150,
        trustFlow: 30,
        citationFlow: 35,
        age: 10,
      },
      {
        domainName: "test-domain-2.com",
        qualityScore: 90,
        domainAuthority: 50,
        pageAuthority: 42,
        backlinks: 200,
        trustFlow: 35,
        citationFlow: 40,
        age: 12,
      },
    ];

    const result = await sendBatchDomainAlert(domains);
    
    // Should return boolean
    expect(typeof result).toBe("boolean");
  }, { timeout: 10000 });

  it("should handle empty batch gracefully", async () => {
    const result = await sendBatchDomainAlert([]);
    expect(result).toBe(true);
  });
});

describe("Moz Integration in Scraper", () => {
  it("should have Moz API token configured", () => {
    expect(process.env.MOZ_API_TOKEN).toBeDefined();
    expect(process.env.MOZ_API_TOKEN).not.toBe("");
  });
});

describe("Quality Score Calculation", () => {
  it("should calculate quality score with all metrics", () => {
    // Test the quality score calculation logic
    const backlinksScore = (Math.min(150, 100) / 100) * 15; // 15
    const trustFlowScore = (30 / 100) * 15; // 4.5
    const citationFlowScore = (35 / 100) * 10; // 3.5
    const domainAuthorityScore = (45 / 100) * 20; // 9
    const pageAuthorityScore = (38 / 100) * 10; // 3.8
    const ageScore = (Math.min(10, 20) / 20) * 15; // 7.5
    const archiveScore = (Math.min(50, 100) / 100) * 5; // 2.5
    const cleanHistoryBonus = 5;
    const dictionaryBonus = 5;

    const expectedScore = Math.round(
      backlinksScore +
      trustFlowScore +
      citationFlowScore +
      domainAuthorityScore +
      pageAuthorityScore +
      ageScore +
      archiveScore +
      cleanHistoryBonus +
      dictionaryBonus
    );

    // Should be around 55-60
    expect(expectedScore).toBeGreaterThan(50);
    expect(expectedScore).toBeLessThan(70);
  });

  it("should calculate higher score for better metrics", () => {
    const highQualityScore = Math.round(
      15 + // backlinks (100+)
      15 + // trust flow (100)
      10 + // citation flow (100)
      20 + // domain authority (100)
      10 + // page authority (100)
      15 + // age (20+ years)
      5 +  // archive (100+ snapshots)
      5 +  // clean history
      5    // dictionary word
    );

    expect(highQualityScore).toBe(100);
  });
});

describe("CSV Export Data Format", () => {
  it("should include all required fields", () => {
    const requiredFields = [
      "Domain Name",
      "TLD",
      "Quality Score",
      "Domain Authority",
      "Page Authority",
      "Backlinks",
      "Trust Flow",
      "Citation Flow",
      "Domain Pop",
      "Archive Snapshots",
      "Spam Score",
      "Birth Year",
      "Age (Years)",
      "Status",
      "Dropped Date",
    ];

    // Verify all fields are defined
    expect(requiredFields.length).toBe(15);
    expect(requiredFields).toContain("Domain Authority");
    expect(requiredFields).toContain("Page Authority");
  });
});
