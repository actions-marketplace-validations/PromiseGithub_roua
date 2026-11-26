import { describe, expect, it } from "vitest";
import { detectSecretValue, entropy, toJunit, toSarif } from "@roua-dev/core";

describe("value sampling detector (X2)", () => {
  it("finds well-known secret formats", () => {
    const cases: [string, string][] = [
      ["-----BEGIN RSA PRIVATE KEY-----\nMIIE...", "private key (PEM)"],
      ["Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop", "JSON Web Token"],
      ["AKIAIOSFODNN7EXAMPLE", "AWS access key ID"],
      ["ghp_" + "a".repeat(36), "GitHub token"],
      ["xoxb-1234567890-abcdefghij", "Slack token"],
      ["sk_live_abcdefghijklmnop1234", "Stripe secret key"],
      ["AIza" + "B".repeat(35), "Google API key"],
      ["$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012", "password hash"],
      ["postgres://app:hunter22@db.internal:5432/app", "connection string with password"],
      ["key=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A", "high-entropy string"],
    ];
    for (const [v, kind] of cases) expect(detectSecretValue(v), v).toContain(kind);
  });

  it("leaves ordinary values alone", () => {
    for (const v of ["hello world", "ada@example.com", "550e8400-e29b-41d4-a716-446655440000", "2026-11-24T10:00:00Z", "https://kaizam.com/mysql/", "The quick brown fox jumps over the lazy dog", "0123456789012345678901234567890123"]) {
      expect(detectSecretValue(v), v).toEqual([]);
    }
    expect(entropy("aaaa")).toBe(0);
  });
});

describe("SARIF and JUnit", () => {
  const report = {
    roua_report_version: "0.1" as const, role: "ro", server_version_num: 160000, generated_at: "2026-11-24T00:00:00Z", ok: false,
    summary: { pass: 1, info: 0, warn: 1, fail: 1, error: 0 },
    results: [
      { id: "R1", title: "No superuser", severity: "pass" as const, details: [] },
      { id: "T1", title: "No write privileges <on tables>", severity: "fail" as const, details: ["public.t: INSERT"], fix: "REVOKE ..." },
      { id: "G1", title: "Queries are time-limited", severity: "warn" as const, details: ["No statement_timeout"] },
    ],
  };
  it("SARIF lists rules and only failing or warning results", () => {
    const s = JSON.parse(toSarif([report]));
    expect(s.runs[0].tool.driver.rules.map((r: { id: string }) => r.id)).toEqual(["R1", "T1", "G1"]);
    expect(s.runs[0].results.map((r: { ruleId: string; level: string }) => `${r.ruleId}:${r.level}`)).toEqual(["T1:error", "G1:warning"]);
  });
  it("JUnit escapes XML and fails warnings only when strict", () => {
    const x = toJunit([report]);
    expect(x).toContain("&lt;on tables&gt;");
    expect(x).toMatch(/failures="1"/);
    expect(toJunit([report], { strict: true })).toMatch(/failures="2"/);
  });
});
