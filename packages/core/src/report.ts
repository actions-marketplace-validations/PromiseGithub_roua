import type { AuditReport, Severity } from "./postgres/audit.js";

const LABEL: Record<Severity, string> = { pass: "PASS", info: "INFO", warn: "WARN", fail: "FAIL", error: "ERR " };

export interface FormatOptions {
  color?: boolean;
  /** Show details for passing checks too. */
  verbose?: boolean;
}

/** Human-readable report for terminals. */
export function formatReport(report: AuditReport, opts: FormatOptions = {}): string {
  const c = (code: number, s: string) => (opts.color ? `\u001b[${code}m${s}\u001b[0m` : s);
  const paint: Record<Severity, (s: string) => string> = {
    pass: (s) => c(32, s),
    info: (s) => c(36, s),
    warn: (s) => c(33, s),
    fail: (s) => c(31, s),
    error: (s) => c(35, s),
  };
  const lines: string[] = [];
  const ver = report.server_version_num ? ` (PostgreSQL ${Math.floor(report.server_version_num / 10000)})` : "";
  lines.push(`ROUA audit: role ${report.role}${ver}`, "");
  for (const r of report.results) {
    lines.push(`${paint[r.severity](LABEL[r.severity])}  ${r.id.padEnd(3)} ${r.title}`);
    if (r.severity !== "pass" || opts.verbose) for (const d of r.details) lines.push(`           ${d}`);
    if (r.fix && (r.severity === "fail" || r.severity === "warn")) lines.push(`           fix: ${r.fix}`);
  }
  const s = report.summary;
  lines.push("");
  const verdict = report.ok
    ? paint.pass(s.warn ? "READ-ONLY, with warnings" : "READ-ONLY")
    : paint.fail("NOT READ-ONLY (or not safe to hand over)");
  lines.push(`${verdict}   ${s.fail} fail, ${s.warn} warn, ${s.pass} pass, ${s.info} info${s.error ? `, ${s.error} error` : ""}`);
  return lines.join("\n");
}

const SPEC_URL = "https://github.com/PromiseGithub/roua/blob/main/SPEC.md#8-verification";

/**
 * SARIF 2.1.0 for GitHub code scanning and other SARIF viewers. Each check is a
 * rule; each failing or warning check is a result. Audit findings are not in a
 * source file, so results point at `artifactUri` (the account definition by
 * default) and name the role as a logical location.
 */
export function toSarif(reports: AuditReport[], opts: { version?: string; artifactUri?: string } = {}): string {
  const rules = new Map<string, { id: string; name: string; shortDescription: { text: string }; helpUri: string }>();
  const results: unknown[] = [];
  for (const r of reports) {
    for (const c of r.results) {
      if (!rules.has(c.id)) rules.set(c.id, { id: c.id, name: c.title.replace(/[^A-Za-z0-9]+/g, " ").trim(), shortDescription: { text: c.title }, helpUri: SPEC_URL });
      if (c.severity === "pass" || c.severity === "info") continue;
      results.push({
        ruleId: c.id,
        level: c.severity === "warn" ? "warning" : "error",
        message: { text: `${r.role}: ${c.title}.${c.details.length ? " " + c.details.slice(0, 5).join("; ") : ""}${c.fix ? ` Fix: ${c.fix}` : ""}` },
        locations: [
          {
            physicalLocation: { artifactLocation: { uri: opts.artifactUri ?? "roua.yaml" } },
            logicalLocations: [{ name: r.role, kind: "member", fullyQualifiedName: `database role ${r.role}` }],
          },
        ],
        partialFingerprints: { rouaCheck: `${r.role}/${c.id}` },
      });
    }
  }
  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [{ tool: { driver: { name: "ROUA audit", version: opts.version ?? "0.1", informationUri: "https://kaizam.com", rules: [...rules.values()] } }, results }],
    },
    null,
    2,
  );
}

const xml = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** JUnit XML: one test suite per role, one test case per check. Warnings fail only when strict. */
export function toJunit(reports: AuditReport[], opts: { strict?: boolean } = {}): string {
  const suites = reports.map((r) => {
    const bad = (s: string) => s === "fail" || s === "error" || (opts.strict && s === "warn");
    const cases = r.results.map((c) => {
      const body = bad(c.severity)
        ? `<failure message="${xml(c.title)}" type="${c.severity}">${xml([...c.details, c.fix ? `fix: ${c.fix}` : ""].filter(Boolean).join("\n"))}</failure>`
        : c.severity === "warn" || c.severity === "info"
          ? `<system-out>${xml(`${c.severity.toUpperCase()}: ${c.details.join("\n")}`)}</system-out>`
          : "";
      return `    <testcase classname="roua.${xml(r.role)}" name="${xml(`${c.id} ${c.title}`)}">${body}</testcase>`;
    });
    const failures = r.results.filter((c) => bad(c.severity)).length;
    return `  <testsuite name="ROUA audit: ${xml(r.role)}" tests="${r.results.length}" failures="${failures}" timestamp="${xml(r.generated_at)}">\n${cases.join("\n")}\n  </testsuite>`;
  });
  return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuites name="ROUA audit">\n${suites.join("\n")}\n</testsuites>\n`;
}
