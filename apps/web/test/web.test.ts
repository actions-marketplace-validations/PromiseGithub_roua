import { readFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it, beforeAll } from "vitest";
import { planPostgres, validateConfig, configToYaml } from "@roua-dev/core";
import { parse } from "yaml";
import { formToConfig, type FormValues } from "../src/form.js";
// @ts-expect-error plain ES module without types
import { PAGES, SITE } from "../src/pages.mjs";

const NOW = new Date("2026-11-23T12:00:00Z");
const form: FormValues = {
  name: "roua_agent_docs", profile: "agent", level: "L2", owner: "you@example.com", purpose: "Docs agent",
  approvedBy: "cto@example.com", approvalRef: "T-1", expiresDate: "2027-01-31", maxConnections: "5", statementTimeout: "30",
  allowedSources: "10.0.0.0/24", database: "appdb", schemas: "public, sales", objectOwner: "app_owner", include: "",
  exclude: "public.salaries public.api_keys", publicObjects: "", analyticsViews: "", columnsDeny: "public.users.national_id",
  columnsAllow: "", mask: "", revokeTemp: true, revokePublicCreate: false, plaintext: false,
};

describe("web generator", () => {
  it("form -> config is valid, and its roua.yaml gives the CLI the same plan (I14)", () => {
    const { config, errors } = formToConfig(form);
    expect(errors).toEqual([]);
    const v = validateConfig(config, { now: NOW });
    expect(v.errors).toEqual([]);
    const fromWeb = planPostgres(v.config!, { now: NOW, secret: { kind: "placeholder" } });
    // Round-trip through the YAML the page offers for download, as the CLI would read it.
    const reread = validateConfig(parse(configToYaml(v.config!)), { now: NOW });
    expect(reread.errors).toEqual([]);
    const fromCli = planPostgres(reread.config!, { now: NOW, secret: { kind: "placeholder" } });
    expect(fromCli.setupSql).toBe(fromWeb.setupSql);
  });

  it("parses mask lines and reports bad ones", () => {
    const { config, errors } = formToConfig({ ...form, level: "L4", profile: "audit", mask: "public.users.email: email\nnonsense" });
    expect(config.scope?.mask).toEqual({ "public.users.email": "email" });
    expect(errors[0]).toMatch(/Mask line 2/);
  });

  describe("built site (I15)", () => {
    const distDir = fileURLToPath(new URL("../dist/", import.meta.url));
    const read = (rel: string) => readFileSync(distDir + rel, "utf8");
    beforeAll(() => {
      if (!existsSync(distDir + "index.html")) execFileSync(process.execPath, [fileURLToPath(new URL("../build.mjs", import.meta.url))]);
    });
    const pages = [...PAGES.map((p) => `${p.path}index.html`), "404.html"];

    it.each(pages)("%s is self-contained, with a CSP that forbids all network access", (rel) => {
      const html = read(rel);
      const csp = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html)?.[1] ?? "";
      expect(csp).toContain("default-src 'none'");
      expect(csp).toContain("connect-src 'none'");
      expect(csp).toContain("form-action 'none'");
      expect(csp).toMatch(/script-src 'sha256-[A-Za-z0-9+/=]+'/);
      expect(csp).not.toContain("unsafe");
      // Nothing is loaded from anywhere: no external scripts, styles, icons or images.
      expect(html).not.toMatch(/<script[^>]+src=|<link(?![^>]*rel="canonical")[^>]*>|<img[^>]+src=["']?https?:|<iframe/i);
      // Outbound links load nothing; only these hosts are linked.
      const hosts = new Set([...html.matchAll(/href="https?:\/\/([^/"]+)/g)].map((m) => m[1]));
      for (const h of hosts) expect(["github.com", "www.npmjs.com", "kaizam.com"]).toContain(h);
      // Every link to another site opens in a new tab, with noopener and noreferrer.
      const external = [...html.matchAll(/<a [^>]*href="https?:\/\/(?!kaizam\.com)[^"]+"[^>]*>/g)].map((m) => m[0]);
      expect(external.length).toBeGreaterThan(0);
      for (const a of external) expect(a, a).toMatch(/target="_blank" rel="noopener noreferrer"/);
      // Links within the site stay in the same tab.
      for (const a of html.matchAll(/<a [^>]*href="(\/|#)[^"]*"[^>]*>/g)) expect(a[0]).not.toContain("_blank");
      expect(html).not.toMatch(/__[A-Z_]+__/);
    });

    it("every page has its own title, description and canonical URL", () => {
      const titles = new Set<string>();
      for (const p of PAGES) {
        const html = read(`${p.path}index.html`);
        const title = /<title>([^<]+)<\/title>/.exec(html)![1]!;
        expect(titles.has(title)).toBe(false);
        titles.add(title);
        expect(html).toContain(`<link rel="canonical" href="${SITE}/${p.path}">`);
        expect(html).toMatch(/<meta name="description" content="[^"]{80,}">/);
        expect(html).toContain(`data-engine="${p.engine}"`);
        JSON.parse(/<script type="application\/ld\+json">(.*?)<\/script>/s.exec(html)![1]!);
      }
      expect(read("404.html")).toContain('<meta name="robots" content="noindex">');
    });

    it("the sitemap and robots.txt list every page", () => {
      const sitemap = read("sitemap.xml");
      for (const p of PAGES) expect(sitemap).toContain(`<loc>${SITE}/${p.path}</loc>`);
      expect(read("robots.txt")).toContain(`Sitemap: ${SITE}/sitemap.xml`);
      for (const p of PAGES) expect(read("SHA256SUMS")).toContain(`  ${p.path}index.html`);
    });

    it("offers every database and the account check", () => {
      const html = read("index.html");
      for (const id of ["engines", "checkForm", "dbTable", "generator", "check", "faq"]) expect(html).toContain(`id="${id}"`);
      // The support, profile and level tables are in the HTML itself (crawlable, readable without JavaScript).
      expect(html.match(/data-use="/g)?.length).toBe(9);
      expect(/<table class="mini" id="profileTable">.*?<tbody>(.*?)<\/tbody>/s.exec(html)![1]!.match(/<tr>/g)?.length).toBe(8);
      expect(/<table class="mini" id="levelTable">.*?<tbody>(.*?)<\/tbody>/s.exec(html)![1]!.match(/<tr>/g)?.length).toBe(6);
    });
  });
});
