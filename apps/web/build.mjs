// Builds the kaizam.com site into dist/: one self-contained HTML file per page
// (home, one per database, guides), plus 404.html, sitemap.xml and robots.txt.
// Every page inlines the same script and styles, pinned by SHA-256 in its
// Content-Security-Policy, so each works offline and cannot load or send anything.
import { build } from "esbuild";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { pathToFileURL } from "node:url";
import { PAGES, SITE } from "./src/pages.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const src = (p) => join(here, "src", p);
const dist = join(here, "dist");

const result = await build({
  entryPoints: [src("main.ts")],
  bundle: true,
  format: "iife",
  target: ["es2020"],
  minify: true,
  legalComments: "none",
  write: false,
  alias: { "@roua-dev/core": join(here, "../../packages/core/src/index.ts") },
});
// Escape "</" so the bundle cannot close the <script> element early.
const script = result.outputFiles[0].text.replace(/<\/(script)/gi, "<\\/$1").trimEnd();
const style = readFileSync(src("styles.css"), "utf8").trim();

const hash = (s) => `'sha256-${createHash("sha256").update(s, "utf8").digest("base64")}'`;
const csp = [
  "default-src 'none'",
  `script-src ${hash(script)}`,
  `style-src ${hash(style)}`,
  "img-src data:",
  "connect-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");

const forbidden = ["fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "EventSource", "importScripts"];
const found = forbidden.filter((f) => script.includes(f));
if (found.length) throw new Error(`Bundle must not use network APIs: ${found.join(", ")}`);

const buildId = createHash("sha256").update(script + style).digest("hex").slice(0, 12);

// Tables rendered into the HTML (not by JavaScript), so search engines, AI
// assistants and readers without JavaScript see them. Data comes from core.
const core = await import(pathToFileURL(join(here, "../../packages/core/dist/index.js")).href);
const h = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const SUPPORT_LABEL = { full: "Full", tested: "Tested in CI", preview: "Preview" };
const levelsFor = (id, info) => (id === "postgresql" ? "L0–L5" : "how" in info.fields.metadata ? "L0, L1, L2" : "L1, L2");
const dbRows = core.ENGINES.map((id) => {
  const i = core.ENGINE_INFO[id];
  return `<tr><td><a href="/${id}/">${h(i.name)}</a><br><button type="button" class="use" data-use="${id}">Create one</button></td><td><span class="badge ${i.support}">${SUPPORT_LABEL[i.support]}</span></td><td>${h(i.versions)}</td><td>${levelsFor(id, i)}</td><td>${h(i.summary)}</td><td>${h(i.covers || "")}</td></tr>`;
}).join("\n        ");
const profileRows = core.PROFILES.map((p) => `<tr><td><b>${h(core.PROFILE_INFO[p].title)}</b> <code>${p}</code></td><td>${core.PROFILE_INFO[p].maxExpiryDays} days</td></tr>`).join("\n          ");
const levelRows = core.LEVELS.map((l) => `<tr><td><b>${l}</b> ${h(core.LEVEL_INFO[l].name)}</td><td>${h(core.LEVEL_INFO[l].canRead)}</td></tr>`).join("\n          ");
const template = readFileSync(src("template.html"), "utf8");
const attr = (s) => s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
const json = (o) => JSON.stringify(o).replace(/</g, "\\u003c");

const footerLinks = [
  ...PAGES.filter((p) => p.engine).map((p) => `<a href="/${p.path}">${p.eyebrow.replace("ROUA for ", "")}</a>`),
  `<a href="/ai-agents/">AI agents</a>`,
  `<a href="/app-review/">App review accounts</a>`,
  `<a href="/compare/">ROUA vs built-in read roles</a>`,
  `<a href="/threat-model/">Threat model</a>`,
  `<a href="/SHA256SUMS">Verify this page (SHA-256)</a>`,
].join("\n      ");

function render(page, { notFound = false } = {}) {
  const url = `${SITE}/${page.path}`;
  const ld = page.path === ""
    ? {
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        name: "ROUA",
        alternateName: "Read-Only User Account",
        applicationCategory: "DeveloperApplication",
        operatingSystem: "Any (runs in a web browser)",
        offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
        url,
        description: page.description,
        author: { "@type": "Person", name: "Promise Okoroji", url: "https://github.com/PromiseGithub" },
        license: "https://www.apache.org/licenses/LICENSE-2.0",
        codeRepository: "https://github.com/PromiseGithub/roua",
      }
    : {
        "@context": "https://schema.org",
        "@type": "TechArticle",
        headline: page.h1,
        description: page.description,
        url,
        author: { "@type": "Person", name: "Promise Okoroji", url: "https://github.com/PromiseGithub" },
        isPartOf: { "@type": "WebSite", name: "ROUA", url: `${SITE}/` },
      };
  let html = template
    .replace("__CSP__", csp)
    .replaceAll("__TITLE__", attr(page.title))
    .replaceAll("__DESCRIPTION__", attr(page.description))
    .replaceAll("__CANONICAL__", url)
    .replace("__JSONLD__", () => json(ld))
    .replace("__ENGINE__", page.engine)
    .replace("__PROFILE__", page.profile ?? "")
    .replace("__EYEBROW__", page.eyebrow)
    .replace("__H1__", page.h1)
    .replace("__LEDE__", page.lede)
    .replace("__PAGE_SECTION__", () => page.section)
    .replace("__FOOTER_LINKS__", footerLinks)
    .replace("__DB_ROWS__", () => dbRows)
    .replace("__PROFILE_ROWS__", () => profileRows)
    .replace("__LEVEL_ROWS__", () => levelRows)
    .replace("__BUILD__", buildId)
    .replace("<style>__STYLE__</style>", () => `<style>${style}</style>`)
    .replace("<script>__SCRIPT__</script>", () => `<script>${script}</script>`);
  if (notFound) {
    html = html
      .replace(/<link rel="canonical"[^>]*>/, `<meta name="robots" content="noindex">`)
      .replace(/<meta property="og:url"[^>]*>\n/, "")
      .replace(/<script type="application\/ld\+json">.*?<\/script>\n/s, "");
  }
  // Links to other sites (GitHub, npm…) open in a new tab, without giving that tab
  // a handle on this page (noopener) or telling it where the visitor came from (noreferrer).
  html = html.replace(/<a ([^>]*?)href="(https?:\/\/[^"]+)"([^>]*)>/g, (m, before, url, after) => {
    if (new URL(url).hostname === new URL(SITE).hostname) return m;
    const attrs = `${before}${after}`.replace(/\s*\b(rel|target)="[^"]*"/g, "").trim();
    return `<a ${attrs ? attrs + " " : ""}href="${url}" target="_blank" rel="noopener noreferrer">`;
  });
  const left = html.match(/__[A-Z_]+__/);
  if (left) throw new Error(`Unfilled placeholder ${left[0]} in ${page.path || "index"}`);
  return html;
}

rmSync(dist, { recursive: true, force: true });
const sums = [];
const write = (rel, content) => {
  const file = join(dist, rel);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, content);
  if (rel.endsWith(".html")) sums.push(`${createHash("sha256").update(content).digest("hex")}  ${rel}`);
};

for (const page of PAGES) write(`${page.path}index.html`, render(page));
write(
  "404.html",
  render(
    {
      path: "404.html",
      engine: "",
      title: "Page not found | ROUA",
      description: "This page does not exist.",
      eyebrow: "404",
      h1: "That page does not exist.",
      lede: `Try the <a href="/">home page</a>, or pick a database below.`,
      section: "",
    },
    { notFound: true },
  ),
);

const today = new Date().toISOString().slice(0, 10);
write(
  "sitemap.xml",
  `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${PAGES.map((p) => `  <url><loc>${SITE}/${p.path}</loc><lastmod>${today}</lastmod><priority>${p.path === "" ? "1.0" : "0.8"}</priority></url>`).join("\n")}
</urlset>
`,
);
write("robots.txt", `User-agent: *\nAllow: /\n\nSitemap: ${SITE}/sitemap.xml\n`);
writeFileSync(join(dist, "SHA256SUMS"), sums.join("\n") + "\n");
writeFileSync(join(dist, "index.html.sha256"), `${sums.find((s) => s.endsWith("  index.html"))}\n`);

const size = readFileSync(join(dist, "index.html")).length;
console.log(`apps/web/dist: ${PAGES.length} pages + 404, sitemap.xml, robots.txt  (${(size / 1024).toFixed(1)} KiB each)`);
console.log(sums.find((s) => s.endsWith("  index.html")));
