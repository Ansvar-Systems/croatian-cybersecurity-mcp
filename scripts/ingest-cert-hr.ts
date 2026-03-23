#!/usr/bin/env tsx
/**
 * CERT.hr Ingestion Crawler
 *
 * Crawls the CERT.hr website (cert.hr) and populates the SQLite database
 * with real cybersecurity advisories, guidance documents, and knowledge
 * base publications from Croatia's National CERT.
 *
 * Data sources:
 *   1. WordPress RSS feed     — https://www.cert.hr/feed/ (all posts, paginated)
 *   2. Security advisories    — https://www.cert.hr/upustva-za-trenutne-pretnje/ (listing)
 *      and individual advisory pages (e.g. /sigurnosni-nedostaci-programskog-paketa-*)
 *   3. Knowledge base docs    — https://www.cert.hr/baza-znanja/dokumenti/ (listing)
 *      and PDF publications (CCERT-PUBDOC-*, NCERT-PUBDOC-*)
 *   4. CERT.hr guidelines     — https://www.cert.hr/tag/upozorenje/ (warnings)
 *      and https://www.cert.hr/baza-znanja/ (guidance hub)
 *
 * The site runs WordPress, so we use both the RSS feed for broad coverage and
 * HTML scraping with cheerio for structured content extraction. Advisory pages
 * use a consistent pattern with numeric IDs (e.g. /108826/, /94700/) or
 * descriptive slugs.
 *
 * Usage:
 *   npx tsx scripts/ingest-cert-hr.ts                  # full crawl
 *   npx tsx scripts/ingest-cert-hr.ts --resume          # resume from last checkpoint
 *   npx tsx scripts/ingest-cert-hr.ts --dry-run         # log what would be inserted
 *   npx tsx scripts/ingest-cert-hr.ts --force           # drop and recreate DB first
 *   npx tsx scripts/ingest-cert-hr.ts --advisories-only # only crawl advisories
 *   npx tsx scripts/ingest-cert-hr.ts --guidance-only   # only crawl guidance/knowledge base
 *   npx tsx scripts/ingest-cert-hr.ts --max-pages 5     # limit RSS/listing page crawl depth
 */

import Database from "better-sqlite3";
import * as cheerio from "cheerio";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DB_PATH = process.env["CERTHR_DB_PATH"] ?? "data/certhr.db";
const STATE_FILE = join(dirname(DB_PATH), ".ingest-state.json");

const CERT_HR_BASE = "https://www.cert.hr";
const RSS_FEED_URL = `${CERT_HR_BASE}/feed/`;
const ADVISORIES_LISTING = `${CERT_HR_BASE}/upustva-za-trenutne-pretnje/`;
const KNOWLEDGE_BASE_URL = `${CERT_HR_BASE}/baza-znanja/dokumenti/`;
const WARNINGS_TAG_URL = `${CERT_HR_BASE}/tag/upozorenje/`;

const RATE_LIMIT_MS = 1500;
const MAX_RETRIES = 3;
const RETRY_BACKOFF_MS = 2000;
const REQUEST_TIMEOUT_MS = 30_000;
const USER_AGENT =
  "ansvar-certhr-mcp-crawler/1.0 (contact: hello@ansvar.ai; compliance research)";

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const resume = args.includes("--resume");
const force = args.includes("--force");
const advisoriesOnly = args.includes("--advisories-only");
const guidanceOnly = args.includes("--guidance-only");

function getArgValue(flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1];
}

const maxPages =
  parseInt(getArgValue("--max-pages") ?? "0", 10) || 0;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GuidanceRow {
  reference: string;
  title: string;
  title_en: string | null;
  date: string | null;
  type: string;
  series: string;
  summary: string;
  full_text: string;
  topics: string;
  status: string;
}

interface AdvisoryRow {
  reference: string;
  title: string;
  date: string | null;
  severity: string | null;
  affected_products: string | null;
  summary: string;
  full_text: string;
  cve_references: string | null;
}

interface FrameworkRow {
  id: string;
  name: string;
  name_en: string | null;
  description: string;
  document_count: number;
}

interface IngestState {
  advisoriesCompleted: string[];
  guidanceCompleted: string[];
  rssPagesCrawled: number;
  lastRun: string;
}

interface IngestStats {
  rssPagesCrawled: number;
  advisoryPagesScraped: number;
  guidancePagesScraped: number;
  advisoriesInserted: number;
  guidanceInserted: number;
  frameworksInserted: number;
  skipped: number;
  errors: number;
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function log(level: string, message: string): void {
  const ts = new Date().toISOString().slice(0, 19);
  console.log(`[${ts}] [${level}] ${message}`);
}

function logProgress(stats: IngestStats): void {
  log(
    "INFO",
    `Progress: ${stats.rssPagesCrawled} RSS pages | ` +
      `${stats.advisoriesInserted} advisories | ` +
      `${stats.guidanceInserted} guidance | ` +
      `${stats.frameworksInserted} frameworks | ` +
      `${stats.skipped} skipped | ${stats.errors} errors`,
  );
}

// ---------------------------------------------------------------------------
// State persistence (for --resume)
// ---------------------------------------------------------------------------

function loadState(): IngestState {
  if (resume && existsSync(STATE_FILE)) {
    try {
      const raw = readFileSync(STATE_FILE, "utf-8");
      const state = JSON.parse(raw) as IngestState;
      log(
        "INFO",
        `Resuming from checkpoint (${state.lastRun}): ` +
          `${state.advisoriesCompleted.length} advisories, ` +
          `${state.guidanceCompleted.length} guidance already ingested`,
      );
      return state;
    } catch {
      log("WARN", "Could not parse state file, starting fresh");
    }
  }
  return {
    advisoriesCompleted: [],
    guidanceCompleted: [],
    rssPagesCrawled: 0,
    lastRun: "",
  };
}

function saveState(state: IngestState): void {
  state.lastRun = new Date().toISOString();
  const dir = dirname(STATE_FILE);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

let lastRequestTime = 0;

async function rateLimitedFetch(
  url: string,
  retries = MAX_RETRIES,
): Promise<Response> {
  const now = Date.now();
  const elapsed = now - lastRequestTime;
  if (elapsed < RATE_LIMIT_MS) {
    await sleep(RATE_LIMIT_MS - elapsed);
  }
  lastRequestTime = Date.now();

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const resp = await fetch(url, {
        signal: controller.signal,
        headers: {
          "User-Agent": USER_AGENT,
          Accept:
            "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8",
          "Accept-Language": "hr-HR,hr;q=0.9,en;q=0.5",
        },
        redirect: "follow",
      });

      clearTimeout(timeout);

      if (resp.status === 429) {
        const retryAfter = parseInt(
          resp.headers.get("Retry-After") ?? "10",
          10,
        );
        log("WARN", `Rate limited (429) on ${url}, waiting ${retryAfter}s`);
        await sleep(retryAfter * 1000);
        continue;
      }

      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
      }

      return resp;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (attempt < retries) {
        const backoff = RETRY_BACKOFF_MS * attempt;
        log(
          "WARN",
          `Attempt ${attempt}/${retries} failed for ${url}: ${msg}. Retrying in ${backoff}ms...`,
        );
        await sleep(backoff);
      } else {
        throw new Error(`All ${retries} attempts failed for ${url}: ${msg}`);
      }
    }
  }

  throw new Error(`Fetch failed for ${url}`);
}

async function fetchText(url: string): Promise<string> {
  const resp = await rateLimitedFetch(url);
  return resp.text();
}

// ---------------------------------------------------------------------------
// RSS feed parsing
// ---------------------------------------------------------------------------

interface RssItem {
  title: string;
  link: string;
  pubDate: string;
  description: string;
  categories: string[];
}

/**
 * Parse WordPress RSS/XML feed into a list of items.
 * Uses regex to avoid an XML parser dependency.
 */
function parseRssFeed(xml: string): RssItem[] {
  const items: RssItem[] = [];
  const itemRe = /<item>([\s\S]*?)<\/item>/gi;
  let match: RegExpExecArray | null;

  while ((match = itemRe.exec(xml)) !== null) {
    const block = match[1]!;

    const title = extractXmlTag(block, "title");
    const link = extractXmlTag(block, "link");
    const pubDate = extractXmlTag(block, "pubDate");
    const description = extractXmlTag(block, "description");

    const categories: string[] = [];
    const catRe = /<category[^>]*><!\[CDATA\[(.*?)\]\]><\/category>/gi;
    let catMatch: RegExpExecArray | null;
    while ((catMatch = catRe.exec(block)) !== null) {
      categories.push(catMatch[1]!.trim());
    }
    // Also handle categories without CDATA
    const catReSimple = /<category[^>]*>([^<]+)<\/category>/gi;
    while ((catMatch = catReSimple.exec(block)) !== null) {
      const cat = catMatch[1]!.trim();
      if (!categories.includes(cat)) {
        categories.push(cat);
      }
    }

    if (title && link) {
      items.push({ title, link, pubDate, description, categories });
    }
  }

  return items;
}

function extractXmlTag(xml: string, tagName: string): string {
  // Handle CDATA wrapped content
  const cdataRe = new RegExp(
    `<${tagName}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/${tagName}>`,
    "i",
  );
  const cdataMatch = cdataRe.exec(xml);
  if (cdataMatch) return cdataMatch[1]!.trim();

  // Handle plain content
  const plainRe = new RegExp(
    `<${tagName}[^>]*>([\\s\\S]*?)<\\/${tagName}>`,
    "i",
  );
  const plainMatch = plainRe.exec(xml);
  if (plainMatch) return plainMatch[1]!.trim();

  return "";
}

/**
 * Convert RSS pubDate (RFC 822) to YYYY-MM-DD.
 */
function parseRssDate(pubDate: string): string | null {
  if (!pubDate) return null;
  try {
    const d = new Date(pubDate);
    if (isNaN(d.getTime())) return null;
    return d.toISOString().slice(0, 10);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// HTML content extraction (cheerio-based)
// ---------------------------------------------------------------------------

/**
 * Scrape an individual CERT.hr article/post page and extract structured content.
 */
function parseArticlePage(
  html: string,
  url: string,
): {
  title: string;
  date: string | null;
  fullText: string;
  summary: string;
  categories: string[];
  cves: string[];
  affectedProducts: string[];
  severity: string | null;
} {
  const $ = cheerio.load(html);

  // Title: <h1> or WordPress .entry-title
  const title =
    $("h1.entry-title").first().text().trim() ||
    $("h1").first().text().trim() ||
    $(".entry-title").first().text().trim() ||
    "";

  // Date: look for .entry-date, time element, or meta tag
  let date: string | null = null;
  const timeEl = $("time.entry-date, time.published, time[datetime]")
    .first()
    .attr("datetime");
  if (timeEl) {
    date = timeEl.slice(0, 10);
  } else {
    const metaDate = $('meta[property="article:published_time"]').attr(
      "content",
    );
    if (metaDate) {
      date = metaDate.slice(0, 10);
    }
  }

  // Extract main content area
  const contentEl =
    $(".entry-content").first().length > 0
      ? $(".entry-content").first()
      : $("article .content, .post-content, .article-body, main article")
          .first();

  // Remove scripts, styles, nav, sidebar
  contentEl.find("script, style, nav, .sidebar, .sharedaddy, .jp-relatedposts").remove();

  const fullText = contentEl.text().replace(/\s+/g, " ").trim();

  // Summary: first paragraph or meta description
  let summary =
    $('meta[name="description"]').attr("content")?.trim() ??
    $('meta[property="og:description"]').attr("content")?.trim() ??
    "";
  if (!summary) {
    const firstP = contentEl.find("p").first().text().trim();
    summary = firstP.length > 300 ? firstP.slice(0, 297) + "..." : firstP;
  }

  // Categories from WordPress category links
  const categories: string[] = [];
  $("a[rel='category tag'], .cat-links a, .entry-categories a").each(
    (_i, el) => {
      const cat = $(el).text().trim();
      if (cat) categories.push(cat);
    },
  );

  // Extract CVE references from the full page text
  const cves = extractCves(fullText);

  // Extract affected products from content patterns
  const affectedProducts = extractAffectedProducts($, fullText);

  // Determine severity
  const severity = classifySeverity(fullText, title);

  return {
    title,
    date,
    fullText,
    summary,
    categories,
    cves,
    affectedProducts,
    severity,
  };
}

/**
 * Extract CVE identifiers from text content.
 */
function extractCves(text: string): string[] {
  const cveRe = /CVE-\d{4}-\d{4,}/g;
  const matches = text.match(cveRe);
  if (!matches) return [];
  return [...new Set(matches)];
}

/**
 * Extract affected software/product names from CERT.hr advisory pages.
 * CERT.hr titles often follow the pattern "Sigurnosni nedostaci programskog paketa <product>"
 * or list products in the content body.
 */
function extractAffectedProducts(
  $: cheerio.CheerioAPI,
  fullText: string,
): string[] {
  const products: string[] = [];

  // Pattern 1: "programskog paketa <product>" in title/content
  const packageMatch = fullText.match(
    /programskog paketa\s+([A-Za-z0-9\s\-_.]+?)(?:\s*[-–—]|\s*$|\s*\n)/i,
  );
  if (packageMatch?.[1]) {
    products.push(packageMatch[1].trim());
  }

  // Pattern 2: "Pogođeni proizvodi:" or "Pogođeni sustavi:" sections
  const affectedRe =
    /(?:Pogo[đd]eni\s+(?:proizvodi|sustavi|softver)|Affected\s+(?:products|software)):\s*([\s\S]*?)(?:\n\n|\r\n\r\n|$)/i;
  const affectedMatch = affectedRe.exec(fullText);
  if (affectedMatch?.[1]) {
    const lines = affectedMatch[1]
      .split(/[,\n;]/)
      .map((l) => l.replace(/^[-•*]\s*/, "").trim())
      .filter((l) => l.length > 2 && l.length < 100);
    products.push(...lines);
  }

  // Pattern 3: Look for product names in list items with version numbers
  $("li").each((_i, el) => {
    const text = $(el).text().trim();
    if (/\d+\.\d+/.test(text) && text.length < 100 && text.length > 3) {
      // Likely a versioned product reference
      if (/(?:server|client|browser|office|windows|linux|apache|nginx|oracle|red hat|microsoft|mozilla|chrome|firefox|thunderbird)/i.test(text)) {
        products.push(text);
      }
    }
  });

  return [...new Set(products)].slice(0, 20);
}

/**
 * Classify advisory severity from Croatian-language content.
 */
function classifySeverity(text: string, title: string): string | null {
  const combined = `${title} ${text}`.toLowerCase();

  // CVSS score extraction
  const cvssMatch = combined.match(
    /cvss[:\s]*(\d+(?:\.\d+)?)/i,
  );
  if (cvssMatch?.[1]) {
    const score = parseFloat(cvssMatch[1]);
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    if (score > 0) return "low";
  }

  // Croatian severity keywords
  const severityPatterns: Array<[string, RegExp]> = [
    [
      "critical",
      /kriticn[aeiou]|critical|cvss\s*(?:9|10)|kriticno\s*upozorenje/i,
    ],
    [
      "high",
      /visok[aeiou]\s*(?:razin[aeiou]|opasnost|rizik)|opasnos|high|cvss\s*[78]/i,
    ],
    [
      "medium",
      /sredn[aeiou]\s*(?:razin|opasnost|rizik)|umjeren|medium|cvss\s*[456]/i,
    ],
    ["low", /nisk[aeiou]\s*(?:razin|opasnost|rizik)|low|cvss\s*[123]/i],
  ];

  for (const [sev, pattern] of severityPatterns) {
    if (pattern.test(combined)) return sev;
  }

  return null;
}

// ---------------------------------------------------------------------------
// Content classification — advisory vs. guidance
// ---------------------------------------------------------------------------

/**
 * Determine whether an RSS item or scraped page is an advisory or guidance.
 * CERT.hr posts about specific vulnerabilities (sigurnosni nedostaci) and
 * warnings (upozorenja) are advisories. Knowledge base articles, guidelines,
 * and recommendations are guidance.
 */
function classifyContent(
  title: string,
  categories: string[],
  url: string,
): "advisory" | "guidance" {
  const lowerTitle = title.toLowerCase();
  const lowerCats = categories.map((c) => c.toLowerCase());

  // Advisory signals
  const advisorySignals = [
    /sigurnosni\s+nedosta/i.test(lowerTitle), // "Sigurnosni nedostaci" — vulnerability notices
    /upozorenje/i.test(lowerTitle), // "Upozorenje" — warnings
    /ranjivost/i.test(lowerTitle), // "Ranjivost" — vulnerability
    /ransomware/i.test(lowerTitle),
    /phishing/i.test(lowerTitle),
    /malver|malware/i.test(lowerTitle),
    /CVE-\d{4}/i.test(lowerTitle),
    /kriticn[aeiou]\s*upozorenje/i.test(lowerTitle), // "Kritično upozorenje"
    /zero[- ]day/i.test(lowerTitle),
    /iskoristavanje|exploit/i.test(lowerTitle),
    lowerCats.some(
      (c) =>
        c.includes("upozorenje") ||
        c.includes("ranjivost") ||
        c.includes("sigurnosni nedosta"),
    ),
    /\/\d{4,6}\/$/.test(url), // Numeric ID posts are often vulnerability notices
  ];

  // Guidance signals
  const guidanceSignals = [
    /smjernic[ae]/i.test(lowerTitle), // "Smjernice" — guidelines
    /preporuk[ae]/i.test(lowerTitle), // "Preporuke" — recommendations
    /vodic|vodič/i.test(lowerTitle), // "Vodič" — guide
    /sigurnosn[aeiou]\s*politika/i.test(lowerTitle), // Security policy
    /upravljanje/i.test(lowerTitle), // Management
    /NIS2/i.test(lowerTitle),
    /PUBDOC/i.test(lowerTitle),
    /baza.znanja/i.test(url),
    lowerCats.some(
      (c) =>
        c.includes("smjernic") ||
        c.includes("preporuk") ||
        c.includes("edukacija"),
    ),
  ];

  const advisoryScore = advisorySignals.filter(Boolean).length;
  const guidanceScore = guidanceSignals.filter(Boolean).length;

  return advisoryScore >= guidanceScore ? "advisory" : "guidance";
}

/**
 * Generate a reference ID from a URL or title.
 * Uses the URL slug or post ID to create a stable reference.
 */
function generateReference(
  url: string,
  title: string,
  type: "advisory" | "guidance",
): string {
  // Extract WordPress post ID from numeric URL like /108826/
  const numericMatch = url.match(/\/(\d{4,})\/?$/);
  if (numericMatch?.[1]) {
    const prefix = type === "advisory" ? "CERTHR-ADV" : "CERTHR-DOC";
    return `${prefix}-${numericMatch[1]}`;
  }

  // Extract meaningful slug
  const slugMatch = url.match(/cert\.hr\/(.+?)\/?$/);
  if (slugMatch?.[1]) {
    const slug = slugMatch[1]
      .replace(/\//g, "-")
      .replace(/[^a-z0-9-]/gi, "")
      .slice(0, 60)
      .toUpperCase();
    const prefix = type === "advisory" ? "CERTHR-ADV" : "CERTHR-DOC";
    return `${prefix}-${slug}`;
  }

  // Fallback: hash from title
  const hash = simpleHash(title);
  const prefix = type === "advisory" ? "CERTHR-ADV" : "CERTHR-DOC";
  return `${prefix}-${hash}`;
}

function simpleHash(input: string): string {
  let h = 0;
  for (let i = 0; i < input.length; i++) {
    h = ((h << 5) - h + input.charCodeAt(i)) | 0;
  }
  return Math.abs(h).toString(36).toUpperCase().slice(0, 8);
}

/**
 * Classify the guidance type based on title and content patterns.
 */
function classifyGuidanceType(title: string, categories: string[]): string {
  const lower = title.toLowerCase();
  const cats = categories.map((c) => c.toLowerCase()).join(" ");

  if (/smjernic[ae]/i.test(lower)) return "guideline";
  if (/preporuk[ae]/i.test(lower)) return "recommendation";
  if (/standard/i.test(lower)) return "standard";
  if (/zakon|direktiv|regulativ|uredba/i.test(lower)) return "regulation";
  if (/vodic|vodič/i.test(lower)) return "guide";
  if (/izvjesta|izvještaj/i.test(lower)) return "report";
  if (/brosur|brošur/i.test(lower)) return "brochure";
  if (/infografi/i.test(lower)) return "infographic";
  if (/politika/i.test(lower)) return "policy";
  if (cats.includes("edukacija") || cats.includes("osvjest")) return "awareness";

  return "publication";
}

/**
 * Determine the guidance series.
 */
function classifyGuidanceSeries(
  title: string,
  url: string,
  reference: string,
): string {
  if (/NIS2|kiberneticke sigurnosti/i.test(title)) return "NIS2";
  if (/PUBDOC/i.test(reference)) return "CERT.hr PUBDOC";
  if (/baza.znanja/i.test(url)) return "Baza znanja";
  if (/sigurna.knjizica/i.test(url)) return "Sigurna knjižica";
  return "CERT.hr";
}

/**
 * Extract topics from title and content.
 */
function extractTopics(title: string, fullText: string): string {
  const topics: string[] = [];
  const combined = `${title} ${fullText}`.toLowerCase();

  const topicKeywords: Array<[string, RegExp]> = [
    ["phishing", /phishing/i],
    ["ransomware", /ransomware/i],
    ["malver", /malver|malware/i],
    ["ranjivost", /ranjivost|vulnerabilit/i],
    ["NIS2", /NIS2/i],
    ["GDPR", /GDPR|opca uredba/i],
    ["oblak", /oblak|cloud/i],
    ["IoT", /IoT|internet\s+stvari/i],
    ["ICS", /ICS|SCADA|industrijski/i],
    ["MFA", /MFA|visefaktors|multifactor/i],
    ["lozinka", /lozink[ae]|password/i],
    ["enkripcija", /enkripcij|kriptiranj|encryption/i],
    ["DDoS", /DDoS|distribuiran/i],
    ["SQL injection", /SQL\s*inject/i],
    ["XSS", /XSS|cross[- ]site/i],
    ["backup", /sigurnosn[ae]\s*kopij|backup/i],
    ["incident", /incident/i],
    ["kriticna infrastruktura", /kriticn[ae]\s*infrastruktur/i],
    ["autentifikacija", /autentifikacij/i],
    ["UI", /umjetn[ae]\s*inteligencij|AI\s+Act/i],
  ];

  for (const [topic, pattern] of topicKeywords) {
    if (pattern.test(combined)) {
      topics.push(topic);
    }
  }

  return topics.slice(0, 10).join(",");
}

// ---------------------------------------------------------------------------
// HTML listing page parsers
// ---------------------------------------------------------------------------

/**
 * Parse a WordPress listing/archive page to extract post links.
 * Works on tag pages, category pages, and date archives.
 */
function parseListingPage(
  html: string,
): Array<{ title: string; url: string; date: string | null }> {
  const $ = cheerio.load(html);
  const entries: Array<{ title: string; url: string; date: string | null }> =
    [];

  // WordPress typically wraps post entries in <article> elements
  $("article, .post, .entry, .hentry").each((_i, el) => {
    const $el = $(el);
    const $link =
      $el.find("h2 a, h3 a, .entry-title a").first();
    const href = $link.attr("href");
    const title = $link.text().trim();

    if (!href || !title) return;

    // Extract date
    let date: string | null = null;
    const timeEl = $el
      .find("time[datetime], .entry-date, .published")
      .first()
      .attr("datetime");
    if (timeEl) {
      date = timeEl.slice(0, 10);
    } else {
      const dateText = $el.find(".entry-date, .post-date, time").first().text();
      const dateMatch = dateText.match(/(\d{4})-(\d{2})-(\d{2})/);
      if (dateMatch) {
        date = dateMatch[0];
      }
    }

    const url = href.startsWith("http") ? href : `${CERT_HR_BASE}${href}`;
    entries.push({ title, url, date });
  });

  // Fallback: try generic link extraction for simpler listing pages
  if (entries.length === 0) {
    $("a").each((_i, el) => {
      const href = $(el).attr("href") ?? "";
      const title = $(el).text().trim();
      if (
        href.includes("cert.hr/") &&
        title.length > 10 &&
        title.length < 300 &&
        !href.includes("/tag/") &&
        !href.includes("/category/") &&
        !href.includes("/page/") &&
        !href.includes("/feed/") &&
        !href.includes("#")
      ) {
        const url = href.startsWith("http") ? href : `${CERT_HR_BASE}${href}`;
        if (!entries.some((e) => e.url === url)) {
          entries.push({ title, url, date: null });
        }
      }
    });
  }

  return entries;
}

/**
 * Extract the next page URL from WordPress pagination.
 */
function getNextPageUrl(html: string): string | null {
  const $ = cheerio.load(html);

  // WordPress pagination: "next" link
  const nextLink =
    $("a.next, .nav-links a.next, .pagination a.next, a[rel='next']")
      .first()
      .attr("href") ?? null;

  return nextLink;
}

// ---------------------------------------------------------------------------
// Knowledge base document listing parser
// ---------------------------------------------------------------------------

/**
 * Parse the CERT.hr knowledge base documents page.
 * Documents are listed under /baza-znanja/dokumenti/ and include
 * links to PDF publications (CCERT-PUBDOC-*, NCERT-PUBDOC-*).
 */
function parseKnowledgeBasePage(
  html: string,
): Array<{ title: string; url: string; reference: string | null }> {
  const $ = cheerio.load(html);
  const docs: Array<{ title: string; url: string; reference: string | null }> =
    [];

  // Look for links to PDFs and document pages
  $("a").each((_i, el) => {
    const href = $(el).attr("href") ?? "";
    const title = $(el).text().trim();

    if (!title || title.length < 5) return;

    // PDF documents (PUBDOC pattern)
    if (href.endsWith(".pdf") && href.includes("cert.hr")) {
      const pubdocMatch = href.match(
        /((?:CCERT|NCERT)-PUBDOC-\d{4}-\d{2}-\d+)/i,
      );
      const reference = pubdocMatch?.[1] ?? null;
      docs.push({ title, url: href, reference });
      return;
    }

    // Regular document pages on cert.hr
    if (
      href.includes("cert.hr/") &&
      !href.includes("/tag/") &&
      !href.includes("/category/") &&
      !href.includes("/page/") &&
      title.length > 10
    ) {
      const url = href.startsWith("http") ? href : `${CERT_HR_BASE}${href}`;
      docs.push({ title, url, reference: null });
    }
  });

  return docs;
}

// ---------------------------------------------------------------------------
// Advisory ingestion
// ---------------------------------------------------------------------------

async function ingestAdvisories(
  db: Database.Database,
  state: IngestState,
  stats: IngestStats,
): Promise<void> {
  log("INFO", "--- Starting advisory ingestion ---");

  const completedSet = new Set(state.advisoriesCompleted);
  const insertAdvisory = db.prepare(`
    INSERT OR REPLACE INTO advisories
      (reference, title, date, severity, affected_products, summary, full_text, cve_references)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  // Step 1: Collect advisory URLs from multiple listing pages
  const advisoryUrls: Array<{
    title: string;
    url: string;
    date: string | null;
  }> = [];

  // Crawl the security advisories listing
  const listingPages = [ADVISORIES_LISTING, WARNINGS_TAG_URL];

  for (const startUrl of listingPages) {
    let currentUrl: string | null = startUrl;
    let pageCount = 0;

    while (currentUrl) {
      if (maxPages > 0 && pageCount >= maxPages) {
        log("INFO", `Reached max pages (${maxPages}) for ${startUrl}`);
        break;
      }

      try {
        log("INFO", `Fetching advisory listing: ${currentUrl}`);
        const html = await fetchText(currentUrl);
        const entries = parseListingPage(html);
        log("INFO", `Found ${entries.length} entries on page ${pageCount + 1}`);

        for (const entry of entries) {
          if (!advisoryUrls.some((a) => a.url === entry.url)) {
            advisoryUrls.push(entry);
          }
        }

        currentUrl = getNextPageUrl(html);
        pageCount++;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        log("ERROR", `Failed to fetch listing page ${currentUrl}: ${msg}`);
        stats.errors++;
        break;
      }
    }
  }

  // Step 2: Crawl RSS feed for additional advisory URLs
  log("INFO", "Crawling RSS feed for additional advisories...");
  let rssPage = 1;
  let hasMoreRss = true;

  while (hasMoreRss) {
    if (maxPages > 0 && rssPage > maxPages) break;
    if (resume && rssPage <= state.rssPagesCrawled) {
      rssPage++;
      continue;
    }

    const rssUrl =
      rssPage === 1 ? RSS_FEED_URL : `${RSS_FEED_URL}?paged=${rssPage}`;

    try {
      log("INFO", `Fetching RSS feed page ${rssPage}: ${rssUrl}`);
      const xml = await fetchText(rssUrl);
      const items = parseRssFeed(xml);

      if (items.length === 0) {
        hasMoreRss = false;
        break;
      }

      for (const item of items) {
        const contentType = classifyContent(
          item.title,
          item.categories,
          item.link,
        );
        if (contentType === "advisory") {
          if (!advisoryUrls.some((a) => a.url === item.link)) {
            advisoryUrls.push({
              title: item.title,
              url: item.link,
              date: parseRssDate(item.pubDate),
            });
          }
        }
      }

      stats.rssPagesCrawled = rssPage;
      state.rssPagesCrawled = rssPage;
      rssPage++;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // 404 on higher pages means we've reached the end
      if (msg.includes("404")) {
        hasMoreRss = false;
      } else {
        log("ERROR", `RSS page ${rssPage} failed: ${msg}`);
        stats.errors++;
        hasMoreRss = false;
      }
    }
  }

  log(
    "INFO",
    `Collected ${advisoryUrls.length} advisory URLs, processing detail pages...`,
  );

  // Step 3: Scrape each advisory detail page
  for (let i = 0; i < advisoryUrls.length; i++) {
    const entry = advisoryUrls[i]!;
    const reference = generateReference(entry.url, entry.title, "advisory");

    if (completedSet.has(reference)) {
      stats.skipped++;
      continue;
    }

    try {
      log(
        "INFO",
        `[${i + 1}/${advisoryUrls.length}] Scraping advisory: ${entry.title.slice(0, 80)}`,
      );
      const html = await fetchText(entry.url);
      const parsed = parseArticlePage(html, entry.url);

      const title = parsed.title || entry.title;
      const date = parsed.date ?? entry.date;
      const fullText = parsed.fullText || title;

      if (fullText.length < 20) {
        log("WARN", `Skipping advisory with insufficient content: ${title}`);
        stats.skipped++;
        continue;
      }

      const row: AdvisoryRow = {
        reference,
        title,
        date,
        severity: parsed.severity,
        affected_products:
          parsed.affectedProducts.length > 0
            ? parsed.affectedProducts.join(", ")
            : null,
        summary: parsed.summary || title,
        full_text: fullText,
        cve_references:
          parsed.cves.length > 0 ? parsed.cves.join(", ") : null,
      };

      if (dryRun) {
        log(
          "DRY-RUN",
          `Would insert advisory: ${reference} — ${title.slice(0, 60)} (${date ?? "no date"}, severity: ${row.severity ?? "unknown"})`,
        );
      } else {
        insertAdvisory.run(
          row.reference,
          row.title,
          row.date,
          row.severity,
          row.affected_products,
          row.summary,
          row.full_text,
          row.cve_references,
        );
      }

      stats.advisoriesInserted++;
      state.advisoriesCompleted.push(reference);

      // Periodically save state
      if (stats.advisoriesInserted % 25 === 0) {
        saveState(state);
        logProgress(stats);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log("ERROR", `Failed to scrape advisory ${entry.url}: ${msg}`);
      stats.errors++;
    }
  }

  saveState(state);
  log("INFO", `Advisory ingestion complete: ${stats.advisoriesInserted} inserted, ${stats.errors} errors`);
}

// ---------------------------------------------------------------------------
// Guidance ingestion
// ---------------------------------------------------------------------------

async function ingestGuidance(
  db: Database.Database,
  state: IngestState,
  stats: IngestStats,
): Promise<void> {
  log("INFO", "--- Starting guidance ingestion ---");

  const completedSet = new Set(state.guidanceCompleted);
  const insertGuidance = db.prepare(`
    INSERT OR REPLACE INTO guidance
      (reference, title, title_en, date, type, series, summary, full_text, topics, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  // Collect guidance URLs from multiple sources
  const guidanceUrls: Array<{
    title: string;
    url: string;
    date: string | null;
    reference: string | null;
  }> = [];

  // Source 1: Knowledge base documents page
  try {
    log("INFO", `Fetching knowledge base documents: ${KNOWLEDGE_BASE_URL}`);
    const html = await fetchText(KNOWLEDGE_BASE_URL);
    const docs = parseKnowledgeBasePage(html);
    log("INFO", `Found ${docs.length} knowledge base entries`);
    for (const doc of docs) {
      if (!guidanceUrls.some((g) => g.url === doc.url)) {
        guidanceUrls.push({
          title: doc.title,
          url: doc.url,
          date: null,
          reference: doc.reference,
        });
      }
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log("ERROR", `Failed to fetch knowledge base: ${msg}`);
    stats.errors++;
  }

  // Source 2: Known guidance section pages
  const guidanceSections = [
    `${CERT_HR_BASE}/baza-znanja/`,
    `${CERT_HR_BASE}/sigurna-knjizica/`,
    `${CERT_HR_BASE}/baza-znanja/brosure/`,
    `${CERT_HR_BASE}/baza-znanja/godisnji-izvjestaji/`,
    `${CERT_HR_BASE}/infografike/`,
  ];

  for (const sectionUrl of guidanceSections) {
    try {
      log("INFO", `Fetching guidance section: ${sectionUrl}`);
      const html = await fetchText(sectionUrl);
      const entries = parseListingPage(html);
      for (const entry of entries) {
        if (!guidanceUrls.some((g) => g.url === entry.url)) {
          guidanceUrls.push({
            title: entry.title,
            url: entry.url,
            date: entry.date,
            reference: null,
          });
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log("WARN", `Failed to fetch section ${sectionUrl}: ${msg}`);
      stats.errors++;
    }
  }

  // Source 3: RSS feed for guidance-classified posts
  log("INFO", "Crawling RSS feed for guidance posts...");
  let rssPage = 1;
  let hasMoreRss = true;

  while (hasMoreRss) {
    if (maxPages > 0 && rssPage > maxPages) break;

    const rssUrl =
      rssPage === 1 ? RSS_FEED_URL : `${RSS_FEED_URL}?paged=${rssPage}`;

    try {
      const xml = await fetchText(rssUrl);
      const items = parseRssFeed(xml);

      if (items.length === 0) {
        hasMoreRss = false;
        break;
      }

      for (const item of items) {
        const contentType = classifyContent(
          item.title,
          item.categories,
          item.link,
        );
        if (contentType === "guidance") {
          if (!guidanceUrls.some((g) => g.url === item.link)) {
            guidanceUrls.push({
              title: item.title,
              url: item.link,
              date: parseRssDate(item.pubDate),
              reference: null,
            });
          }
        }
      }

      rssPage++;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("404")) {
        hasMoreRss = false;
      } else {
        log("WARN", `RSS guidance page ${rssPage} failed: ${msg}`);
        hasMoreRss = false;
      }
    }
  }

  log(
    "INFO",
    `Collected ${guidanceUrls.length} guidance URLs, processing detail pages...`,
  );

  // Scrape each guidance page
  for (let i = 0; i < guidanceUrls.length; i++) {
    const entry = guidanceUrls[i]!;

    // Skip PDFs — we cannot scrape PDF content with cheerio
    if (entry.url.toLowerCase().endsWith(".pdf")) {
      // Insert a minimal record from the PDF metadata we have
      const reference =
        entry.reference ??
        generateReference(entry.url, entry.title, "guidance");
      if (completedSet.has(reference)) {
        stats.skipped++;
        continue;
      }

      const pdfTitle = entry.title || "Nepoznati dokument";
      const row: GuidanceRow = {
        reference,
        title: pdfTitle,
        title_en: null,
        date: entry.date,
        type: "publication",
        series: "CERT.hr PUBDOC",
        summary: `CERT.hr publikacija: ${pdfTitle}`,
        full_text: `${reference}\n\n${pdfTitle}\n\nDokument dostupan na: ${entry.url}`,
        topics: extractTopics(pdfTitle, ""),
        status: "current",
      };

      if (dryRun) {
        log(
          "DRY-RUN",
          `Would insert PDF guidance: ${reference} — ${pdfTitle.slice(0, 60)}`,
        );
      } else {
        insertGuidance.run(
          row.reference,
          row.title,
          row.title_en,
          row.date,
          row.type,
          row.series,
          row.summary,
          row.full_text,
          row.topics,
          row.status,
        );
      }

      stats.guidanceInserted++;
      state.guidanceCompleted.push(reference);
      continue;
    }

    // HTML pages
    const reference = generateReference(entry.url, entry.title, "guidance");
    if (completedSet.has(reference)) {
      stats.skipped++;
      continue;
    }

    try {
      log(
        "INFO",
        `[${i + 1}/${guidanceUrls.length}] Scraping guidance: ${entry.title.slice(0, 80)}`,
      );
      const html = await fetchText(entry.url);
      const parsed = parseArticlePage(html, entry.url);

      const title = parsed.title || entry.title;
      const date = parsed.date ?? entry.date;
      const fullText = parsed.fullText || title;

      if (fullText.length < 20) {
        log("WARN", `Skipping guidance with insufficient content: ${title}`);
        stats.skipped++;
        continue;
      }

      const guidanceType = classifyGuidanceType(title, parsed.categories);
      const series = classifyGuidanceSeries(title, entry.url, reference);

      const row: GuidanceRow = {
        reference,
        title,
        title_en: null,
        date,
        type: guidanceType,
        series,
        summary: parsed.summary || title,
        full_text: fullText,
        topics: extractTopics(title, fullText),
        status: "current",
      };

      if (dryRun) {
        log(
          "DRY-RUN",
          `Would insert guidance: ${reference} — ${title.slice(0, 60)} (${guidanceType}, ${series})`,
        );
      } else {
        insertGuidance.run(
          row.reference,
          row.title,
          row.title_en,
          row.date,
          row.type,
          row.series,
          row.summary,
          row.full_text,
          row.topics,
          row.status,
        );
      }

      stats.guidanceInserted++;
      state.guidanceCompleted.push(reference);

      // Periodically save state
      if (stats.guidanceInserted % 25 === 0) {
        saveState(state);
        logProgress(stats);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log("ERROR", `Failed to scrape guidance ${entry.url}: ${msg}`);
      stats.errors++;
    }
  }

  saveState(state);
  log("INFO", `Guidance ingestion complete: ${stats.guidanceInserted} inserted, ${stats.errors} errors`);
}

// ---------------------------------------------------------------------------
// Framework seeding
// ---------------------------------------------------------------------------

function seedFrameworks(
  db: Database.Database,
  stats: IngestStats,
): void {
  log("INFO", "--- Seeding frameworks ---");

  const frameworks: FrameworkRow[] = [
    {
      id: "certhr-framework",
      name: "Nacionalni okvir kibernetičke sigurnosti",
      name_en: "National Cybersecurity Framework",
      description:
        "CERT.hr okvir za zaštitu informacijskih sustava i kritične infrastrukture u Hrvatskoj. " +
        "Obuhvaća smjernice, preporuke i tehničke standarde za javni i privatni sektor.",
      document_count: 0,
    },
    {
      id: "nis2-hr",
      name: "Implementacija NIS2 direktive u Hrvatskoj",
      name_en: "NIS2 Directive Implementation in Croatia",
      description:
        "Zakon o kibernetičkoj sigurnosti (NN 14/24) transponira NIS2 direktivu " +
        "u hrvatsko zakonodavstvo. CERT.hr objavljuje smjernice za obvezane subjekte " +
        "uključujući obavještavanje o incidentima i upravljanje rizicima.",
      document_count: 0,
    },
    {
      id: "isms-certhr",
      name: "Upravljanje informacijskom sigurnošću (ISMS)",
      name_en: "Information Security Management System",
      description:
        "CERT.hr dokumenti i smjernice za uspostavu sustava upravljanja " +
        "informacijskom sigurnošću sukladno ISO/IEC 27001 i povezanim normama.",
      document_count: 0,
    },
    {
      id: "certhr-alerts",
      name: "Sigurnosna upozorenja CERT.hr",
      name_en: "CERT.hr Security Alerts",
      description:
        "Prikupljanje i distribucija sigurnosnih upozorenja o ranjivostima, " +
        "aktivnim prijetnjama i preporukama za zaštitu od kibernetičkih napada.",
      document_count: 0,
    },
    {
      id: "certhr-pubdoc",
      name: "CERT.hr publikacije (PUBDOC)",
      name_en: "CERT.hr Publications",
      description:
        "Serija tehničkih publikacija CERT.hr (CCERT-PUBDOC, NCERT-PUBDOC) " +
        "koje pokrivaju teme od sigurnog kodiranja do upravljanja lozinkama " +
        "i zaštite od specifičnih prijetnji.",
      document_count: 0,
    },
    {
      id: "certhr-taxonomy",
      name: "Nacionalna taksonomija kibernetičkih incidenata",
      name_en: "National Cybersecurity Incident Taxonomy",
      description:
        "Standardizirana klasifikacija računalno-sigurnosnih incidenata " +
        "za potrebe prijavljivanja i statistike prema Zakonu o kibernetičkoj sigurnosti.",
      document_count: 0,
    },
  ];

  const insertFramework = db.prepare(`
    INSERT OR REPLACE INTO frameworks (id, name, name_en, description, document_count)
    VALUES (?, ?, ?, ?, ?)
  `);

  for (const fw of frameworks) {
    if (dryRun) {
      log("DRY-RUN", `Would insert framework: ${fw.id} — ${fw.name}`);
    } else {
      insertFramework.run(fw.id, fw.name, fw.name_en, fw.description, fw.document_count);
    }
    stats.frameworksInserted++;
  }

  // Update document counts based on actual data
  if (!dryRun) {
    updateFrameworkCounts(db);
  }
}

/**
 * Update framework document_count fields based on ingested guidance entries.
 */
function updateFrameworkCounts(db: Database.Database): void {
  const countBySeries = db
    .prepare(
      "SELECT series, COUNT(*) as cnt FROM guidance GROUP BY series",
    )
    .all() as Array<{ series: string; cnt: number }>;

  const seriesToFramework: Record<string, string> = {
    "NIS2": "nis2-hr",
    "CERT.hr": "certhr-framework",
    "CERT.hr PUBDOC": "certhr-pubdoc",
    "Baza znanja": "certhr-framework",
    "Sigurna knjižica": "certhr-framework",
  };

  const frameworkCounts: Record<string, number> = {};

  for (const row of countBySeries) {
    const fwId = seriesToFramework[row.series] ?? "certhr-framework";
    frameworkCounts[fwId] = (frameworkCounts[fwId] ?? 0) + row.cnt;
  }

  // Also count advisories toward the alerts framework
  const advisoryCount = (
    db
      .prepare("SELECT COUNT(*) as cnt FROM advisories")
      .get() as { cnt: number }
  ).cnt;
  frameworkCounts["certhr-alerts"] = advisoryCount;

  const updateStmt = db.prepare(
    "UPDATE frameworks SET document_count = ? WHERE id = ?",
  );
  for (const [fwId, count] of Object.entries(frameworkCounts)) {
    updateStmt.run(count, fwId);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  log("INFO", "=== CERT.hr Ingestion Crawler ===");
  log("INFO", `Database: ${DB_PATH}`);
  log("INFO", `Flags: ${dryRun ? "--dry-run " : ""}${resume ? "--resume " : ""}${force ? "--force " : ""}${advisoriesOnly ? "--advisories-only " : ""}${guidanceOnly ? "--guidance-only " : ""}${maxPages > 0 ? `--max-pages ${maxPages}` : ""}`);

  // Prepare database
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

  if (force && existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
    log("INFO", `Deleted existing database: ${DB_PATH}`);
  }

  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);

  const state = loadState();
  const stats: IngestStats = {
    rssPagesCrawled: 0,
    advisoryPagesScraped: 0,
    guidancePagesScraped: 0,
    advisoriesInserted: 0,
    guidanceInserted: 0,
    frameworksInserted: 0,
    skipped: 0,
    errors: 0,
  };

  try {
    // Seed frameworks (always — they are static metadata)
    seedFrameworks(db, stats);

    // Ingest advisories
    if (!guidanceOnly) {
      await ingestAdvisories(db, state, stats);
    }

    // Ingest guidance
    if (!advisoriesOnly) {
      await ingestGuidance(db, state, stats);
    }

    // Final framework count update
    if (!dryRun) {
      updateFrameworkCounts(db);
    }
  } finally {
    saveState(state);
    db.close();
  }

  log("INFO", "=== Ingestion Complete ===");
  logProgress(stats);

  if (stats.errors > 0) {
    log("WARN", `Completed with ${stats.errors} errors — review output above`);
  }
}

main().catch((err) => {
  const msg = err instanceof Error ? err.message : String(err);
  log("FATAL", `Ingestion failed: ${msg}`);
  process.exit(1);
});
