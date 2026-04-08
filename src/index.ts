#!/usr/bin/env node

/**
 * Croatian Cybersecurity MCP — stdio entry point.
 *
 * Provides MCP tools for querying CERT.hr (Nacionalni CERT) guidelines,
 * technical standards, security advisories, and cybersecurity frameworks
 * for Croatia.
 *
 * Tool prefix: hr_cyber_
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  searchGuidance,
  getGuidance,
  searchAdvisories,
  getAdvisory,
  listFrameworks,
  getLatestDataDate,
} from "./db.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback to default
}

const SERVER_NAME = "croatian-cybersecurity-mcp";

// --- Tool definitions ---------------------------------------------------------

const TOOLS = [
  {
    name: "hr_cyber_search_guidance",
    description:
      "Full-text search across CERT.hr guidelines and technical standards. Covers national cybersecurity recommendations, NIS2 implementation guidance, ISMS standards, and critical infrastructure protection requirements for Croatia. Returns matching documents with reference, title, series, and summary.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query (e.g., 'kibernetička sigurnost', 'NIS2', 'ISMS', 'kriptografija')",
        },
        type: {
          type: "string",
          enum: ["guideline", "standard", "recommendation", "regulation"],
          description: "Filter by document type. Optional.",
        },
        series: {
          type: "string",
          enum: ["CERT.hr", "NIS2", "ISMS"],
          description: "Filter by framework series. Optional.",
        },
        status: {
          type: "string",
          enum: ["current", "superseded", "draft"],
          description: "Filter by document status. Defaults to returning all statuses.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "hr_cyber_get_guidance",
    description:
      "Get a specific CERT.hr guidance document by reference (e.g., 'CERT.hr-GUIDE-2024-01', 'CERT.hr-REC-2023-02').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "CERT.hr document reference",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "hr_cyber_search_advisories",
    description:
      "Search CERT.hr security advisories and alerts. Returns advisories with severity, affected products, and CVE references where available.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query (e.g., 'kritična ranjivost', 'ransomware', 'VPN')",
        },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level. Optional.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "hr_cyber_get_advisory",
    description:
      "Get a specific CERT.hr security advisory by reference (e.g., 'CERT.hr-PUBDOC-2024-001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "CERT.hr advisory reference",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "hr_cyber_list_frameworks",
    description:
      "List all CERT.hr frameworks and standard series covered in this MCP, including National Cybersecurity Strategy, NIS2 implementation, and ISMS guidance for Croatia.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "hr_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "hr_cyber_list_sources",
    description:
      "List all data sources used by this MCP server with provenance metadata: name, URL, retrieval method, update frequency, and known limitations.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "hr_cyber_check_data_freshness",
    description:
      "Check data freshness for each source. Reports the latest document date, whether data is stale (>30 days old), and instructions for triggering updates.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
];

// --- Zod schemas for argument validation --------------------------------------

const SearchGuidanceArgs = z.object({
  query: z.string().min(1),
  type: z.enum(["guideline", "standard", "recommendation", "regulation"]).optional(),
  series: z.enum(["CERT.hr", "NIS2", "ISMS"]).optional(),
  status: z.enum(["current", "superseded", "draft"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetGuidanceArgs = z.object({
  reference: z.string().min(1),
});

const SearchAdvisoriesArgs = z.object({
  query: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetAdvisoryArgs = z.object({
  reference: z.string().min(1),
});

// --- Helper ------------------------------------------------------------------

function buildMeta() {
  return {
    disclaimer:
      "This is a research tool, not legal or regulatory advice. Verify all references against primary sources before making compliance decisions.",
    data_age: getLatestDataDate(),
    copyright: "© CERT.hr / CARNET",
    source_url: "https://www.cert.hr/",
  };
}

function textContent(data: unknown) {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify({ ...(data as object), _meta: buildMeta() }, null, 2) },
    ],
  };
}

function errorContent(message: string) {
  return {
    content: [{ type: "text" as const, text: message }],
    isError: true as const,
  };
}

// --- Server setup ------------------------------------------------------------

const server = new Server(
  { name: SERVER_NAME, version: pkgVersion },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  try {
    switch (name) {
      case "hr_cyber_search_guidance": {
        const parsed = SearchGuidanceArgs.parse(args);
        const results = searchGuidance({
          query: parsed.query,
          type: parsed.type,
          series: parsed.series,
          status: parsed.status,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length });
      }

      case "hr_cyber_get_guidance": {
        const parsed = GetGuidanceArgs.parse(args);
        const doc = getGuidance(parsed.reference);
        if (!doc) {
          return errorContent(`Guidance document not found: ${parsed.reference}`);
        }
        return textContent(doc);
      }

      case "hr_cyber_search_advisories": {
        const parsed = SearchAdvisoriesArgs.parse(args);
        const results = searchAdvisories({
          query: parsed.query,
          severity: parsed.severity,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length });
      }

      case "hr_cyber_get_advisory": {
        const parsed = GetAdvisoryArgs.parse(args);
        const advisory = getAdvisory(parsed.reference);
        if (!advisory) {
          return errorContent(`Advisory not found: ${parsed.reference}`);
        }
        return textContent(advisory);
      }

      case "hr_cyber_list_frameworks": {
        const frameworks = listFrameworks();
        return textContent({ frameworks, count: frameworks.length });
      }

      case "hr_cyber_about": {
        return textContent({
          name: SERVER_NAME,
          version: pkgVersion,
          description:
            "CERT.hr (Nacionalni CERT — Croatian National CERT) MCP server. Provides access to CERT.hr guidelines, technical standards, NIS2 implementation guidance, and security advisories for Croatia.",
          data_source: "CERT.hr (https://www.cert.hr/)",
          coverage: {
            guidance: "CERT.hr technical guidelines, recommendations, NIS2 implementation standards",
            advisories: "CERT.hr security advisories and vulnerability alerts",
            frameworks: "National Cybersecurity Strategy, NIS2 implementation, ISMS guidance",
          },
          tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
        });
      }

      case "hr_cyber_list_sources": {
        return textContent({
          sources: [
            {
              name: "CERT.hr — Croatian National CERT",
              url: "https://www.cert.hr/",
              retrieval_method: "Web crawler (cheerio) — publicus.cert.hr and www.cert.hr",
              update_frequency: "Periodic (triggered via GitHub Actions workflow)",
              license: "Public domain — official Croatian government publications",
              limitations: [
                "Restricted or classified documents are not available",
                "Pre-2023 advisories may be incomplete",
                "NIS2 legislative changes pending full transposition may not yet be reflected",
                "Machine-translated English titles may contain errors",
              ],
            },
          ],
        });
      }

      case "hr_cyber_check_data_freshness": {
        const latestDate = getLatestDataDate();
        const isStale =
          latestDate === null ||
          (Date.now() - new Date(latestDate).getTime()) / 86_400_000 > 30;
        return textContent({
          freshness: {
            latest_document_date: latestDate,
            is_stale: isStale,
            stale_threshold_days: 30,
            update_instructions:
              "Run the ingest workflow via GitHub Actions or execute 'npm run ingest' locally to refresh data.",
          },
        });
      }

      default:
        return errorContent(`Unknown tool: ${name}`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return errorContent(`Error executing ${name}: ${message}`);
  }
});

// --- Main --------------------------------------------------------------------

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`${SERVER_NAME} v${pkgVersion} running on stdio\n`);
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
