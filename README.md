# Croatian Cybersecurity MCP

**Croatian cybersecurity data for AI compliance tools.**

[![npm version](https://badge.fury.io/js/%40ansvar%2Fcroatian-cybersecurity-mcp.svg)](https://www.npmjs.com/package/@ansvar/croatian-cybersecurity-mcp)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/Ansvar-Systems/croatian-cybersecurity-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Ansvar-Systems/croatian-cybersecurity-mcp/actions/workflows/ci.yml)

Query Croatian cybersecurity data -- regulations, decisions, and requirements from CERT.hr (National CERT Croatia) -- directly from Claude, Cursor, or any MCP-compatible client.

Built by [Ansvar Systems](https://ansvar.eu) -- Stockholm, Sweden

---

## Quick Start

### Use Remotely (No Install Needed)

> Connect directly to the hosted version -- zero dependencies, nothing to install.

**Endpoint:** `https://mcp.ansvar.eu/croatian-cybersecurity/mcp`

| Client | How to Connect |
|--------|---------------|
| **Claude.ai** | Settings > Connectors > Add Integration > paste URL |
| **Claude Code** | `claude mcp add croatian-cybersecurity-mcp --transport http https://mcp.ansvar.eu/croatian-cybersecurity/mcp` |
| **Claude Desktop** | Add to config (see below) |
| **GitHub Copilot** | Add to VS Code settings (see below) |

**Claude Desktop** -- add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "croatian-cybersecurity-mcp": {
      "type": "url",
      "url": "https://mcp.ansvar.eu/croatian-cybersecurity/mcp"
    }
  }
}
```

**GitHub Copilot** -- add to VS Code `settings.json`:

```json
{
  "github.copilot.chat.mcp.servers": {
    "croatian-cybersecurity-mcp": {
      "type": "http",
      "url": "https://mcp.ansvar.eu/croatian-cybersecurity/mcp"
    }
  }
}
```

### Use Locally (npm)

```bash
npx @ansvar/croatian-cybersecurity-mcp
```

**Claude Desktop** -- add to `claude_desktop_config.json`:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "croatian-cybersecurity-mcp": {
      "command": "npx",
      "args": ["-y", "@ansvar/croatian-cybersecurity-mcp"]
    }
  }
}
```

**Cursor / VS Code:**

```json
{
  "mcp.servers": {
    "croatian-cybersecurity-mcp": {
      "command": "npx",
      "args": ["-y", "@ansvar/croatian-cybersecurity-mcp"]
    }
  }
}
```

---

## Available Tools (8)

| Tool | Description |
|------|-------------|
| `hr_cyber_search_guidance` | Full-text search across CERT.hr guidelines and technical standards. Covers national cybersecurity recommendations, NIS2 implementation guidance, ISMS standards, and critical infrastructure requirements for Croatia. |
| `hr_cyber_get_guidance` | Get a specific CERT.hr guidance document by reference (e.g., `CERT.hr-GUIDE-2024-01`). |
| `hr_cyber_search_advisories` | Search CERT.hr security advisories and alerts. Returns advisories with severity, affected products, and CVE references. |
| `hr_cyber_get_advisory` | Get a specific CERT.hr security advisory by reference (e.g., `CERT.hr-PUBDOC-2024-001`). |
| `hr_cyber_list_frameworks` | List all CERT.hr frameworks and standard series covered in this MCP, including National Cybersecurity Strategy, NIS2 implementation, and ISMS guidance. |
| `hr_cyber_about` | Return metadata about this MCP server: version, data source, coverage, and tool list. |
| `hr_cyber_list_sources` | List all data sources with provenance metadata: name, URL, retrieval method, update frequency, and known limitations. |
| `hr_cyber_check_data_freshness` | Check data freshness — returns latest document date and stale flag (threshold: 30 days). |

All tools return structured data with source references and timestamps.

---

## Data Sources and Freshness

All content is sourced from official Croatian regulatory publications:

- **CERT.hr (National CERT Croatia)** -- Official regulatory authority

### Data Currency

- Database updates are periodic and may lag official publications
- Use `hr_cyber_check_data_freshness` to query the latest document date and stale flag
- Every tool response includes a `_meta.data_age` field with the most recent document date

See [COVERAGE.md](COVERAGE.md) for corpus scope and known gaps, and [`data/coverage.json`](data/coverage.json) for machine-readable provenance metadata.

---

## Security

This project uses multiple layers of automated security scanning:

| Scanner | What It Does | Schedule |
|---------|-------------|----------|
| **CodeQL** | Static analysis for security vulnerabilities | Weekly + PRs |
| **Semgrep** | SAST scanning (OWASP top 10, secrets, TypeScript) | Every push |
| **Gitleaks** | Secret detection across git history | Every push |
| **Trivy** | CVE scanning on filesystem and npm dependencies | Daily |
| **Docker Security** | Container image scanning + SBOM generation | Daily |
| **Socket.dev** | Supply chain attack detection | PRs |
| **Dependabot** | Automated dependency updates | Weekly |

See [SECURITY.md](SECURITY.md) for the full policy and vulnerability reporting.

---

## Important Disclaimers

### Not Regulatory Advice

> **THIS TOOL IS NOT REGULATORY OR LEGAL ADVICE**
>
> Regulatory data is sourced from official publications by CERT.hr (National CERT Croatia). However:
> - This is a **research tool**, not a substitute for professional regulatory counsel
> - **Verify all references** against primary sources before making compliance decisions
> - **Coverage may be incomplete** -- do not rely solely on this for regulatory research

**Before using professionally, read:** [DISCLAIMER.md](DISCLAIMER.md) | [PRIVACY.md](PRIVACY.md)

### Confidentiality

Queries go through the Claude API. For privileged or confidential matters, use on-premise deployment. See [PRIVACY.md](PRIVACY.md) for details.

---

## Development

### Setup

```bash
git clone https://github.com/Ansvar-Systems/croatian-cybersecurity-mcp
cd croatian-cybersecurity-mcp
npm install
npm run build
npm test
```

### Running Locally

```bash
npm run dev                                       # Start MCP server
npx @anthropic/mcp-inspector node dist/index.js   # Test with MCP Inspector
```

### Data Management

```bash
npm run seed    # Seed database with sample data
npm run ingest  # Crawl and ingest latest CERT.hr data
```

---

## Related Projects

This server is part of **Ansvar's MCP fleet** -- 276 MCP servers covering law, regulation, and compliance across 119 jurisdictions.

### Law MCPs

Full national legislation for 108 countries. Example: [@ansvar/swedish-law-mcp](https://github.com/Ansvar-Systems/swedish-law-mcp) -- 2,415 Swedish statutes with EU cross-references.

### Sector Regulator MCPs

National regulatory authority data for 29 EU/EFTA countries across financial regulation, data protection, cybersecurity, and competition. This MCP is one of 116 sector regulator servers.

### Domain MCPs

Specialized compliance domains: [EU Regulations](https://github.com/Ansvar-Systems/EU_compliance_MCP), [Security Frameworks](https://github.com/Ansvar-Systems/security-frameworks-mcp), [Automotive Cybersecurity](https://github.com/Ansvar-Systems/Automotive-MCP), [OT/ICS Security](https://github.com/Ansvar-Systems/ot-security-mcp), [Sanctions](https://github.com/Ansvar-Systems/Sanctions-MCP), and more.

Browse the full fleet at [mcp.ansvar.eu](https://mcp.ansvar.eu).

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

Apache License 2.0. See [LICENSE](./LICENSE) for details.

### Data Licenses

Regulatory data sourced from official Croatian government publications (CERT.hr / CARNET). See [COVERAGE.md](COVERAGE.md) for per-source licensing details.

---

## About Ansvar Systems

We build AI-powered compliance and legal research tools for the European market. Our MCP fleet provides structured, verified regulatory data to AI assistants -- so compliance professionals can work with accurate sources instead of guessing.

**[ansvar.eu](https://ansvar.eu)** -- Stockholm, Sweden

---

<p align="center">
  <sub>Built with care in Stockholm, Sweden</sub>
</p>
