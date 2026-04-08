# Coverage

This document describes the corpus scope, known gaps, and data freshness for the Croatian Cybersecurity MCP server.

## Data Source

**CERT.hr — Croatian National CERT (Nacionalni CERT)**
- Publisher: CARNET (Croatian Academic and Research Network)
- URL: <https://www.cert.hr/>
- Scope: Official Croatian cybersecurity guidelines, security advisories, NIS2 implementation guidance, and ISMS standards

## Document Categories

| Category | Description |
|----------|-------------|
| **guidance** | CERT.hr technical guidelines, national recommendations, NIS2 implementation standards, ISMS guidance |
| **advisories** | CERT.hr security advisories and vulnerability alerts with severity ratings and CVE references |
| **frameworks** | CERT.hr framework series: National Cybersecurity Strategy, NIS2, ISMS |

## Known Gaps

- **Restricted documents**: Classified or restricted CERT.hr documents are not publicly available and are excluded from this corpus.
- **Pre-2023 advisories**: CERT.hr archive coverage before 2023 is partial — older advisories may be missing.
- **NIS2 transposition**: NIS2 legislative changes pending full Croatian parliamentary transposition may not yet be reflected in the data.
- **Language**: Documents published only in Croatian may have limited English metadata. Machine-translated `title_en` values may contain minor errors.
- **Real-time updates**: This MCP does not stream live data. There is a lag between official CERT.hr publications and ingestion into this database.

## Checking Freshness

Use the `hr_cyber_check_data_freshness` tool to query the latest document date and determine whether the database is stale (>30 days since last update).

```
hr_cyber_check_data_freshness → { latest_document_date, is_stale, stale_threshold_days }
```

For machine-readable coverage metadata, see [`data/coverage.json`](data/coverage.json).

## Update Frequency

Data is refreshed periodically via GitHub Actions. To trigger a manual refresh:

```bash
npm run ingest
```
