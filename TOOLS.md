# Tools Reference

This document describes all 8 tools provided by the Croatian Cybersecurity MCP server.

All tool names use the prefix `hr_cyber_`. Every response includes a `_meta` block with:
- `disclaimer` — reminder that this is a research tool, not legal advice
- `data_age` — date of the most recent document in the database
- `copyright` — `© CERT.hr / CARNET`
- `source_url` — `https://www.cert.hr/`

---

## `hr_cyber_search_guidance`

Full-text search across CERT.hr guidelines and technical standards.

**Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | Search terms (e.g., `'kibernetička sigurnost'`, `'NIS2'`, `'ISMS'`) |
| `type` | string | No | Filter by document type: `guideline`, `standard`, `recommendation`, `regulation` |
| `series` | string | No | Filter by framework series: `CERT.hr`, `NIS2`, `ISMS` |
| `status` | string | No | Filter by status: `current`, `superseded`, `draft` |
| `limit` | number | No | Max results (default 20, max 100) |

**Example**

```json
{ "query": "NIS2 critical infrastructure", "series": "NIS2", "limit": 10 }
```

---

## `hr_cyber_get_guidance`

Retrieve a specific CERT.hr guidance document by its reference code.

**Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reference` | string | Yes | CERT.hr document reference (e.g., `'CERT.hr-GUIDE-2024-01'`) |

**Example**

```json
{ "reference": "CERT.hr-REC-2023-02" }
```

---

## `hr_cyber_search_advisories`

Search CERT.hr security advisories and vulnerability alerts.

**Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | Search terms (e.g., `'kritična ranjivost'`, `'ransomware'`, `'VPN'`) |
| `severity` | string | No | Filter by severity: `critical`, `high`, `medium`, `low` |
| `limit` | number | No | Max results (default 20, max 100) |

**Example**

```json
{ "query": "ransomware", "severity": "critical" }
```

---

## `hr_cyber_get_advisory`

Retrieve a specific CERT.hr security advisory by its reference code.

**Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reference` | string | Yes | CERT.hr advisory reference (e.g., `'CERT.hr-PUBDOC-2024-001'`) |

**Example**

```json
{ "reference": "CERT.hr-PUBDOC-2024-001" }
```

---

## `hr_cyber_list_frameworks`

List all CERT.hr frameworks and standard series covered in this MCP.

**Parameters**: none

**Returns**: Array of framework objects with `id`, `name`, `name_en`, `description`, and `document_count`.

---

## `hr_cyber_about`

Return metadata about this MCP server: version, data source, coverage summary, and tool list.

**Parameters**: none

---

## `hr_cyber_list_sources`

List all data sources used by this MCP server with full provenance metadata.

**Parameters**: none

**Returns**

```json
{
  "sources": [
    {
      "name": "CERT.hr — Croatian National CERT",
      "url": "https://www.cert.hr/",
      "retrieval_method": "Web crawler (cheerio)",
      "update_frequency": "Periodic (GitHub Actions)",
      "license": "Public domain — official Croatian government publications",
      "limitations": ["..."]
    }
  ]
}
```

---

## `hr_cyber_check_data_freshness`

Check data freshness. Queries the latest document date from the database and returns a stale flag.

**Parameters**: none

**Returns**

```json
{
  "freshness": {
    "latest_document_date": "2024-11-15",
    "is_stale": false,
    "stale_threshold_days": 30,
    "update_instructions": "Run the ingest workflow via GitHub Actions or execute 'npm run ingest' locally."
  }
}
```
