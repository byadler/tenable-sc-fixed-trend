---
name: "Tenable SC Fixed Vulnerability Trend Builder"
author: "byadler"
github_url: "https://github.com/byadler/tenable-sc-fixed-trend"
description: "Generate weekly/monthly Fixed Vulnerability Trend reports directly from Tenable Security Center — multi-asset, severity filtering, unique asset tracking. No dependencies, works offline."
license: "MIT"
tier: "unreviewed"
tags: ["tenable-sc", "vulnerability-management", "reporting", "remediation", "trend-analysis"]
integrations: ["Tenable"]
date_added: 2026-06-21
compatible_platforms: ["Claude Code"]
invocation: "py report_builder.py"
---

Prove your remediation program is working — with a single command.

Security teams spend enormous effort fixing vulnerabilities, yet struggle to show the trend over time. This tool connects directly to your Tenable Security Center and generates a fully visual, standalone HTML report — showing exactly how many vulnerabilities your team has fixed, period by period, with zero setup and no internet dependency after the first run.

## What it does

- Pulls **Fixed (Patched)** vulnerability data week by week (or month by month) from Tenable SC via REST API
- Generates a standalone HTML report with interactive Chart.js charts:
  - Stacked bar chart by severity (Critical / High / Medium / Low / Info) across any date range
  - Trend line with 4-period moving average
  - KPI summary: Total Fixed, Critical, High, Medium counts
  - Full exportable data table with per-column visibility toggles
- **Severity filter** — select which severity levels to include in charts and totals
- **Multiple asset groups** — Ctrl+Click to select multiple; real-time search bar for filtering
- **Unique Assets column** — how many distinct IPs were remediated each period (no double-counting)
- Two modes: CLI script (`sc_trend.py`) and Web UI server (`report_builder.py` at localhost:8080)

## How it works

Authenticates to Tenable SC using the REST API (`/rest/token`), then queries `/rest/analysis` with `sourceType: "patched"` and the `lastMitigated` filter using the days-based format (`"0:7"` = last 7 days). Iterates period by period for the selected time range and aggregates severity counts using `tool: "sumseverity"`. For unique asset tracking, a second query per period uses `tool: "sumip"` and reads `totalRecords`. Generates a self-contained HTML file with inlined Chart.js for offline viewing.

**Key discovery:** Tenable SC's `lastMitigated` filter uses days (not Unix timestamps) — `"0:7"` means mitigated in the last 7 days.

**F5/SSO environments:** If your SC is behind an F5 BIG-IP APM, use the internal IP address directly. The tool handles HTTP 307 redirects automatically for direct connections.

## Requirements

- Python 3.6+
- Network access to Tenable Security Center
- No pip installs required — Python stdlib only
