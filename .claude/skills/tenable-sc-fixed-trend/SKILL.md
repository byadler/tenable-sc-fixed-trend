---
name: tenable-sc-fixed-trend
description: Generate fixed vulnerability trend reports from Tenable Security Center. Use when the user wants to visualize remediation progress, generate a fixed-vuln trend report, or launch the Tenable SC Report Builder. Handles setup verification and launches the web UI.
---

# Tenable SC Fixed Vulnerability Trend Report

Generate visual HTML reports showing fixed vulnerabilities over time from Tenable Security Center.

## Preflight checks

Before launching, verify the environment:

1. **Python 3.6+** available:
   ```bash
   python3 --version || python --version || py --version
   ```
2. **Repository files present** — confirm `report_builder.py` and `sc_trend.py` exist in the working directory

If any check fails, guide the user through setup (see Setup section below).

## Launch the Web UI

Once preflight passes:

```bash
python3 report_builder.py
```

On Windows:
```bash
py report_builder.py
```

The server starts at `http://localhost:8080` and opens Chrome automatically. Tell the user:

> Report Builder is running at http://localhost:8080
> Enter your Tenable SC URL, credentials, choose repositories/assets/date range, and click Generate Report.
> Press Ctrl+C in the terminal when done.

## Setup (if needed)

If the repo is not cloned:

```bash
git clone https://github.com/byadler/tenable-sc-fixed-trend.git
cd tenable-sc-fixed-trend
```

No pip dependencies required — the tool uses only Python standard library.

## CLI alternative

For quick one-off reports without the browser:

```bash
python3 sc_trend.py
```

This prompts interactively for SC URL, credentials, repository, asset tag, and time range, then generates `Fixed_Trend_Report.html`.

## Troubleshooting

- **SSL errors**: Open the SC URL in Chrome first, accept the certificate, then retry
- **Charts not rendering**: Use Chrome (not Edge). The web UI inlines Chart.js for offline use
- **Connection timeout (WinError 10060)**: Verify network access to your SC instance; the script retries 3 times automatically
- **Port 8080 in use**: Kill the existing process or edit `PORT` in `report_builder.py`
