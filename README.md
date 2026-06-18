# Tenable SC – Fixed Vulnerability Trend Builder

> Generate weekly/monthly Fixed Vulnerability Trend reports directly from Tenable Security Center.  
> No pip installs. No dependencies. Python stdlib only. Works offline after first run.

[![Python 3.6+](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/)
[![No Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](.)
[![Works Offline](https://img.shields.io/badge/offline-ready-brightgreen)](.)

---

## What It Does

Connects to your Tenable Security Center instance, pulls **Fixed (Patched) vulnerability** data week by week, and generates a standalone HTML report with:

- Stacked bar chart by severity (Critical / High / Medium / Low)
- Trend line with 4-week moving average
- Period comparison (Last Week / Last Month / Last Quarter / Last Year)
- Full data table

**Two modes:**

| Tool | Mode | Best for |
|------|------|----------|
| `sc_trend.py` | CLI (interactive prompts) | Quick one-off reports |
| `report_builder.py` | Web UI at localhost:8080 | Custom date range, logo, colors |

---

## Requirements

- Python 3.6 or higher
- Network access to your Tenable SC instance
- Chrome browser (Edge sometimes blocks CDN scripts)
- Internet connection on first run only (downloads Chart.js ~200KB)

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/byadler/tenable-sc-fixed-trend.git
cd tenable-sc-fixed-trend

# Option A: CLI script
py sc_trend.py          # Windows
python3 sc_trend.py     # Mac / Linux

# Option B: Web UI
py report_builder.py    # Windows
python3 report_builder.py  # Mac / Linux
# → Opens Chrome at http://localhost:8080
```

---

## CLI Usage (sc_trend.py)

The script asks 5 questions interactively:

```
SC URL  [https://localhost:8443]: https://your-sc-server:8443
Username: admin
Password: ********

Repositories:
  0. All Repositories
  1. Main_Repo (id=1)
  2. DMZ_Repo  (id=2)
Select repository number [0=All]: 0

Asset Tags:
  0. No filter (all assets)
  1. Windows Servers
Select asset number [0=None]: 0

Time range:
  1. Last week only
  2. Last 4 weeks (1 month)
  3. Last 3 months (13 weeks)
  4. Last year (52 weeks)
Select [1-4, default=4]: 4

Fetching data (52 weeks)...
  [ 1/52] 06/20-06/27/24 → 1,243
  [ 2/52] 06/27-07/04/24 → 987
  ...
✅ Report saved: Fixed_Trend_Report.html
```

---

## Web UI Usage (report_builder.py)

1. Run the script → Chrome opens at `http://localhost:8080`
2. **Step 1:** Enter SC URL, username, password → click **Test Connection**
3. **Step 2:** Choose repositories, asset tag, date range, granularity, optional logo
4. **Step 3:** Click **Generate Report** → view inline, export HTML, or print

---

## How It Works

```
Script
  │
  ├── POST /rest/token          → Login (TNS_SESSIONID cookie + X-SecurityCenter token)
  │
  └── POST /rest/analysis
        type:       "vuln"
        sourceType: "patched"   ← Fixed vulnerabilities only
        tool:       "sumseverity"
        filter:     lastMitigated = "day_end:day_start"  ← days ago (not timestamps!)
```

**Key discovery:** Tenable SC's `lastMitigated` filter uses **days** (not Unix timestamps).  
`"0:7"` = mitigated in the last 7 days. `"7:14"` = 7–14 days ago.

---

## Validating Results in SC GUI

To verify numbers match:

1. Go to **Analysis → Vulnerabilities**
2. Click **Mitigated** (top-right toggle)
3. Add filter: **Vulnerability Mitigated → Last Week** (or matching range)
4. Sum the **Total** column across all pages = what the script reports

---

## Files

| File | Description |
|------|-------------|
| `sc_trend.py` | CLI script – interactive prompts |
| `report_builder.py` | Web UI server – browser interface |
| `sc_debug.py` | Diagnostic: tests available SC filters |
| `sc_debug2.py` | Diagnostic: validates lastMitigated format |

---

## Troubleshooting

**Python not found (Windows)**
```cmd
py sc_trend.py
# or find python:
where python
where py
```

**SSL Certificate Error**  
Open your SC URL in Chrome → click "Continue anyway" → retry the script.

**Charts not showing**  
Open the HTML file in Chrome (not Edge). Or use `report_builder.py` which inlines Chart.js.

**WinError 10060 – Timeout**  
The script retries automatically 3 times. Check SC is reachable on your network.

---

## Contributing

Pull requests welcome. If you add support for:
- Additional SC filter types
- Export to PDF / Excel
- Multi-repo comparison charts

...please open a PR!

---

## License

MIT License – free to use, modify, and share.

---

*Built by Benny Adler – Tenable Technical Support*  
*Contributed to the [Cyber Agents Exchange](https://exchange.tenable.com)*
