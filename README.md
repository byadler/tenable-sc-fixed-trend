# Tenable SC – Fixed Vulnerability Trend Builder

> **Prove your remediation program is working** — with a single command.

Security teams spend enormous effort fixing vulnerabilities, yet struggle to show the trend over time. This tool connects directly to your Tenable Security Center and generates a fully visual, standalone HTML report in minutes — showing exactly how many vulnerabilities your team has fixed, week by week or month by month, with zero setup and no internet dependency after the first run.

[![Python 3.6+](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/)
[![No Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](.)
[![Works Offline](https://img.shields.io/badge/offline-ready-brightgreen)](.)

---

## What It Does

Answer the question every CISO asks — *"Is our remediation effort actually improving?"* — with a report that pulls live data from Tenable SC and visualizes it as:

- **Stacked bar chart** by severity (Critical / High / Medium / Low / Info) across any date range
- **Trend line** with 4-period moving average to cut through week-to-week noise
- **KPI summary boxes** — Total Fixed, Critical, High, Medium at a glance
- **Full data table** — with per-column visibility toggles, exportable and printable
- **Unique Assets column** — shows how many distinct IPs were remediated each period (no double-counting)

**Two modes:**

| Tool | Mode | Best for |
|------|------|----------|
| `sc_trend.py` | CLI (interactive prompts) | Quick one-off reports |
| `report_builder.py` | Web UI at localhost:8080 | Custom filters, logo, colors, multi-asset |

---

## Requirements

- Python 3.6 or higher
- Network access to your Tenable SC instance
- Chrome browser (Edge sometimes blocks CDN scripts)
- Internet connection on first run only (downloads Chart.js ~200KB automatically)

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/byadler/tenable-sc-fixed-trend.git
cd tenable-sc-fixed-trend

# Option A: Web UI (recommended)
py report_builder.py       # Windows
python3 report_builder.py  # Mac / Linux
# → Opens Chrome at http://localhost:8080

# Option B: CLI script
py sc_trend.py             # Windows
python3 sc_trend.py        # Mac / Linux
```

---

## Web UI (report_builder.py)

The web UI provides a full point-and-click interface — no command-line needed.

### Step 1 — Connect
Enter your SC URL, username, and password. Click **Test Connection**.
The tool loads your repositories and asset groups automatically.

> **Note:** If your SC is behind an F5 / SSO gateway, use the **internal IP address** of the SC server directly (e.g. `https://10.x.x.x`) to bypass the SSO redirect.

### Step 2 — Configure

| Setting | Details |
|---------|---------|
| **Asset Groups** | Ctrl+Click to select multiple. Use the search bar to filter by name. Leave empty for all assets. |
| **Repositories** | Ctrl+Click to select multiple. Leave empty for all repositories. |
| **Date Range** | Any start/end date. Can span weeks, months, or a full year. |
| **Granularity** | Weekly or Monthly periods |
| **Severity Filter** | Choose which severity levels to include (Critical / High / Medium / Low / Info) |
| **Colors** | Customize the color for each severity level |
| **Logo** | Optional PNG/JPG logo embedded in the report header |

### Step 3 — Report

- **View inline** in the browser
- **Export HTML** — self-contained, works offline, shareable
- **Print / PDF** — browser print dialog

### Report Sections

1. **Header** — Title, asset/repo names, generation timestamp
2. **KPI Summary** — Total Fixed, Critical, High, Medium counts for the full period
3. **Chart 1: Stacked Bar + Trend Line** — Severity breakdown per period with Total overlay
4. **Chart 2: Trend + Moving Average** — Total fixed trend with 4-period smoothing
5. **Data Table** — Full period-by-period breakdown with column toggles:
   - Critical / High / Medium / Low / Info (show/hide each independently)
   - Total (sum of selected severities)
   - **Unique Assets** — distinct IPs remediated (no double-counting of plugin×IP)

---

## CLI Usage (sc_trend.py)

The script asks 5 questions interactively:

```
SC URL  [https://localhost:8443]: https://your-sc-server
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
  [ 1/52] 06/20–06/27/24 → 1,243
  [ 2/52] 06/27–07/04/24 → 987
  ...
✅ Report saved: Fixed_Trend_Report.html
```

---

## How It Works

### Authentication
```
POST /rest/token  →  Login (returns TNS_SESSIONID cookie + X-SecurityCenter token)
DELETE /rest/token  →  Logout
```

### Vulnerability Count (per period)
```
POST /rest/analysis
  type:       "vuln"
  sourceType: "patched"        ← Fixed vulnerabilities only
  tool:       "sumseverity"    ← Count per severity level
  filter:     lastMitigated = "day_end:day_start"
```

### Unique Asset Count (per period)
```
POST /rest/analysis
  type:       "vuln"
  sourceType: "patched"
  tool:       "sumip"          ← Count distinct IPs
  filter:     lastMitigated = "day_end:day_start"
  → reads totalRecords
```

> **Key discovery:** Tenable SC's `lastMitigated` filter uses **days** (not Unix timestamps).  
> `"0:7"` = mitigated in the last 7 days. `"7:14"` = 7–14 days ago.

---

## Understanding the Numbers

### Vulnerability Instances vs. Unique Assets

The tool reports two distinct metrics:

| Metric | API Tool | What it counts |
|--------|----------|----------------|
| **Fixed count** (bar chart) | `sumseverity` | Plugin × Host combinations — one vulnerability on 10 hosts = 10 |
| **Unique Assets** (last column) | `sumip` | Distinct IPs — the same 10 hosts = 1 unique asset count of 10 |

To verify the fixed count in the SC GUI:
1. Go to **Analysis → Vulnerabilities**
2. Click **Mitigated** (top-right toggle)
3. Add filter: **Vulnerability Mitigated → Last Week** (or matching range)
4. Click **Go to Vulnerability Detail** → the Count column sum = the script's total

---

## Files

| File | Description |
|------|-------------|
| `report_builder.py` | Web UI server — full-featured browser interface |
| `sc_trend.py` | CLI script — interactive prompts, quick one-off reports |
| `sc_debug.py` | Diagnostic: tests available SC API filters |
| `sc_debug2.py` | Diagnostic: validates lastMitigated date format |
| `CHANGELOG.md` | Version history |

---

## Troubleshooting

**Blank error / connection refused**
- Use the internal IP address if your SC is behind F5/SSO (e.g. `https://10.x.x.x`)
- Make sure you're not using port 8443 unless your SC actually listens there

**HTTP 307 redirect**
- Your SC is behind an F5 APM or SSO gateway
- Use the internal IP directly — the script handles 307 redirects automatically for direct connections

**SSL Certificate Error**
Open your SC URL in Chrome → click "Continue anyway" → retry the script.

**Charts not showing**
Open the HTML in Chrome (not Edge). `report_builder.py` inlines Chart.js automatically.

**Numbers don't match SC GUI**
The report counts vulnerability *instances* (Plugin × IP). The SC GUI "543 plugin IDs" view groups by plugin — click "Go to Vulnerability Detail" to see the instance count which should match.

**WinError 10060 – Timeout**
Check SC is reachable on your network. The script retries automatically.

---

## Contributing

Pull requests welcome. Ideas for future features:
- Export to Excel / PDF
- Multi-repo comparison side-by-side
- Email delivery on a schedule
- Integration with Tenable One Exposure View

---

## License

MIT License – free to use, modify, and share.

---

*Built by Benny Adler*  
*Contributed to the [Cyber Agents Exchange](https://github.com/tenable-cyberagents-exchange/exchange-founders-prelaunch-agents)*
