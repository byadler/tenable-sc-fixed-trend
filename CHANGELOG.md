# Changelog

All notable changes to the Tenable SC Fixed Vulnerability Trend Builder.

---

## [1.2.0] – 2026-07-15

### report_builder.py – Major Feature Update

#### New Features
- **Multiple asset group selection** — Ctrl+Click to select multiple asset groups simultaneously
- **Asset group search bar** — Filter asset list by name in real time; selections are preserved while filtering
- **Severity filter** — Checkboxes to include/exclude Critical / High / Medium / Low / Info from both the charts and totals. Info is unchecked by default.
- **Unique Assets column** — New column in the data table showing how many distinct IPs were remediated each period (uses `sumip` tool, no double-counting)
- **Column visibility toggles** — Show/hide individual columns in the data table (Critical, High, Medium, Low, Info, Total, Unique Assets)
- **Two-chart layout:**
  - Chart 1: Stacked bar by severity + Total trend line overlay
  - Chart 2: Total Fixed line + 4-period moving average (clean, no severity toggle)

#### Bug Fixes
- **HTTP 307 redirect handling** — Fixed POST requests failing silently when SC is behind an F5 BIG-IP APM / SSO gateway. The client now follows 301/302/307/308 redirects correctly for all HTTP methods.
- **Blank error bar** — Fixed empty error messages when connection fails; now always shows a human-readable error string.
- **Asset list parsing** — Handles SC API responses where assets are nested under `usable` or `manageable` keys.

#### Technical Details
- New `query_unique_assets()` method uses `tool: "sumip"` and reads `totalRecords`
- New `_asset_filter()` method handles both single-asset (`{"id": "X"}`) and multi-asset (`[{"id": "X"}, ...]`) filter formats
- `fetch_data()` now runs both `query_fixed()` and `query_unique_assets()` per period
- `render_report()` calculates `total` as sum of only the selected severities
- Token is cast to `str()` to handle SC 6.7.x which returns token as integer

---

## [1.1.0] – 2026-06-25

### report_builder.py – Web UI Launch

#### New Features
- Web UI server at `http://localhost:8080`
- Step-by-step form: Connect → Configure → Report
- Optional logo upload (embedded as base64 in the report)
- Custom colors per severity level
- Weekly / Monthly granularity toggle
- Export HTML (self-contained, works offline)
- Print support

#### sc_trend.py
- Added 307 redirect handling
- Added `User-Agent` and `Accept` headers
- Added `retries` parameter (default 3)

---

## [1.0.0] – 2026-06-21

### Initial Release

- `sc_trend.py` — CLI script with interactive prompts
- Pulls Fixed (Patched) vulnerabilities week by week via `/rest/analysis`
- `sourceType: "patched"` with `lastMitigated` days-based filter
- Generates standalone HTML report with:
  - Stacked bar chart by severity (Chart.js)
  - Trend line with 4-week moving average
  - Full data table
- Supports repository and asset tag filtering
- Auto-downloads Chart.js on first run
- No pip installs required (Python stdlib only)

#### Key Discovery
`lastMitigated` filter uses **days** (not Unix timestamps): `"0:7"` = last 7 days, `"7:14"` = 7–14 days ago.
