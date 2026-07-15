"""
Tenable.SC – Fixed Vulnerabilities Trend Report
================================================
Queries real SC data and generates an HTML report with charts.

Run:
  py sc_trend_en.py
"""
import urllib.request, http.cookiejar, json, ssl, webbrowser, os
from datetime import datetime, timedelta

# ── SSL ────────────────────────────────────────────────────
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode    = ssl.CERT_NONE

# ── Connection details ──────────────────────────────────────
print("=" * 50)
print("  Tenable.SC – Fixed Trend Report")
print("=" * 50)
SC_HOST  = input("SC URL  [https://localhost:8443]: ").strip() or "https://localhost:8443"
USERNAME = input("Username: ").strip()
PASSWORD = input("Password: ").strip()
print()

SC_HOST = SC_HOST.rstrip("/")

# ── Login ──────────────────────────────────────────────────
jar    = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=CTX),
    urllib.request.HTTPCookieProcessor(jar)
)

def sc_call(path, method="GET", data=None, token=None, retries=3, _url=None):
    url = _url or f"{SC_HOST}/rest/{path}"
    body = json.dumps(data).encode() if data else None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, data=body, method=method)
            req.add_header("Content-Type", "application/json")
            req.add_header("Accept",       "application/json")
            req.add_header("User-Agent",   "Mozilla/5.0")
            if token:
                req.add_header("X-SecurityCenter", token)
            resp = json.loads(opener.open(req, timeout=60).read().decode("utf-8"))
            if resp.get("error_code", 0) != 0:
                raise RuntimeError(f"SC Error {resp['error_code']}: {resp.get('error_msg','')}")
            return resp
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 307, 308):
                location = e.headers.get("Location", "")
                if location:
                    if location.startswith("/"):
                        from urllib.parse import urlparse
                        p = urlparse(SC_HOST)
                        location = f"{p.scheme}://{p.netloc}{location}"
                    print(f"\n[redirect {e.code}] → {location}")
                    return sc_call(path, method, data, token, retries, _url=location)
            msg = e.read().decode("utf-8", "ignore")[:300]
            raise RuntimeError(f"HTTP {e.code}: {msg}")
        except Exception as e:
            if attempt < retries:
                print(f" [retry {attempt}/{retries}]", end=" ", flush=True)
                import time; time.sleep(3)
            else:
                raise

print("Connecting to SC...", end=" ", flush=True)
login_resp = sc_call("token", "POST", {"username": USERNAME, "password": PASSWORD})
TOKEN      = str(login_resp["response"]["token"])
print("✓\n")

# ── Fetch Repositories ─────────────────────────────────────
repos_resp = sc_call("repository?fields=id,name", token=TOKEN)
repos = repos_resp.get("response", [])
print("Repositories:")
print("  0. All Repositories")
for i, r in enumerate(repos, 1):
    print(f"  {i}. {r['name']} (id={r['id']})")
repo_choice = input("Select repository number [0=All]: ").strip() or "0"
REPO_IDS = []
if repo_choice != "0":
    try:
        REPO_IDS = [repos[int(repo_choice)-1]["id"]]
    except: pass
print()

# ── Fetch Asset Tags ───────────────────────────────────────
assets_resp = sc_call("asset?fields=id,name,type", token=TOKEN)
ar = assets_resp.get("response", [])
if isinstance(ar, dict):
    ar = ar.get("usable", ar.get("manageable", []))
print("Asset Tags:")
print("  0. No filter (all assets)")
for i, a in enumerate(ar, 1):
    print(f"  {i}. {a['name']}")
asset_choice = input("Select asset number [0=None]: ").strip() or "0"
ASSET_ID = None
if asset_choice != "0":
    try:
        ASSET_ID = ar[int(asset_choice)-1]["id"]
    except: pass
print()

# ── Select Time Range ──────────────────────────────────────
print("Time range:")
print("  1. Last week only")
print("  2. Last 4 weeks (1 month)")
print("  3. Last 3 months (13 weeks)")
print("  4. Last year (52 weeks)")
time_choice = input("Select [1-4, default=4]: ").strip() or "4"
WEEKS_MAP = {"1": 1, "2": 4, "3": 13, "4": 52}
NUM_WEEKS = WEEKS_MAP.get(time_choice, 52)
print()

# ── Fetch function ─────────────────────────────────────────
SEV_MAP = {"4": "Critical", "3": "High", "2": "Medium", "1": "Low", "0": "Info"}

def fetch_week(day_end, day_start):
    filters = [{"filterName": "lastMitigated", "operator": "=",
                "value": f"{day_end}:{day_start}"}]
    if REPO_IDS:
        filters.append({"filterName": "repository", "operator": "=",
                        "value": [{"id": str(r)} for r in REPO_IDS]})
    if ASSET_ID:
        filters.append({"filterName": "asset", "operator": "=",
                        "value": {"id": str(ASSET_ID)}})
    payload = {
        "type": "vuln", "sourceType": "patched",
        "query": {"tool": "sumseverity", "type": "vuln",
                  "startOffset": 0, "endOffset": 10, "filters": filters}
    }
    resp    = sc_call("analysis", "POST", payload, TOKEN)
    results = resp.get("response", {})
    if isinstance(results, dict):
        results = results.get("results", [])
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for item in results:
        sev_id = str(item.get("severity", {}).get("id", "0"))
        counts[SEV_MAP.get(sev_id, "Info")] += int(item.get("count", 0))
    return counts

# ── Fetch data ─────────────────────────────────────────────
now   = datetime.now()
weeks = []

print(f"Fetching data ({NUM_WEEKS} weeks)...")
for i in range(NUM_WEEKS):
    day_end   = (NUM_WEEKS - 1 - i) * 7
    day_start = day_end + 7
    end_dt    = now - timedelta(days=day_end)
    start_dt  = now - timedelta(days=day_start)
    label     = f"{start_dt.strftime('%m/%d')}-{end_dt.strftime('%m/%d/%y')}"
    print(f"  [{i+1:2d}/{NUM_WEEKS}] {label}", end=" ", flush=True)
    counts    = fetch_week(day_end, day_start)
    total     = counts["Critical"] + counts["High"] + counts["Medium"] + counts["Low"]
    weeks.append({**counts, "Total": total, "Period": label})
    print(f"→ {total:,}")

# Logout
try: sc_call("token", "DELETE", token=TOKEN)
except: pass

# ── Period summaries ───────────────────────────────────────
def sum_weeks(n):
    r = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for w in weeks[-n:]:
        for k in r: r[k] += w.get(k, 0)
    r["Total"] = sum(r.values())
    return r

_p = []
if NUM_WEEKS >= 1:  _p.append({**sum_weeks(min(1,  NUM_WEEKS)), "Period": "Last Week"})
if NUM_WEEKS >= 4:  _p.append({**sum_weeks(min(4,  NUM_WEEKS)), "Period": "Last 4 Weeks"})
if NUM_WEEKS >= 13: _p.append({**sum_weeks(min(13, NUM_WEEKS)), "Period": "Last 3 Months"})
if NUM_WEEKS >= 52: _p.append({**sum_weeks(52),                "Period": "Last Year"})
periods  = _p if _p else [{**sum_weeks(NUM_WEEKS), "Period": f"Last {NUM_WEEKS} Weeks"}]
total_db = sum_weeks(NUM_WEEKS)["Total"]

# ── Moving Average ─────────────────────────────────────────
totals = [w["Total"] for w in weeks]
mavg   = [round(sum(totals[max(0,i-3):i+1]) / len(totals[max(0,i-3):i+1])) for i in range(len(totals))]

# ── JSON for charts ────────────────────────────────────────
wl  = json.dumps([w["Period"]   for w in weeks])
wc  = json.dumps([w["Critical"] for w in weeks])
wh  = json.dumps([w["High"]     for w in weeks])
wm  = json.dumps([w["Medium"]   for w in weeks])
wlo = json.dumps([w["Low"]      for w in weeks])
wt  = json.dumps(totals)
wma = json.dumps(mavg)

pl  = json.dumps([p["Period"]   for p in periods])
pc  = json.dumps([p["Critical"] for p in periods])
ph  = json.dumps([p["High"]     for p in periods])
pm  = json.dumps([p["Medium"]   for p in periods])
plo = json.dumps([p["Low"]      for p in periods])

# ── HTML ───────────────────────────────────────────────────
period_rows = "".join(
    f'<div class="box"><h3>Fixed – {p["Period"]}</h3>'
    f'<div class="num">{p["Total"]:,}</div>'
    f'<div class="sev">C:{p["Critical"]:,} &nbsp; H:{p["High"]:,} &nbsp; M:{p["Medium"]:,} &nbsp; L:{p["Low"]:,}</div></div>'
    for p in periods
)

table_rows = "".join(
    f'<tr><td>{w["Period"]}</td><td style="color:#C00000">{w["Critical"]:,}</td>'
    f'<td style="color:#FF4444">{w["High"]:,}</td>'
    f'<td style="color:#FFC000">{w["Medium"]:,}</td>'
    f'<td style="color:#00B0F0">{w["Low"]:,}</td>'
    f'<td><b>{w["Total"]:,}</b></td></tr>'
    for w in reversed(weeks)
)

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Fixed Vulnerabilities Trend - Tenable.SC</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{{font-family:Arial,sans-serif;background:#f0f4f8;padding:24px;margin:0}}
h1{{color:#1F4E79;text-align:center;margin-bottom:4px;font-size:22px}}
.sub{{text-align:center;color:#888;font-size:13px;margin-bottom:24px}}
.card{{background:#fff;border-radius:12px;padding:24px;margin-bottom:20px;box-shadow:0 2px 8px rgba(0,0,0,.08)}}
h2{{color:#2E75B6;border-bottom:2px solid #2E75B6;padding-bottom:6px;margin-top:0;font-size:15px}}
.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}}
.box{{background:#f5f8fc;border-radius:10px;padding:18px;text-align:center;border:1px solid #dde6f0}}
.box h3{{margin:0 0 6px;font-size:12px;color:#555;font-weight:normal}}
.num{{font-size:32px;font-weight:bold;color:#1F4E79}}
.sev{{font-size:11px;color:#888;margin-top:5px}}
.legend{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:12px}}
.leg{{display:flex;align-items:center;gap:5px;font-size:12px;color:#555}}
.dot{{width:10px;height:10px;border-radius:2px;display:inline-block}}
.dash{{display:inline-block;width:20px;height:0;border-top:2.5px dashed #1F4E79}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#1F4E79;color:#fff;padding:9px 8px;text-align:center}}
td{{padding:8px;text-align:center;border-bottom:1px solid #eee}}
tr:nth-child(even) td{{background:#f8fafc}}
</style>
</head>
<body>
<h1>Fixed Vulnerabilities Trend – Tenable.SC</h1>
<p class="sub">Generated: {datetime.now().strftime('%m/%d/%Y %H:%M')} &nbsp;|&nbsp; Total Fixed: {total_db:,}</p>

<div class="card">
  <h2>Period Summary</h2>
  <div class="grid">{period_rows}</div>
</div>

<div class="card">
  <h2>Weekly Trend – Stacked Bar + Trend Line</h2>
  <div class="legend">
    <span class="leg"><span class="dot" style="background:#C00000"></span>Critical</span>
    <span class="leg"><span class="dot" style="background:#FF4444"></span>High</span>
    <span class="leg"><span class="dot" style="background:#FFC000"></span>Medium</span>
    <span class="leg"><span class="dot" style="background:#00B0F0"></span>Low</span>
    <span class="leg"><span class="dash"></span>Trend Line (4-week avg)</span>
  </div>
  <canvas id="weeklyChart" style="max-height:340px"></canvas>
</div>

<div class="card">
  <h2>Total Fixed – Trend Line</h2>
  <canvas id="lineChart" style="max-height:240px"></canvas>
</div>

<div class="card">
  <h2>Period Comparison</h2>
  <canvas id="periodChart" style="max-height:240px"></canvas>
</div>

<div class="card">
  <h2>Weekly Data Table</h2>
  <table>
    <tr><th>Period</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr>
    {table_rows}
  </table>
</div>

<script>
const wl  = {wl};
const wc  = {wc};
const wh  = {wh};
const wm  = {wm};
const wlo = {wlo};
const wt  = {wt};
const wma = {wma};
const pl  = {pl};
const pc  = {pc};
const ph  = {ph};
const pm  = {pm};
const plo = {plo};

// Weekly stacked bar + trend line
new Chart(document.getElementById('weeklyChart'), {{
  type: 'bar',
  data: {{
    labels: wl,
    datasets: [
      {{label:'Critical', data:wc,  backgroundColor:'#C00000', stack:'s'}},
      {{label:'High',     data:wh,  backgroundColor:'#FF4444', stack:'s'}},
      {{label:'Medium',   data:wm,  backgroundColor:'#FFC000', stack:'s'}},
      {{label:'Low',      data:wlo, backgroundColor:'#00B0F0', stack:'s'}},
      {{label:'Trend Line', data:wma, type:'line', borderColor:'#1F4E79',
        borderDash:[6,3], borderWidth:2, pointRadius:0, fill:false,
        yAxisID:'y', tension:0.3}}
    ]
  }},
  options:{{
    responsive:true, plugins:{{legend:{{position:'top'}}}},
    scales:{{x:{{stacked:true,ticks:{{maxTicksLimit:13}}}}, y:{{stacked:true, beginAtZero:true}}}}
  }}
}});

// Total trend line + moving average
new Chart(document.getElementById('lineChart'), {{
  type: 'line',
  data: {{
    labels: wl,
    datasets: [
      {{label:'Total Fixed', data:wt, borderColor:'#2E75B6', backgroundColor:'rgba(46,117,182,0.08)',
        fill:true, tension:0.3, pointRadius:2}},
      {{label:'Moving Avg (4w)', data:wma, borderColor:'#C00000', borderDash:[6,3],
        borderWidth:2, pointRadius:0, fill:false}}
    ]
  }},
  options:{{responsive:true, plugins:{{legend:{{position:'top'}}}},
    scales:{{x:{{ticks:{{maxTicksLimit:13}}}}, y:{{beginAtZero:true}}}}}}
}});

// Period comparison
new Chart(document.getElementById('periodChart'), {{
  type: 'bar',
  data: {{
    labels: pl,
    datasets: [
      {{label:'Critical', data:pc,  backgroundColor:'#C00000'}},
      {{label:'High',     data:ph,  backgroundColor:'#FF4444'}},
      {{label:'Medium',   data:pm,  backgroundColor:'#FFC000'}},
      {{label:'Low',      data:plo, backgroundColor:'#00B0F0'}}
    ]
  }},
  options:{{responsive:true, plugins:{{legend:{{position:'top'}}}},
    scales:{{x:{{stacked:true}}, y:{{stacked:true, beginAtZero:true}}}}}}
}});
</script>
</body>
</html>"""

# ── Save and open ──────────────────────────────────────────
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Fixed_Trend_Report.html")
with open(out, "w", encoding="utf-8") as f:
    f.write(html)

print(f"\n✅ Report saved: {out}")
webbrowser.open(f"file:///{out.replace(os.sep, '/')}")
