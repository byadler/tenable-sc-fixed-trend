#!/usr/bin/env python3
"""
Tenable.SC – Report Builder
============================
Single file · No external dependencies · Works Offline

Run:  py report_builder.py
Open: http://localhost:8080

For offline Chart.js:
  Download: https://cdn.jsdelivr.net/npm/chart.js/dist/chart.min.js
  Place chart.min.js in the same folder as this script.
"""

import http.cookiejar
import http.server
import json
import os
import ssl
import sys
import threading
import urllib.error
import urllib.request
import webbrowser
from datetime import datetime, timedelta

# ─────────────────────────────────────────────
PORT       = 8080
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_CHART_LOCAL = os.path.join(SCRIPT_DIR, "chart.min.js")

# הורד chart.min.js אוטומטית אם לא קיים
if not os.path.exists(_CHART_LOCAL):
    try:
        print("מוריד Chart.js...", end=" ", flush=True)
        _ctx = ssl.create_default_context()
        _ctx.check_hostname = False
        _ctx.verify_mode    = ssl.CERT_NONE
        _req = urllib.request.urlopen(
            "https://cdn.jsdelivr.net/npm/chart.js/dist/chart.umd.min.js",
            context=_ctx, timeout=15)
        with open(_CHART_LOCAL, "wb") as _f:
            _f.write(_req.read())
        print("✓")
    except Exception as _e:
        print(f"נכשל ({_e}) – ישתמש ב-CDN")

CHART_SRC = "chart.min.js" if os.path.exists(_CHART_LOCAL) \
            else "https://cdn.jsdelivr.net/npm/chart.js"
# ─────────────────────────────────────────────

SSL_CTX                  = ssl.create_default_context()
SSL_CTX.check_hostname   = False
SSL_CTX.verify_mode      = ssl.CERT_NONE


# ══════════════════════════════════════════════
#  Tenable.SC API Client
# ══════════════════════════════════════════════

class SCClient:
    def __init__(self, host, username, password):
        self.host     = host.rstrip("/")
        self.username = username
        self.password = password
        self.token    = None
        self._jar     = http.cookiejar.CookieJar()
        self._opener  = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=SSL_CTX),
            urllib.request.HTTPCookieProcessor(self._jar),
        )

    def _call(self, path, method="GET", data=None):
        url  = f"{self.host}/rest/{path}"
        body = json.dumps(data).encode("utf-8") if data else None
        req  = urllib.request.Request(url, data=body, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("X-SecurityCenter", self.token)
        try:
            with self._opener.open(req, timeout=30) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            msg = e.read().decode("utf-8")[:400]
            raise RuntimeError(f"HTTP {e.code}: {msg}")

    # ── Auth ──────────────────────────────────
    def login(self):
        resp = self._call("token", "POST",
                          {"username": self.username, "password": self.password})
        if resp.get("error_code", 0) != 0:
            raise RuntimeError(f"Login failed: {resp.get('error_msg', str(resp))}")
        r = resp.get("response", {})
        if not isinstance(r, dict) or "token" not in r:
            raise RuntimeError(f"Unexpected login response: {resp}")
        self.token = str(r["token"])   # token is int in SC 6.7.x

    def logout(self):
        try:
            self._call("token", "DELETE")
        except Exception:
            pass

    # ── Metadata ──────────────────────────────
    def repositories(self):
        return self._call("repository?fields=id,name,description,type") \
                   .get("response", [])

    def assets(self):
        r = self._call("asset?fields=id,name,type,description").get("response", [])
        if isinstance(r, dict):
            return r.get("usable", r.get("manageable", []))
        return r if isinstance(r, list) else []

    # ── Analysis ──────────────────────────────
    def query_fixed(self, start_ts, end_ts, repo_ids=None, asset_id=None):
        """
        POST /rest/analysis  sourceType="patched"
        lastMitigated מקבל ימים (לא timestamps):
          "0:7"  = תוקן בין 0 ל-7 ימים אחורה
          "7:14" = תוקן בין 7 ל-14 ימים אחורה
        """
        now_ts   = datetime.now().timestamp()
        day_end  = max(0, int((now_ts - end_ts)   / 86400))
        day_start = max(0, int((now_ts - start_ts) / 86400))
        filters = [{
            "filterName": "lastMitigated",
            "operator":   "=",
            "value":      f"{day_end}:{day_start}"
        }]
        if repo_ids:
            filters.append({
                "filterName": "repository",
                "operator":   "=",
                "value":      [{"id": str(r)} for r in repo_ids]
            })
        if asset_id:
            filters.append({
                "filterName": "asset",
                "operator":   "=",
                "value":      {"id": str(asset_id)}
            })

        payload = {
            "type":       "vuln",
            "sourceType": "patched",
            "query": {
                "tool":        "sumseverity",
                "type":        "vuln",
                "startOffset": 0,
                "endOffset":   5000,
                "filters":     filters,
            }
        }
        return self._call("analysis", "POST", payload).get("response", {})

    @staticmethod
    def parse_counts(response_data):
        sev = {"4": "Critical", "3": "High", "2": "Medium", "1": "Low", "0": "Info"}
        out = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for item in response_data.get("results", []):
            sid = str(item.get("severity", {}).get("id", "0"))
            out[sev.get(sid, "Info")] += int(item.get("count", 0))
        out["Total"] = sum(out.values())
        return out


# ══════════════════════════════════════════════
#  Report Generator
# ══════════════════════════════════════════════

def moving_avg(series, window=4):
    return [round(sum(series[max(0, i - window + 1):i + 1]) /
                  len(series[max(0, i - window + 1):i + 1]))
            for i in range(len(series))]


def build_periods(start_dt, end_dt, granularity):
    periods = []
    cur = start_dt
    if granularity == "monthly":
        while cur < end_dt:
            nxt = (cur.replace(day=28) + timedelta(days=4)).replace(day=1)
            nxt = min(nxt, end_dt)
            periods.append((cur.strftime("%m/%Y"), cur, nxt))
            cur = nxt
    else:  # weekly (default)
        while cur < end_dt:
            nxt = min(cur + timedelta(weeks=1), end_dt)
            periods.append((f"{cur.strftime('%d/%m')}–{nxt.strftime('%d/%m/%y')}", cur, nxt))
            cur = nxt
    return periods


def fetch_data(client, periods, repo_ids, asset_id):
    rows = []
    for label, p_start, p_end in periods:
        raw    = client.query_fixed(p_start.timestamp(), p_end.timestamp(),
                                    repo_ids, asset_id)
        counts = client.parse_counts(raw)
        counts["Period"] = label
        rows.append(counts)
    return rows


def render_report(cfg, rows):
    """Build the standalone report HTML."""

    labels  = [r["Period"]   for r in rows]
    crit    = [r["Critical"] for r in rows]
    high    = [r["High"]     for r in rows]
    med     = [r["Medium"]   for r in rows]
    low     = [r["Low"]      for r in rows]
    info_v  = [r["Info"]     for r in rows]
    total   = [r["Total"]    for r in rows]
    mavg    = moving_avg(total)

    # Period summary (last 7 / 30 / 90 days from rows)
    now = datetime.now()
    def sum_period(days):
        cutoff = now - timedelta(days=days)
        # approximate: sum last N rows proportionally
        # (rows are already filtered; just use total of all rows as approximation)
        return sum(total)

    colors  = cfg.get("colors", {})
    c_crit  = colors.get("Critical", "#C00000")
    c_high  = colors.get("High",     "#FF4444")
    c_med   = colors.get("Medium",   "#FFC000")
    c_low   = colors.get("Low",      "#00B0F0")
    c_info  = colors.get("Info",     "#AAAAAA")

    title       = cfg.get("title",    "Fixed Vulnerabilities Trend")
    logo_src    = cfg.get("logo")     # base64 data URL or None
    asset_name  = cfg.get("assetName", "—")
    repo_names  = ", ".join(cfg.get("repoNames", [])) or "—"
    generated   = datetime.now().strftime("%d/%m/%Y %H:%M")
    total_fixed = sum(total)

    logo_html = (f'<img src="{logo_src}" style="max-height:45px;max-width:180px;'
                 f'vertical-align:middle;margin-left:16px">'
                 if logo_src and logo_src not in ("null", "None", "") else "")

    # Inline Chart.js so the HTML is self-contained (needed for iframe srcdoc)
    if os.path.exists(_CHART_LOCAL):
        with open(_CHART_LOCAL, "r", encoding="utf-8", errors="replace") as _cf:
            _chart_tag = "<script>" + _cf.read() + "</script>"
    else:
        _chart_tag = '<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>'

    # Table rows
    table_rows = ""
    for r in rows:
        table_rows += (
            f"<tr><td>{r['Period']}</td>"
            f"<td style='color:{c_crit};font-weight:bold'>{r['Critical']:,}</td>"
            f"<td style='color:{c_high}'>{r['High']:,}</td>"
            f"<td style='color:{c_med}'>{r['Medium']:,}</td>"
            f"<td style='color:{c_low}'>{r['Low']:,}</td>"
            f"<td>{r['Info']:,}</td>"
            f"<td><strong>{r['Total']:,}</strong></td></tr>\n"
        )

    html = f"""<!DOCTYPE html>
<html dir="rtl" lang="he">
<head>
<meta charset="UTF-8">
<title>{title}</title>
{_chart_tag}
<style>
  body   {{font-family:'Segoe UI',Arial,sans-serif;background:#f0f4f8;margin:0;padding:20px;direction:rtl}}
  h1     {{color:#1F4E79;margin:0;font-size:22px;vertical-align:middle}}
  h2     {{color:#2E75B6;border-bottom:2px solid #2E75B6;padding-bottom:6px;margin-bottom:16px;font-size:15px}}
  .hdr   {{background:#fff;border-radius:10px;padding:18px 24px;margin-bottom:20px;
           box-shadow:0 2px 8px rgba(0,0,0,.08);display:flex;align-items:center;justify-content:space-between}}
  .meta  {{font-size:12px;color:#888;line-height:1.8}}
  .card  {{background:#fff;border-radius:10px;padding:22px 24px;margin-bottom:20px;
           box-shadow:0 2px 8px rgba(0,0,0,.08)}}
  .kpi-grid {{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:0}}
  .kpi   {{background:#1F4E79;color:#fff;border-radius:8px;padding:16px;text-align:center}}
  .kpi h3{{font-size:11px;opacity:.75;margin-bottom:6px}}
  .kpi .n{{font-size:32px;font-weight:700}}
  table  {{width:100%;border-collapse:collapse;font-size:13px}}
  th     {{background:#1F4E79;color:#fff;padding:9px 12px;text-align:center}}
  td     {{padding:8px 12px;text-align:center;border-bottom:1px solid #eee}}
  tr:nth-child(even) td{{background:#f5f8fc}}
  canvas {{max-height:340px}}
  @media print{{.no-print{{display:none}}}}
</style>
</head>
<body>

<!-- Header -->
<div class="hdr">
  <div style="display:flex;align-items:center">
    {logo_html}
    <h1>{title}</h1>
  </div>
  <div class="meta">
    <div>⚙ Asset: <strong>{asset_name}</strong></div>
    <div>🗄 Repos: <strong>{repo_names}</strong></div>
    <div>📅 נוצר: {generated}</div>
  </div>
</div>

<!-- KPI boxes -->
<div class="card">
  <h2>סיכום – כלל התקופה</h2>
  <div class="kpi-grid">
    <div class="kpi"><h3>סה"כ Fixed</h3><div class="n">{total_fixed:,}</div></div>
    <div class="kpi" style="background:#8B0000"><h3>Critical</h3><div class="n">{sum(crit):,}</div></div>
    <div class="kpi" style="background:#CC0000"><h3>High</h3><div class="n">{sum(high):,}</div></div>
    <div class="kpi" style="background:#B8860B"><h3>Medium</h3><div class="n">{sum(med):,}</div></div>
  </div>
</div>

<!-- Chart 1: Stacked Bar + Line -->
<div class="card">
  <h2>מגמת Fixed לפי Severity – Bar + Trend Line</h2>
  <canvas id="chart1"></canvas>
</div>

<!-- Chart 2: Total + Moving Average -->
<div class="card">
  <h2>קו מגמה + ממוצע נע (4 תקופות)</h2>
  <canvas id="chart2"></canvas>
</div>

<!-- Data Table -->
<div class="card">
  <h2>טבלת נתונים מלאה</h2>
  <table>
    <tr><th>תקופה</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Total</th></tr>
    {table_rows}
  </table>
</div>

<script>
// Chart 1 – Stacked Bar + Line overlay
new Chart(document.getElementById('chart1'), {{
  type: 'bar',
  data: {{
    labels: {json.dumps(labels, ensure_ascii=False)},
    datasets: [
      {{label:'Critical', data:{crit},   backgroundColor:'{c_crit}', stack:'s'}},
      {{label:'High',     data:{high},   backgroundColor:'{c_high}', stack:'s'}},
      {{label:'Medium',   data:{med},    backgroundColor:'{c_med}',  stack:'s'}},
      {{label:'Low',      data:{low},    backgroundColor:'{c_low}',  stack:'s'}},
      {{label:'Info',     data:{info_v}, backgroundColor:'{c_info}', stack:'s'}},
      {{label:'Total', data:{total}, type:'line',
        borderColor:'#1F4E79', borderWidth:2.5, pointRadius:3,
        backgroundColor:'rgba(31,78,121,0.07)', fill:true, tension:0.3,
        yAxisID:'y', stack:undefined}}
    ]
  }},
  options:{{
    responsive:true,
    plugins:{{legend:{{position:'top'}}}},
    scales:{{
      x:{{stacked:true, ticks:{{maxRotation:45, font:{{size:10}}}}}},
      y:{{stacked:true, beginAtZero:true, title:{{display:true,text:'פגיעויות'}}}}
    }}
  }}
}});

// Chart 2 – Line + Moving Average
new Chart(document.getElementById('chart2'), {{
  type: 'line',
  data: {{
    labels: {json.dumps(labels, ensure_ascii=False)},
    datasets: [
      {{label:'סה"כ Fixed', data:{total},
        borderColor:'{c_high}', backgroundColor:'rgba(255,68,68,.1)',
        borderWidth:2, pointRadius:4, fill:true, tension:0.3}},
      {{label:'ממוצע נע (4)', data:{mavg},
        borderColor:'#1F4E79', borderDash:[6,3],
        borderWidth:2, pointRadius:0, fill:false, tension:0.4}}
    ]
  }},
  options:{{
    responsive:true,
    plugins:{{legend:{{position:'top'}}}},
    scales:{{
      x:{{ticks:{{maxRotation:45, font:{{size:10}}}}}},
      y:{{beginAtZero:true, title:{{display:true,text:'פגיעויות'}}}}
    }}
  }}
}});
</script>
</body>
</html>"""
    return html


# ══════════════════════════════════════════════
#  Embedded HTML Form
# ══════════════════════════════════════════════

HTML_FORM = """<!DOCTYPE html>
<html dir="rtl" lang="he">
<head>
<meta charset="UTF-8">
<title>Tenable.SC – Report Builder</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f4f8;color:#333;direction:rtl}
  .wrap{max-width:860px;margin:0 auto;padding:28px 18px}
  h1{color:#1F4E79;text-align:center;font-size:22px;margin-bottom:4px}
  .sub{text-align:center;color:#666;font-size:13px;margin-bottom:26px}
  .card{background:#fff;border-radius:12px;padding:26px;margin-bottom:18px;box-shadow:0 2px 10px rgba(0,0,0,.08)}
  .card h2{color:#2E75B6;font-size:14px;font-weight:700;margin-bottom:16px;
            padding-bottom:8px;border-bottom:2px solid #2E75B6;display:flex;align-items:center;gap:8px}
  .badge{display:inline-flex;align-items:center;justify-content:center;
         background:#1F4E79;color:#fff;border-radius:50%;width:22px;height:22px;font-size:12px}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
  .grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:14px}
  .full{grid-column:1/-1}
  label{display:block;font-size:11px;color:#555;font-weight:600;margin-bottom:4px}
  input,select{width:100%;padding:8px 11px;border:1px solid #ccc;border-radius:6px;font-size:13px;direction:ltr}
  input[type=color]{padding:3px 5px;height:34px;cursor:pointer}
  input[type=file]{direction:rtl;font-size:12px}
  select[multiple]{height:86px}
  .btn{display:inline-block;padding:9px 22px;border:none;border-radius:8px;
       font-size:13px;font-weight:600;cursor:pointer;transition:.2s}
  .btn-primary{background:#1F4E79;color:#fff}.btn-primary:hover{background:#163b5c}
  .btn-success{background:#2E7D32;color:#fff}.btn-success:hover{background:#1B5E20}
  .btn-export{background:#fff;color:#1F4E79;border:2px solid #1F4E79}
  .msg{padding:9px 14px;border-radius:6px;font-size:12px;margin-top:10px}
  .ok{background:#E8F5E9;color:#2E7D32;border:1px solid #A5D6A7}
  .err{background:#FFEBEE;color:#C62828;border:1px solid #EF9A9A}
  .info{background:#E3F2FD;color:#1565C0;border:1px solid #90CAF9}
  .colors{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:8px}
  .colors label{text-align:center;font-size:10px}
  .spin{display:inline-block;width:14px;height:14px;border:2px solid #ccc;
        border-top-color:#1F4E79;border-radius:50%;animation:sp .7s linear infinite;vertical-align:middle;margin-left:6px}
  @keyframes sp{to{transform:rotate(360deg)}}
  .hidden{display:none!important}
  #report-frame{margin-top:0}
  .actions{display:flex;gap:10px;justify-content:center;margin-top:14px}
</style>
</head>
<body>
<div class="wrap">
  <h1>🔒 Tenable.SC – Report Builder</h1>
  <p class="sub">בניית דוחות מגמה מותאמים · ללא התקנה · עובד Offline</p>

  <!-- ── Step 1: Connection ── -->
  <div class="card" id="c1">
    <h2><span class="badge">1</span> חיבור ל-Tenable.SC</h2>
    <div class="grid2">
      <div><label>SC URL</label>
           <input id="host" value="https://localhost:8443" placeholder="https://your-tenable-sc"></div>
      <div><label>שם משתמש (Security Manager)</label>
           <input id="user" placeholder="username"></div>
    </div>
    <div class="grid2">
      <div><label>סיסמה</label>
           <input id="pass" type="password" placeholder="password"></div>
      <div style="display:flex;align-items:flex-end">
           <button class="btn btn-primary" onclick="connect()" style="width:100%">בדוק חיבור ←</button></div>
    </div>
    <div id="cmsg"></div>
  </div>

  <!-- ── Step 2: Config (hidden until connected) ── -->
  <div class="card hidden" id="c2">
    <h2><span class="badge">2</span> הגדרות הדוח</h2>
    <div class="grid2">
      <div class="full"><label>כותרת הדוח</label>
           <input id="rtitle" value="Fixed Vulnerabilities Trend – 3 Months" dir="auto"></div>
      <div><label>Asset Tag / Asset List</label>
           <select id="asset"><option value="">-- כל ה-Assets --</option></select></div>
      <div><label>Repositories (Ctrl+Click לבחירה מרובה)</label>
           <select id="repos" multiple></select></div>
      <div><label>תאריך התחלה</label><input id="dstart" type="date"></div>
      <div><label>תאריך סיום</label><input id="dend" type="date"></div>
      <div><label>פירוט</label>
           <select id="gran"><option value="weekly">שבועי</option>
                              <option value="monthly">חודשי</option></select></div>
    </div>

    <div><label>לוגו (אופציונלי – PNG/JPG)</label>
         <input type="file" id="logo" accept="image/*" onchange="previewLogo(this)">
         <img id="lprev" style="max-height:38px;margin-top:6px;display:none"></div>

    <div style="margin-top:14px"><label>צבעים לפי Severity</label>
      <div class="colors">
        <div><label>Critical</label><input type="color" id="cc" value="#C00000"></div>
        <div><label>High</label>    <input type="color" id="ch" value="#FF4444"></div>
        <div><label>Medium</label>  <input type="color" id="cm" value="#FFC000"></div>
        <div><label>Low</label>     <input type="color" id="cl" value="#00B0F0"></div>
        <div><label>Info</label>    <input type="color" id="ci" value="#AAAAAA"></div>
      </div>
    </div>

    <div class="actions" style="margin-top:18px">
      <button class="btn btn-success" onclick="generate()">▶ צור דוח</button>
    </div>
    <div id="gmsg"></div>
  </div>

  <!-- ── Step 3: Report ── -->
  <div id="c3" class="hidden">
    <div class="actions">
      <button class="btn btn-export" onclick="exportHTML()">💾 ייצא HTML</button>
      <button class="btn btn-export" onclick="window.print()">🖨 הדפס</button>
    </div>
    <iframe id="report-frame" style="width:100%;border:none;min-height:1100px;display:block"></iframe>
  </div>
</div>

<script>
// Default dates: today – 3 months
(function(){
  const now = new Date(), s = new Date(now);
  s.setMonth(s.getMonth() - 3);
  document.getElementById('dend').valueAsDate = now;
  document.getElementById('dstart').valueAsDate = s;
})();

function msg(id, text, cls){document.getElementById(id).innerHTML=`<div class="msg ${cls}">${text}</div>`}

function previewLogo(inp){
  const f=inp.files[0]; if(!f)return;
  const r=new FileReader();
  r.onload=e=>{const i=document.getElementById('lprev');i.src=e.target.result;i.style.display='block'};
  r.readAsDataURL(f);
}

async function connect(){
  const host=document.getElementById('host').value.trim(),
        user=document.getElementById('user').value.trim(),
        pass=document.getElementById('pass').value.trim();
  msg('cmsg','<span class="spin"></span> מתחבר...','info');
  try{
    const r=await fetch('/api/connect',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({host,user,pass})});
    const d=await r.json();
    if(d.error)throw new Error(d.error);
    // Populate repos
    const rsel=document.getElementById('repos');
    rsel.innerHTML='';
    d.repositories.forEach(x=>{
      const o=new Option(`${x.name} (${x.type})`,x.id);
      if(['New_Default_Repo','PCI_Repo'].includes(x.name)) o.selected=true;
      rsel.appendChild(o);
    });
    // Populate assets
    const asel=document.getElementById('asset');
    asel.innerHTML='<option value="">-- כל ה-Assets --</option>';
    d.assets.forEach(x=>asel.appendChild(new Option(`${x.name} (${x.type})`,x.id)));
    msg('cmsg',`✅ מחובר | ${d.repositories.length} Repositories · ${d.assets.length} Asset Lists`,'ok');
    document.getElementById('c2').classList.remove('hidden');
  }catch(e){msg('cmsg',`❌ ${e.message}`,'err')}
}

async function generate(){
  const host=document.getElementById('host').value.trim(),
        user=document.getElementById('user').value.trim(),
        pass=document.getElementById('pass').value.trim();
  const asel=document.getElementById('asset');
  const rsel=document.getElementById('repos');
  const cfg={
    host, user, pass,
    title:   document.getElementById('rtitle').value,
    logo:    document.getElementById('lprev').src||null,
    dstart:  document.getElementById('dstart').value,
    dend:    document.getElementById('dend').value,
    gran:    document.getElementById('gran').value,
    assetId: asel.value||null,
    assetName: asel.selectedOptions[0]?.text||'',
    repoIds:   Array.from(rsel.selectedOptions).map(o=>o.value),
    repoNames: Array.from(rsel.selectedOptions).map(o=>o.text.split(' (')[0]),
    colors:{
      Critical: document.getElementById('cc').value,
      High:     document.getElementById('ch').value,
      Medium:   document.getElementById('cm').value,
      Low:      document.getElementById('cl').value,
      Info:     document.getElementById('ci').value,
    }
  };
  if(cfg.logo==='') cfg.logo=null;
  msg('gmsg','<span class="spin"></span> שולף נתונים מ-Tenable.SC...','info');
  try{
    const r=await fetch('/api/generate',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(cfg)});
    const d=await r.json();
    if(d.error)throw new Error(d.error);
    msg('gmsg',`✅ הדוח נוצר – ${d.periods} תקופות · ${d.total.toLocaleString()} Fixed vulns`,'ok');
    // Render inline
    const frame=document.getElementById('report-frame');
    frame.srcdoc=d.html;
    document.getElementById('c3').classList.remove('hidden');
    frame.scrollIntoView({behavior:'smooth'});
    window._exportHtml=d.html;
  }catch(e){msg('gmsg',`❌ ${e.message}`,'err')}
}

function exportHTML(){
  if(!window._exportHtml)return;
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([window._exportHtml],{type:'text/html;charset=utf-8'}));
  a.download=`SC_Report_${new Date().toISOString().slice(0,10)}.html`;
  a.click();
}
</script>
</body>
</html>"""


# ══════════════════════════════════════════════
#  HTTP Request Handler
# ══════════════════════════════════════════════

class Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # suppress console noise

    # ── Helpers ───────────────────────────────
    def _json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, text):
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n).decode("utf-8"))

    # ── GET ───────────────────────────────────
    def do_GET(self):
        if self.path == "/":
            self._html(HTML_FORM)
        elif self.path == "/chart.min.js" and os.path.exists(_CHART_LOCAL):
            with open(_CHART_LOCAL, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    # ── POST ──────────────────────────────────
    def do_POST(self):
        try:
            body = self._read_body()
        except Exception:
            self._json({"error": "Invalid JSON"}, 400)
            return

        if   self.path == "/api/connect":  self._connect(body)
        elif self.path == "/api/generate": self._generate(body)
        else:
            self._json({"error": "Not found"}, 404)

    def _connect(self, body):
        try:
            c = SCClient(body["host"], body["user"], body["pass"])
            c.login()
            repos  = c.repositories()
            assets = c.assets()
            c.logout()
            self._json({
                "repositories": [{"id": r["id"], "name": r["name"],
                                   "type": r.get("type", "")} for r in repos],
                "assets":       [{"id": a["id"], "name": a["name"],
                                   "type": a.get("type", "")} for a in assets],
            })
        except Exception as e:
            self._json({"error": str(e)})

    def _generate(self, cfg):
        try:
            c = SCClient(cfg["host"], cfg["user"], cfg["pass"])
            c.login()

            start_dt  = datetime.strptime(cfg["dstart"][:10], "%Y-%m-%d")
            end_dt    = datetime.strptime(cfg["dend"][:10],   "%Y-%m-%d")
            repo_ids  = cfg.get("repoIds")  or []
            asset_id  = cfg.get("assetId")  or None
            gran      = cfg.get("gran", "weekly")

            periods   = build_periods(start_dt, end_dt, gran)
            rows      = fetch_data(c, periods, repo_ids, asset_id)
            c.logout()

            html = render_report(cfg, rows)
            self._json({
                "html":    html,
                "periods": len(rows),
                "total":   sum(r["Total"] for r in rows),
            })
        except Exception as e:
            self._json({"error": str(e)})


# ══════════════════════════════════════════════
#  Entry Point
# ══════════════════════════════════════════════

def main():
    server = http.server.HTTPServer(("localhost", PORT), Handler)
    url    = f"http://localhost:{PORT}"
    print(f"""
╔══════════════════════════════════════════════╗
║   Tenable.SC Report Builder                  ║
║   http://localhost:{PORT}                       ║
╠══════════════════════════════════════════════╣
║  Ctrl+C להפסקה                               ║
╚══════════════════════════════════════════════╝
""")
    # פתח בכרום ישירות (עוקף Edge)
    def _open_chrome(u):
        import subprocess
        chrome_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ]
        for p in chrome_paths:
            if os.path.exists(p):
                subprocess.Popen([p, u])
                return
        webbrowser.open(u)  # fallback
    threading.Timer(0.8, lambda: _open_chrome(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n⏹ Server stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
