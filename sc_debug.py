"""
SC Filter Diagnostic – מוצא את שם הפילטר הנכון לתאריך תיקון
הרצה: py sc_debug.py
"""
import urllib.request, http.cookiejar, json, ssl
from datetime import datetime, timedelta

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode    = ssl.CERT_NONE

print("=" * 50)
SC_HOST  = input("SC URL  [https://localhost:8443]: ").strip() or "https://localhost:8443"
USERNAME = input("Username: ").strip()
PASSWORD = input("Password: ").strip()
print()
SC_HOST = SC_HOST.rstrip("/")

jar    = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=CTX),
    urllib.request.HTTPCookieProcessor(jar)
)

def sc_call(path, method="GET", data=None, token=None):
    url  = f"{SC_HOST}/rest/{path}"
    body = json.dumps(data).encode() if data else None
    req  = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    if token: req.add_header("X-SecurityCenter", token)
    try:
        return json.loads(opener.open(req, timeout=30).read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"error": e.read().decode("utf-8","ignore")[:200], "code": e.code}

# Login
resp  = sc_call("token", "POST", {"username": USERNAME, "password": PASSWORD})
TOKEN = str(resp["response"]["token"])
print("✓ Login OK\n")

# טווח: 30 יום אחרונים
now      = datetime.now()
ts_end   = int(now.timestamp())
ts_start = int((now - timedelta(days=30)).timestamp())
print(f"טווח בדיקה: 30 יום אחרונים ({ts_start}:{ts_end})\n")

# בדוק ללא פילטר תאריך (כדי לאמת שיש נתונים בכלל)
print("1. ללא פילטר תאריך (כל ה-Fixed):")
r = sc_call("analysis", "POST", {
    "type": "vuln", "sourceType": "patched",
    "query": {"tool": "sumseverity", "type": "vuln",
              "startOffset": 0, "endOffset": 10, "filters": []}
}, TOKEN)
rr = r.get("response", {})
total_all = sum(int(x.get("count",0)) for x in rr.get("results",[]))
print(f"   totalRecords={rr.get('totalRecords','?')}  סה\"כ count={total_all}\n")

# נסה פילטרים שונים
filters_to_try = ["lastMitigated", "mitigated", "fixedDate", "lastFixed", "pluginModDate"]
for fname in filters_to_try:
    print(f"2. פילטר: {fname}")
    r = sc_call("analysis", "POST", {
        "type": "vuln", "sourceType": "patched",
        "query": {"tool": "sumseverity", "type": "vuln",
                  "startOffset": 0, "endOffset": 10,
                  "filters": [{"filterName": fname, "operator": "=",
                                "value": f"{ts_start}:{ts_end}"}]}
    }, TOKEN)
    rr   = r.get("response", {})
    ec   = r.get("error_code", 0)
    emsg = r.get("error_msg", "")
    if ec != 0:
        print(f"   ✗ error_code={ec}: {emsg}")
    else:
        total = sum(int(x.get("count",0)) for x in (rr.get("results") or []))
        print(f"   ✓ totalRecords={rr.get('totalRecords','?')}  count={total}")
    print()

# Logout
try: sc_call("token", "DELETE", token=TOKEN)
except: pass
print("סיום.")
