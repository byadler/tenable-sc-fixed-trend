"""
Tenable.SC – Date Range Diagnostic
=====================================
Validates the lastMitigated filter format and checks which
date ranges contain Fixed vulnerability data.

Run:  py sc_debug2.py
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
        return {"_http_error": e.code, "body": e.read().decode("utf-8","ignore")[:300]}

resp  = sc_call("token", "POST", {"username": USERNAME, "password": PASSWORD})
TOKEN = str(resp["response"]["token"])
print("Login OK\n")

now = datetime.now()

# 1. Fetch sample records with date fields
print("1. Fetching 3 sample Fixed records with date fields...")
r = sc_call("analysis", "POST", {
    "type": "vuln", "sourceType": "patched",
    "query": {
        "tool": "vulndetails", "type": "vuln",
        "startOffset": 0, "endOffset": 3,
        "filters": [],
        "fields": "pluginID,severity,firstSeen,lastSeen,lastFixed,mitigated,pluginModDate"
    }
}, TOKEN)
results = r.get("response", {}).get("results", [])
for rec in results:
    print(f"   pluginID={rec.get('pluginID')} severity={rec.get('severity',{}).get('name')}")
    for f in ["firstSeen","lastSeen","lastFixed","mitigated","pluginModDate"]:
        v = rec.get(f)
        if v:
            try:
                dt = datetime.utcfromtimestamp(int(v)).strftime('%Y-%m-%d')
            except:
                dt = str(v)
            print(f"     {f}: {v} -> {dt}")
print()

# 2. Test lastMitigated with Unix timestamps (wrong format – expect 0 results)
print("2. lastMitigated with Unix timestamps (expected: 0 results):")
ts_old = int((now - timedelta(days=365*5)).timestamp())
ts_now = int(now.timestamp())
r = sc_call("analysis", "POST", {
    "type": "vuln", "sourceType": "patched",
    "query": {"tool": "sumseverity", "type": "vuln",
              "startOffset": 0, "endOffset": 10,
              "filters": [{"filterName": "lastMitigated", "operator": "=",
                           "value": f"{ts_old}:{ts_now}"}]}
}, TOKEN)
rr = r.get("response", {})
total = sum(int(x.get("count",0)) for x in rr.get("results",[]))
print(f"   count={total}  totalRecords={rr.get('totalRecords','?')}\n")

# 3. Test lastMitigated with DAYS format (correct format)
print("3. lastMitigated with DAYS format '0:30' (expected: results):")
r = sc_call("analysis", "POST", {
    "type": "vuln", "sourceType": "patched",
    "query": {"tool": "sumseverity", "type": "vuln",
              "startOffset": 0, "endOffset": 10,
              "filters": [{"filterName": "lastMitigated", "operator": "=",
                           "value": "0:30"}]}
}, TOKEN)
rr = r.get("response", {})
total = sum(int(x.get("count",0)) for x in rr.get("results",[]))
print(f"   count={total}  totalRecords={rr.get('totalRecords','?')}\n")

# 4. Test last year using days
print("4. lastMitigated last year ('0:365'):")
r = sc_call("analysis", "POST", {
    "type": "vuln", "sourceType": "patched",
    "query": {"tool": "sumseverity", "type": "vuln",
              "startOffset": 0, "endOffset": 10,
              "filters": [{"filterName": "lastMitigated", "operator": "=",
                           "value": "0:365"}]}
}, TOKEN)
rr = r.get("response", {})
total = sum(int(x.get("count",0)) for x in rr.get("results",[]))
print(f"   count={total}  totalRecords={rr.get('totalRecords','?')}\n")

try: sc_call("token", "DELETE", token=TOKEN)
except: pass
print("Done.")
