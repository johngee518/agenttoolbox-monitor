#!/usr/bin/env python3
"""Light, no-browser health check for https://agenttoolbox.net.
Exits non-zero on any problem so GitHub Actions emails the repo owner."""
import json, os, re, sys, urllib.request, urllib.error
from datetime import datetime, timezone, date
from email.utils import parsedate_to_datetime

BASE = os.environ.get("SITE_BASE", "https://agenttoolbox.net").rstrip("/")
UA = {"User-Agent": "AgentToolbox-LightCheck/1.0"}
PAGES = ["/", "/directory", "/tools", "/pricing", "/blog", "/blog/rss.xml", "/games",
         "/sponsor", "/sponsor-terms", "/privacy", "/terms", "/sitemap.xml",
         "/robots.txt", "/llms.txt", "/openapi.json"]
MODEL_MAX_DAYS, BLOG_MAX_DAYS = 3, 2
BAD = re.compile(r"(?i)(lorem ipsum|\blorem\b|\bPLACEHOLDER\b|>\s*NaN\s*<|>\s*undefined\s*<|\bNaN\b(?=[ %$])|\$NaN|\[insert )")
SCRIPT = re.compile(r"(?is)<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>")
PH_ATTR = re.compile(r'(?i)\splaceholder\s*=\s*("[^"]*"|\'[^\']*\')')
problems, ok = [], []

def fetch(path, data=None, headers=None):
    h = dict(UA); h.update(headers or {})
    req = urllib.request.Request(BASE + path, data=data, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return 0, str(e)

bodies = {}
for p in PAGES:
    s, b = fetch(p)
    if s != 200:
        problems.append(f"{p} returned {s}"); continue
    bodies[p] = b
    vis = PH_ATTR.sub("", SCRIPT.sub("", b)) if "<html" in b[:2000].lower() else b
    m = BAD.search(vis)
    if m:
        problems.append(f"{p} contains suspicious text: {m.group(0)!r}")
    else:
        ok.append(p)

# API tool list + model verified date
today = datetime.now(timezone.utc).date()
s, b = fetch("/api/tools")
if s != 200:
    problems.append(f"/api/tools returned {s}")
else:
    try:
        tools = json.loads(b); assert isinstance(tools, list) and tools
        ok.append(f"/api/tools ({len(tools)} tools)")
    except Exception:
        problems.append("/api/tools did not return a non-empty JSON list")
    dates = re.findall(r"verified (\d{4}-\d{2}-\d{2})", b)
    if not dates:
        problems.append("model verified date not found in /api/tools")
    else:
        v = max(date.fromisoformat(d) for d in dates); age = (today - v).days
        (problems.append(f"model data verified {v} is {age} days old (> {MODEL_MAX_DAYS})")
         if age > MODEL_MAX_DAYS else ok.append(f"models verified {v} ({age}d)"))

# MCP endpoint
s, b = fetch("/api/mcp", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode(),
             {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
if s == 200 and '"tools"' in b:
    ok.append("/api/mcp tools/list")
else:
    problems.append(f"/api/mcp tools/list failed (status {s})")

# Newest blog post
rss = bodies.get("/blog/rss.xml", "")
pubs = re.findall(r"<pubDate>([^<]+)</pubDate>", rss)
if not pubs:
    problems.append("no <pubDate> found in /blog/rss.xml")
else:
    newest = max(parsedate_to_datetime(x) for x in pubs)
    age = (datetime.now(timezone.utc) - newest).total_seconds() / 86400
    (problems.append(f"newest blog post {newest:%Y-%m-%d} is {age:.1f} days old (> {BLOG_MAX_DAYS})")
     if age > BLOG_MAX_DAYS else ok.append(f"newest blog post {newest:%Y-%m-%d} ({age:.1f}d)"))

lines = [f"## Agent Toolbox light check: {'FAIL' if problems else 'PASS'}", ""]
lines += [f"- ❌ {p}" for p in problems] + [f"- ✅ {o}" for o in ok]
out = "\n".join(lines); print(out)
if os.environ.get("GITHUB_STEP_SUMMARY"):
    open(os.environ["GITHUB_STEP_SUMMARY"], "a").write(out + "\n")
sys.exit(1 if problems else 0)
