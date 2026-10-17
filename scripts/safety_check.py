#!/usr/bin/env python3
"""Hourly $0 safety checker for https://agenttoolbox.net (GitHub Actions, stdlib only).

Exit code 1 = at least one FAIL. Warnings never fail the run unless promoted in
safety/config.json ("strict_headers": true, or add names to "fail_on_missing_headers").
Writes a Markdown report to $GITHUB_STEP_SUMMARY (if set) and out/summary.md,
plus out/status.json (fail list + signature) for the alert-issue step.

Modes (env MODE): normal | full | update-baseline | simulate-failure
  full             -> also runs the outbound link scan + listed community recheck (normally every 6h)
  update-baseline  -> re-records page-text hashes + checkout allowlist + listing fingerprints
  simulate-failure -> adds a deliberately broken URL to prove alerting works
Listed community games/tools are rechecked on every full scan (HTTP/DNS/redirect/parked/
allowlist for games/malware). Weekly content fingerprints WARN on change (re-review), never FAIL.
Never prints secret values: secret findings are redacted to rule + location.
"""
import concurrent.futures as cf, datetime as dt, hashlib, html, json, os, re, socket, ssl
import subprocess, sys, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CFG = json.loads((ROOT / "safety/config.json").read_text())
BASE = CFG["base"].rstrip("/")
HOST = urllib.parse.urlparse(BASE).hostname
MODE = os.environ.get("MODE", "normal").strip() or "normal"
SITE_DIR = Path(os.environ.get("SITE_DIR", ROOT / "site"))
SITE_TOKEN_AVAILABLE = os.environ.get("SITE_REPO_OK", "") == "true"
# a failed actions/checkout leaves an empty git repo behind, so require a successful step AND real files
SITE_OK = os.environ.get("SITE_CHECKOUT", "success" if (SITE_DIR / "package.json").exists() else "") == "success" \
    and (SITE_DIR / "package.json").exists()
NOW = dt.datetime.now(dt.timezone.utc)
FULL_LINKS = MODE in ("full", "simulate-failure") or NOW.hour % CFG.get("link_scan_every_hours", 6) == 0 \
    or os.environ.get("FORCE_LINKS") == "1"
BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 AgentToolbox-SafetyCheck/1.0"
OUT = ROOT / "out"; OUT.mkdir(exist_ok=True)

results = []  # (section, level, message)  level in PASS/WARN/FAIL/SKIP
def rec(section, level, msg): results.append((section, level, msg)); print(f"[{level}] {section}: {msg}", flush=True)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None

def http(url, method="GET", data=None, headers=None, timeout=20, follow=True, max_bytes=600_000):
    """Returns dict(status, headers, body, final_url, elapsed, error)."""
    h = {"User-Agent": BROWSER_UA, "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
         "Accept-Language": "en-US,en;q=0.8"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedirect)
    t0 = time.time()
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(max_bytes).decode("utf-8", "replace")
            return dict(status=r.status, headers={k.lower(): v for k, v in r.headers.items()}, body=body,
                        final_url=r.geturl(), elapsed=time.time() - t0, error=None)
    except urllib.error.HTTPError as e:
        try: body = e.read(max_bytes).decode("utf-8", "replace")
        except Exception: body = ""
        return dict(status=e.code, headers={k.lower(): v for k, v in (e.headers or {}).items()}, body=body,
                    final_url=getattr(e, "url", url) or url, elapsed=time.time() - t0, error=None)
    except Exception as e:
        return dict(status=0, headers={}, body="", final_url=url, elapsed=time.time() - t0, error=f"{type(e).__name__}: {e}"[:200])

# ---------------------------------------------------------------- 1. uptime
pages = {}
def check_uptime():
    S = "1. Uptime"
    paths = list(CFG["pages_required"]) + list(CFG["pages_optional"])
    if MODE == "simulate-failure":
        paths.append(CFG["simulated_failure_path"])
    for p in paths:
        r = http(BASE + p, timeout=CFG["page_timeout_s"])
        if r["status"] == 0 or r["status"] >= 500:
            time.sleep(3); r = http(BASE + p, timeout=CFG["page_timeout_s"])  # one retry for flakiness
        optional = p in CFG["pages_optional"]
        if r["status"] == 200:
            pages[p] = r
            lvl = "PASS" if r["elapsed"] <= CFG["page_slow_s"] else "WARN"
            rec(S, lvl, f"{p} 200 in {r['elapsed']:.2f}s" + ("" if lvl == "PASS" else f" (slower than {CFG['page_slow_s']}s)"))
        elif r["status"] == 404 and optional:
            rec(S, "SKIP", f"{p} 404 (not live yet)")
        else:
            rec(S, "FAIL", f"{p} returned {r['status'] or r['error']}")

# ---------------------------------------------------------------- 2. SSL
def check_ssl():
    S = "2. SSL"
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((HOST, 443), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=HOST) as ss:
                cert = ss.getpeercert()
        exp = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), dt.timezone.utc)
        days = (exp - NOW).days
        issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "?")
        if days < CFG["ssl_min_days"]:
            rec(S, "FAIL", f"certificate expires {exp:%Y-%m-%d} ({days} days, minimum {CFG['ssl_min_days']})")
        else:
            rec(S, "PASS", f"valid, issuer {issuer}, expires {exp:%Y-%m-%d} ({days} days)")
    except Exception as e:
        rec(S, "FAIL", f"TLS handshake/verification failed: {type(e).__name__}: {e}"[:250])
    r = http(f"http://{HOST}/", follow=False, timeout=15)
    loc = r["headers"].get("location", "")
    if r["status"] in (301, 302, 307, 308) and loc.startswith("https://"):
        rec(S, "PASS", f"http:// redirects to https ({r['status']})")
    else:
        rec(S, "WARN", f"http:// did not redirect to https (status {r['status'] or r['error']})")

# ---------------------------------------------------------------- 3. headers
def check_headers():
    S = "3. Security headers"
    strict = CFG.get("strict_headers", False); fail_set = set(CFG.get("fail_on_missing_headers", []))
    for p in CFG["header_pages"]:
        r = pages.get(p) or http(BASE + p)
        h = r["headers"]
        if not h:
            rec(S, "FAIL", f"{p}: no response"); continue
        csp = h.get("content-security-policy", "")
        checks = {
            "Strict-Transport-Security": "strict-transport-security" in h,
            "X-Content-Type-Options": h.get("x-content-type-options", "").lower() == "nosniff",
            "Referrer-Policy": "referrer-policy" in h,
            "Content-Security-Policy": bool(csp),
            "Clickjacking (CSP frame-ancestors or X-Frame-Options)": "frame-ancestors" in csp or "x-frame-options" in h,
        }
        # Hosting expectations (Cloudflare Pages since 2026-10-17). pages.dev serves noindex; the real domain must never.
        if CFG.get("forbid_noindex", False):
            body = r.get("body") or r.get("text") or ""
            xr = h.get("x-robots-tag", "").lower()
            meta = re.search(r'<meta[^>]+name=["\']robots["\'][^>]+noindex', body, re.I) if isinstance(body, str) else None
            if "noindex" in xr or meta:
                rec(S, "FAIL", f"{p}: noindex on production ({'X-Robots-Tag' if 'noindex' in xr else 'meta robots'}) - search engines would drop the site")
            else:
                rec(S, "PASS", f"{p}: indexable (no noindex)")
        exp = CFG.get("expect_server", "")
        if exp:
            srv = h.get("server", "")
            if exp.lower() not in srv.lower() or "x-vercel-id" in h:
                rec(S, "WARN", f"{p}: served by '{srv or '?'}'{' (x-vercel-id present)' if 'x-vercel-id' in h else ''}, expected {exp} - DNS rolled back or changed?")
            else:
                rec(S, "PASS", f"{p}: served by {srv}")
        missing = [k for k, ok in checks.items() if not ok]
        if not missing:
            rec(S, "PASS", f"{p}: all present"); continue
        hard = [m for m in missing if strict or m in fail_set]
        if hard: rec(S, "FAIL", f"{p}: missing {', '.join(hard)}")
        soft = [m for m in missing if m not in hard]
        if soft: rec(S, "WARN", f"{p}: missing {', '.join(soft)}")
        hsts = h.get("strict-transport-security", "")
        m = re.search(r"max-age=(\d+)", hsts)
        if hsts and (not m or int(m.group(1)) < 15552000):
            rec(S, "WARN", f"{p}: HSTS max-age below 180 days ({hsts})")

# ---------------------------------------------------------------- shared: threat feeds + Safe Browsing
_feeds = None
def feeds():
    """Free, no-key threat feeds: URLhaus host file (abuse.ch) + OpenPhish community feed."""
    global _feeds
    if _feeds is not None: return _feeds
    hosts, urls, ok = set(), set(), []
    r = http("https://urlhaus.abuse.ch/downloads/hostfile/", timeout=30, max_bytes=30_000_000)
    if r["status"] == 200:
        for line in r["body"].splitlines():
            parts = line.split()
            if len(parts) >= 2 and not line.startswith("#"): hosts.add(parts[1].lower())
        ok.append(f"URLhaus ({len(hosts)} hosts)")
    r = http("https://openphish.com/feed.txt", timeout=30, max_bytes=30_000_000)
    if r["status"] == 200:
        for line in r["body"].splitlines():
            line = line.strip()
            if line.startswith("http"):
                urls.add(line.rstrip("/")); hosts_ = urllib.parse.urlparse(line).hostname
        ok.append(f"OpenPhish ({len(urls)} URLs)")
    _feeds = (hosts, urls, ok)
    return _feeds

def feed_hits(url_list):
    hosts, urls, _ = feeds()
    hits = []
    for u in url_list:
        hn = (urllib.parse.urlparse(u).hostname or "").lower()
        if hn in hosts or hn.removeprefix("www.") in hosts: hits.append((u, "URLhaus malware host"))
        elif u.rstrip("/") in urls: hits.append((u, "OpenPhish phishing URL"))
    return hits

# Google Safe Browsing via the keyless Transparency Report endpoint (same approach as
# johngee518/jrg-safety-check check.py). Unofficial: errors/captchas only WARN, never fail.
SB_TEXT = {1: "no unsafe content found", 2: "UNSAFE", 3: "SOME PAGES UNSAFE", 4: "no site-level verdict (check specific URLs)",
           5: "hosts uncommon downloads", 6: "no data yet (normal for a new site)"}
SB_DELAY_S = 1.5          # rate limit between lookups (sequential, never parallel)
_sb_state = {"last": 0.0, "blocked": False}
def transparency_sb(site, third_party=False):
    """Returns (level, message). level PASS/FAIL, or WARN when the lookup is unavailable."""
    if _sb_state["blocked"]:
        return "WARN", "skipped (Google rate-limited earlier lookups this run)"
    wait = SB_DELAY_S - (time.time() - _sb_state["last"])
    if wait > 0: time.sleep(wait)
    url = "https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site=" + urllib.parse.quote(site)
    r = http(url, timeout=15, headers={"Accept": "*/*"})
    _sb_state["last"] = time.time()
    body = r["body"]
    try:
        data = json.loads(body.split("\n", 1)[1].strip()) if body.startswith(")]}'") else json.loads(body)
        row = data[0]; code = row[1]; flags = row[2:7]
    except Exception:
        if r["status"] in (0, 302, 429, 503) or "google.com/sorry" in (r["final_url"] or "") + body[:2000]:
            _sb_state["blocked"] = True
        return "WARN", f"lookup unavailable (status {r['status'] or r['error']}); skipped this run"
    if third_party and code == 3:
        # big platforms that host user content (e.g. railway.com) often carry a standing "some pages unsafe"
        # site-level verdict; that is not a hijack of the listed page, so warn instead of alerting every 6h
        return "WARN", f"site-level verdict: {SB_TEXT[3]} (flags {flags}) - review the listing by hand"
    if code in (2, 3, 5) or any(f is True for f in flags):
        return "FAIL", f"flagged: {SB_TEXT.get(code, code)} (flags {flags})"
    return "PASS", SB_TEXT.get(code, str(code))

def sb_hosts(url_dict, section, label):
    """Rate-limited host-level lookup for a {url: source} dict. Records FAIL per flagged host, one WARN summary."""
    hosts = {}
    for u, src in url_dict.items():
        hn = (urllib.parse.urlparse(u).hostname or "").lower()
        if hn: hosts.setdefault(hn, src)
    flagged = unavailable = 0
    for hn, src in sorted(hosts.items()):
        lvl, msg = transparency_sb(hn, third_party=True)
        if lvl == "FAIL": flagged += 1; rec(section, "FAIL", f"Google Safe Browsing: {hn} ({src}) {msg}")
        elif lvl == "WARN" and "site-level" in msg: rec(section, "WARN", f"Google Safe Browsing: {hn} ({src}) {msg}")
        elif lvl == "WARN": unavailable += 1
    if unavailable:
        rec(section, "WARN", f"Google Safe Browsing (Transparency Report) unavailable for {unavailable}/{len(hosts)} {label} hosts this run")
    if hosts and not flagged and unavailable < len(hosts):
        rec(section, "PASS", f"Google Safe Browsing: {len(hosts) - unavailable} {label} hosts clean")

def check_malware():
    S = "4. Safe Browsing / malware"
    site_urls = [BASE + "/"] + [BASE + p for p in pages]
    lvl, msg = transparency_sb(HOST)
    rec(S, lvl, f"Google Safe Browsing (Transparency Report) for {HOST}: {msg}")
    hosts, urls, ok = feeds()
    if not ok:
        rec(S, "WARN", "free threat feeds (URLhaus, OpenPhish) could not be downloaded"); return
    hits = feed_hits(site_urls)
    if hits:
        for u, why in hits: rec(S, "FAIL", f"{u} listed in {why}")
    else:
        rec(S, "PASS", f"{HOST} not listed in {', '.join(ok)}")

# ---------------------------------------------------------------- 5. outbound links
PSL2 = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz", "com.br", "co.in",
        "com.cn", "com.mx", "co.za", "github.io", "vercel.app", "netlify.app", "pages.dev", "hf.space",
        "itch.io", "glitch.me", "herokuapp.com", "web.app", "firebaseapp.com"}
def regdom(host):
    host = (host or "").lower().rstrip(".")
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in PSL2: return ".".join(parts[-3:])
    return ".".join(parts[-2:])

PARKED = re.compile(r"(?i)(this domain (name )?(is|may be) for sale|domain is for sale|buy this domain|"
                    r"the domain [\w.-]+ is for sale|make an offer on this domain|this domain has expired|"
                    r"domain (has )?expired|parked (free|domain)|is parked free|courtesy of godaddy|"
                    r"sedoparking|parkingcrew|bodis\.com|above\.com/marketplace|dan\.com/buy-domain|"
                    r"afternic|hugedomains|undeveloped\.com|domainmarket\.com|parklogic|"
                    r"window\.park\s*=|/park\.js|domain-for-sale|namecheap parking|this page is parked)")
PARK_HOSTS = ("sedo.com", "dan.com", "afternic.com", "hugedomains.com", "godaddy.com", "bodis.com", "parkingcrew.net",
              "above.com", "undeveloped.com", "domainmarket.com", "sav.com", "porkbun.com", "namecheap.com", "atom.com")

def outbound_urls():
    urls = {}
    r = http(BASE + "/api/directory", headers={"Accept": "application/json"})
    try:
        for t in json.loads(r["body"]):
            for k in ("url", "affiliateUrl"):
                if t.get(k): urls[t[k]] = f"directory: {t.get('name','?')}"
    except Exception:
        rec("5. Outbound links", "FAIL", f"/api/directory not parseable (status {r['status']})")
    for p in CFG["outbound_link_pages"]:
        pr = pages.get(p)
        if not pr: continue
        for u in re.findall(r'href="(https?://[^"#\s]+)"', pr["body"]):
            u = html.unescape(u)
            hn = urllib.parse.urlparse(u).hostname or ""
            if regdom(hn) in CFG["outbound_ignore_domains"] or regdom(hn) == regdom(HOST): continue
            urls.setdefault(u, f"link on {p}")
    return urls

def probe(url):
    """Returns (level, message) for one outbound URL."""
    hn = urllib.parse.urlparse(url).hostname or ""
    try:
        socket.getaddrinfo(hn, 443)
    except Exception:
        time.sleep(2)
        try: socket.getaddrinfo(hn, 443)
        except Exception: return "FAIL", f"DNS failure for {hn} (domain may have expired)"
    r = http(url, timeout=20, max_bytes=300_000)
    if r["status"] == 0 or r["status"] >= 400:
        time.sleep(4); r = http(url, timeout=25, max_bytes=300_000)
    st = r["status"]
    if st == 0: return "FAIL", f"unreachable after retry: {r['error']}"
    if st in (401, 403, 429, 999) or (st == 503 and "cloudflare" in r["headers"].get("server", "").lower()):
        return "WARN", f"HTTP {st} (likely bot protection; check by hand if it persists)"
    if st >= 400: return "FAIL", f"HTTP {st} after retry"
    final = urllib.parse.urlparse(r["final_url"]).hostname or ""
    if regdom(final) != regdom(hn):
        allowed = CFG["allowed_redirects"].get(regdom(hn), [])
        if regdom(final) in PARK_HOSTS or any(regdom(final).endswith(x) for x in PARK_HOSTS):
            return "FAIL", f"redirects to domain marketplace {final}"
        if regdom(final) not in allowed:
            return "FAIL", f"redirects to a different domain: {hn} -> {final} (if legit, add to allowed_redirects in safety/config.json)"
    m = PARKED.search(r["body"][:300_000])
    if m: return "FAIL", f"page looks parked / for sale (matched '{m.group(0)[:60]}')"
    return "PASS", f"HTTP {st}"

def check_outbound():
    S = "5. Outbound links"
    if not FULL_LINKS:
        rec(S, "SKIP", f"full link scan runs every {CFG.get('link_scan_every_hours', 6)}h (UTC hours divisible by 6) or with mode=full"); return
    urls = outbound_urls()
    with cf.ThreadPoolExecutor(12) as ex:
        res = dict(zip(urls, ex.map(probe, urls)))
    bad = 0
    for u, (lvl, msg) in sorted(res.items()):
        if lvl != "PASS":
            bad += 1; rec(S, lvl, f"{u} ({urls[u]}): {msg}")
    hits = feed_hits(list(urls))
    for u, why in hits: rec(S, "FAIL", f"{u} ({urls[u]}) listed in {why}")
    sb_hosts(urls, S, "outbound")
    rec(S, "PASS", f"scanned {len(urls)} outbound URLs, {len(urls) - bad} clean")

# ---------------------------------------------------------------- 6. unexpected changes
NORMALIZE = [
    (r"\b\d+ of \d+ (sponsor )?spots? (open|left)\b", "N of N spots left"),
    (r"\b\d+ left\b", "N left"),
    (r"\b\d+ spots? left\b", "N spots left"),
]
def main_text(body, path):
    m = re.search(r"(?is)<main\b.*?</main>", body)
    t = m.group(0) if m else body
    t = re.sub(r"(?is)<(script|style|noscript|svg|template)\b.*?</\1>", " ", t)
    t = re.sub(r"<[^>]+>", " ", t); t = html.unescape(t); t = re.sub(r"\s+", " ", t).strip()
    for pat, rep in NORMALIZE: t = re.sub(pat, rep, t, flags=re.I)
    for pat in CFG["text_ignore"].get(path, []): t = re.sub(pat, "#", t)
    return t

PAY_HOSTS = re.compile(r"(?i)https?://([a-z0-9.-]*\b(stripe\.com|paypal\.com|paypal\.me|gumroad\.com|lemonsqueezy\.com|"
                       r"paddle\.com|checkout\.com|ko-fi\.com|buymeacoffee\.com|patreon\.com|commerce\.coinbase\.com|"
                       r"square\.link|squareup\.com|venmo\.com|cash\.app|payhip\.com|sellix\.io|polar\.sh|"
                       r"chargebee\.com|fastspring\.com|2checkout\.com|razorpay\.com|link\.com))(/[^\s\"'<>\\]*)?")

def check_changes():
    S = "6. Unexpected changes"
    bpath = ROOT / "safety/baseline.json"
    base = json.loads(bpath.read_text()) if bpath.exists() else {"pages": {}, "checkout_allowlist": []}
    new = {"pages": {}, "checkout_allowlist": base.get("checkout_allowlist", []), "updated": NOW.isoformat()}
    for p in CFG["hash_pages"]:
        r = pages.get(p) or http(BASE + p)
        if r["status"] != 200:
            rec(S, "FAIL", f"{p} not reachable for change check ({r['status']})"); continue
        t = main_text(r["body"], p); h = hashlib.sha256(t.encode()).hexdigest()
        new["pages"][p] = h
        tfile = ROOT / "safety/pages" / (p.strip("/").replace("/", "_") or "home"); tfile = tfile.with_suffix(".txt")
        old = base["pages"].get(p)
        if MODE == "update-baseline" or old is None:
            tfile.parent.mkdir(exist_ok=True); tfile.write_text(t.replace(". ", ".\n"))
            rec(S, "PASS", f"{p} baseline recorded ({h[:12]})")
        elif old == h:
            rec(S, "PASS", f"{p} text unchanged ({h[:12]})")
        else:
            import difflib
            oldt = tfile.read_text().splitlines() if tfile.exists() else []
            diff = [l for l in difflib.unified_diff(oldt, t.replace(". ", ".\n").splitlines(), lineterm="", n=0)
                    if l[:1] in "+-" and not l.startswith(("+++", "---"))][:12]
            rec(S, "FAIL", f"{p} main text changed vs baseline ({old[:12]} -> {h[:12]}). If this was an approved deploy, run "
                           f"`gh workflow run safety-check.yml -R johngee518/agenttoolbox-monitor -f mode=update-baseline`. "
                           f"Changed lines: " + " | ".join(d[:140] for d in diff))
    # checkout links
    found, other_pay = {}, set()
    for p in CFG["checkout_pages"]:
        r = pages.get(p) or http(BASE + p)
        body = r["body"].replace("\\u002F", "/").replace("\\/", "/")
        for m in PAY_HOSTS.finditer(body):
            u = m.group(0).rstrip(".,);\\"); hostp = m.group(1).lower()
            if hostp == "buy.stripe.com":
                found.setdefault(u.split("?")[0], set()).add(p)
            elif hostp in CFG["payment_host_allow_nonlink"]:
                continue
            else:
                other_pay.add(f"{u[:120]} (on {p})")
    allow = set(new["checkout_allowlist"])
    if MODE == "update-baseline" or not allow:
        allow = set(found) | set(CFG.get("checkout_allowlist_extra", []))
        new["checkout_allowlist"] = sorted(allow)
        rec(S, "PASS", f"checkout allowlist recorded: {len(allow)} buy.stripe.com links")
    unknown = sorted(set(found) - allow)
    for u in unknown: rec(S, "FAIL", f"unknown checkout link {u} on {', '.join(sorted(found[u]))} (not on allowlist)")
    for u in sorted(other_pay): rec(S, "FAIL", f"unexpected payment domain: {u}")
    if not unknown and not other_pay:
        rec(S, "PASS", f"{len(found)} checkout links on {', '.join(CFG['checkout_pages'])}, all on the allowlist; no other payment domains")
    missing = sorted(set(CFG.get("checkout_must_appear", [])) - set(found))
    for u in missing: rec(S, "WARN", f"expected checkout link not found on pages: {u}")
    if MODE == "update-baseline" or not bpath.exists() or any(p not in base["pages"] for p in new["pages"]):
        merged = dict(base.get("pages", {})); merged.update({k: v for k, v in new["pages"].items()
                                                             if MODE == "update-baseline" or k not in base["pages"]})
        new["pages"] = merged
        bpath.write_text(json.dumps(new, indent=2) + "\n")

# ---------------------------------------------------------------- 7. secrets
SECRET_PATTERNS = [
    ("Stripe live secret key", r"\bsk_live_[0-9A-Za-z]{16,}"), ("Stripe restricted key", r"\brk_live_[0-9A-Za-z]{16,}"),
    ("Stripe test secret key", r"\bsk_test_[0-9A-Za-z]{16,}"), ("Stripe webhook secret", r"\bwhsec_[0-9A-Za-z]{20,}"),
    ("GitHub token", r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{30,}"), ("GitHub fine-grained token", r"\bgithub_pat_[0-9A-Za-z_]{40,}"),
    ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b"), ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("Slack token", r"\bxox[abprs]-[0-9A-Za-z-]{10,}"), ("Private key", r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"),
    ("OpenAI key", r"\bsk-(proj-)?[A-Za-z0-9_\-]{40,}"), ("Anthropic key", r"\bsk-ant-[A-Za-z0-9_\-]{30,}"),
    ("xAI key", r"\bxai-[A-Za-z0-9]{40,}"), ("Resend key", r"\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{20,}"),
    ("Vercel token", r"\bvercel_[A-Za-z0-9]{20,}"),
]
def redact(s): return s[:8] + "…" if len(s) > 8 else "…"

def check_secrets():
    S = "7. Exposed secrets"
    # 7a gitleaks on repos
    targets = [("monitor repo", ROOT)]
    if SITE_OK: targets.append(("site repo johngee518/agenttoolbox-site", SITE_DIR))
    else: rec(S, "SKIP", "site repo not checked out: add the SITE_REPO_TOKEN secret (read-only fine-grained token, see README)")
    for name, d in targets:
        rep = OUT / f"gitleaks-{abs(hash(name))}.json"
        try:
            p = subprocess.run(["gitleaks", "git", str(d), "--redact", "--no-banner", "--exit-code", "0",
                                "--report-format", "json", "--report-path", str(rep), "--log-level", "error"],
                               capture_output=True, text=True, timeout=240)
            if p.returncode != 0: raise RuntimeError(p.stderr.strip()[:200])
            leaks = json.loads(rep.read_text() or "[]")
            if leaks:
                for l in leaks[:15]:
                    rec(S, "FAIL", f"gitleaks ({name}): {l.get('RuleID')} in {l.get('File')}:{l.get('StartLine')} commit {str(l.get('Commit'))[:8]} - rotate the secret, then purge it from history")
            else:
                rec(S, "PASS", f"gitleaks: no secrets in {name} (full history)")
        except FileNotFoundError:
            rec(S, "WARN", "gitleaks not installed on runner")
        except Exception as e:
            rec(S, "WARN", f"gitleaks failed on {name}: {e}")
    # 7b live JS bundles
    js = set()
    for p, r in pages.items():
        for s in re.findall(r'(?:src|href)="([^"]+\.js(?:\?[^"]*)?)"', r["body"]):
            u = urllib.parse.urlparse(urllib.parse.urljoin(BASE + "/", html.unescape(s)))
            if u.hostname == HOST: js.add(u.path + (("?" + u.query) if u.query else ""))
    hits = []
    def scan(path):
        r = http(BASE + path, timeout=20, max_bytes=5_000_000)
        out = []
        for label, pat in SECRET_PATTERNS:
            for m in re.finditer(pat, r["body"]): out.append((path, label, redact(m.group(0))))
        return out
    with cf.ThreadPoolExecutor(8) as ex:
        for o in ex.map(scan, sorted(js)): hits += o
    # also the HTML itself (inline __NEXT_DATA__/RSC payloads)
    for p, r in pages.items():
        for label, pat in SECRET_PATTERNS:
            for m in re.finditer(pat, r["body"]): hits.append((p, label, redact(m.group(0))))
    if hits:
        for path, label, red in hits[:15]: rec(S, "FAIL", f"live site exposes a {label} in {path} ({red}) - rotate it now")
    else:
        rec(S, "PASS", f"no secret-looking strings in {len(js)} JS bundles + {len(pages)} pages")

# ---------------------------------------------------------------- 8. npm audit
def check_npm():
    S = "8. npm audit"
    lock = SITE_DIR / "package-lock.json"
    if not SITE_OK or not lock.exists():
        rec(S, "SKIP", "site package-lock.json unavailable (needs SITE_REPO_TOKEN)"); return
    p = subprocess.run(["npm", "audit", "--package-lock-only", "--json", "--omit=dev"], cwd=SITE_DIR,
                       capture_output=True, text=True, timeout=180)
    try:
        data = json.loads(p.stdout)
        v = data.get("metadata", {}).get("vulnerabilities", {})
    except Exception:
        rec(S, "WARN", f"npm audit output unreadable: {(p.stderr or p.stdout)[:200]}"); return
    hi, crit = v.get("high", 0), v.get("critical", 0)
    names = [f"{k} ({x.get('severity')})" for k, x in data.get("vulnerabilities", {}).items() if x.get("severity") in ("high", "critical")]
    if hi or crit:
        rec(S, "FAIL", f"{crit} critical / {hi} high vulnerable packages: {', '.join(names[:12])} - run `npm audit fix` in the site repo")
    else:
        rec(S, "PASS", f"no high/critical vulnerabilities (moderate {v.get('moderate',0)}, low {v.get('low',0)})")

# ---------------------------------------------------------------- 9. community submissions
def check_submissions():
    S = "9. Community submissions"
    urls = {}
    repo = CFG["site_repo"]
    if SITE_TOKEN_AVAILABLE:
        for label in ("tool-submission", "game-submission"):
            p = subprocess.run(["gh", "issue", "list", "-R", repo, "-l", label, "--state", "open", "--limit", "100",
                                "--json", "number,title,body"], capture_output=True, text=True, timeout=60)
            if p.returncode != 0:
                if "not found" in p.stderr.lower() or "could not" in p.stderr.lower():
                    rec(S, "SKIP", f"label '{label}' not found in {repo} yet")
                else:
                    rec(S, "WARN", f"could not list '{label}' issues: {p.stderr.strip()[:150]}")
                continue
            for it in json.loads(p.stdout or "[]"):
                for u in re.findall(r"https?://[^\s)\]>\"'`]+", it.get("body") or ""):
                    urls.setdefault(u.rstrip(".,"), f"{label} #{it['number']}")
    else:
        rec(S, "SKIP", "submission issues not readable without SITE_REPO_TOKEN")
    for f in sorted(SITE_DIR.glob("data/*submissions*.jsonl")) if SITE_OK else []:
        for line in f.read_text().splitlines():
            for u in re.findall(r"https?://[^\s\"'\\]+", line):
                urls.setdefault(u.rstrip(".,"), f"{f.name}")
    urls = {u: s for u, s in urls.items() if regdom(urllib.parse.urlparse(u).hostname or "") not in CFG["outbound_ignore_domains"]
            and regdom(urllib.parse.urlparse(u).hostname or "") != regdom(HOST)}
    if not urls:
        rec(S, "SKIP", "no pending submission URLs to scan (approved ones are covered by the outbound link scan)"); return
    for u, why in feed_hits(list(urls)): rec(S, "FAIL", f"submission {u} ({urls[u]}) listed in {why} - reject it")
    if FULL_LINKS: sb_hosts(urls, S, "submission")
    with cf.ThreadPoolExecutor(8) as ex:
        res = dict(zip(urls, ex.map(probe, urls)))
    for u, (lvl, msg) in res.items():
        if lvl == "FAIL" and ("parked" in msg or "marketplace" in msg or "DNS" in msg):
            rec(S, "FAIL", f"submission {u} ({urls[u]}): {msg} - reject it")
        elif lvl != "PASS":
            rec(S, "WARN", f"submission {u} ({urls[u]}): {msg}")
    rec(S, "PASS", f"scanned {len(urls)} pending submission URLs")

# ---------------------------------------------------------------- 10. listed community games + tools (post-approval recheck)
# John's rule: nothing stays listed without periodic rechecks. URLs come from the live public site
# (/api/directory community entries + /games play links / any games JSON). Allowlist matches gamesconf.js
# HOSTS plus huggingface.co / hf.space. Allowlist FAIL applies to games only; community tools may live on
# any public https host (same as the submit form), so tools skip the host allowlist.
DEFAULT_LISTING_ALLOWLIST = [
    "itch.io", "codepen.io", "github.io", "glitch.me", "replit.app", "netlify.app",
    "vercel.app", "pages.dev", "scratch.mit.edu", "huggingface.co", "hf.space",
]
WEEKLY_FP = (
    (FULL_LINKS or MODE == "update-baseline")
    and (
        NOW.weekday() == CFG.get("listing_fingerprint_weekday", 0)
        or os.environ.get("FORCE_LISTING_FP") == "1"
        or MODE == "update-baseline"
    )
)

def listing_allowlist():
    """Prefer HOSTS from the site source (gamesconf.js) when checked out; always include HF hosts."""
    hosts = list(CFG.get("listing_allowlist") or DEFAULT_LISTING_ALLOWLIST)
    if SITE_OK:
        for rel in ("gamesconf.js", "community.js"):
            f = SITE_DIR / rel
            if not f.exists():
                continue
            raw = f.read_text(errors="replace")
            for key in ("HOSTS", "EMBED_HOSTS"):
                m = re.search(rf"(?:export\s+)?(?:const|let|var)\s+{key}\s*=\s*\[([^\]]+)\]", raw)
                if not m:
                    continue
                found = re.findall(r"['\"]([a-z0-9.-]+)['\"]", m.group(1), flags=re.I)
                for h in found:
                    if h not in hosts:
                        hosts.append(h)
    # Ensure the task's HF hosts are always present even if an older gamesconf is checked out
    for h in ("huggingface.co", "hf.space"):
        if h not in hosts:
            hosts.append(h)
    return hosts

def host_on_allowlist(url, allow):
    hn = (urllib.parse.urlparse(url).hostname or "").lower()
    if not hn:
        return False
    return any(hn == d or hn.endswith("." + d) for d in allow)

def listed_community_urls():
    """Return {url: label} for approved community tools + games from live public data."""
    urls = {}
    # Community tools: /api/directory entries marked community:true (added on approve)
    r = http(BASE + "/api/directory", headers={"Accept": "application/json"})
    try:
        data = json.loads(r["body"])
        if isinstance(data, list):
            for t in data:
                if t.get("community") and t.get("url"):
                    urls[str(t["url"]).strip()] = f"community tool: {t.get('name', '?')}"
    except Exception:
        rec("10. Listed community", "WARN", f"/api/directory not parseable for community filter (status {r['status']})")

    allow = listing_allowlist()
    # Games JSON endpoints (none live yet; keep looking so a future /api/games just works)
    for path in ("/api/games", "/games.json", "/data/games.json"):
        gr = http(BASE + path, headers={"Accept": "application/json"}, timeout=15)
        if gr["status"] != 200:
            continue
        try:
            data = json.loads(gr["body"])
        except Exception:
            continue
        items = data if isinstance(data, list) else data.get("games") or data.get("items") or []
        if not isinstance(items, list):
            continue
        for g in items:
            u = g.get("playUrl") or g.get("url")
            if u:
                urls[str(u).strip()] = f"community game: {g.get('title') or g.get('name') or '?'}"
        break

    # /games HTML: play links are external hrefs on allowlisted hosts, plus any "playUrl":"..." in RSC/JSON
    gr = pages.get("/games") or http(BASE + "/games")
    if gr["status"] == 200:
        body = gr["body"]
        for u in re.findall(r'"playUrl"\s*:\s*"(https://[^"\\]+)"', body):
            u = html.unescape(u)
            urls.setdefault(u, "community game")
        for u in re.findall(r'href="(https://[^"#\s]+)"', body):
            u = html.unescape(u)
            hn = urllib.parse.urlparse(u).hostname or ""
            if regdom(hn) == regdom(HOST):
                continue
            if host_on_allowlist(u, allow):
                urls.setdefault(u, "community game")
    return {u: lab for u, lab in urls.items() if u.startswith("https://")}

def probe_listing(url, *, require_allowlist=False, allow=None):
    """Like probe(), plus an optional host-allowlist FAIL for games."""
    if require_allowlist and allow is not None and not host_on_allowlist(url, allow):
        hn = urllib.parse.urlparse(url).hostname or "?"
        return "FAIL", f"host off allowlist: {hn}"
    return probe(url)

def listing_page_fingerprint(url):
    """SHA-256 of title + main text. Used weekly; changes are WARN (re-review), never FAIL."""
    r = http(url, timeout=25, max_bytes=400_000)
    if r["status"] == 0 or r["status"] >= 400:
        time.sleep(3)
        r = http(url, timeout=25, max_bytes=400_000)
    if r["status"] == 0 or r["status"] >= 400:
        return None, f"unreachable ({r['status'] or r['error']})"
    body = r["body"]
    tm = re.search(r"(?is)<title[^>]*>(.*?)</title>", body)
    title = re.sub(r"\s+", " ", html.unescape(tm.group(1) if tm else "")).strip()[:300]
    text = main_text(body, "")
    blob = title + "\n" + text
    return hashlib.sha256(blob.encode()).hexdigest(), title

def check_listed_community():
    S = "10. Listed community"
    if not FULL_LINKS and MODE != "update-baseline":
        rec(S, "SKIP", f"listed game/tool recheck runs with the full link scan (every {CFG.get('link_scan_every_hours', 6)}h) or mode=full")
        return
    urls = listed_community_urls()
    if not urls:
        rec(S, "SKIP", "no listed community games or community tools yet")
        return

    allow = listing_allowlist()
    # Classify: games need allowlist; tools (label starts with community tool) do not
    kinds = {}
    for u, lab in urls.items():
        kinds[u] = "game" if lab.startswith("community game") else "tool"

    with cf.ThreadPoolExecutor(8) as ex:
        futs = {
            u: ex.submit(probe_listing, u, require_allowlist=(kinds[u] == "game"), allow=allow)
            for u in urls
        }
        res = {u: f.result() for u, f in futs.items()}

    bad = 0
    for u, (lvl, msg) in sorted(res.items()):
        if lvl != "PASS":
            bad += 1
            rec(S, lvl, f"{u} ({urls[u]}): {msg}")

    hits = feed_hits(list(urls))
    for u, why in hits:
        rec(S, "FAIL", f"{u} ({urls[u]}) listed in {why}")

    sb_hosts(urls, S, "listed community")

    n_games = sum(1 for u in urls if kinds[u] == "game")
    n_tools = len(urls) - n_games
    rec(S, "PASS", f"rechecked {len(urls)} listed URLs ({n_games} games, {n_tools} community tools), {len(urls) - bad} clean; allowlist {', '.join(allow)}")

    # Weekly content fingerprint: change => WARN "re-review needed", never FAIL
    if not WEEKLY_FP:
        rec(S, "SKIP", "weekly content fingerprint runs on weekday "
            f"{CFG.get('listing_fingerprint_weekday', 0)} UTC during a full scan "
            "(or FORCE_LISTING_FP=1 / mode=update-baseline)")
        return

    bpath = ROOT / "safety/listing_baseline.json"
    base = json.loads(bpath.read_text()) if bpath.exists() else {"urls": {}}
    new_urls = dict(base.get("urls") or {})
    for u, lab in sorted(urls.items()):
        h, title_or_err = listing_page_fingerprint(u)
        if h is None:
            rec(S, "WARN", f"{u} ({lab}): fingerprint skipped — {title_or_err}")
            continue
        title = title_or_err
        old = (base.get("urls") or {}).get(u) or {}
        entry = {"hash": h, "title": title, "kind": kinds[u], "label": lab, "updated": NOW.isoformat()}
        new_urls[u] = entry
        if MODE == "update-baseline" or not old.get("hash"):
            rec(S, "PASS", f"{u} ({lab}): fingerprint baseline recorded ({h[:12]})")
        elif old["hash"] == h:
            rec(S, "PASS", f"{u} ({lab}): content unchanged ({h[:12]})")
        else:
            rec(S, "WARN", f"{u} ({lab}): content changed vs baseline ({old['hash'][:12]} -> {h[:12]}) — re-review needed"
                + (f" (title now: {title[:80]})" if title else ""))
    # Drop baselines for URLs no longer listed
    new_urls = {u: v for u, v in new_urls.items() if u in urls}
    bpath.write_text(json.dumps({"updated": NOW.isoformat(), "urls": new_urls}, indent=2) + "\n")

# ---------------------------------------------------------------- run
def main():
    for fn in (check_uptime, check_ssl, check_headers, check_malware, check_outbound, check_changes,
               check_secrets, check_npm, check_submissions, check_listed_community):
        try: fn()
        except Exception as e: rec(fn.__name__, "FAIL", f"checker crashed: {type(e).__name__}: {e}"[:300])
    fails = [f"{s}: {m}" for s, l, m in results if l == "FAIL"]
    warns = [f"{s}: {m}" for s, l, m in results if l == "WARN"]
    icon = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "SKIP": "⏭️"}
    md = [f"# Agent Toolbox safety check: {'FAILED' if fails else 'passed'}",
          f"{NOW:%Y-%m-%d %H:%M} UTC · mode `{MODE}` · link scan {'on' if FULL_LINKS else 'off this hour'} · "
          f"{len(fails)} fail, {len(warns)} warn", ""]
    if fails: md += ["## Failures", *[f"- ❌ {f}" for f in fails], ""]
    if warns: md += ["## Warnings", *[f"- ⚠️ {w}" for w in warns], ""]
    md += ["## All checks", "| | Check | Detail |", "|---|---|---|"]
    md += [f"| {icon[l]} | {s} | {m.replace('|', '/')} |" for s, l, m in results]
    text = "\n".join(md) + "\n"
    (OUT / "summary.md").write_text(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f: f.write(text)
    sig = hashlib.sha256("\n".join(sorted(re.sub(r"\d+\.\d+s", "", f) for f in fails)).encode()).hexdigest()[:16]
    (OUT / "status.json").write_text(json.dumps({"failed": bool(fails), "fails": fails, "warns": warns, "signature": sig}, indent=2))
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
