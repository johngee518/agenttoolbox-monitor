#!/usr/bin/env python3
"""Daily technical SEO check (stdlib only).

Usage:
  python3 seo_check.py https://example.com [--max-pages 25] [--json report.json]
                       [--warn-only] [--timeout 15]

Reads robots.txt and sitemap.xml, samples pages from the sitemap (homepage first),
and checks: titles, meta descriptions, canonical, exactly one H1, heading order,
noindex, JSON-LD validity/types, image alt text, Open Graph/Twitter tags, viewport,
lang, favicon, hreflang (if present), real 404 status, broken internal links,
www/apex canonical host, http->https redirect.

Exit code: 0 = no FAIL, 1 = at least one FAIL, 2 = could not run.
"""
import argparse, json, re, sys, ssl, gzip, time
import urllib.request, urllib.error, urllib.parse
from html.parser import HTMLParser
import xml.etree.ElementTree as ET

UA = "Mozilla/5.0 (compatible; SEOCheckBot/1.0; +https://github.com/johngee518)"
CTX = ssl.create_default_context()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch(url, timeout=15, follow=True, method="GET"):
    """Return dict(status, url, headers, body, error, redirects)."""
    redirects = []
    cur = url
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=CTX))
    for _ in range(10):
        req = urllib.request.Request(cur, method=method, headers={"User-Agent": UA, "Accept-Encoding": "gzip"})
        try:
            r = opener.open(req, timeout=timeout)
            status, headers, body = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            status, headers = e.code, e.headers
            try:
                body = e.read()
            except Exception:
                body = b""
        except Exception as e:
            return {"status": None, "url": cur, "headers": {}, "body": "", "error": str(e), "redirects": redirects}
        if headers.get("Content-Encoding") == "gzip" and body:
            try:
                body = gzip.decompress(body)
            except Exception:
                pass
        if status in (301, 302, 303, 307, 308) and follow:
            loc = urllib.parse.urljoin(cur, headers.get("Location", ""))
            redirects.append((status, cur, loc))
            cur = loc
            continue
        text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
        return {"status": status, "url": cur, "headers": headers, "body": text, "bytes": len(body),
                "error": None, "redirects": redirects}
    return {"status": None, "url": cur, "headers": {}, "body": "", "error": "too many redirects", "redirects": redirects}


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = None; self._in_title = False
        self.metas = []; self.links = []; self.anchors = []; self.imgs = []
        self.headings = []; self._h = None; self._htext = ""
        self.html_lang = None; self.jsonld = []; self._in_ld = False; self._ld = ""
        self.scripts = 0; self.styles = 0

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "html":
            self.html_lang = a.get("lang")
        elif tag == "title" and self.title is None:
            self._in_title = True; self.title = ""
        elif tag == "meta":
            self.metas.append(a)
        elif tag == "link":
            self.links.append(a)
            if "stylesheet" in a.get("rel", "").lower():
                self.styles += 1
        elif tag == "a" and "href" in a:
            self.anchors.append(a["href"])
        elif tag == "img":
            self.imgs.append(a)
        elif tag == "script":
            if a.get("type", "").lower() == "application/ld+json":
                self._in_ld = True; self._ld = ""
            elif a.get("src"):
                self.scripts += 1
        elif re.fullmatch(r"h[1-6]", tag):
            self._h = int(tag[1]); self._htext = ""

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "script" and self._in_ld:
            self._in_ld = False; self.jsonld.append(self._ld)
        elif self._h and tag == f"h{self._h}":
            self.headings.append((self._h, " ".join(self._htext.split())))
            self._h = None

    def handle_data(self, d):
        if self._in_title:
            self.title += d
        if self._in_ld:
            self._ld += d
        if self._h:
            self._htext += d

    def meta(self, key):
        key = key.lower()
        for m in self.metas:
            if m.get("name", "").lower() == key or m.get("property", "").lower() == key:
                return m.get("content")
        return None


def ld_types(obj, out):
    if isinstance(obj, list):
        for o in obj:
            ld_types(o, out)
    elif isinstance(obj, dict):
        t = obj.get("@type")
        if isinstance(t, list):
            out.extend(map(str, t))
        elif t:
            out.append(str(t))
        for k in ("@graph", "mainEntity", "itemListElement", "publisher", "author", "offers"):
            if k in obj:
                ld_types(obj[k], out)
    return out


def parse_sitemap(url, timeout, seen=None, depth=0):
    seen = seen if seen is not None else set()
    urls, problems = [], []
    if url in seen or depth > 3:
        return urls, problems
    seen.add(url)
    r = fetch(url, timeout)
    if r["status"] != 200:
        return urls, [f"sitemap {url} returned {r['status'] or r['error']}"]
    try:
        root = ET.fromstring(r["body"].encode("utf-8"))
    except ET.ParseError as e:
        return urls, [f"sitemap {url} is not valid XML: {e}"]
    ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    if root.tag.endswith("sitemapindex"):
        for loc in root.findall(".//s:sitemap/s:loc", ns):
            u, p = parse_sitemap(loc.text.strip(), timeout, seen, depth + 1)
            urls += u; problems += p
    elif root.tag.endswith("urlset"):
        urls += [l.text.strip() for l in root.findall(".//s:url/s:loc", ns) if l.text]
    else:
        problems.append(f"sitemap {url} root is <{root.tag}>, expected urlset/sitemapindex")
    return urls, problems


class Report:
    def __init__(self):
        self.items = []  # (level, scope, message)

    def add(self, level, scope, msg):
        self.items.append((level, scope, msg))

    def fail(self, s, m): self.add("FAIL", s, m)
    def warn(self, s, m): self.add("WARN", s, m)
    def ok(self, s, m): self.add("PASS", s, m)


def check_page(url, base_host, rep, timeout, all_titles, all_descs, link_targets):
    r = fetch(url, timeout)
    path = urllib.parse.urlparse(url).path or "/"
    if r["status"] != 200:
        rep.fail(path, f"returned HTTP {r['status'] or r['error']}")
        return None
    if r["redirects"]:
        rep.warn(path, f"sitemap URL redirects ({len(r['redirects'])} hop) to {r['url']}")
    if len(r["redirects"]) > 1:
        rep.fail(path, f"redirect chain of {len(r['redirects'])} hops")
    p = PageParser()
    try:
        p.feed(r["body"])
    except Exception as e:
        rep.warn(path, f"HTML parse issue: {e}")
    info = {"url": url, "bytes": r.get("bytes", 0), "scripts": p.scripts, "styles": p.styles}
    # robots meta / header
    robots = (p.meta("robots") or "") + " " + (p.meta("googlebot") or "") + " " + str(r["headers"].get("X-Robots-Tag", ""))
    if "noindex" in robots.lower():
        rep.fail(path, "page is set to noindex (meta robots or X-Robots-Tag)")
    # title
    t = " ".join((p.title or "").split())
    info["title"] = t
    if not t:
        rep.fail(path, "missing <title>")
    else:
        if not 30 <= len(t) <= 65:
            rep.warn(path, f"title length {len(t)} (aim 30-60): {t!r}")
        all_titles.setdefault(t, []).append(path)
    # description
    d = " ".join((p.meta("description") or "").split())
    info["description"] = d
    if not d:
        rep.fail(path, "missing meta description")
    else:
        if not 70 <= len(d) <= 165:
            rep.warn(path, f"meta description length {len(d)} (aim 70-160)")
        all_descs.setdefault(d, []).append(path)
    # canonical
    canon = [l.get("href") for l in p.links if "canonical" in l.get("rel", "").lower().split()]
    info["canonical"] = canon
    if not canon:
        rep.fail(path, "missing rel=canonical")
    elif len(canon) > 1:
        rep.fail(path, f"{len(canon)} canonical tags")
    else:
        ch = urllib.parse.urlparse(urllib.parse.urljoin(url, canon[0])).netloc
        if ch != base_host:
            rep.fail(path, f"canonical points to other host: {canon[0]}")
    # headings
    h1s = [h for h in p.headings if h[0] == 1]
    info["h1"] = [h[1] for h in h1s]
    if len(h1s) != 1:
        rep.fail(path, f"{len(h1s)} H1 tags (need exactly 1)")
    prev = 0
    for lvl, _ in p.headings:
        if prev and lvl > prev + 1:
            rep.warn(path, f"heading level skips from H{prev} to H{lvl}")
            break
        prev = lvl
    # social
    for k in ("og:title", "og:description", "og:image", "og:url", "og:type"):
        if not p.meta(k):
            (rep.fail if k in ("og:title", "og:image") else rep.warn)(path, f"missing {k}")
    if not p.meta("twitter:card"):
        rep.warn(path, "missing twitter:card")
    img = p.meta("og:image")
    info["og_image"] = img
    # JSON-LD
    types = []
    for blob in p.jsonld:
        try:
            ld_types(json.loads(blob), types)
        except Exception as e:
            rep.fail(path, f"invalid JSON-LD: {e}")
    info["jsonld"] = types
    if not p.jsonld:
        rep.warn(path, "no JSON-LD structured data")
    if re.search(r"/(blog|news|posts?|articles?)/(?!category/|tag/|page/)[^/]+", path) and not any(
            t in ("Article", "BlogPosting", "NewsArticle") for t in types):
        rep.warn(path, "blog/news post has no Article/BlogPosting JSON-LD")
    # images
    missing = [i.get("src", "")[:80] for i in p.imgs if "alt" not in i]
    info["imgs"] = len(p.imgs); info["imgs_no_alt"] = len(missing)
    if missing:
        rep.warn(path, f"{len(missing)}/{len(p.imgs)} <img> without alt attribute")
    # basics
    vp = p.meta("viewport")
    if not vp or "width=device-width" not in vp:
        rep.fail(path, "missing/incorrect viewport meta")
    if not p.html_lang:
        rep.fail(path, "missing <html lang>")
    info["lang"] = p.html_lang
    if not any(set(l.get("rel", "").lower().split()) & {"icon"} for l in p.links):
        rep.warn(path, "no <link rel=icon> (favicon)")
    # hreflang
    hl = [(l.get("hreflang"), l.get("href")) for l in p.links if l.get("hreflang")]
    info["hreflang"] = hl
    if hl:
        codes = [c for c, _ in hl]
        if "x-default" not in [c.lower() for c in codes]:
            rep.warn(path, "hreflang set present but no x-default")
        if not any(urllib.parse.urljoin(url, h).rstrip("/") == url.rstrip("/") for _, h in hl):
            rep.warn(path, "hreflang set does not include a self-reference")
        for c, h in hl:
            if not re.fullmatch(r"(x-default|[a-z]{2,3}(-[A-Za-z]{2,4})?)", c, re.I):
                rep.fail(path, f"invalid hreflang code {c!r}")
            link_targets.add(urllib.parse.urljoin(url, h).split("#")[0])
    # GSC
    if p.meta("google-site-verification"):
        info["gsc_meta"] = True
    # internal links
    for href in p.anchors:
        if href.startswith(("mailto:", "tel:", "javascript:", "#", "data:")) or "/cdn-cgi/" in href:
            continue
        absu = urllib.parse.urljoin(url, href).split("#")[0]
        if urllib.parse.urlparse(absu).netloc == base_host:
            link_targets.add(absu)
    return info


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base")
    ap.add_argument("--max-pages", type=int, default=25)
    ap.add_argument("--max-links", type=int, default=150, help="max internal links to verify")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", help="write full results to this JSON file")
    ap.add_argument("--warn-only", action="store_true", help="always exit 0")
    ap.add_argument("--skip-http", action="store_true", help="skip the http:// -> https:// check (port 80 blocked)")
    a = ap.parse_args()

    base = a.base.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base
    rep = Report()
    home = fetch(base + "/", a.timeout)
    if home["status"] != 200:
        print(f"ERROR: homepage {base}/ returned {home['status'] or home['error']}")
        return 2
    final = urllib.parse.urlparse(home["url"])
    host = final.netloc
    if final.scheme != "https":
        rep.fail("site", "homepage does not end on https")
    if len(home["redirects"]) > 1:
        rep.fail("site", f"homepage redirect chain: {home['redirects']}")

    # host variants
    bare = host[4:] if host.startswith("www.") else host
    variants = [f"https://{bare}/", f"https://www.{bare}/"]
    if not a.skip_http:
        variants += [f"http://{bare}/", f"http://www.{bare}/"]
    for v in variants:
        r = fetch(v, a.timeout)
        hops = len(r["redirects"])
        if r["status"] is None:
            (rep.warn if v.startswith("http://") else rep.fail)("site", f"{v} unreachable: {r['error']}")
        elif urllib.parse.urlparse(r["url"]).netloc != host:
            rep.fail("site", f"{v} ends on {r['url']} (not canonical host {host})")
        elif v.rstrip("/") != f"https://{host}" and hops == 0:
            rep.fail("site", f"{v} serves 200 without redirecting to https://{host}/ (duplicate host)")
        elif hops > 1:
            rep.warn("site", f"{v} takes {hops} redirects to reach canonical")

    # robots
    rb = fetch(f"https://{host}/robots.txt", a.timeout)
    sitemaps = []
    if rb["status"] != 200:
        rep.fail("robots.txt", f"returned {rb['status'] or rb['error']}")
    else:
        body = rb["body"]
        sitemaps = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", body)
        cur_ua, blocks = None, []
        for line in body.splitlines():
            line = line.split("#")[0].strip()
            if line.lower().startswith("user-agent:"):
                cur_ua = line.split(":", 1)[1].strip()
            elif line.lower().startswith("disallow:") and cur_ua in ("*", "Googlebot"):
                val = line.split(":", 1)[1].strip()
                if val == "/":
                    rep.fail("robots.txt", f"Disallow: / for {cur_ua} blocks the whole site")
                elif val:
                    blocks.append(val)
        if blocks:
            rep.ok("robots.txt", "disallows: " + ", ".join(blocks))
        if not sitemaps:
            rep.warn("robots.txt", "no Sitemap: line")
    if not sitemaps:
        sitemaps = [f"https://{host}/sitemap.xml"]
    urls, probs = [], []
    for sm in sitemaps:
        u, p = parse_sitemap(sm, a.timeout)
        urls += u; probs += p
    for p in probs:
        rep.fail("sitemap", p)
    urls = list(dict.fromkeys(urls))
    if not urls and not probs:
        rep.fail("sitemap", "sitemap has no URLs")
    for u in urls:
        if urllib.parse.urlparse(u).netloc != host:
            rep.fail("sitemap", f"URL on non-canonical host: {u}")
            break

    # sitemap URL statuses (HEAD-ish, all of them up to 200)
    bad_sm = 0
    for u in urls[:200]:
        r = fetch(u, a.timeout, follow=False)
        if r["status"] != 200:
            bad_sm += 1
            rep.fail("sitemap", f"{u} returned {r['status'] or r['error']}")
    # pages
    # round-robin across top-level sections so every page type gets sampled
    groups = {}
    for u in urls:
        if u.rstrip("/") == f"https://{host}":
            continue
        seg = (urllib.parse.urlparse(u).path.strip("/").split("/") or [""])[0]
        groups.setdefault(seg, []).append(u)
    sample, i = [f"https://{host}/"], 0
    while len(sample) < a.max_pages and any(len(g) > i for g in groups.values()):
        for g in groups.values():
            if len(g) > i and len(sample) < a.max_pages:
                sample.append(g[i])
        i += 1
    titles, descs, targets, pages = {}, {}, set(), []
    for u in sample:
        info = check_page(u, host, rep, a.timeout, titles, descs, targets)
        if info:
            pages.append(info)
    for t, ps in titles.items():
        if len(ps) > 1:
            rep.fail("site", f"duplicate title on {ps}: {t!r}")
    for d, ps in descs.items():
        if len(ps) > 1:
            rep.warn("site", f"duplicate meta description on {len(ps)} pages: {ps[:5]}")
    # broken links
    checked = set(sample)
    broken = []
    for t in sorted(targets - checked)[: a.max_links]:
        r = fetch(t, a.timeout)
        if r["status"] is None or r["status"] >= 400:
            broken.append((t, r["status"] or r["error"]))
    for t, s in broken:
        rep.fail("links", f"broken internal link {t} -> {s}")
    # 404
    r = fetch(f"https://{host}/this-page-should-not-exist-{int(time.time())}/", a.timeout)
    if r["status"] != 404:
        rep.fail("site", f"missing page returns HTTP {r['status']} instead of 404 (soft 404)")
    # GSC
    if any(p.get("gsc_meta") for p in pages):
        rep.ok("site", "google-site-verification meta present")

    fails = [i for i in rep.items if i[0] == "FAIL"]
    warns = [i for i in rep.items if i[0] == "WARN"]
    print(f"SEO check for https://{host}/  pages={len(pages)} sitemap_urls={len(urls)} "
          f"links_checked={min(len(targets - checked), a.max_links)}")
    for lvl in ("FAIL", "WARN", "PASS"):
        for l, s, m in rep.items:
            if l == lvl:
                print(f"  [{l}] {s}: {m}")
    print(f"SUMMARY: {len(fails)} fail, {len(warns)} warn")
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"host": host, "sitemap_urls": urls, "pages": pages,
                       "items": rep.items}, f, indent=2, default=str)
    if fails and not a.warn_only:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
