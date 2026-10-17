# agenttoolbox-monitor
Free health and safety checks for https://agenttoolbox.net (GitHub Actions). No site source, no secrets committed.

## Safety check (hourly, `.github/workflows/safety-check.yml`)
Runs at :41 every hour (outbound link scan at 00/06/12/18 UTC) on free GitHub Actions minutes (public repo).
Checks: uptime, SSL expiry > 14 days, security headers (warnings; set `strict_headers` or `fail_on_missing_headers`
in `safety/config.json` to make them failures), Google Safe Browsing (keyless Transparency Report lookup, rate-limited,
warn-only on lookup errors) plus free URLhaus/OpenPhish feeds, outbound directory links (DNS, HTTP errors after retry, cross-domain redirects, parked/for-sale
pages), page-text change detection vs `safety/baseline.json`, checkout links vs allowlist, gitleaks + live JS bundle
secret scan, npm audit (site repo, needs `SITE_REPO_TOKEN`), and pending community submissions.

Any failure fails the job and opens/updates one open issue labeled `safety-alert` (auto-closed when passing).
- Detect an open alert: `gh issue list -R johngee518/agenttoolbox-monitor -l safety-alert --state open --json number,title,updatedAt,url`
- After an approved deploy changes page text or checkout links: `gh workflow run safety-check.yml -R johngee518/agenttoolbox-monitor -f mode=update-baseline`
- Full run with link scan: `-f mode=full`. Test alerting: `-f mode=simulate-failure`.

Optional secrets (repo Settings > Secrets and variables > Actions):
- `SITE_REPO_TOKEN`: fine-grained token, only repo johngee518/agenttoolbox-site, Contents: Read + Issues: Read.

Host-agnostic: no Vercel-specific headers or paths are required, so a move to Cloudflare Pages needs no changes here.
