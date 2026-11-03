# Patchwarden build spec

> Renamed from **PHP Guard** to **Patchwarden** on Nov 4, 2026 (the owner's decision). Only the product name changed; the rest is the build sheet as given.

Copied verbatim from the build sheet the user pasted into chat (the PDF is only a summary infographic). This is the source of truth.

## 1. WHAT YOU ARE BUILDING

A product called Patchwarden: a set of 5 agents that protect PHP websites after the PHP2Shell crisis (CVE-2026-109618 and CVE-2026-109619, CVSS 9.2, unauthenticated remote code execution, fixed in PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, released Oct 21, 2026).

Context that drives the product:
- PHP runs on about 70% of websites whose server-side language is known.
- WordPress alone is about 40% of all websites, and WordPress runs on PHP.
- About 1 in 3 WordPress sites run PHP 8.1 or older. The PHP project ships no official patch for 8.1 and older, only minimal source backports for 7.4 / 8.0 / 8.1, plus whatever a host or Linux distribution backports. In practice, most of those sites must migrate, not patch.
- PHP 8.2 loses all security fixes on Dec 31, 2026. Those sites must move before that date.
- On Oct 26, 2026, CISA added both PHP2Shell CVEs to its Known Exploited Vulnerabilities catalog.

The business model, which shapes the build:
1. Scanner agent is FREE. It finds customers.
2. Patch agent is sold per site, one time.
3. Watchdog agent is sold per site, monthly.
4. Migration agent is sold per project (highest price).
5. WordPress Guard is sold per site, monthly (volume product).
6. Agencies white-label all five for hundreds of client sites at once.

## 2. TECH STACK (do not substitute without asking)

- Language: Python 3.12.
- API + dashboard backend: FastAPI. Serve the API and a simple server-rendered dashboard from the same app (Jinja templates, no separate frontend build step).
- Database: PostgreSQL in production, SQLite for local dev. Use SQLAlchemy models so the switch is a connection string change only.
- Background jobs: APScheduler inside the app. No Redis, no Celery, no extra infrastructure in Phase 1-3.
- HTTP client: httpx.
- Auth: JWT access tokens, bcrypt password hashes.
- Credential storage: Fernet (symmetric encryption) with a key from .env. Never store a raw credential in the database.
- Packaging: Docker + docker-compose for the whole stack. A Makefile with make dev, make test, make up.
- Tests: pytest. Every agent ships with tests before it is called done.

## 3. ARCHITECTURE

```
                  +------------------+
                  |  Dashboard (web) |
                  |  owner approves, |
                  |  reads reports   |
                  +--------+---------+
                           | JWT + API key
 +-------------------------+-------------------------+
 |                         |                         |
+---------------+  +---------------+  +---------------+
| Scanner       |  | Patch         |  | Watchdog      |
| (external,    |  | (backup,      |  | (scheduled    |
|  no access)   |  |  patch, test, |  |  CVE checks)  |
|               |  |  rollback)    |  |               |
+---------------+  +---------------+  +---------------+
 |                         |                         |
 +------------+------------+-----------+-------------+
              |                        |
      +--------------+         +--------------+
      | Migration    |         | WP Guard     |
      | (staging,    |         | (WP plugin   |
      |  breakage    |         |  + API)      |
      |  scan, plan) |         |              |
      +--------------+         +--------------+
                           |
              +------------+------------+
              | PostgreSQL (sites,      |
              | scans, jobs, reports,   |
              | encrypted credentials)  |
              +-------------------------+
```

Client-side pieces (installed on the customer's site, never the reverse):
- WordPress sites: a small PHP plugin that reports the PHP version, plugin/theme inventory, and accepts approved actions via API key.
- Non-WordPress servers: a small Python installer script that registers the server with an API key and reports its PHP version.

The server NEVER logs into a customer site with a password. It talks to the installed plugin/agent with an API key, or to a hosting panel with an API token the owner created. Password sharing is not a supported flow.

## 4. PHASE 1 — SCANNER AGENT (build this first, fully)

Goal: given a domain, produce a 1-page risk report with no access at all.

Inputs:
- A domain/URL, or a bulk list of domains (CSV upload + manual entry).
- Optional: a WordPress site URL for the deeper plugin/theme check.

How it works:
1. Fetch the site homepage and record response headers. Extract the PHP version from X-Powered-By and any other version-revealing header when present. Record honestly when the version is hidden: status unknown, never a guessed version.
2. Compare a detected version against the known fixed versions (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) and the known dead versions (8.1 and older: no official PHP patch; 8.2: security ends Dec 31, 2026).
3. Score risk: safe (patched version), patch_now (supported version, unpatched), must_migrate (8.1 or older, or 8.2 approaching end of life), unknown (version hidden, needs the plugin/agent check).
4. For WordPress URLs, query the public WordPress.org API to list installed plugin/theme slugs when the site exposes them, and flag any with known CVEs from the WPScan-style public feed used in this build.
5. Store every scan: domain, detected version, risk score, raw headers, timestamp. Scans are re-runnable and history is kept.

Outputs:
- GET /api/scans/{id} returns the report as JSON.
- GET /scans/{id} renders the same report as a clean 1-page HTML report a non-technical owner can read (no jargon: "Your version / Your risk / What to do next").
- POST /api/scans accepts one domain or a CSV of domains.
- A shareable report link (signed, expiring URL) the owner can forward.

Access needed: NONE for the external scan. This is the free lead magnet.

Acceptance tests (all must pass before Phase 2):
- Scanning a demo site on PHP 8.4 unpatched returns patch_now.
- Scanning a demo site on a fixed version returns safe.
- Scanning a demo site on PHP 8.1 returns must_migrate.
- Scanning a site that hides its version returns unknown, not a guess.
- Bulk CSV of 10 domains completes and stores 10 scan records.
- The HTML report renders correctly with no login required via its signed link.

## 5. PHASE 2 — PATCH AGENT

Goal: fix a site safely, with the owner approving every change.

Inputs:
- An approved site (from a scan) + target fixed version.
- A backup point created before any change.
- The access method the owner chose: hosting panel API token (cPanel/WHM or Plesk) OR the installed plugin/agent API key.

How it works, in this exact order, no step skippable:
1. Create a full backup (files + database) and verify the backup is restorable (checksum + a restore dry-run record). If backup fails, STOP. Do not patch.
2. Record the before-state: PHP version, homepage status, login page status, one checkout/form page status where applicable.
3. Switch/patch the PHP version via the hosting panel API or the agent.
4. Restart PHP workers (FPM pool restart / hosting panel restart action).
5. Re-run the before-state checks. If any check fails, roll back to the backup automatically and report the failure.
6. Write the before/after report: old version, new version, tests passed, backup location, timestamp.

Safety rules (non-negotiable, enforce in code, not just docs):
- Default mode is DRY-RUN: show exactly what would change, change nothing, until the owner clicks Approve in the dashboard.
- Never auto-patch production without an approval record.
- Never store a hosting password. API tokens only, Fernet-encrypted.
- Every action writes an audit log entry: who approved, what changed, when, and the backup id.
- Rollback is one click from the report page.

Outputs:
- POST /api/patches (creates a patch job in dry-run state).
- POST /api/patches/{id}/approve (owner approval, starts execution).
- POST /api/patches/{id}/rollback (one-click rollback).
- The before/after report page, printable.

Acceptance tests:
- A dry-run patch changes nothing on the demo site.
- An approved patch on a demo PHP 8.4 site moves it to the fixed version and all checks pass.
- A deliberately failing post-check triggers automatic rollback and the report says so.
- No credential appears in logs, reports, or API responses (test asserts this with a canary token).

## 6. PHASE 3 — WATCHDOG AGENT

Goal: recurring monitoring that earns the monthly fee.

Inputs:
- The list of protected sites (from Phases 1-2).
- A CVE feed: the NVD API (key optional, higher rate limit with key) plus the PHP release feed.

How it works:
1. On a schedule (daily version check, hourly CVE feed poll), re-check each site's PHP version and match new CVEs against it.
2. On a new risk: create an alert, email the owner, and show it on the dashboard. Alert text is plain language: what changed, what it means, what to do (link to the patch flow from Phase 2).
3. Monthly: generate the monthly safety report per site (checks run, risks found, actions taken, current version).

Outputs:
- Alert records + email notifications.
- GET /dashboard/alerts and the monthly report page per site.
- A per-site billing hook: a subscription_status field (active / past_due / cancelled) that later phases use for Stripe. Do NOT build payments in this phase, only the field and the status transitions.

Acceptance tests:
- Adding a fake CVE to the feed creates an alert for matching sites only, not for patched sites.
- The monthly report generates for a site with 30 days of checks.
- Turning a site's monitoring off stops its checks (test asserts zero new checks after off).

## 7. PHASE 4 — MIGRATION AGENT

Goal: move sites that cannot patch (8.1 and older, and 8.2 before Dec 31, 2026). Highest price, so it must be the most careful agent.

Inputs:
- A site on a dead/dying PHP version + its codebase + plugin/theme list.
- A staging copy. Never migrate production directly.

How it works:
1. Scan the codebase for breaking changes between the current and target PHP version (removed functions, changed behaviour, deprecated calls). Produce a breakage list with file + line references.
2. Build the migration plan: ordered fix list, estimated effort bucket (small / medium / large), and the target version.
3. Apply fixes on staging, run the Phase 2 check suite on staging.
4. Only with owner/IT sign-off in the dashboard, promote staging to production, then run the Phase 2 before/after report.

Outputs:
- Breakage report + migration plan document per site.
- Staging test report + production promotion record.

Acceptance tests:
- A demo PHP 7.4 WordPress site produces a breakage list that includes at least one real removed-function hit from its own code.
- Promotion without sign-off is refused by the API (test asserts 403).
- A promoted migration produces the same before/after report as Phase 2.

## 8. PHASE 5 — WORDPRESS GUARD (volume product)

Goal: one simple product for WordPress owners that bundles Phases 1-3.

Inputs:
- A WordPress site URL + plugin/theme inventory (from the Phase 1 WordPress check or the installed plugin).

How it works:
1. Package the Scanner + Patch + Watchdog flows behind one product name, one price, one dashboard page per site.
2. Ship the WordPress plugin (PHP, WordPress coding standards): reports PHP version + inventory on a schedule, accepts approved patch actions via API key, and can remove itself cleanly (uninstall hook deletes its data and keys).
3. The owner-facing report uses plain language only, no jargon, and one button: "Fix it" (which starts the Phase 2 approval flow).

Outputs:
- The plugin zip + install instructions (upload in WP admin, paste the API key from the dashboard, done).
- The single-page-per-site dashboard view.

Acceptance tests:
- The plugin installs on a demo WordPress site, reports correctly, and uninstalls leaving no data or keys behind.
- The "Fix it" button routes into the Phase 2 approval flow, not a direct patch.

## 9. DATA MODEL (create these tables)

- users (id, email unique, password_hash, role: owner/admin/agency).
- sites (id, owner_id, domain, platform: wordpress/custom, access_method: external/plugin/cpanel/plesk/ssh, status).
- credentials (id, site_id, kind: cpanel_token/plesk_token/ssh_key/wp_app_password/api_key, encrypted_value, created_at). Encrypted with Fernet. Never logged, never returned by any API.
- scans (id, site_id, detected_version, risk: safe/patch_now/must_migrate/unknown, raw_headers JSON, created_at).
- backups (id, site_id, location, checksum, verified boolean, created_at).
- patch_jobs (id, site_id, from_version, to_version, state: dry_run/awaiting_approval/running/succeeded/failed/rolled_back, backup_id, approved_by, approved_at, report JSON).
- alerts (id, site_id, cve_id, severity, message, sent_at, read).
- migrations (id, site_id, from_version, to_version, breakage JSON, plan JSON, staging_report JSON, signed_off_by, state).
- audit_log (id, user_id, site_id, action, detail JSON, created_at).
- subscriptions (id, site_id, product: watchdog/wp_guard, status: active/past_due/cancelled).

## 10. API ENDPOINTS (minimum set)

- POST /api/auth/register, POST /api/auth/login (JWT).
- POST /api/sites, GET /api/sites, GET /api/sites/{id}.
- POST /api/scans, GET /api/scans/{id}, GET /scans/{id} (HTML report), GET /api/scans/{id}/share (signed expiring link).
- POST /api/patches, POST /api/patches/{id}/approve, POST /api/patches/{id}/rollback, GET /api/patches/{id}.
- GET /api/alerts, POST /api/alerts/{id}/read.
- POST /api/migrations, POST /api/migrations/{id}/signoff, GET /api/migrations/{id}.
- GET /dashboard/* server-rendered pages for sites, scans, patches, alerts, migrations, and the per-site WordPress Guard view.
- Every endpoint returns JSON errors in the shape {"error": "<code>", "message": "<plain language>"}. No stack traces to clients. No credential ever appears in a response, log, or error.

## 11. SECRETS — WHAT THIS BUILD NEEDS

Rules first:
- NO secret is ever written in code, docs, tests, or git history.
- Everything below lives in .env at the project root. .env is in .gitignore from the first commit. Ship a .env.example with empty values and the "where to get it" notes from this section.
- The app must refuse to start in production mode if a REQUIRED secret is missing, and print exactly which one is missing.
- No LLM/AI API key is needed for the core build. These agents are deterministic checkers (version compare, header read, test suite), not chatbots. Do not add an LLM dependency unless asked.

### 11a. Required to run anything

| Secret | Where to get it | Used by |
| --- | --- | --- |
| DATABASE_URL | Your PostgreSQL provider (local dev: SQLite path instead) | All phases |
| JWT_SECRET | Generate: `openssl rand -hex 32` | Auth, all phases |
| CREDENTIAL_KEY | Generate: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` | Fernet encryption of stored credentials, Phases 2-5 |

### 11b. Required per customer site (owner supplies, never you)

| Secret | Where the owner gets it | Used by |
| --- | --- | --- |
| Hosting panel API token (cPanel/WHM or Plesk) | Owner creates it in their hosting panel (API Tokens section) with permission to change PHP version and restart workers only | Patch agent |
| WordPress Application Password | Owner creates it in WP admin under Users > Profile > Application Passwords, for a dedicated user with the lowest role that can install/upgrade | WP Guard, Patch agent on WP sites |
| SSH deploy key (VPS/custom servers only) | Owner generates a keypair and adds the public key to the server, restricted to the site's user | Patch/Migration on non-panel servers |
| Plugin API key | Auto-generated by the dashboard when a site is added; owner pastes it into the plugin | Plugin/agent communication |

What the owner must NEVER be asked for: their hosting account password, their WordPress admin password, or a root password. If a flow needs one of those, stop and redesign it to use a token or key instead.

### 11c. Optional, only when that feature is switched on

| Secret | When needed | Where to get it |
| --- | --- | --- |
| NVD_API_KEY | Higher CVE feed rate limit (works without it, slower) | NVD API key request page (free) |
| SMTP_HOST, SMTP_USER, SMTP_PASSWORD (or RESEND_API_KEY) | Email alerts + monthly reports | Any SMTP provider or Resend |
| S3_BACKUP_ENDPOINT, S3_BACKUP_KEY, S3_BACKUP_SECRET, S3_BACKUP_BUCKET | Off-site backups (default is local disk backups, which need no secret) | Any S3-compatible storage |
| STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY, STRIPE_WEBHOOK_SECRET | Only when selling starts (Phase 6, not in this build) | Stripe dashboard |
| SENTRY_DSN | Error tracking in production (optional) | Sentry project settings |

### 11d. .env.example to ship with the repo

```
# Required
DATABASE_URL=postgresql://user:password@localhost:5432/patchwarden
JWT_SECRET=
CREDENTIAL_KEY=
# Optional: alerts
SMTP_HOST=
SMTP_USER=
SMTP_PASSWORD=
# Optional: CVE feed rate limit
NVD_API_KEY=
# Optional: off-site backups
S3_BACKUP_ENDPOINT=
S3_BACKUP_KEY=
S3_BACKUP_SECRET=
S3_BACKUP_BUCKET=
# Only when selling (Phase 6, not this build)
STRIPE_SECRET_KEY=
STRIPE_PUBLISHABLE_KEY=
STRIPE_WEBHOOK_SECRET=
```

## 12. DEFINITION OF DONE (whole build)

- [ ] All 5 phases implemented in order, each with its acceptance tests passing, before the next phase is marked done.
- [ ] make dev runs the app + database locally with zero secrets beyond the .env.example values.
- [ ] make test passes fully, including the canary-token test that proves no credential leaks into logs, reports, or API responses.
- [ ] docker-compose up runs the full stack.
- [ ] README documents: how to run it, how to add a site, how the approval + rollback flow works, and the secrets table from Section 11.
- [ ] No real secret, password, token, or key anywhere in the repo. Verify with a scan for high-entropy strings before finishing.
- [ ] A demo walkthrough: scan a demo PHP 8.1 site, see must_migrate, run the migration plan, and end with a before/after report.

## 13. WHAT NOT TO BUILD

- No auto-patching without owner approval. Ever.
- No password storage. Tokens and keys only, encrypted.
- No LLM features, no chatbot, no AI summary in this build.
- No payments/Stripe in this build (only the subscription status field).
- No multi-tenancy agency billing in this build (agencies use one account per agency; white-label billing is Phase 6).
- No feature beyond the 5 agents above. If an idea is not in this sheet, do not add it; list it in README under "Future ideas" instead.

## 14. PLAIN-WORDS EXPLAINER (for the reel, and for site owners)

This section is not build instructions. It is the simple explanation of the problem, written so anyone can understand it, including on camera.

**What is the problem, in 2 simple sentences?**
There is a flaw in PHP that lets a hacker take over a website without needing to log in. Since most websites run on PHP and many still use old, unpatched versions, millions of sites are open to attack until they update.

**Is PHP a UI code?**
No. UI code is what you see on screen: HTML, CSS, and JavaScript. That runs in your browser, on your phone or laptop.

PHP is the opposite side: it runs on the website's server, behind the scenes. When you open a site, PHP builds the page, talks to the database, checks your login, and then sends the finished page to your browser. WordPress itself is built on PHP.

That is why this flaw is so dangerous. It is not a broken button on screen. It is a hole in the back room of the website, where the attacker can reach the server itself.

**Is PHP an old design?**
Yes. PHP was created in 1994, more than 30 years ago, to build simple websites.

That is exactly why this flaw is so big. An old design that never went away: it still runs most of the web today through WordPress and thousands of other sites. So a hole in that old engine does not hit one new app, it hits millions of sites built over decades.
