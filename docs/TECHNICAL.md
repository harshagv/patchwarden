# Patchwarden: technical guide

The full technical reference: every flow, endpoint, safety rule and spec difference. For the product overview and the quick start, see the [README](../README.md).

Five agents that protect PHP websites after **PHP2Shell** (CVE-2026-109618 / CVE-2026-109619, CVSS 9.2,
unauthenticated remote code execution; fixed in PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35).

The build sheet is [SPEC.md](../SPEC.md). It is the source of truth. The phases are built in order, and each one must pass its
acceptance tests before the next one starts.

| Phase | Agent | Status |
| --- | --- | --- |
| 1 | Scanner (free, external check) | **Built: all 6 acceptance tests pass** |
| 2 | Patch (backup, patch, test, rollback, owner approval) | **Built: all 4 acceptance tests pass** (against fake panels; real cPanel/Plesk adapters not connected yet) |
| 3 | Watchdog (scheduled version + CVE checks, alerts) | **Built: all 3 acceptance tests pass** (NVD and php.net mocked in tests; not run against the live APIs) |
| 4 | Migration (breakage scan, staging, sign-off) | **Built: all 3 acceptance tests pass** (staging and promotion against fake hosts; real panels not connected yet) |
| 5 | WordPress Guard (plugin + bundled flow) | **Built: both acceptance tests pass** (the real plugin code runs in tests against a WordPress stand-in, not full WordPress) |

## Run it

Get the code:

```bash
git clone https://github.com/harshagv/patchwarden.git && cd patchwarden
```

You need Python 3.12 (`brew install python@3.12`). The WordPress plugin tests need PHP (`brew install php`):
without it, they are skipped and `make test` says so. `make up` also needs Docker.

```bash
make dev     # http://localhost:8000/docs and /dashboard; SQLite + demo sites and fake panels, no secrets needed
make test    # full test suite, offline
make env     # create .env with generated JWT_SECRET, CREDENTIAL_KEY, POSTGRES_PASSWORD
make up      # docker compose: app (production mode) + PostgreSQL 16
make plugin  # dist/patchwarden.zip: the WordPress plugin, pointed at PUBLIC_BASE_URL
```

In development, any secret left empty is replaced with a throwaway value, so `make dev` works with nothing
beyond the `.env.example` values. In production (`APP_ENV=production`), the app refuses to start and names
the missing secret:

```
$ APP_ENV=production JWT_SECRET= python -m patchwarden --check-config
Patchwarden: Refusing to start in production: missing required secret JWT_SECRET. Set it in .env (see .env.example for where to get it).
```

## Scan a site (Phase 1)

A scan needs no account: the Scanner is the free lead magnet. If you are logged in, the scan is filed under
your sites.

```bash
# one domain
curl -s localhost:8000/api/scans -H 'content-type: application/json' \
  -d '{"domain": "php84-unpatched.demo.patchwarden.test"}'

# a CSV, one domain per row (an optional header row "domain" is skipped)
curl -s localhost:8000/api/scans -F file=@sites.csv
```

Each scan in the response has a `risk`, a plain-language `summary` and `next_step`, and a `share_url`. The
`share_url` is a signed link to the one-page HTML report. It expires after 7 days (`SHARE_LINK_HOURS`) and
needs no login.

| Endpoint | What it does |
| --- | --- |
| `POST /api/auth/register`, `POST /api/auth/login` | Account + JWT (bcrypt-hashed password) |
| `POST /api/sites`, `GET /api/sites`, `GET /api/sites/{id}` | Add a site / list your sites / one site with its scan history |
| `POST /api/scans` | Scan one domain (JSON), a list (JSON `domains`), or a CSV upload (`file`) |
| `GET /api/scans/{id}` | The report as JSON (owner login, or `?token=` from a share link) |
| `GET /api/scans/{id}/share` | A new signed, expiring report link (owner login) |
| `GET /scans/{id}` | The one-page HTML report: Your version / Your risk / What to do next |

Every error uses the shape `{"error": "<code>", "message": "<plain language>"}`. Clients never get a stack trace.

### How the risk is scored

| Risk | When |
| --- | --- |
| `safe` | A supported branch at or above its fixed release (8.5.12 / 8.4.27 / 8.3.36) |
| `patch_now` | A supported branch below its fixed release |
| `must_migrate` | 8.1 or older (no official patch), or 8.2 within 90 days of its Dec 31, 2026 end of security support (patched or not) |
| `unknown` | The version is hidden, only the branch is shown (e.g. `PHP/8.4`), the version is not in our table, or the site could not be reached. We never guess. |

The version is read from `X-Powered-By`, then `Server`, then `X-PHP-Version`. If a distribution build string
is found (for example `8.1.2-1ubuntu2.14`), the report adds a note that the host may have backported the fix.

**WordPress.** When the homepage looks like WordPress, the scanner lists the plugin and theme slugs that the
page exposes, looks each one up on the WordPress.org API, and matches it against a WPScan-style feed
(`WP_VULN_FEED_PATH`). The bundled feed in `src/patchwarden/data/wp_vuln_feed.json` is **demo data with made-up
IDs**. The real WPScan API needs a paid token and is not used. If a plugin's version can't be seen, it is
flagged as "check needed", never as "affected". These findings appear in their own section of the report and
do not change the PHP risk score.

### Demo sites

In development and test, hosts under `*.demo.patchwarden.test` are served in-process. The `.test` domain never
resolves on the public internet. Production refuses to start with `DEMO_SITES` on.

`php84-unpatched`, `php84-fixed`, `php85-fixed`, `php83-unpatched`, `php82-fixed`, `php81`, `php74`, `hidden`,
`branch-only`, `static`, `wordpress`, `bulk-01` … `bulk-10`, `redirect`, `redirect-internal` (redirects to
the cloud metadata address and must be refused), `redirect-loop`.

### SSRF protection

The scanner fetches addresses that users supply, from our server. Every hop (the first request and each redirect) is checked:

- http/https only; no `user:pass@` in the URL; ports 80/443 only (`SCAN_ALLOWED_PORTS`).
- The host must resolve **only** to public addresses. Private, loopback, link-local (including
  169.254.169.254), CGNAT, multicast, reserved, documentation and IPv4-mapped/6to4 forms of those are refused,
  and so are `localhost`, `*.local`, `*.internal` and `*.home.arpa`. A mixed DNS answer (public + private) is refused.
- The connection goes to the IP address we checked (Host header and TLS SNI keep the name), so DNS rebinding between check and connect does not work.
- At most 3 redirects, a 10 s overall time limit, and a 1 MB body cap. Proxy environment variables are ignored.
- A direct internal target is rejected with `400` and nothing is stored. If a public site redirects inward, the scan is stored as `unknown` with the reason.

## Credentials and logs

- No credential appears in any response, log or error. `tests/unit/test_canary_and_errors.py` sends random canary
  passwords through registration, login, validation errors, bad JSON and an unexpected crash. It then checks
  every response body and header, every log record and the audit log for the canaries, `JWT_SECRET` and
  `CREDENTIAL_KEY`.
- Unexpected crashes are logged by exception type and route only. The exception text could hold input.
- Log handlers also redact `?token=` query values, bearer tokens and the configured secrets. This is defence in depth.
- Stored response headers keep cookie names only, never the values.
- A share-link token can't be used as a login token, and a login token can't be used as a share link.
- Hosting tokens are Fernet-encrypted at rest and decrypted only inside the adapter call. They never appear
  in an API response, the dashboard, a patch report, an audit entry, a backup or a log line.
  `tests/spec/test_phase2_acceptance.py::test_no_credential_in_logs_reports_or_responses` proves this with a canary
  token through the whole flow: dry run, approve, success, rollback, a rejected token, and invalid input.
- `NVD_API_KEY` and `SMTP_PASSWORD` are redacted from logs. They never appear in alerts, emails, pages or
  responses, and `tests/unit/test_watchdog.py::test_watchdog_secrets_never_leak` checks this with canaries. SMTP
  failures are logged by exception type only, because the server's reply can quote the login.
- The dashboard uses an HttpOnly, SameSite=Strict session cookie. Every form carries a CSRF token, and
  forms posted from another origin are refused.

## Secrets

Rules: no secret is ever written in code, docs, tests or git history. Secrets go in `.env` (git-ignored). The
`.env.example` file ships with empty values. No LLM/AI key is used: these agents are deterministic checkers.

**Required to run anything**

| Secret | Where to get it | Used by |
| --- | --- | --- |
| `DATABASE_URL` | Your PostgreSQL provider (local dev: leave empty for SQLite) | All phases |
| `JWT_SECRET` | Generate: `openssl rand -hex 32` | Auth, all phases |
| `CREDENTIAL_KEY` | Generate: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` | Fernet encryption of stored credentials, Phases 2-5 |

**Per customer site (the owner supplies these, never you)**

| Secret | Where the owner gets it | Used by |
| --- | --- | --- |
| Hosting panel API token (cPanel/WHM or Plesk) | Hosting panel, API Tokens section; permission to change PHP version and restart workers only | Patch agent |
| WordPress Application Password | WP admin > Users > Profile > Application Passwords, for a dedicated lowest-role user that can install/upgrade | WP Guard, Patch agent on WP sites |
| SSH deploy key (VPS/custom servers only) | Owner generates a keypair and adds the public key, restricted to the site's user | Patch/Migration on non-panel servers |
| Plugin API key | Auto-generated by the dashboard when a site is added | Plugin/agent communication |

Never ask an owner for their hosting account password, WordPress admin password or root password.

**Optional, only when that feature is switched on**

| Secret | When needed | Where to get it |
| --- | --- | --- |
| `NVD_API_KEY` | Higher CVE feed rate limit | NVD API key request page (free) |
| `SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD` (or `RESEND_API_KEY`) | Email alerts + monthly reports | Any SMTP provider or Resend |
| `S3_BACKUP_ENDPOINT`, `S3_BACKUP_KEY`, `S3_BACKUP_SECRET`, `S3_BACKUP_BUCKET` | Off-site backups (default: local disk) | Any S3-compatible storage |
| `STRIPE_SECRET_KEY`, `STRIPE_PUBLISHABLE_KEY`, `STRIPE_WEBHOOK_SECRET` | Phase 6 only, not this build | Stripe dashboard |
| `SENTRY_DSN` | Production error tracking | Sentry project settings |

Settings that are not secrets: `APP_ENV`, `PUBLIC_BASE_URL`, `DEMO_SITES`, `POSTGRES_PASSWORD` (compose only), `SCAN_*`, `SHARE_LINK_HOURS`, `ACCESS_TOKEN_MINUTES`, `WPORG_API_ENABLED`, `WP_VULN_FEED_PATH`, `BACKUP_DIR`,
`WATCHDOG_SCHEDULER`, `CVE_FEED`, `CVE_FIXTURE_PATH`, `CVE_LOOKBACK_DAYS`, `SMTP_PORT`, `ALERT_FROM_EMAIL`.

## Add a site, then patch it (Phase 2)

1. **Create an account** (`POST /api/auth/register`), then log in to the dashboard at `/dashboard/login`.
2. **Add the site** on the dashboard, or with `POST /api/sites`
   (`{"domain", "platform", "login_path", "form_path"}`). The login and form paths are the pages that get
   checked before and after a change. WordPress sites check `/wp-login.php` by default.
3. **Give access with a token, never a password.** Paste a cPanel or Plesk API token, or the agent API key
   (`POST /api/sites/{id}/credentials`, `{"kind": "cpanel_token" | "plesk_token" | "api_key", "value"}`).
   The token is Fernet-encrypted with `CREDENTIAL_KEY` and never shown again. `DELETE
   /api/sites/{id}/credentials/{cid}` revokes it at any time. SSH keys and WordPress application passwords
   arrive with Phases 4 and 5.

### The approval and rollback flow

```
Plan (dry run) ──owner clicks Approve──▶ backup + verify ──▶ before-checks ──▶ switch PHP ──▶ restart ──▶ after-checks
      │ nothing changes                    │ fails: STOP        │ fail: STOP                                   │ fail:
      ▼                                     ▼ nothing changed    ▼ nothing changed                              ▼
 state: dry_run                         state: failed        state: failed               restore backup + old PHP → rolled_back
                                                                                         all pass → succeeded ──(one click)──▶ rolled_back
```

- **Dry run by default.** `POST /api/patches {"site_id"}` (or "Plan a PHP update" on the dashboard) only
  reads the current version and the versions the host offers. It writes the plan and changes nothing. The
  target is the newest release on the same PHP line that has the fix. Moving to another line (for example
  8.1 → 8.3) is a migration, which is the Migration agent's job (Phase 4).
- **No change without an approval record.** `POST /api/patches/{id}/approve` (or "Approve and run") is
  allowed only for the site owner. It records `approved_by` and `approved_at`, and moves the job to `running`
  in one atomic step, so a double click can't start it twice. The run happens in the background, and the
  report page refreshes itself.
- **The order is fixed.** Backup (files + database; the checksum is verified and a restore dry-run is
  recorded) → before-state (version, homepage, login page, form page) → switch PHP → restart workers →
  after-state. A failed backup, or a site that is already broken before the change, stops the run with
  nothing changed. A failed after-check, or any error after the switch, restores the backup and puts the
  old version back automatically. The report says so.
- **Rollback is one click** from the report page (`POST /api/patches/{id}/rollback`), for a job that succeeded.
- **Everything is audited.** Each action is written to `audit_log` with who, what, when and the backup id:
  `patch.dry_run`, `patch.approved`, `backup.created`, `php.version_changed`, `php.restarted`,
  `backup.restored`, `patch.succeeded` / `failed` / `rolled_back`.
- **The report** at `/dashboard/patches/{id}` shows the old and new versions, every check before and after,
  the backup location and checksum, who approved and when, and the step log. Use the browser's Print to save a copy.

| Endpoint | What it does |
| --- | --- |
| `POST /api/patches` | Create a patch job in dry-run state |
| `GET /api/patches/{id}` | The job and its before/after report |
| `POST /api/patches/{id}/approve` | Owner approval; starts the run (202) |
| `POST /api/patches/{id}/rollback` | One-click rollback of a succeeded job (202) |
| `PATCH /api/sites/{id}` | Set the login/form pages to check |
| `POST /api/sites/{id}/credentials`, `DELETE /api/sites/{id}/credentials/{cid}` | Add / revoke access |
| `/dashboard/login`, `/dashboard/sites`, `/dashboard/patches/{id}` | Dashboard: add sites and tokens, scan, plan, approve, roll back |

### Hosting adapters

Every access method implements one interface (`src/patchwarden/patch/adapters.py`, `HostingAdapter`):
`php_version`, `available_versions`, `create_backup`, `verify_restore`, `set_php_version`, `restart_php` and
`restore_backup`.

- **Real adapters** (`CpanelAdapter`, `PleskAdapter`, `AgentAdapter`) are stubs in this build. They refuse with
  `adapter_not_connected` and change nothing, rather than pretend. They still need to be built and tested
  against a real panel or staging account.
- **The fake adapter** (`src/patchwarden/fakes.py`) runs the same interface against in-process fake hosts. Tests and
  `make dev` use it for these demo sites only:

| Demo host | Starts on | What happens when you patch it |
| --- | --- | --- |
| `shop84.demo.patchwarden.test` | 8.4.13 | Patches to 8.4.27; all checks pass |
| `fragile84.demo.patchwarden.test` | 8.4.13 | `/checkout` breaks on 8.4.27, so the patch rolls back automatically |
| `shop83.demo.patchwarden.test` | 8.3.20 | Patches to 8.3.36 |

Any token value works on the demo hosts. Add each one with `login_path` `/login` and `form_path` `/checkout`.

Backups go to local disk (`BACKUP_DIR`, default `data/backups`). S3 is optional and not built yet.

## Keep watching (Phase 3: Watchdog)

Turn monitoring on for a site (dashboard button, or `POST /api/sites/{id}/monitoring {"enabled": true}`). This
creates an active `watchdog` subscription. From then on the Watchdog, which runs inside the app on
APScheduler (no Redis, no Celery):

- **Daily: re-checks the site's PHP version.** Each check is an external scan. If the version is hidden and
  the owner gave access, a read-only inside check asks the host. If the risk got worse (for example, someone
  downgraded PHP to an unpatched release), it raises an alert.
- **Hourly: polls the CVE feeds** and matches every advisory against each site's current version:
  - the NVD CVE API 2.0, filtered to the PHP product (`cpe:2.3:a:php:php`), with the affected version ranges.
    `NVD_API_KEY` is optional: it raises the rate limit and is sent in a header, never in the URL.
  - php.net's release feed, for each supported line. A new release tagged *security* alerts sites on older
    releases of that line.
- **Raises one alert per site per advisory, ever.** Each alert is in plain language: *What changed / What it
  means / What to do*, with a link to the site on the dashboard where the Phase 2 patch flow starts. It shows
  under `/dashboard/alerts` and `GET /api/alerts`, and is emailed to the owner when SMTP is set up. The
  `sent_at` field stays empty, and the page says "Not emailed", when no email went out.
- **Monthly: a safety report per site.** It covers the checks run, the risks found, the actions taken (patch
  jobs) and the current version. See `/dashboard/sites/{id}/monthly?month=2026-10` and `GET
  /api/sites/{id}/monthly-report?month=2026-10`. It is emailed on the 1st.
- **Off means off.** Turning monitoring off cancels the subscription, and the site gets no more checks of any kind.

The scheduler runs an hourly tick (version checks for sites that are due, then a feed poll) and a monthly
job on the 1st at 06:00 UTC. "Run Watchdog checks now" on the dashboard (`POST /api/watchdog/run`) runs a
check of your own sites straight away. Run one app process: each process starts its own scheduler. Alerts
are deduplicated, so a second process only wastes requests.

**In development**, `CVE_FEED=fixture` (the default when demo sites are on) reads
`src/patchwarden/data/cve_feed.demo.json` instead of NVD. To try an alert, add an entry in NVD format and press
"Run Watchdog checks now". The shipped entry, `PHPG-DEMO-2026-0101`, is made up and affects PHP 8.3 before
8.3.40, so `php83-unpatched.demo.patchwarden.test` and `shop83.demo.patchwarden.test` get an alert.

**Billing hook, no payments.** `subscriptions.status` is `active`, `past_due` or `cancelled`. Monitoring keeps
running while a subscription is `past_due`, as a grace period. Allowed changes: active → past_due /
cancelled; past_due → active / cancelled; cancelled → active. Any other change is refused with `409
invalid_transition`. `POST /api/subscriptions/{id}/status` (admin only) is where a Phase 6 Stripe webhook
would connect. Each change is audited.

| Endpoint | What it does |
| --- | --- |
| `POST /api/sites/{id}/monitoring` | Turn the Watchdog on/off for a site |
| `GET /api/alerts` (`?unread=true`), `POST /api/alerts/{id}/read` | Your alerts |
| `GET /api/sites/{id}/monthly-report?month=YYYY-MM` | Monthly safety report (JSON) |
| `POST /api/watchdog/run` | Check your sites now |
| `POST /api/subscriptions/{id}/status` | Billing status change (admin) |
| `/dashboard/alerts`, `/dashboard/sites/{id}/monthly` | Dashboard pages |

## Move sites that cannot patch (Phase 4: Migration)

This is for PHP 8.2 and older. 8.1 and older have no official patch, and 8.2 loses security fixes on Dec 31,
2026. Sites on 8.3 and newer are sent to the Patch agent instead. Production is never migrated directly.

1. **Plan** (`POST /api/migrations {"site_id"}`, or "Plan a migration" on the dashboard). This step is
   read-only. It reads the site's code through the host access and scans it for breaking changes between the
   current version and the target. The default target is the newest fixed 8.4 release the host offers (8.4 is
   supported to the end of 2028), then 8.3, then 8.5. The result has two parts:
   - **A breakage report** with file and line references and the code line. String literals are blanked out,
     so a password in a `define()` never reaches a report. WordPress core is skipped (update WordPress itself),
     and so are functions the site already polyfills.
   - **A migration plan**: an ordered fix list (breaking changes first, then deprecations), each fix marked as
     automatic or for a developer; an effort bucket (small / medium / large); and the target version.

   No access token? Upload a zip of the code instead (multipart `file` + `site_id` + `from_version`). The zip
   is read in memory with size limits and is never extracted or run. You get the breakage report and the
   plan; staging needs host access.
2. **Staging** (`POST /api/migrations/{id}/staging`). This copies the site (files, database, PHP version) to a
   staging site. The first run checks that the copy works, then applies the automatic fixes on staging,
   switches staging to the target PHP and restarts it. It runs the Phase 2 checks on staging and re-scans the
   staging code. Staging passes only if every check passes **and** no breaking code is left. A developer
   makes the manual fixes on the staging site, then you run the staging tests again. The staging copy is
   re-used, so their changes are kept. A new staging run clears any earlier sign-off.
3. **Sign-off** (`POST /api/migrations/{id}/signoff`, or the dashboard with a "I checked the staging site"
   box). The site owner signs off after staging has passed. This records `signed_off_by` and `signed_off_at`.
4. **Promote** (`POST /api/migrations/{id}/promote`). Without a sign-off this is refused with **403
   `signoff_required`**. With one, a Phase 2 patch job runs, with the sign-off as its approval record:
   backup → before-checks → **deploy the tested staging code** → switch PHP → restart → after-checks →
   automatic rollback (backup + old version) if anything fails. Only code files are copied. Production keeps
   its own database and config files (`wp-config.php`, `.env`, and so on). If the staging code changed after
   it was tested, promotion stops with nothing changed, and you test and sign off again. The production
   promotion record links to the same before/after report as a patch (`/dashboard/patches/{id}`).

The breakage rules (`src/patchwarden/migration/rules.py`) cover the PHP 7.0 → 8.4 migration guides. Breaking
changes include the `mysql_*` and `ereg*` functions, `create_function`, `each`, `get_magic_quotes_*`,
`money_format`, `__autoload`, `$s{0}` offsets, `(real)` / `(unset)` casts, `$php_errormsg`, `match` as a
name, and IMAP being unbundled in 8.4. Deprecations to review include `strftime`, `mhash`,
`FILTER_SANITIZE_STRING`, `utf8_encode`, `"${var}"`, `get_class()` with no arguments, implicitly nullable
parameters, `E_STRICT` and `E_USER_ERROR`. Automatic fixes are limited to exact rewrites:
`get_magic_quotes_gpc()` → `false`, `$s{0}` → `$s[0]`, `(real)` → `(float)`, `(unset) $x` → `null`,
`Type $x = null` → `?Type $x = null`, and `"${v}"` → `"{$v}"`. Config files are never auto-edited. This is a
static scan: it can't see behaviour that only shows up at runtime (dynamic properties, number-vs-string
comparisons). That is what the staging checks and your own review of staging are for.

| Demo host | Starts on | What happens |
| --- | --- | --- |
| `wp74.demo.patchwarden.test` | WordPress on 7.4.33 | 4 breaking hits (each, create_function, get_magic_quotes_gpc, `$title{0}`); staging fails until the two manual fixes are made on `staging.wp74…` |
| `legacy81.demo.patchwarden.test` | custom PHP 8.1.31 | Only automatic fixes and deprecations: staging passes first time, then sign off and promote |

The demo fake hosts "run" their code: a function removed in the running PHP version makes every page return
500. That is why `wp74` really breaks on staging until it is fixed.

| Endpoint | What it does |
| --- | --- |
| `POST /api/migrations` | Breakage report + migration plan (JSON with `site_id`, or a zip upload) |
| `GET /api/migrations/{id}` | The migration, its reports and its promotion record |
| `POST /api/migrations/{id}/staging` | Copy to staging (or re-use it), auto-fix, switch, test (202) |
| `POST /api/migrations/{id}/signoff` | Owner/IT sign-off after staging passed |
| `POST /api/migrations/{id}/promote` | Promote to production (403 without sign-off; 202) |
| `/dashboard/migrations/{id}` | Printable plan, breakage table, staging report and buttons |

## WordPress Guard (Phase 5)

This is one product for WordPress owners: the Scanner, Patch and Watchdog behind one name, one price (the
`wp_guard` subscription; no payments in this build) and one page per site (`/dashboard/wp-guard/{site}`).

**Install, for the owner** (the same steps are on the site's dashboard page and in the plugin's `readme.txt`):
1. Download the plugin from the site's WordPress Guard page (`patchwarden.zip`).
2. In WordPress: Plugins > Add New > Upload Plugin, then Install and Activate.
3. Press "Get your plugin key" and copy it. It is shown once; Patchwarden keeps only a SHA-256 hash.
4. In WordPress: Settings > Patchwarden, paste the key, then "Save and connect". Done.

**The plugin** (`wordpress-plugin/patchwarden/`, written to WordPress coding standards):
- **Reports** the PHP version, the WordPress version, plugins and themes (with versions, whether each is
  active, and any update WordPress knows about). It reports when the key is saved and then twice a day by
  WP-Cron. It sends no users, content or settings.
- **Runs only actions the owner approved**, which it pulls hourly. Patchwarden never connects into the site.
  It knows exactly two action kinds: update an installed plugin or theme from WordPress.org with
  WordPress's own updater, and send a report now. Anything else is answered "not supported". It cannot
  change PHP; that needs the hosting panel token (Phase 2).
- **Is safe by construction.** Settings need `manage_options` and a nonce, and input is sanitized and
  output escaped. The saved key is never printed back. It uses HTTPS only (plain http is allowed only to
  localhost, for development), follows no redirects, and keeps the key in a non-autoloaded option.
- **Removes itself cleanly.** `uninstall.php` deletes its options and scheduled events, and calls
  `/api/plugin/disconnect`, so the key is also switched off on the server. Deactivating only stops the schedule.

**On the server:**
- **The safety score** starts at 100. It loses 40 for unpatched PHP, 50 for PHP that must migrate and 15 for
  an unknown version. Each plugin or theme with a known flaw costs 25 / 15 / 8 / 4 points (critical / high /
  medium / low), a "maybe affected" one costs 3, and an unwatched site costs 10. The fix list is plain
  language, with no CVE IDs or jargon.
- **The one "Fix it" button** never changes anything. For unpatched PHP (hosting token needed), it creates a
  Phase 2 patch job in `awaiting_approval`, with any plugin/theme updates added to the same plan. For a
  plugin or theme only, it creates a job that waits for approval and is carried out by the plugin. For
  8.2-and-older PHP, it creates a Phase 4 migration plan. The owner is then taken to the approval page, and
  the usual Phase 2 approval (who, when, audit log, backup, checks, rollback) is the only way forward.
  Plugin updates are queued for the plugin only after that approval, and only after the PHP step succeeded.
- **Plugin reports count as the Watchdog's daily inside check.** The version is exact even when the site
  hides it, so new CVEs are matched against it.

| Endpoint | Who | What it does |
| --- | --- | --- |
| `POST /api/sites/{id}/plugin-key` | owner | New plugin key, shown once; the old one stops working |
| `POST /api/sites/{id}/wp-guard`, `GET /api/sites/{id}/wp-guard` | owner | Turn WordPress Guard on/off; score + fix list |
| `POST /api/sites/{id}/fix` | owner | "Fix it": a plan waiting for approval |
| `GET /api/wp-guard/plugin.zip`, `/dashboard/wp-guard-plugin.zip` | owner | The plugin, set up for this server |
| `POST /api/plugin/report`, `GET /api/plugin/actions`, `POST /api/plugin/actions/{id}/result`, `POST /api/plugin/disconnect` | plugin (`X-Patchwarden-Key`) | Report, pull approved actions, report results, switch the key off |

**How the plugin is tested.** `tests/support/wp_harness/harness.php` is a stand-in for the WordPress functions the
plugin uses: options, WP-Cron, hooks, transients, nonces, capabilities, upgraders, and HTTP through curl. It
keeps its "database" in a JSON file. The tests run the real plugin code with PHP against a live Patchwarden
server on localhost. They install, activate, save the key, report, run approved actions, show the settings
page and uninstall, and then check what is left behind. WordPress core itself is not loaded. Running the
plugin in a real WordPress (for example WordPress Playground) is listed under Future ideas.

## Demo walkthrough (definition of done)

With `make dev`, register (`POST /api/auth/register`) and log in at `/dashboard`:
1. **Scan a PHP 8.1 site.** Add `legacy81.demo.patchwarden.test` with any token and press "Scan now". It shows
   **Must migrate**.
2. **Run the migration plan.** Press "Plan a migration", read the breakage report, then press "Run staging
   tests" (it passes), tick the box and "Sign off", then "Promote to production".
3. **Before/after report.** "Before / after report for production" shows PHP 8.1.31 → 8.4.27, every check
   before and after, the backup, and who signed off.

`tests/unit/test_migration_flow.py::test_custom_php81_site_passes_staging_first_time` and the Phase 4 acceptance tests cover the same path.

## Trust hardening (Phase A)

These changes close the gaps where the trust promise was ahead of the code.

### Durable jobs and crash recovery

Patch, rollback, staging and promotion runs are rows in the `jobs` table (`src/patchwarden/jobs.py`). An
approval records the job and starts it straight away.

- **Claiming and leases.** A worker claims a job with an atomic update that takes a lease
  (`JOBS_LEASE_SECONDS`, default 60), and keeps the lease alive with heartbeats while the job runs.
- **A dead worker's job is picked up.** If the process dies, the lease runs out. The in-app poller
  (`JOBS_POLL_SECONDS`), or the next start-up, then claims the job again and runs it with `resume=True`.
- **Orphans at start-up.** Any patch or migration left `running` without a live job gets a recovery job.
- **The resume rule.** Before the first change to production, the runner records `"changing": true` in
  the job's report. On resume:
  - **Nothing had changed yet:** the run starts again from the beginning.
  - **Production had started to change:** the outcome of the interrupted step is unknown, so the safe
    move is taken. The verified backup and the old PHP version are restored, the site is re-checked,
    and the report says *"rolled back automatically, after an interruption"*. A resumed rollback simply
    runs the rollback again.
  - **A promotion** that was interrupted mid-change restores production the same way.
- **Retries and giving up.** An unexpected error retries with backoff. After 5 attempts the job fails,
  and the patch or migration is marked *"may need attention"*, so it never stays "running" forever.
- **Plugin actions.** A resumed WordPress Guard job never queues plugin actions twice.

### Encrypted backups and retention

Hosts hand Patchwarden the backup archive plus the checksum they computed. `src/patchwarden/patch/backups.py`
then handles the rest:

- **Checksum check.** The host's checksum is compared with the archive. A mismatch stops the patch with
  nothing changed.
- **Encryption.** The archive is encrypted with a fresh AES-256-GCM key, and that key is wrapped by the
  backup key ring: `BACKUP_KEY`, or keys derived from `CREDENTIAL_KEY` with HKDF. The file header is
  authenticated along with the content.
- **Storage.** The file is written as `.pwbak` with `600` permissions.
- **Before relying on a backup.** Patchwarden decrypts it, checks the SHA-256 again, and runs the host's
  restore dry-run on the decrypted copy.
- **Damage is caught.** Any change to the file fails decryption. A rollback from a damaged backup stops,
  says so, and leaves the site alone.
- **Retention.** Backups expire after `BACKUP_RETENTION_DAYS` (default 30). A daily job (and
  `python -m patchwarden purge-backups`) deletes them and records `backup.purged`. A backup that an
  in-progress change still needs is never deleted. After expiry, owner rollback is refused with
  `backup_expired`.

### Rotating keys

`CREDENTIAL_KEY` and `BACKUP_KEY` accept comma-separated keys: the first encrypts, and all of them decrypt.

1. Put a new key first: `CREDENTIAL_KEY=new,old`. Restart the app.
2. Run `python -m patchwarden rotate-credentials`. It re-encrypts stored hosting tokens and two-step
   secrets with the new key.
3. Remove the old key. Restart the app.

### Tamper-evident audit log

Each `audit_log` entry stores `prev_hash` and
`entry_hash = SHA-256(prev_hash + canonical JSON of the entry)`. The hash is computed in a
SQLAlchemy `before_flush` hook, so no code path can skip it. On PostgreSQL, an advisory lock stops two
processes from forking the chain.

- `python -m patchwarden verify-audit` (exits 1 if broken), or `GET /api/admin/audit/verify` (admin
  only), reports the first changed, deleted or reordered entry.
- `python -m patchwarden export-audit --out audit.jsonl` writes the log as JSON lines, for copying to
  write-once storage.

### Login, sessions and limits

- **Two-step login (TOTP, RFC 6238).** Turn it on with `POST /api/auth/mfa/setup`, then confirm with
  `POST /api/auth/mfa/enable {"code"}`. That returns 10 single-use recovery codes, shown once.
  - From then on, login needs a `code`. The API answers `401 mfa_required` without one, and the
    dashboard asks for it.
  - A code can't be replayed. Recovery codes work once.
  - The secret is stored encrypted, and the recovery codes as hashes.
  - `POST /api/auth/mfa/disable {"code"}` turns it off.
- **Log out everywhere.** `POST /api/auth/logout-all` invalidates every token issued so far, including
  dashboard sessions.
- **Revocable report links.** `POST /api/scans/{id}/share/revoke` makes every link issued so far stop
  working. New links still work.
- **Rate limits.**
  - Free scans: `SCAN_RATE_LIMIT` domains per `SCAN_RATE_WINDOW` per connection (default 30 a minute),
    or `SCAN_RATE_LIMIT_USER` per account (300). A bulk list counts every domain.
  - Failed logins: `LOGIN_FAILURE_LIMIT` per `LOGIN_FAILURE_WINDOW` (10 per 15 minutes), counted per
    connection *and* per email.
  - Answers are `429 rate_limited` with `Retry-After`.
  - `X-Forwarded-For` is honoured only from addresses listed in `TRUSTED_PROXIES`.

### Known limits of Phase A

- Rate limits are counted in each app process's memory. Several processes behind a load balancer each
  keep their own counts; a shared store is listed under Future ideas.
- Keys come from environment variables. A cloud KMS key and backups in object storage with Object Lock
  (write-once) are not built yet. The backup store is the single place to add them.
- Backups are kept by Patchwarden, encrypted. Keeping them on the customer's own hosting (storing only a
  reference) needs the real panel adapters.

## Scanner funnel (Phase B)

### List scans run in the background

`POST /api/scans` with a list (JSON `domains` or a CSV upload) needs an account. It answers **202** with
`status_url` (`GET /api/scan-batches/{id}`: progress, results and rejected rows), and you can close the page.

- **Size limit:** up to `SCAN_BULK_MAX` domains (default 1,000) per list.
- **Durable:** the list is a `bulk_scan` job on the same queue as patches.
- **Resumes without duplicates:** domains are scanned in chunks of 25, and each chunk's scans commit
  together with the progress counter. A crash resumes where it stopped, with nothing scanned twice.
- **Single domains** are still free and immediate (`201`), with or without an account.

### Ownership verification

`POST /api/sites/{id}/verification` returns a per-site, per-owner token and three ways to prove control:

| Method | What to publish |
| --- | --- |
| DNS | TXT record `_patchwarden-challenge.<domain>` = `patchwarden-verification=<token>` |
| File | `https://<domain>/.well-known/patchwarden-verification.txt` containing the token (fetched with the SSRF-safe fetcher) |
| Plugin | The WordPress plugin's first report from the site's own address verifies it automatically |

`POST /api/sites/{id}/verification/check` looks for the token and says in plain words what it found.

- Tokens are compared in constant time.
- Another owner's token never verifies your copy of the same domain.
- **Demo sites in `make dev`:** the verify page has a *"publish the DNS record for me"* button that
  writes the record into the fake DNS. It is shown only for `*.demo.patchwarden.test`.

### Who sees what

Every scan response carries `"detail": "basic"` or `"full"`.

- **Everyone** sees the version, the risk, the summary, what to do, and the CVEs. The site shows those
  to the world anyway.
- **Full detail** (response headers, and which plugin or theme has which flaw) is shown to the
  verified owner, to admins, and to anyone opening a share link that a verified owner sent.
- **Basic** responses carry an `unlock` hint, and the WordPress section shows only counts
  (*"3 plugins and themes, 2 known problems"*).

### Claiming a site

The report page shows **Claim this site**. When the version is hidden, it shows **See your real
version** instead.

1. **Sign up.** A visitor who isn't logged in goes to `/dashboard/signup`, which brings them back
   afterwards. `next=` accepts only `/dashboard/...` paths, so it can never become an open redirect.
2. **Claim.** `POST /api/scans/{id}/claim` (it needs the share token for someone else's scan) adds the
   domain to the user's sites, copies the report into its history, and starts verification. Claiming
   twice returns the same site.
3. **Rate limit.** Sign-ups are limited to `SIGNUP_LIMIT` per hour per connection.

### Guided hosting connection

- **Setup page.** `/dashboard/sites/{id}/connect` walks through creating a cPanel API token (Security →
  Manage API Tokens, with an expiry date) or a Plesk API key, and points WordPress-only owners to the plugin.
- **Connection test.** *Test the connection* (`POST /api/sites/{id}/test-connection`) is read-only: it
  asks the host for the PHP version and the versions on offer, and changes nothing.

### Funnel metrics

`GET /api/admin/funnel?days=30` (admin only) counts each stage over the period, with the conversion
ratio between each pair:

free scans → accounts → claimed sites → verified sites → patch plans → approved → succeeded → active subscriptions

## Watchdog at scale (Phase C)

The Watchdog is the recurring product, so it has to stay cheap and quiet as the number of sites grows,
and loud only when it matters.

### Cost per site

- **Parallel version checks.** The daily checks are fetched concurrently, at most `WATCHDOG_CONCURRENCY`
  (default 20) at a time, then written in site order. Credentials are loaded before the parallel part, so
  it does no database work.
- **Counters, not rows.** Each check adds one to a per-site, per-day counter (`watch_counters`). A
  `watch_checks` row is kept for each version check and only for CVE polls that found something. The
  monthly report adds up the counters.
- **Match what changed.** A feed poll matches only advisories that are new or whose affected versions
  NVD revised. Each distinct PHP version is evaluated once per advisory, not once per site. When a site's
  version changes, every stored advisory is matched against the new version.
  `Watchdog.match_all()` still re-matches everything, for maintenance.

### Alert priority

Each advisory is enriched with two exploitation signals:

| Signal | Source | Stored as |
|---|---|---|
| Known exploited | CISA KEV catalog | `advisories.kev`, `kev_added` |
| Likely to be exploited | FIRST EPSS (probability in the next 30 days) | `advisories.epss` |

An alert is **urgent** (email and channels at once) when the flaw is in KEV, its EPSS is at least
`EPSS_URGENT` (default 0.1), or its severity is critical or high. Otherwise it is a **digest** alert:
the daily digest job (08:00 UTC) sends one message per owner listing them.

**Escalation.** When a flaw already alerted on is added to KEV later, the owner gets a "now being
exploited" message at once. The alert becomes urgent, and `alert.escalated` is written to the audit log.
This happens once per alert.

In fixture mode, KEV and EPSS are read from the `kev` and `epss` keys of the fixture file.

### Alert channels

Besides email, an owner can add Slack, Microsoft Teams or generic webhooks.

| Endpoint | What it does |
|---|---|
| `GET /api/channels` | List (kind, host, enabled; never the URL) |
| `POST /api/channels` `{"kind","url"}` | Add one (201). A webhook returns `signing_secret` once |
| `POST /api/channels/{id}/test` | Send a test message to that channel only |
| `DELETE /api/channels/{id}` | Remove |

- Slack URLs must be on `hooks.slack.com`. Teams URLs must be on `*.webhook.office.com` or
  `*.logic.azure.com`. Every URL must be https with no user or password in it.
- A webhook URL is a credential, so it is stored Fernet-encrypted. Only its host is shown back.
- Delivery uses the same SSRF guard as scans: public addresses only, connection pinned to the checked
  address, no redirects. A webhook pointing inside the network fails with `blocked_private`.
- Generic webhooks receive `{"event","data","text"}` with these headers:
  - `X-Patchwarden-Timestamp`
  - `X-Patchwarden-Signature: sha256=<HMAC-SHA256(secret, "<timestamp>.<body>")>`

  Receivers should check the signature, and reject timestamps older than a few minutes.
- Each alert records the per-channel delivery result in `alerts.delivered`.

### Dunning

When a subscription goes `past_due`, `past_due_since` is recorded. The daily dunning job (09:00 UTC)
emails the owner on day 1, day 7 and the day before the grace period ends (`DUNNING_GRACE_DAYS`,
default 14). Monitoring continues during the grace period.

After the grace period, the subscription is cancelled, `subscription.lapsed` is written to the audit
log, and the owner is told that monitoring stopped. Setting the status back to `active` clears the clock.
No payment is taken here: the status field is still set by billing (or an admin).

## Teams, billing and proof (Phase D)

### Teams and roles

An organisation (a "team": an agency and its clients, or a company's IT) shares sites between people.
The site's owner keeps every right; team members get what their role allows. Every access decision goes
through one helper, `src/patchwarden/security/access.py`.

| Action | owner | admin | member | approver | viewer |
|---|:-:|:-:|:-:|:-:|:-:|
| See the site, reports, alerts | yes | yes | yes | yes | yes |
| Plan patches, connect hosts, monitoring, staging | yes | yes | yes | | |
| Approve, roll back, sign off, promote, accept quotes | yes | yes | | yes | |
| Members, branding, rates | yes | yes | | | |

- A platform administrator (`users.role = admin`) can look at every site but never plans or approves.
- **Four-eyes rule.** With `require_separate_approver` on, the person who planned a change cannot
  approve it (`separate_approver_required`).
- A team always keeps at least one owner (`last_owner`). Only the site's owner can put a site in a team,
  and only into a team they manage.
- Members must already have an account; there are no invitation emails in this build.

| Endpoint | What it does |
|---|---|
| `POST /api/orgs` `{"name"}` | Create a team; you become its owner |
| `GET /api/orgs`, `GET /api/orgs/{id}` | Your teams, members, sites and your role |
| `PATCH /api/orgs/{id}` | Name, four-eyes rule, hourly rate, branding |
| `POST /api/orgs/{id}/members` `{"email","role"}` | Add a member, or change their role |
| `DELETE /api/orgs/{id}/members/{user_id}` | Remove a member |
| `POST /api/sites/{id}/team` `{"org_id"}` | Share a site with a team (`null` stops sharing) |

### Entitlements and the billing export

No payment is taken. Patchwarden records what is owed, and a payment system or an accountant collects it.

- When a patch is approved, its `billing` is fixed on the job:
  - `included` if the site has an active Watchdog or WordPress Guard subscription;
  - otherwise `patch_fee` at `PRICE_PATCH`.

  A later price change never rewrites history. Migration promotions are covered by the migration quote.
- `GET /api/admin/billing?month=2026-10[&format=csv]` (admin only) lists every item in the month:
  - subscriptions that are not cancelled (`PRICE_WATCHDOG`, `PRICE_WP_GUARD`);
  - patch fees, and included patches at 0;
  - accepted migration quotes;
  - active virtual patches (Phase E).

  In the CSV, a cell that starts with `= + - @` is prefixed with `'`, so a spreadsheet does not run it as
  a formula.

### Outcome-based monthly report

The monthly report (`outcomes`) now says what the service achieved, not only what it did:

- days the site was exposed;
- exploited (KEV) flaws found;
- updates that succeeded;
- risks fixed, and the median hours from alert to fix.

The summary sentence and the report page include them.

### Signed attestations

A verified site whose latest check (at most two days old) found a patched PHP version can get a signed
statement. It can go on a site footer, or to a customer, insurer or auditor.

| Endpoint | Who | What |
|---|---|---|
| `POST /api/sites/{id}/attestations` | edit role | Issue one (201), valid for `ATTESTATION_DAYS` |
| `GET /api/attestations/{id}` | anyone | Payload, signature, `status` (valid, expired, revoked, invalid) |
| `GET /api/attestations/{id}/badge.svg` | anyone | A badge for the site |
| `POST /api/attestations/{id}/revoke` | edit role | Revoke |
| `GET /.well-known/patchwarden-attestation-keys.json` | anyone | The public key as a JWK (OKP / Ed25519) |

The signature is Ed25519 over the payload as canonical JSON: sorted keys, no spaces, UTF-8. It is
base64url-encoded without padding, so anyone can check it offline. Set `ATTESTATION_KEY` (a base64url
32-byte seed) in production. Without it, the key is derived from `CREDENTIAL_KEY`, and rotating that key
would make older statements fail to verify.

### Instant migration quotes

`GET /api/migrations/{id}/quote` turns the breakage scan into a fixed price:

- 4 h base (staging, test run, sign-off walkthrough, promotion);
- 1.5 h per manual error fix and 0.5 h per manual deprecation fix;
- 0.5 h per hand-edited file and 0.1 h per automatic fix.

Hours are rounded up to the half hour. The rate is the team's `hourly_rate`, otherwise
`MIGRATION_HOURLY_RATE`. The quote carries a plain-language statement of work (scope, method, exclusions,
done-when, price) and is valid for 30 days. It is made once and kept as offered.
`POST /api/migrations/{id}/quote/accept` (approve role) records the acceptance, which then appears in the
billing export.

### White-label

A team's `brand_name`, `brand_color`, `brand_logo_url` (https only) and `brand_footer` replace
Patchwarden's on its sites' alert emails, channel messages, monthly report emails and the report page.
To show the logo, the dashboard's Content-Security-Policy allows `img-src https:`, and the logo is loaded
with `referrerpolicy="no-referrer"`.

## Virtual patches at the edge (Phase E)

Some sites cannot be updated today, for example during a change freeze or while a migration is
planned. A virtual patch is a WAF rule in front of the site that blocks attack-shaped requests before
they reach PHP. It buys time; it does not replace the PHP update.

### What it blocks

`src/patchwarden/virtual_patch/signatures.py` lists generic PHP code-injection shapes. Each is matched
after URL-decoding and lower-casing:

- ini overrides from the URL (`allow_url_include`, `auto_prepend_file`);
- stream wrappers (`php://input`, `php://filter`, `data://`);
- `<?php` in the query;
- direct `php-cgi` requests.

They are not PHP2Shell's exact exploit, which is not public here. When a vendor or CERT publishes a
precise signature, replace the list: every provider builds its rule from it.

### Providers

| Provider | Where the rule goes | Credential (`secret`, encrypted) | `config` |
|---|---|---|---|
| Cloudflare | Rulesets API, zone custom rules (`http_request_firewall_custom`), action block | API token with *Zone WAF: Edit* on that zone | `zone_id` |
| Akamai | App & API Protector custom rule, attached to a security policy with action `deny`, then the config version is activated | EdgeGrid JSON: `host`, `client_token`, `client_secret`, `access_token` | `config_id`, `version`, `policy_id`, `network` (STAGING or PRODUCTION) |
| AWS WAF | Existing WAFv2 web ACL: AWS managed `AWSManagedRulesPHPRuleSet` plus a custom OR-of-byte-match block rule | Optional JSON `aws_access_key_id`, `aws_secret_access_key` (otherwise the server's IAM role) | `web_acl_name`, `web_acl_id`, `region`, `scope` (REGIONAL or CLOUDFRONT) |
| demo | A fake edge in the demo world, for `*.demo.patchwarden.test` only | none | none |

How each provider is tested:

- **Akamai** is **not verified against a live account**. The field names follow Akamai's public API
  reference. The tests check the request flow and the EdgeGrid signature (against an independent
  reference implementation), not Akamai's acceptance of the rule. The EdgeGrid host must be an
  `*.luna.akamaiapis.net` address.
- **AWS WAF** is tested with botocore's Stubber, which validates every request against the WAFv2 API
  model. AWS Shield Advanced includes AWS WAF, so this is also the Shield answer: Shield itself handles
  DDoS, and the application-layer block is a WAF rule.
- **Cloudflare** is tested against a mocked Rulesets API.

### Flow and safety

Endpoints:

- `POST /api/sites/{id}/virtual-patches` `{"provider","config","secret"}` (edit role) is the **dry run**.
  It checks the settings and returns the rules it would add. Nothing is sent to the provider.
- `POST /api/virtual-patches/{id}/approve` (approve role, four-eyes rule respected) records a durable job
  (`vpatch_apply`) that adds the rule.
- `POST /api/virtual-patches/{id}/remove` (approve role) records `vpatch_remove`.
- `GET /api/virtual-patches/{id}` and `GET /api/sites/{id}/virtual-patches` show the state and report.

States: `planned → applying → active → removing → removed`, or `failed`.

Safety rules:

- Apply and remove are safe to repeat: the rule is tagged `patchwarden-vp-<id>`, and an existing tagged
  rule is reused. A crashed job simply runs again, and start-up gives orphaned `applying` or `removing`
  patches a recovery job.
- Removal deletes only the tagged rule. The customer's own rules are untouched.
- Errors are handled by kind:
  - A refused credential or a wrong id fails at once, with a plain message.
  - An unreachable provider, or an AWS `WAFOptimisticLockException`, is retried by the job queue with
    backoff. After the queue gives up, the patch is marked failed.
- The provider secret is Fernet-encrypted, never returned (`has_secret` only), and never logged or
  audited.
- An active virtual patch is billed per month at `PRICE_VIRTUAL_PATCH` (default 19) in the billing export.

## Real PHP tooling and the SBOM (Phase F)

### Rector, PHPStan and `php -l` in a sandbox

The built-in breakage scan is fast and explainable, and it is always on. When `MIGRATION_TOOLS` is
set, a migration plan also runs real tools over the site's code, for the target PHP version:

| Tool | What it adds to the plan | How it runs |
|---|---|---|
| `php -l` | Files that do not parse (step `tool:php-lint`) | 200 files per run |
| PHPStan (level 0, `phpVersion` = target) | Calls and constants the new version lacks (step `tool:phpstan`) | `analyse --error-format=json` |
| Rector (`withPhpSets(phpXY)`) | The upgrade changes it proposes, as diffs (step `tool:rector`) | `process --dry-run --output-format=json` |

Results are stored in `breakage.tools`. Their steps are added to `plan.fixes`, and the instant quote
counts them. A missing or failing tool is reported (`unavailable`, `failed`, `timed_out`) and never
blocks the plan. The tools only get the code files and their own config, never `composer.lock` or other
files.

**Settings:**

- `MIGRATION_TOOLS=off` (default)
- `MIGRATION_TOOLS=docker`: production.
- `MIGRATION_TOOLS=local`: development only, refused when `APP_ENV=production`.

**The Docker sandbox** runs each tool with:

- `--network none`
- `--read-only`
- `--cap-drop ALL`
- `--security-opt no-new-privileges`
- `--user 65534:65534`
- PID, memory and CPU limits
- a small `noexec` `/tmp`
- the code mounted read-only at `/app`
- a timeout (`SANDBOX_TIMEOUT`, 300 s)

Commands are argument lists, never a shell string. Code paths with `..`, an absolute path or a leading
`-` are refused.

**The image:** build it yourself; nothing is pulled at run time. It is multi-arch, so it builds on arm64.
```bash
docker build -t patchwarden/php-tools:1 docker/php-tools
```

**The local sandbox** runs the locally installed `php`, `rector` and `phpstan` in a temporary folder,
with a clean environment, CPU and file-size limits and the same timeout. It has no network isolation,
which is why it is refused in production.

**What the tests cover:**

- Parsing of real tool output formats.
- The Docker flags.
- The production refusal.
- A real `php -l` run through the local sandbox.
- The plan and quote integration.

A test that runs real Rector and PHPStan is skipped unless both are installed.

### Per-site SBOM (CycloneDX 1.5)

`GET /api/sites/{id}/sbom` (view role, **verified sites only**, because an inventory shows an attacker
exactly what to aim at) returns `application/vnd.cyclonedx+json` with:

- **PHP**: the latest detected version, with its CPE (`cpe:2.3:a:php:php:<v>`).
- **WordPress core, plugins and themes**: from the freshest evidence (a plugin report, else the outside
  scan).
- **Composer packages**: from `composer.lock`, read from the host (read-only) when hosting access is set
  up. `packages-dev` get `scope: optional`.
- **Vulnerabilities**:
  - PHP advisories the Watchdog matched, with the CVSS rating, `patchwarden:kev` and `patchwarden:epss`;
  - WordPress component flaws from the feed.

  Each points at the component it affects.

Package URLs: `pkg:composer/...` is the standard type. PHP, WordPress core, plugins and themes have no
purl type of their own, so they use `pkg:generic` with a clear namespace. Each export is recorded in the
audit log (`site.sbom_exported`).

## Where this differs from the spec

- `.env.example` leaves `DATABASE_URL` empty, so local dev uses SQLite. The spec's PostgreSQL URL is shown as a
  comment. It also adds `APP_ENV`, `PUBLIC_BASE_URL`, `DEMO_SITES` and `POSTGRES_PASSWORD`.
- The `scans` table adds `scanned_url` and `findings` (JSON: version source, plain-language summary, WordPress
  results, fetch errors) to the spec's columns.
- Tables are created per phase (Phase 1: `users`, `sites`, `scans`, `audit_log`; Phase 2: `credentials`,
  `backups`, `patch_jobs`). On startup, new nullable columns are also added to an existing dev database.
- `sites` adds `check_paths` (JSON): the login/form pages the Patch agent checks.
- Phase 3 adds three tables beyond the spec's list. `watch_checks` is each check run (the monthly report and
  the "monitoring off" rule are built on it). `advisories` holds the CVEs and releases being matched.
  `feed_cursors` records where each feed poll stopped. `alerts.cve_id` also holds `PHP-8.4.28` for a release
  and `risk:<level>:<check>` for a risk change. It is unique per site, which is how alerts are deduplicated.
- Watchdog version checks are stored as scans too (`findings.source = "watchdog"`), so a site's scan history shows them.
- `migrations` adds `signed_off_at`, `source` (host or upload), `promotion` (the production promotion
  record), `patch_job_id` (its before/after report) and `created_at` to the spec's columns.
- The adapter interface gains `read_code`, `create_staging`, `open_staging` and `write_files` for the
  Migration agent. The real cPanel/Plesk/agent adapters refuse these too until they are built.
- The plugin key is generated when the owner presses "Get your plugin key", not silently when a site is
  added. This is so it can be shown exactly once and stored only as a hash. The spec's credential kind
  `api_key` (Fernet, Phase 2) stays for keys that Patchwarden sends *to* an agent.
- Phase 5 adds `plugin_keys` and `plugin_actions` tables.
- Sign-off can be given by the site owner or, since Phase D, by a team member with the approver role.
- Endpoints added beyond the minimum set: `PATCH /api/sites/{id}`, `POST`/`DELETE /api/sites/{id}/credentials`.
- `patch_jobs.state` `awaiting_approval` is in the model but unused so far. A new job is `dry_run` and is
  approved from there. Phase 5's "Fix it" button is expected to create jobs in `awaiting_approval`.
- The backup restore dry-run is recorded in the patch report and in the `backup.created` audit entry. The
  spec's `backups` table has no column for it.
- The dashboard covers sites, patches, alerts, monthly reports, migrations and one WordPress Guard page per site.
- No dashboard sign-up page: create the account with `POST /api/auth/register`.

## Future ideas

These are not in the spec, so they are not built:

- A shared rate-limit store (for example Redis) when running several app processes.
- Keys in a cloud KMS, and backups in object storage with Object Lock (write-once).

- Quiet hours and SMS alerts.
- Invitation emails for team members who do not have an account yet.
- Running the plugin's tests inside a real WordPress (WordPress Playground via npx, or the official Docker image).
- Publishing the plugin on WordPress.org, and checking it with the WordPress Coding Standards (PHPCS) in CI.
- Deleting the staging site after a promotion, and a staging site's own expiry.
- Uploading a developer's fixed files to staging through Patchwarden (today the developer edits staging directly).
- Applying Rector's diffs on staging automatically (today a developer reviews and applies them).
- A single scheduler across several app processes (a database lock or a dedicated worker).
- A "dry run again" button when a dry run goes stale (today you plan a new one).

- Reading plugin versions from `readme.txt`, for more exact WordPress matching.
- Alembic migrations instead of `create_all` at startup.
