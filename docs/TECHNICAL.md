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
(`WP_VULN_FEED_PATH`). The bundled feed in `patchwarden/data/wp_vuln_feed.json` is **demo data with made-up
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

- No credential appears in any response, log or error. `tests/test_canary_and_errors.py` sends random canary
  passwords through registration, login, validation errors, bad JSON and an unexpected crash. It then checks
  every response body and header, every log record and the audit log for the canaries, `JWT_SECRET` and
  `CREDENTIAL_KEY`.
- Unexpected crashes are logged by exception type and route only. The exception text could hold input.
- Log handlers also redact `?token=` query values, bearer tokens and the configured secrets. This is defence in depth.
- Stored response headers keep cookie names only, never the values.
- A share-link token can't be used as a login token, and a login token can't be used as a share link.
- Hosting tokens are Fernet-encrypted at rest and decrypted only inside the adapter call. They never appear
  in an API response, the dashboard, a patch report, an audit entry, a backup or a log line.
  `tests/test_phase2_acceptance.py::test_no_credential_in_logs_reports_or_responses` proves this with a canary
  token through the whole flow: dry run, approve, success, rollback, a rejected token, and invalid input.
- `NVD_API_KEY` and `SMTP_PASSWORD` are redacted from logs. They never appear in alerts, emails, pages or
  responses, and `tests/test_watchdog.py::test_watchdog_secrets_never_leak` checks this with canaries. SMTP
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

Every access method implements one interface (`patchwarden/patch/adapters.py`, `HostingAdapter`):
`php_version`, `available_versions`, `create_backup`, `verify_restore`, `set_php_version`, `restart_php` and
`restore_backup`.

- **Real adapters** (`CpanelAdapter`, `PleskAdapter`, `AgentAdapter`) are stubs in this build. They refuse with
  `adapter_not_connected` and change nothing, rather than pretend. They still need to be built and tested
  against a real panel or staging account.
- **The fake adapter** (`patchwarden/fakes.py`) runs the same interface against in-process fake hosts. Tests and
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
`patchwarden/data/cve_feed.demo.json` instead of NVD. To try an alert, add an entry in NVD format and press
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

The breakage rules (`patchwarden/migration/rules.py`) cover the PHP 7.0 → 8.4 migration guides. Breaking
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

**How the plugin is tested.** `tests/wp_harness/harness.php` is a stand-in for the WordPress functions the
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

`tests/test_migration_flow.py::test_custom_php81_site_passes_staging_first_time` and the Phase 4 acceptance tests cover the same path.

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
- Sign-off is by the site owner's account ("owner/IT": IT signs off on the owner's account). Separate IT
  accounts with sign-off rights would need agency/team accounts, which are out of scope (no multi-tenancy in this build).
- Endpoints added beyond the minimum set: `PATCH /api/sites/{id}`, `POST`/`DELETE /api/sites/{id}/credentials`.
- `patch_jobs.state` `awaiting_approval` is in the model but unused so far. A new job is `dry_run` and is
  approved from there. Phase 5's "Fix it" button is expected to create jobs in `awaiting_approval`.
- The backup restore dry-run is recorded in the patch report and in the `backup.created` audit entry. The
  spec's `backups` table has no column for it.
- The dashboard covers sites, patches, alerts, monthly reports, migrations and one WordPress Guard page per site.
- No dashboard sign-up page: create the account with `POST /api/auth/register`.

## Future ideas

These are not in the spec, so they are not built:

- Backup retention and clean-up rules.
- Running the plugin's tests inside a real WordPress (WordPress Playground via npx, or the official Docker image).
- Publishing the plugin on WordPress.org, and checking it with the WordPress Coding Standards (PHPCS) in CI.
- Deleting the staging site after a promotion, and a staging site's own expiry.
- Uploading a developer's fixed files to staging through Patchwarden (today the developer edits staging directly).
- A PHP tokenizer-based scan (via `php -l` / a PHP AST in a sandbox) for runtime-only changes.
- A single scheduler across several app processes (a database lock or a dedicated worker).
- Per-owner alert preferences (email digest, quiet hours) and other channels (SMS, Slack).
- A "dry run again" button when a dry run goes stale (today you plan a new one).

- Rate limiting for the free scan endpoint and login (per IP and per account).
- Background (scheduled) bulk scans for very large CSVs. Today up to 100 domains are scanned in the request.
- Reading plugin versions from `readme.txt`, for more exact WordPress matching.
- Alembic migrations instead of `create_all` at startup.
- A public "free scan" landing page.
