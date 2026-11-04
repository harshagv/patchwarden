# Patchwarden

*Formerly PHP Guard.* Website and docs: **https://patchwarden.harshagv.me** · Source: **https://github.com/harshagv/patchwarden** · MIT licence

**Find, fix and watch every PHP website at risk from PHP2Shell, without ever asking for a password.**

Patchwarden is a self-hosted platform with five agents. Together they scan PHP websites for the PHP2Shell
flaws (CVE-2026-109618 and CVE-2026-109619), update them safely with the owner's approval, watch them every
day for new risks, move sites that can no longer be patched, and give WordPress owners a one-button guard.

It is built for agencies, hosting resellers, freelancers and managed-service providers who look after many
PHP and WordPress sites, and want a product they can offer their clients today.

> **Status: preview.** The scanner, the approval and rollback workflow, the watchdog, the migration planner
> and the WordPress plugin are built and tested (224 automated tests). Changing PHP on real hosting needs the
> cPanel/Plesk connectors, which are not connected yet. See [What is ready today](#what-is-ready-today)
> before you offer the paid services.

---

## The problem, in plain words

There is a flaw in PHP that lets an attacker take over a website **without logging in**. PHP runs behind
most of the web, including every WordPress site, and many sites still run old, unpatched versions. Until
they update, those sites are open to attack.

| Fact | Detail |
| --- | --- |
| The flaws | CVE-2026-109618 and CVE-2026-109619 ("PHP2Shell"), CVSS 9.2, unauthenticated remote code execution |
| Fixed in | PHP **8.5.12**, **8.4.27**, **8.3.36** and **8.2.35** (released Oct 21, 2026) |
| Actively exploited | Added to CISA's Known Exploited Vulnerabilities catalog on Oct 26, 2026 |
| No patch for old PHP | PHP 8.1 and older get no official fix. Those sites have to move to a newer PHP. |
| Deadline | PHP 8.2 loses all security fixes on **Dec 31, 2026** |
| How many sites | About 70% of websites with a known server-side language run PHP. About 40% of all websites are WordPress, and about 1 in 3 WordPress sites run PHP 8.1 or older. |

Every one of those site owners needs the same three things: to know whether they are exposed, to get fixed
safely, and to stay safe. Patchwarden does all three.

---

## The five agents

| Agent | What it does for the site owner | Access it needs | Business model |
| --- | --- | --- | --- |
| **1. Scanner** | Checks a site from the outside and gives a one-page report: *your version, your risk, what to do next*. Also handles CSV lists of client sites. | None | **Free.** It is the lead magnet that finds your customers. |
| **2. Patch** | Updates PHP safely: backup, update, restart, test, and automatic rollback if anything breaks. Nothing changes until the owner approves. | Hosting panel API token (cPanel or Plesk) | One-time fee per site |
| **3. Watchdog** | Re-checks every protected site every day and matches new CVEs every hour. Alerts the owner the day a new risk appears, and sends a monthly safety report. | None (or the read-only plugin) | Monthly fee per site |
| **4. Migration** | For sites that cannot be patched (8.1 and older; 8.2 before Dec 31). Finds the code that will break, writes the plan, tests on staging, and goes live only after sign-off. | Hosting panel API token + a staging copy | Project price (the biggest ticket) |
| **5. WordPress Guard** | Scanner + Patch + Watchdog in one simple product for WordPress owners: a safety score, a fix list in plain language, and one **Fix it** button. | The Patchwarden WordPress plugin (no password) | Monthly fee per site (volume product) |

**How the money flows:** the free scan finds the customer, the Patch agent fixes them once, the Watchdog
keeps them paying monthly, and the Migration agent takes the big projects.

---

## Why site owners say yes: the trust rules

These rules are enforced in code, not just written in a policy:

- **Backup before every change.** It is verified by checksum and a restore dry-run. If the backup fails, nothing is changed.
- **The owner approves every change.** Every plan starts as a dry run. Each approval records who approved and when, and it is the only way a change to a live site can start.
- **Automatic rollback.** If the homepage, login or checkout page fails after an update, the site is restored and put back on its old PHP version.
- **No password, ever.** Owners give an API token they create and can revoke, or install the plugin. Patchwarden never logs in with a password.
- **Access can be revoked at any time.** Deleting a token, or uninstalling the plugin, switches access off on both sides.
- **Everything is on the record.** Every action is in an audit log, and every change has a printable before/after report.
- **No AI guessing.** The agents are deterministic checkers. A hidden version is reported as "unknown", never guessed.

---

## Who it is for

| You are… | Use Patchwarden to… |
| --- | --- |
| A web agency or freelancer | Scan all your clients' sites in one CSV upload, then sell the fixes and the monthly watch |
| A hosting reseller or MSP | Offer a safety check and a managed PHP-update service across your customer base |
| A WordPress specialist | Give owners one simple guard with a score they understand and a single **Fix it** button |
| A site owner | Know where you stand in one minute, and get fixed without handing over a password |

---

## How it works

```
  Free scan  ─────▶  Fix it (dry run)  ─────▶  Owner approves  ─────▶  Backup → update → test
  (no access)        nothing changes yet       (recorded)              rollback if anything fails
                                                                              │
  Monthly report ◀──  Daily watch + new-CVE alerts  ◀─────────────────────────┘

  Too old to patch?  →  Breakage scan  →  Staging tests  →  Sign-off  →  Promote (same safety steps)
```

---

## Try it in 5 minutes

The demo runs on your own computer. It uses built-in demo websites and pretend hosting panels, so you need
no accounts and no secrets.

**You need:** Python 3.12 (`brew install python@3.12` on a Mac). Optional: PHP (`brew install php`), only to
run the WordPress plugin tests.

**Step 1. Get the code and start Patchwarden.**

```bash
git clone https://github.com/harshagv/patchwarden.git
```

```bash
cd patchwarden
```

```bash
make dev
```

It opens at `http://localhost:8000`. Leave it running.

**Step 2. Create your account** (in a second terminal):

```bash
curl -s localhost:8000/api/auth/register -H 'content-type: application/json' -d '{"email":"you@example.com","password":"choose-a-long-password"}'
```

**Step 3. Log in** at `http://localhost:8000/dashboard` with that email and password.

**Step 4. Try the demo sites.** Add any of these on the dashboard. For the ones that need access, paste any
text as the token; the demo panels accept it.

| Demo site | Try this | What you will see |
| --- | --- | --- |
| `php84-unpatched.demo.patchwarden.test` | Scan now | Risk: **Patch now** (PHP 8.4.13) |
| `hidden.demo.patchwarden.test` | Scan now | Risk: **Unknown**: the version is hidden, so nothing is guessed |
| `shop84.demo.patchwarden.test` | Add a cPanel token, login page `/login`, form page `/checkout`, then **Plan a PHP update** → **Approve and run** | Updated to 8.4.27, all checks pass, with a before/after report |
| `fragile84.demo.patchwarden.test` | Same as above | Checkout breaks on the new version, so it **rolls back automatically** and the report says why |
| `legacy81.demo.patchwarden.test` | Add a token, then **Plan a migration** → **Run staging tests** → **Sign off** → **Promote** | PHP 8.1 → 8.4 with a breakage report and a before/after report |
| `wp74.demo.patchwarden.test` | Add a token, then **Plan a migration** | A WordPress site on PHP 7.4: the exact file and line of code that would break on PHP 8 |
| `wpshop84.demo.patchwarden.test` | Choose WordPress, add a cPanel token, press **Scan now**, then open **WordPress Guard** → **Fix it** | The safety score, and **Fix it** going to the approval page (nothing changes until you approve) |

You can also turn on **monitoring** for a site and press **Run Watchdog checks now** to see alerts. The API
reference opens at `http://localhost:8000/docs`.

---

## Step by step: protecting a real site

These are the steps you or your customer follow on the dashboard (`/dashboard`).

1. **Scan.** Add the site and press **Scan now**, or upload a CSV of up to 1,000 sites (it runs in the background). Send the owner the report link: it opens without a login and expires after 7 days. Owners who find their site through a free scan press **Claim this site** on the report.
2. **Prove it's yours.** Add a DNS TXT record or a small file (or connect the WordPress plugin). Until then, reports show the version, the risk and what to do; the full report (headers, which plugin is vulnerable) opens once ownership is verified.
3. **Give access, without a password.** In the hosting panel (cPanel or Plesk), create an API token that can only change the PHP version and restart PHP. Paste it into Patchwarden under **Save access token**. It is stored encrypted and never shown again.
4. **Plan the fix.** Press **Plan a PHP update**. You get a dry run that lists exactly what will happen; nothing has changed yet.
5. **Approve.** Press **Approve and run**. Patchwarden backs up, updates, restarts and checks the homepage, login and form pages. If any check fails, it rolls back automatically.
6. **Keep it safe.** Turn monitoring on. The site is checked daily, new flaws are matched hourly, the owner is alerted the same day, and a monthly report arrives on the 1st.
7. **Too old to patch?** Press **Plan a migration**. You get a breakage report (file and line), a fix plan with an effort estimate, staging tests, then sign-off and promotion.

### WordPress owners: install the plugin

1. Open the site's **WordPress Guard** page and press **Download the plugin**.
2. In WordPress, go to **Plugins → Add New → Upload Plugin**, choose `patchwarden.zip`, then **Install** and **Activate**.
3. Back in Patchwarden, press **Get your plugin key** and copy it. It is shown once.
4. In WordPress, go to **Settings → Patchwarden**, paste the key and press **Save and connect**. Done.

The plugin sends only the PHP version, the WordPress version, and the list of plugins and themes. It sends
no users, content or settings. It only runs updates the owner has approved, it cannot change PHP, and
deleting it removes all its data and switches its key off.

---

## Deploying Patchwarden for your customers

Patchwarden runs as one web app with a PostgreSQL database, packaged for Docker. The images run natively on
both Apple Silicon (arm64) and x86.

1. **Get the code** on your server: `git clone https://github.com/harshagv/patchwarden.git && cd patchwarden`.
2. **Create your settings file** with generated secrets:
   ```bash
   make env
   ```
   This writes `.env`, which is git-ignored and must never be committed. It fills `JWT_SECRET`,
   `CREDENTIAL_KEY` and `POSTGRES_PASSWORD`.
3. **Set your public address.** In `.env`, set `PUBLIC_BASE_URL=https://your-domain` (used in report links and the plugin).
4. **Optional features.** Set `SMTP_HOST`, `SMTP_USER` and `SMTP_PASSWORD` for email alerts, and `NVD_API_KEY` for faster CVE updates.
5. **Check the settings:**
   ```bash
   make check-config
   ```
   In production, Patchwarden refuses to start if a required secret is missing, and says which one.
6. **Start it:**
   ```bash
   make up
   ```
   The app listens on `127.0.0.1:8000`. Put it behind your HTTPS reverse proxy (nginx, Caddy or Traefik).
7. **Build the WordPress plugin** for your address (or let owners download it from the dashboard):
   ```bash
   make plugin
   ```

**Before going live:** use HTTPS only, back up the PostgreSQL database, keep `.env` private, run one app
process (the scheduler runs inside it), and run `make secret-scan` before every release.

### Settings

| Setting | Required | Where to get it |
| --- | --- | --- |
| `DATABASE_URL` | Yes (production) | Your PostgreSQL provider. In development, leave it empty to use SQLite. |
| `JWT_SECRET` | Yes | `openssl rand -hex 32` (or `make env`) |
| `CREDENTIAL_KEY` | Yes | A Fernet key (or `make env`). It encrypts customers' hosting tokens. |
| `PUBLIC_BASE_URL` | Yes (production) | Your HTTPS address |
| `SMTP_*`, `ALERT_FROM_EMAIL` | For email alerts | Any SMTP provider |
| `NVD_API_KEY` | Optional | The NVD API key request page (free); it raises the rate limit |
| `ATTESTATION_KEY` | Yes, if you offer signed "patched" badges | A base64url 32-byte Ed25519 seed |
| `PRICE_*`, `CURRENCY`, `MIGRATION_HOURLY_RATE` | Optional | Your own prices, for the billing export and instant migration quotes |
| `MIGRATION_TOOLS`, `SANDBOX_IMAGE` | Optional | `docker` plus the image built from `docker/php-tools`, to add Rector and PHPStan to migration plans |

The full list, including what site owners supply themselves, is in the [technical guide](docs/TECHNICAL.md#secrets).

---

## Security and privacy

- **SSRF protection.** The free scanner refuses private, internal and cloud-metadata addresses, checks every redirect, and pins each connection to the checked address.
- **Not a recon tool.** Anyone can see a site's version and risk (the site shows those to the world anyway). The details that help an attacker (response headers, which plugin is vulnerable) need proof of ownership, and list scans need an account.
- **Crash-safe changes.** Patches, rollbacks, staging runs and promotions are durable jobs. If the server dies mid-change, the job is picked up again, and a half-done change is put back from the backup automatically.
- **Encrypted backups.** Each backup (a customer's files and database) is encrypted with its own AES-256-GCM key, kept with `600` permissions, and deleted after `BACKUP_RETENTION_DAYS` (default 30).
- **Customers' hosting tokens** are encrypted at rest and decrypted only for the call that uses them. Keys can be rotated without downtime (`python -m patchwarden rotate-credentials`).
- **Tamper-evident audit log.** Every entry carries the hash of the one before it; `python -m patchwarden verify-audit` finds any changed entry.
- **Two-step login** (any authenticator app, plus single-use recovery codes), "log out everywhere", revocable report links, and rate limits on free scans and failed logins.
- **Plugin keys** are stored only as a hash and shown once.
- **Teams with roles** (owner, admin, member, approver, viewer) and an optional four-eyes rule: whoever planned a change cannot approve it.
- **Untrusted code stays in a box.** Rector, PHPStan and `php -l` run in a container with no network, a read-only file system and no privileges.
- **No credential appears in any response, page, report, alert, email or log.** Automated "canary" tests prove this for every agent.
- **Hardened dashboard.** It uses HttpOnly SameSite cookies, CSRF tokens on every form, strict security headers, and one plain error format with no stack traces.
- **Reports never show string literals from a customer's code**, so a password in their config never reaches a report.
- **No secrets in the repository.** It is checked with gitleaks and a high-entropy scan.

---

## What is ready today

Be clear with your customers about what is live. This is the honest state of the build:

| Area | Status |
| --- | --- |
| Free Scanner, reports, CSV bulk scans, WordPress plugin/theme check | ✅ Ready |
| Approval, backup, checks, automatic rollback and audit log (Patch workflow) | ✅ Ready, tested against simulated hosting panels |
| **Real cPanel / Plesk / server-agent connections** | ⏳ **Not connected yet.** The interface is ready, and the connectors refuse to act rather than pretend. Required before selling Patch or Migration on real hosting. |
| Watchdog: daily checks, CVE and PHP-release matching, alerts, monthly reports | ✅ Ready (NVD and php.net are tested with recorded responses) |
| Watchdog at scale: parallel checks, CISA KEV and EPSS priority, daily digest, escalation, Slack, Teams and signed webhooks, payment reminders | ✅ Ready (KEV and EPSS are tested with recorded responses) |
| Teams and roles, four-eyes approval, white-label reports and emails | ✅ Ready |
| Billing export (subscriptions, patch fees, migration quotes, virtual patches), instant migration quotes | ✅ Ready. It records what is owed; collecting payment is up to you. |
| Signed "patched" attestations, with a public check and a badge | ✅ Ready |
| Virtual patch at the edge: Cloudflare and AWS WAF | ✅ Ready, tested against the providers' API formats (AWS checked against the official API model) |
| Virtual patch at the edge: Akamai | ⚠️ Built to Akamai's public API reference, not yet verified against a live Akamai account |
| Rector / PHPStan in a sandbox for migration plans | ✅ Ready. Build the tools image once (`docker build -t patchwarden/php-tools:1 docker/php-tools`). |
| Per-site software inventory (CycloneDX SBOM) | ✅ Ready |
| Migration: breakage scan, plan, staging, sign-off, promotion | ✅ Ready, tested against simulated hosting. The code scan is static and cannot see runtime-only issues, which staging tests cover. |
| WordPress plugin | ✅ Ready, tested by running the real plugin against a WordPress stand-in. Not yet tested inside a full WordPress install. |
| Docker deployment (`make up`) | ⚠️ Written but not yet run end to end |
| Taking payments (Stripe or similar) | ❌ Not in this release. Subscription status, payment reminders and the billing export are ready for it. |

The planned next steps are in the technical guide's [Future ideas](docs/TECHNICAL.md#future-ideas).

---

## FAQ

**Do you need my hosting or WordPress password?**
No, never. You create an API token in your hosting panel (and can delete it at any time), or install the WordPress plugin.

**Can an update break my site?**
Every change is backed up first and tested on your homepage, login and checkout pages. If any of them fails, the site is restored automatically, and the report shows what happened.

**My site hides its PHP version. Can you still check it?**
The free scan will say "Unknown", because we never guess. Install the plugin, or add a hosting token, and we read the exact version from the inside.

**My site is on PHP 7.4 or 8.1. Can you patch it?**
There is no official patch for those versions. The Migration agent plans the move to a supported PHP, tests it on a staging copy, and goes live only after you sign off.

**What does the plugin send?**
Only your PHP version, your WordPress version, and the names and versions of your plugins and themes.

**How do I stop the service?**
Turn monitoring off, delete your token, or uninstall the plugin. Access ends immediately.

---

## For developers

| | |
| --- | --- |
| Stack | Python 3.12, FastAPI with server-rendered pages, SQLAlchemy (PostgreSQL / SQLite), APScheduler, httpx, JWT + bcrypt, Fernet, Docker Compose |
| Commands | `make dev`, `make test`, `make up`, `make env`, `make plugin`, `make check-config`, `make secret-scan` |
| Tests | 224 automated tests: the acceptance tests for all five agents, security and canary tests, and the real WordPress plugin run under PHP |
| API | OpenAPI docs at `/docs` in development |
| Project layout | `patchwarden/` (the app and agents), `wordpress-plugin/` (the plugin), `tests/`, `docs/` |
| Specification | [SPEC.md](SPEC.md) is the build sheet. Every difference from it is listed in the [technical guide](docs/TECHNICAL.md#where-this-differs-from-the-spec). |
| Full reference | [docs/TECHNICAL.md](docs/TECHNICAL.md): every flow, endpoint and safety rule, the demo hosts and the scoring rules |
| Website | [`site/`](site), published to https://patchwarden.harshagv.me by GitHub Actions. Setup and updates: [docs/PUBLISHING-SITE.md](docs/PUBLISHING-SITE.md) |

---

## Licence and support

Patchwarden is open source under the [MIT licence](LICENSE). The WordPress plugin in `wordpress-plugin/` declares
GPL-2.0-or-later in its own header, as WordPress plugins usually do.

For onboarding, a hosted setup or support, [request access](https://www.linkedin.com/in/harshagv/).
