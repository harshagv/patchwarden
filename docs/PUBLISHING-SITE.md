# Publishing the website to patchwarden.harshagv.me

The website lives in [`site/`](../site). It is plain static files, built locally and committed. A GitHub
Actions workflow ([`.github/workflows/pages.yml`](../.github/workflows/pages.yml)) publishes it with GitHub
Pages, straight from this repository.

| | |
| --- | --- |
| Repository | [`harshagv/patchwarden`](https://github.com/harshagv/patchwarden) (public) |
| Address | `https://patchwarden.harshagv.me` |
| Pages source | GitHub Actions, publishing `site/` on every push to `main` that changes it |

## Subdomain, not a path

The site is served at **`https://patchwarden.harshagv.me`**, not at `harshagv.me/patchwarden`.

- Your user site (`harshagv.github.io`) uses the custom domain `www.harshagv.me`. Any of your project repositories that has **no custom domain of its own** is automatically served at `www.harshagv.me/<repo-name>`. In this case that would be `www.harshagv.me/patchwarden`.
- Step 3 below sets this repository's own custom domain, which moves the site to `patchwarden.harshagv.me`.
- The site uses relative links (and `404.html` uses root links), so it is built for the subdomain root.

## 1. Add the DNS record (once)

At the DNS provider for `harshagv.me`, add:

| Type | Host / name | Value | TTL |
| --- | --- | --- | --- |
| `CNAME` | `patchwarden` | `harshagv.github.io.` | default (or 3600) |

Recommended: verify `harshagv.me` for GitHub Pages, under GitHub → Settings → Pages → *Add a verified domain*.
This means nobody else can claim `*.harshagv.me` on GitHub Pages, which prevents subdomain takeover. GitHub
shows you a TXT record to add.

Check that the record is live (it can take a few minutes, and up to a few hours):

```bash
dig patchwarden.harshagv.me +short
```

It should print `harshagv.github.io.` followed by GitHub's addresses.

## 2. Push the code

```bash
cd ~/Documents/patchwarden
```

```bash
git add -A && git commit -m "Add Patchwarden: code, docs and website"
```

```bash
git push origin main
```

## 3. Turn on GitHub Pages with the custom domain (once)

Tell Pages to publish from GitHub Actions:

```bash
gh api -X POST repos/harshagv/patchwarden/pages -f build_type=workflow
```

Set the custom domain. With Actions publishing, this setting decides the domain; `site/CNAME` is only a reminder.

```bash
gh api -X PUT repos/harshagv/patchwarden/pages -f cname=patchwarden.harshagv.me
```

Run the first deployment (later pushes that change `site/` deploy automatically):

```bash
gh workflow run pages.yml --repo harshagv/patchwarden
```

```bash
gh run watch --repo harshagv/patchwarden
```

After GitHub has issued the certificate (usually within an hour of the DNS record working), enforce HTTPS:

```bash
gh api -X PUT repos/harshagv/patchwarden/pages -F https_enforced=true
```

## 4. Check it is on the subdomain

```bash
gh api repos/harshagv/patchwarden/pages --jq '{cname, html_url, https_enforced, build_type}'
```

It should show `"cname": "patchwarden.harshagv.me"`, `"html_url": "https://patchwarden.harshagv.me/"` and `"build_type": "workflow"`.

```bash
curl -sI https://patchwarden.harshagv.me | head -1
```

It should print `HTTP/2 200`.

## Updating the site later

`make site` regenerates `site/docs/index.html` (from `docs/TECHNICAL.md`) and the example screens in
`site/examples/` (from the built-in demo sites). The build refuses to finish if any page contains a local
path, a token or a secret. Commit the result and push; the workflow publishes it.

```bash
make site
```

```bash
git add site docs && git commit -m "Update website" && git push
```

To preview locally first:

```bash
python3 -m http.server 8790 --bind 127.0.0.1 --directory site
```

Then open `http://127.0.0.1:8790`.

## What to change before you share it widely

- **Contact.** The "Request access" buttons point to your LinkedIn. Search for `linkedin.com/in/harshagv` in `site/index.html` and in `scripts/build_site.py` to change them.
- **Status table.** Update the "What is ready today" section in `site/index.html` as the cPanel/Plesk connectors and Docker deployment are verified.
