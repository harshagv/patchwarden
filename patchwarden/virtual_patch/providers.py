"""Edge providers that can hold a virtual patch: Cloudflare, Akamai, AWS WAF, and a demo WAF.

Each provider does three things, and each is safe to repeat (a job that crashes is simply run again):
- describe(): the rules it would add, shown in the dry run;
- apply(tag): add the rules unless rules with this tag already exist; returns references to them;
- remove(tag, ref): delete the rules with this tag; nothing to delete is fine.

Cloudflare: Rulesets API, a custom rule in the zone's http_request_firewall_custom phase.
  Token permission: Zone > Zone WAF > Edit, for that zone only.
Akamai: Application Security API custom rule, attached to a security policy with action "deny", then
  the configuration version is activated. Requests are signed with EdgeGrid (EG1-HMAC-SHA256).
  NOT verified against a live Akamai account: field names follow Akamai's public API reference, and the
  tests check the request flow and the signing, not Akamai's acceptance.
AWS WAF (WAFv2; Shield Advanced customers use the same WAF): the AWS managed PHP rule group plus a
  custom block rule, added to an existing web ACL with optimistic locking (LockToken).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx

from ..fakes import DEMO_SUFFIX, DemoWorld
from .signatures import RULE_TAG, SIGNATURES, cloudflare_expression

KINDS = ("cloudflare", "akamai", "aws_waf", "demo")


class ProviderError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def _need(config: dict, *keys: str, pattern: str = r"^[A-Za-z0-9_\-.:]{1,128}$") -> dict:
    out = {}
    for key in keys:
        value = str(config.get(key) or "").strip()
        if not re.match(pattern, value):
            raise ProviderError("invalid_config", f"Give a valid {key.replace('_', ' ')}.")
        out[key] = value
    return out


# --- Cloudflare -------------------------------------------------------------------------

class Cloudflare:
    kind = "cloudflare"
    API = "https://api.cloudflare.com/client/v4"
    PHASE = "http_request_firewall_custom"

    def __init__(self, config: dict, secret: str, transport: httpx.AsyncBaseTransport | None = None):
        self.config = _need(config, "zone_id", pattern=r"^[a-f0-9]{32}$")
        if not secret:
            raise ProviderError("secret_required", "Add a Cloudflare API token with Zone WAF Edit permission for this zone.")
        self._client = httpx.AsyncClient(base_url=self.API, transport=transport, timeout=30, trust_env=False,
                                         headers={"Authorization": f"Bearer {secret}"})

    def describe(self) -> dict:
        return {"where": f"Cloudflare zone {self.config['zone_id']}, custom rules ({self.PHASE})",
                "rules": [{"action": "block", "expression": cloudflare_expression()}]}

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _call(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        try:
            r = await self._client.request(method, path, json=body)
            data = r.json() if r.content else {}
        except (httpx.HTTPError, ValueError):
            raise ProviderError("provider_unreachable", "We could not reach Cloudflare.") from None
        if r.status_code in (401, 403):
            raise ProviderError("provider_denied", "Cloudflare refused the token. Check its permissions and zone.")
        return r.status_code, data if isinstance(data, dict) else {}

    async def _entrypoint(self) -> dict | None:
        status, data = await self._call("GET", f"/zones/{self.config['zone_id']}/rulesets/phases/{self.PHASE}/entrypoint")
        if status == 404:
            return None
        if status != 200:
            raise ProviderError("provider_error", f"Cloudflare answered HTTP {status}.")
        return data.get("result") or {}

    async def apply(self, tag: str) -> dict:
        rule = {"action": "block", "expression": cloudflare_expression(), "description": tag, "enabled": True}
        ep = await self._entrypoint()
        if ep is None:  # no custom rules yet in this zone: create the phase entry point with our rule
            status, data = await self._call("PUT", f"/zones/{self.config['zone_id']}/rulesets/phases/{self.PHASE}/entrypoint",
                                            {"rules": [rule]})
            ep = data.get("result") or {}
        else:
            existing = next((r for r in ep.get("rules", []) if r.get("description") == tag), None)
            if existing is not None:
                return {"ruleset_id": ep["id"], "rule_id": existing["id"], "already": True}
            status, data = await self._call("POST", f"/zones/{self.config['zone_id']}/rulesets/{ep['id']}/rules", rule)
            ep = data.get("result") or {}
        if status not in (200, 201):
            raise ProviderError("provider_error", f"Cloudflare did not accept the rule (HTTP {status}).")
        ours = next((r for r in ep.get("rules", []) if r.get("description") == tag), None)
        if ours is None:
            raise ProviderError("provider_error", "Cloudflare did not return the new rule.")
        return {"ruleset_id": ep["id"], "rule_id": ours["id"]}

    async def remove(self, tag: str, ref: dict) -> dict:
        ep = await self._entrypoint()
        ours = [r for r in (ep or {}).get("rules", []) if r.get("description") == tag]
        for r in ours:
            status, _ = await self._call("DELETE", f"/zones/{self.config['zone_id']}/rulesets/{ep['id']}/rules/{r['id']}")
            if status not in (200, 204, 404):
                raise ProviderError("provider_error", f"Cloudflare did not delete the rule (HTTP {status}).")
        return {"removed": len(ours)}


# --- Akamai -----------------------------------------------------------------------------

def edgegrid_header(*, client_token: str, client_secret: str, access_token: str, method: str, url: str,
                    body: bytes = b"", timestamp: str | None = None, nonce: str | None = None,
                    max_body: int = 131072) -> str:
    """Akamai EdgeGrid EG1-HMAC-SHA256 Authorization header."""
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H:%M:%S+0000")
    auth = (f"EG1-HMAC-SHA256 client_token={client_token};access_token={access_token};"
            f"timestamp={ts};nonce={nonce or uuid.uuid4()};")
    parts = urlsplit(url)
    path = parts.path + (f"?{parts.query}" if parts.query else "")
    content_hash = (base64.b64encode(hashlib.sha256(body[:max_body]).digest()).decode()
                    if method.upper() == "POST" and body else "")
    data = "\t".join([method.upper(), parts.scheme, parts.netloc, path, "", content_hash, auth])
    signing_key = base64.b64encode(hmac.new(client_secret.encode(), ts.encode(), hashlib.sha256).digest())
    signature = base64.b64encode(hmac.new(signing_key, data.encode(), hashlib.sha256).digest()).decode()
    return auth + f"signature={signature}"


class Akamai:
    kind = "akamai"

    def __init__(self, config: dict, secret: str, transport: httpx.AsyncBaseTransport | None = None):
        self.config = _need(config, "config_id", "version", "policy_id")
        self.config["network"] = "PRODUCTION" if str(config.get("network", "")).upper() == "PRODUCTION" else "STAGING"
        try:
            creds = json.loads(secret or "{}")
            self.creds = {k: str(creds[k]) for k in ("host", "client_token", "client_secret", "access_token")}
        except (ValueError, KeyError, TypeError):
            raise ProviderError("secret_required", "Add the EdgeGrid credentials as JSON: host, client_token, "
                                                   "client_secret, access_token.") from None
        if not re.match(r"^[a-z0-9\-]+\.luna\.akamaiapis\.net$", self.creds["host"]):
            raise ProviderError("invalid_config", "The EdgeGrid host must be an *.luna.akamaiapis.net address.")
        self.base = f"https://{self.creds['host']}"
        self._client = httpx.AsyncClient(transport=transport, timeout=30, trust_env=False)

    def rule_body(self, tag: str) -> dict:
        return {"name": tag, "description": "Patchwarden virtual patch: PHP code-injection request patterns",
                "operation": "OR",
                "conditions": [{"type": "requestUriMatch", "positiveMatch": True, "valueWildcard": True,
                                "valueCase": False, "value": [f"*{s.contains}*"]} for s in SIGNATURES]}

    def describe(self) -> dict:
        c = self.config
        return {"where": f"Akamai security configuration {c['config_id']} v{c['version']}, policy {c['policy_id']}, "
                         f"activated on {c['network']}",
                "rules": [{"action": "deny", "conditions": [f"*{s.contains}*" for s in SIGNATURES]}],
                "note": "Akamai support is not verified against a live account yet."}

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _call(self, method: str, path: str, body: dict | None = None) -> tuple[int, Any]:
        url = self.base + path
        raw = json.dumps(body).encode() if body is not None else b""
        headers = {"Authorization": edgegrid_header(method=method, url=url, body=raw, **{
            k: self.creds[k] for k in ("client_token", "client_secret", "access_token")})}
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            r = await self._client.request(method, url, content=raw or None, headers=headers)
            data = r.json() if r.content else {}
        except (httpx.HTTPError, ValueError):
            raise ProviderError("provider_unreachable", "We could not reach Akamai.") from None
        if r.status_code in (401, 403):
            raise ProviderError("provider_denied", "Akamai refused the EdgeGrid credentials. Check their API access.")
        if r.status_code >= 400:
            raise ProviderError("provider_error", f"Akamai answered HTTP {r.status_code}.")
        return r.status_code, data

    async def _find(self, tag: str) -> dict | None:
        _, data = await self._call("GET", f"/appsec/v1/configs/{self.config['config_id']}/custom-rules")
        return next((r for r in (data or {}).get("customRules", []) if r.get("name") == tag), None)

    def _policy_rule(self, rule_id) -> str:
        c = self.config
        return (f"/appsec/v1/configs/{c['config_id']}/versions/{c['version']}/security-policies/"
                f"{c['policy_id']}/custom-rules/{rule_id}")

    async def _activate(self) -> dict:
        c = self.config
        _, data = await self._call("POST", "/appsec/v1/activations", {
            "action": "ACTIVATE", "network": c["network"], "note": "Patchwarden virtual patch",
            "notificationEmails": [], "activationConfigs": [{"configId": int(c["config_id"]) if c["config_id"].isdigit()
                                                             else c["config_id"], "configVersion": int(c["version"])
                                                             if c["version"].isdigit() else c["version"]}]})
        return {"activation_id": (data or {}).get("activationId")}

    async def apply(self, tag: str) -> dict:
        rule = await self._find(tag)
        if rule is None:
            _, rule = await self._call("POST", f"/appsec/v1/configs/{self.config['config_id']}/custom-rules",
                                       self.rule_body(tag))
        await self._call("PUT", self._policy_rule(rule["id"]), {"action": "deny"})
        return {"rule_id": rule["id"], **await self._activate()}

    async def remove(self, tag: str, ref: dict) -> dict:
        rule = await self._find(tag)
        if rule is None:
            return {"removed": 0}
        await self._call("PUT", self._policy_rule(rule["id"]), {"action": "none"})
        await self._call("DELETE", f"/appsec/v1/configs/{self.config['config_id']}/custom-rules/{rule['id']}")
        return {"removed": 1, **await self._activate()}


# --- AWS WAF (WAFv2) --------------------------------------------------------------------

_KEEP = ("Description", "CustomResponseBodies", "CaptchaConfig", "ChallengeConfig", "TokenDomains",
         "AssociationConfig")


def aws_client(config: dict, secret: str):
    import boto3

    creds = json.loads(secret) if secret else {}
    return boto3.client("wafv2", region_name=config["region"],
                        aws_access_key_id=creds.get("aws_access_key_id"),
                        aws_secret_access_key=creds.get("aws_secret_access_key"))


def _update_error(exc) -> ProviderError:
    code = exc.response.get("Error", {}).get("Code", "error")
    if code == "WAFOptimisticLockException":  # someone changed the ACL meanwhile: the job retries
        return ProviderError("provider_busy", "The web ACL changed while we were updating it; trying again.")
    return ProviderError("provider_error", f"AWS WAF did not accept the change ({code}).")


class AwsWaf:
    kind = "aws_waf"

    def __init__(self, config: dict, secret: str, client_factory: Callable[[dict, str], Any] | None = None):
        self.config = _need(config, "web_acl_name", "web_acl_id", "region")
        scope = str(config.get("scope", "REGIONAL")).upper()
        if scope not in ("REGIONAL", "CLOUDFRONT"):
            raise ProviderError("invalid_config", "Scope must be REGIONAL or CLOUDFRONT.")
        if scope == "CLOUDFRONT":
            self.config["region"] = "us-east-1"  # CloudFront web ACLs live in us-east-1
        self.config["scope"] = scope
        if secret:
            try:
                creds = json.loads(secret)
                assert creds.get("aws_access_key_id") and creds.get("aws_secret_access_key")
            except (ValueError, AssertionError, AttributeError):
                raise ProviderError("secret_required", "Give the AWS keys as JSON: aws_access_key_id, "
                                                       "aws_secret_access_key (or leave empty to use the server's role).") from None
        self._client = (client_factory or aws_client)(self.config, secret)

    def describe(self) -> dict:
        c = self.config
        return {"where": f"AWS WAF web ACL {c['web_acl_name']} ({c['scope']}, {c['region']})",
                "rules": [{"action": "managed rule group", "name": "AWS-AWSManagedRulesPHPRuleSet"},
                          {"action": "block", "conditions": [f"{s.field} contains {s.contains!r}" for s in SIGNATURES]}]}

    async def aclose(self) -> None:
        return None

    def _rules(self, tag: str, priority: int) -> list[dict]:
        visibility = lambda name: {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,  # noqa: E731
                                   "MetricName": name}
        field = {"query": {"QueryString": {}}, "path": {"UriPath": {}}}
        matches = [{"ByteMatchStatement": {
            "SearchString": s.contains.encode(), "FieldToMatch": field[s.field], "PositionalConstraint": "CONTAINS",
            "TextTransformations": [{"Priority": 0, "Type": "URL_DECODE"}, {"Priority": 1, "Type": "LOWERCASE"}]}}
            for s in SIGNATURES]
        return [
            {"Name": f"{tag}-php", "Priority": priority,
             "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesPHPRuleSet"}},
             "OverrideAction": {"None": {}}, "VisibilityConfig": visibility(f"{tag}-php")},
            {"Name": f"{tag}-sig", "Priority": priority + 1, "Statement": {"OrStatement": {"Statements": matches}},
             "Action": {"Block": {}}, "VisibilityConfig": visibility(f"{tag}-sig")},
        ]

    def _update(self, acl: dict, token: str, rules: list[dict]) -> None:
        c = self.config
        extra = {k: acl[k] for k in _KEEP if acl.get(k)}
        self._client.update_web_acl(Name=c["web_acl_name"], Scope=c["scope"], Id=c["web_acl_id"],
                                    DefaultAction=acl["DefaultAction"], Rules=rules,
                                    VisibilityConfig=acl["VisibilityConfig"], LockToken=token, **extra)

    def _get(self) -> tuple[dict, str]:
        from botocore.exceptions import BotoCoreError, ClientError

        c = self.config
        try:
            resp = self._client.get_web_acl(Name=c["web_acl_name"], Scope=c["scope"], Id=c["web_acl_id"])
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("AccessDeniedException", "WAFNonexistentItemException"):
                raise ProviderError("provider_denied", "AWS WAF refused the request or the web ACL does not exist.") from None
            raise ProviderError("provider_error", f"AWS WAF answered {code or 'an error'}.") from None
        except BotoCoreError:
            raise ProviderError("provider_unreachable", "We could not reach AWS WAF.") from None
        return resp["WebACL"], resp["LockToken"]

    async def apply(self, tag: str) -> dict:
        from botocore.exceptions import ClientError

        acl, token = await asyncio.to_thread(self._get)
        rules = acl.get("Rules", [])
        if any(r["Name"].startswith(tag) for r in rules):
            return {"rules": [r["Name"] for r in rules if r["Name"].startswith(tag)], "already": True}
        new = self._rules(tag, max((r["Priority"] for r in rules), default=0) + 1)
        try:
            await asyncio.to_thread(self._update, acl, token, rules + new)
        except ClientError as exc:
            raise _update_error(exc) from None
        return {"rules": [r["Name"] for r in new]}

    async def remove(self, tag: str, ref: dict) -> dict:
        from botocore.exceptions import ClientError

        acl, token = await asyncio.to_thread(self._get)
        keep = [r for r in acl.get("Rules", []) if not r["Name"].startswith(tag)]
        removed = len(acl.get("Rules", [])) - len(keep)
        if removed:
            try:
                await asyncio.to_thread(self._update, acl, token, keep)
            except ClientError as exc:
                raise _update_error(exc) from None
        return {"removed": removed}


# --- demo -------------------------------------------------------------------------------

class DemoWaf:
    """A fake edge for *.demo.patchwarden.test: rules live in the demo world."""

    kind = "demo"

    def __init__(self, config: dict, world: DemoWorld | None, domain: str):
        if world is None or not domain.endswith(DEMO_SUFFIX):
            raise ProviderError("invalid_provider", "The demo WAF only works for demo sites.")
        self.world, self.domain = world, domain

    def describe(self) -> dict:
        return {"where": f"Demo WAF in front of {self.domain}",
                "rules": [{"action": "block", "conditions": [f"{s.field} contains {s.contains!r}" for s in SIGNATURES]}]}

    async def aclose(self) -> None:
        return None

    async def apply(self, tag: str) -> dict:
        rules = self.world.waf_rules.setdefault(self.domain, [])
        if tag not in rules:
            rules.append(tag)
        return {"rules": [tag]}

    async def remove(self, tag: str, ref: dict) -> dict:
        rules = self.world.waf_rules.get(self.domain, [])
        removed = rules.count(tag)
        self.world.waf_rules[self.domain] = [r for r in rules if r != tag]
        return {"removed": removed}


def build(kind: str, config: dict, secret: str, *, domain: str, world: DemoWorld | None,
          http_transport: httpx.AsyncBaseTransport | None = None, aws_factory=None):
    if kind == "cloudflare":
        return Cloudflare(config, secret, http_transport)
    if kind == "akamai":
        return Akamai(config, secret, http_transport)
    if kind == "aws_waf":
        return AwsWaf(config, secret, aws_factory)
    if kind == "demo":
        return DemoWaf(config, world, domain)
    raise ProviderError("invalid_provider", "Pick cloudflare, akamai, aws_waf (or demo for demo sites).")


def tag_for(vp_id: int) -> str:
    return f"{RULE_TAG}-{vp_id}"
