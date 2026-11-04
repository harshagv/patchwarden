"""Phase E: virtual patches at the edge. Dry run, approval, durable apply/remove, three real providers
(mocked at their API boundary) and a demo WAF."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import boto3
import httpx
import pytest
from botocore.stub import ANY, Stubber

from patchwarden.jobs import JobQueue, make_handlers
from patchwarden.models import AuditLog, User, VirtualPatch
from patchwarden.virtual_patch import service
from patchwarden.virtual_patch.providers import AwsWaf, edgegrid_header, tag_for
from patchwarden.virtual_patch.signatures import blocks, cloudflare_expression

from ..conftest import demo
from ..spec.test_phase2_acceptance import add_site
from ..unit.test_watchdog import _admin
from .test_phaseD_monetization import share, team, user

ZONE = "0123456789abcdef0123456789abcdef"
CF_TOKEN = "cfTokenCanary9Xq"  # test-only value; must never come back in a response
AK_SECRET = "-".join(["ak", "canary", "value"])  # test-only value, built so scanners do not flag it


def run(coro):
    return asyncio.run(coro)


def plan(client, auth, site_id: int, provider: str, config: dict | None = None, secret: str | None = None):
    return client.post(f"/api/sites/{site_id}/virtual-patches",
                       json={"provider": provider, "config": config or {}, "secret": secret}, headers=auth)


def get(client, auth, vp_id: int) -> dict:
    return client.get(f"/api/virtual-patches/{vp_id}", headers=auth).json()


# --- signatures ------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://s.example/index.php?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input",
    "https://s.example/?page=php%3A%2F%2Ffilter/convert.base64-encode/resource=index",
    "https://s.example/?x=%3C%3Fphp+system(id)%3B",
    "https://s.example/cgi-bin/php-cgi?foo",
    "https://s.example/?p=DATA://text/plain;base64,PD9waHA=",
])
def test_attack_shapes_are_blocked(url):
    assert blocks(url) is not None


@pytest.mark.parametrize("url", [
    "https://s.example/", "https://s.example/checkout?item=42&qty=1", "https://s.example/blog/php-tips?q=include",
])
def test_normal_requests_pass(url):
    assert blocks(url) is None


def test_the_cloudflare_expression_covers_every_signature():
    expr = cloudflare_expression()
    assert expr.count(" or ") == 6 and 'contains "allow_url_include"' in expr
    assert "lower(url_decode(http.request.uri.query))" in expr


# --- the flow (demo WAF) -----------------------------------------------------------------

def test_a_virtual_patch_goes_live_only_after_approval_and_comes_off_cleanly(client, auth_headers, world):
    site_id = add_site(client, auth_headers, "shop84")
    r = plan(client, auth_headers, site_id, "demo")
    assert r.status_code == 201, r.text
    vp = r.json()
    assert vp["state"] == "planned" and vp["plan"]["changes_made"].startswith("None yet")
    assert {b["id"] for b in vp["plan"]["blocks"]} >= {"ini-allow-url-include", "php-cgi-direct"}
    assert world.waf_rules == {}  # a dry run touches nothing

    assert client.post(f"/api/virtual-patches/{vp['id']}/approve", headers=auth_headers).status_code == 202
    live = get(client, auth_headers, vp["id"])
    assert live["state"] == "active" and live["activated_at"]
    assert world.waf_rules[demo("shop84")] == [tag_for(vp["id"])]
    again = plan(client, auth_headers, site_id, "demo")
    assert again.status_code == 409 and again.json()["error"] == "virtual_patch_exists"

    assert client.post(f"/api/virtual-patches/{vp['id']}/remove", headers=auth_headers).status_code == 202
    assert get(client, auth_headers, vp["id"])["state"] == "removed" and world.waf_rules[demo("shop84")] == []
    with client.app.state.sessionmaker() as db:
        actions = [a.action for a in db.query(AuditLog).filter(AuditLog.action.like("virtual_patch.%"))]
    assert actions == ["virtual_patch.planned", "virtual_patch.approved", "virtual_patch.active",
                       "virtual_patch.removal_requested", "virtual_patch.removed"]


def test_roles_and_the_four_eyes_rule_apply_to_virtual_patches(client, auth_headers, world):
    member, lead = user(client, "dev@example.com"), user(client, "lead@example.com")
    org = team(client, auth_headers, {"dev@example.com": "member", "lead@example.com": "approver"})
    client.patch(f"/api/orgs/{org}", json={"require_separate_approver": True}, headers=auth_headers)
    site_id = add_site(client, auth_headers, "shop84")
    share(client, auth_headers, site_id, org)
    assert plan(client, lead, site_id, "demo").json()["error"] == "edit_not_allowed"
    vp = plan(client, member, site_id, "demo").json()
    assert client.post(f"/api/virtual-patches/{vp['id']}/approve", headers=member).json()["error"] == "approve_not_allowed"
    assert client.post(f"/api/virtual-patches/{vp['id']}/approve", headers=_admin(client)).status_code == 403
    assert world.waf_rules == {}
    assert client.post(f"/api/virtual-patches/{vp['id']}/approve", headers=lead).status_code == 202
    assert get(client, lead, vp["id"])["state"] == "active"
    assert client.get(f"/api/virtual-patches/{vp['id']}", headers=user(client, "x@example.com")).status_code == 404

    # The owner can approve, but not a patch they planned themselves while the four-eyes rule is on.
    other = add_site(client, auth_headers, "fragile84")
    share(client, auth_headers, other, org)
    mine = plan(client, auth_headers, other, "demo").json()
    r = client.post(f"/api/virtual-patches/{mine['id']}/approve", headers=auth_headers)
    assert r.status_code == 403 and r.json()["error"] == "separate_approver_required"


def test_the_demo_waf_is_only_for_demo_sites(client, auth_headers):
    site_id = client.post("/api/sites", json={"domain": "example.org"}, headers=auth_headers).json()["id"]
    r = plan(client, auth_headers, site_id, "demo")
    assert r.status_code == 422 and r.json()["error"] == "invalid_provider"
    assert plan(client, auth_headers, site_id, "fastly").json()["error"] == "invalid_provider"


def test_an_approved_patch_survives_a_restart(client, auth_headers, world):
    site_id = add_site(client, auth_headers, "shop84")
    vp = plan(client, auth_headers, site_id, "demo").json()
    with client.app.state.sessionmaker() as db:  # approved, then the server died before the job was recorded
        service.approve(db, db.get(VirtualPatch, vp["id"]), db.query(User).filter_by(email="owner@example.com").one())
    assert client.app.state.jobs.reconcile_orphans() == 1
    run(client.app.state.jobs.run_pending())
    assert get(client, auth_headers, vp["id"])["state"] == "active"
    assert world.waf_rules[demo("shop84")] == [tag_for(vp["id"])]


def test_an_active_virtual_patch_is_billed_monthly(client, auth_headers):
    site_id = add_site(client, auth_headers, "shop84")
    vp = plan(client, auth_headers, site_id, "demo").json()
    client.post(f"/api/virtual-patches/{vp['id']}/approve", headers=auth_headers)
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    rows = client.get("/api/admin/billing", params={"month": month}, headers=_admin(client)).json()["rows"]
    assert [(r["item"], r["amount"], r["ref"]) for r in rows] == [("virtual_patch", 19, f"virtual_patch:{vp['id']}")]
    last = (datetime.now(timezone.utc).replace(day=1) - timedelta(days=1)).strftime("%Y-%m")
    assert client.get("/api/admin/billing", params={"month": last}, headers=_admin(client)).json()["rows"] == []

    # Removed before this month started: nothing to bill this month.
    with client.app.state.sessionmaker() as db:
        row = db.get(VirtualPatch, vp["id"])
        row.activated_at = datetime.now(timezone.utc).replace(day=1) - timedelta(days=40)
        row.removed_at, row.state = datetime.now(timezone.utc).replace(day=1) - timedelta(days=20), "removed"
        db.commit()
    assert client.get("/api/admin/billing", params={"month": month}, headers=_admin(client)).json()["rows"] == []


# --- Cloudflare ---------------------------------------------------------------------------

class FakeCloudflare:
    def __init__(self, *, entrypoint: bool = True, status: int = 200):
        self.rules: list[dict] = [{"id": "r-existing", "description": "customer rule", "expression": "true"}]
        self.entrypoint, self.status = entrypoint, status
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.status != 200:
            return httpx.Response(self.status, json={"success": False})
        path, method = request.url.path, request.method
        ep = f"/client/v4/zones/{ZONE}/rulesets/phases/http_request_firewall_custom/entrypoint"
        body = json.loads(request.content) if request.content else {}
        result = lambda: {"success": True, "result": {"id": "rs-1", "rules": self.rules}}  # noqa: E731
        if path == ep and method == "GET":
            return httpx.Response(200, json=result()) if self.entrypoint else httpx.Response(404, json={"success": False})
        if path == ep and method == "PUT":
            self.entrypoint = True
            self.rules = [{**r, "id": f"r-{i}"} for i, r in enumerate(body["rules"])]
            return httpx.Response(200, json=result())
        if path == f"/client/v4/zones/{ZONE}/rulesets/rs-1/rules" and method == "POST":
            self.rules.append({**body, "id": f"r-{len(self.rules)}"})
            return httpx.Response(200, json=result())
        if path.startswith(f"/client/v4/zones/{ZONE}/rulesets/rs-1/rules/") and method == "DELETE":
            self.rules = [r for r in self.rules if r["id"] != path.rsplit("/", 1)[1]]
            return httpx.Response(200, json=result())
        return httpx.Response(404, json={"success": False})


def with_cloudflare(client, fake: FakeCloudflare) -> None:
    client.app.state.vpatch_http_transport = httpx.MockTransport(fake.handler)


def test_cloudflare_rule_is_added_once_and_removed(client, auth_headers):
    cf = FakeCloudflare()
    with_cloudflare(client, cf)
    site_id = add_site(client, auth_headers, "shop84")
    r = plan(client, auth_headers, site_id, "cloudflare", {"zone_id": ZONE}, CF_TOKEN)
    assert r.status_code == 201 and cf.requests == []  # the dry run does not call Cloudflare
    vp = r.json()
    assert CF_TOKEN not in r.text and vp["has_secret"] is True and vp["config"] == {"zone_id": ZONE}

    client.post(f"/api/virtual-patches/{vp['id']}/approve", headers=auth_headers)
    assert get(client, auth_headers, vp["id"])["state"] == "active"
    ours = [x for x in cf.rules if x.get("description") == tag_for(vp["id"])]
    assert len(ours) == 1 and ours[0]["action"] == "block" and ours[0]["expression"] == cloudflare_expression()
    assert all(q.headers["authorization"] == f"Bearer {CF_TOKEN}" for q in cf.requests)

    # Running the apply step again (a job resumed after a crash) does not add a second rule.
    with client.app.state.sessionmaker() as db:
        db.get(VirtualPatch, vp["id"]).state = "applying"
        db.commit()
    s = client.app.state
    run(service.run(s.sessionmaker, s.vault, s.demo_world, vp["id"], None, "apply", state=s))
    assert len([x for x in cf.rules if x.get("description") == tag_for(vp["id"])]) == 1

    client.post(f"/api/virtual-patches/{vp['id']}/remove", headers=auth_headers)
    assert [x["id"] for x in cf.rules] == ["r-existing"]  # the customer's own rule is untouched
    with client.app.state.sessionmaker() as db:
        assert all(CF_TOKEN not in json.dumps(a.detail) for a in db.query(AuditLog))


def test_cloudflare_entry_point_is_created_when_the_zone_has_no_custom_rules(client, auth_headers):
    cf = FakeCloudflare(entrypoint=False)
    with_cloudflare(client, cf)
    vp = plan(client, auth_headers, add_site(client, auth_headers, "shop84"), "cloudflare", {"zone_id": ZONE}, CF_TOKEN).json()
    client.post(f"/api/virtual-patches/{vp['id']}/approve", headers=auth_headers)
    assert get(client, auth_headers, vp["id"])["state"] == "active"
    assert [r.method for r in cf.requests] == ["GET", "PUT"]


def test_a_refused_token_fails_plainly(client, auth_headers):
    with_cloudflare(client, FakeCloudflare(status=403))
    vp = plan(client, auth_headers, add_site(client, auth_headers, "shop84"), "cloudflare", {"zone_id": ZONE}, CF_TOKEN).json()
    client.post(f"/api/virtual-patches/{vp['id']}/approve", headers=auth_headers)
    failed = get(client, auth_headers, vp["id"])
    assert failed["state"] == "failed" and failed["report"]["error"] == "provider_denied"
    assert "permissions" in failed["report"]["message"] and CF_TOKEN not in json.dumps(failed)


def test_an_unreachable_provider_is_retried_then_given_up(client, auth_headers):
    def down(request):
        raise httpx.ConnectError("down")
    client.app.state.vpatch_http_transport = httpx.MockTransport(down)
    vp = plan(client, auth_headers, add_site(client, auth_headers, "shop84"), "cloudflare", {"zone_id": ZONE}, CF_TOKEN).json()
    client.post(f"/api/virtual-patches/{vp['id']}/approve", headers=auth_headers)
    assert get(client, auth_headers, vp["id"])["state"] == "applying"  # not failed yet: the job retries
    clock = {"now": datetime.now(timezone.utc)}
    queue = JobQueue(client.app.state.sessionmaker, make_handlers(client.app.state), clock=lambda: clock["now"])
    for _ in range(6):
        clock["now"] += timedelta(minutes=10)
        run(queue.run_pending())
    gave_up = get(client, auth_headers, vp["id"])
    assert gave_up["state"] == "failed" and gave_up["report"]["error"] == "gave_up"


@pytest.mark.parametrize("config,code", [({"zone_id": "not-a-zone"}, "invalid_config"), ({"zone_id": ZONE}, "secret_required")])
def test_cloudflare_settings_are_checked_in_the_dry_run(client, auth_headers, config, code):
    r = plan(client, auth_headers, add_site(client, auth_headers, "shop84"), "cloudflare", config, None)
    assert r.status_code == 422 and r.json()["error"] == code


# --- Akamai ---------------------------------------------------------------------------

def reference_edgegrid(client_token, client_secret, access_token, method, url, body, ts, nonce):
    """An independent re-implementation from Akamai's published EdgeGrid description."""
    from urllib.parse import urlparse

    u = urlparse(url)
    head = f"EG1-HMAC-SHA256 client_token={client_token};access_token={access_token};timestamp={ts};nonce={nonce};"
    content = base64.b64encode(hashlib.sha256(body).digest()).decode() if method == "POST" and body else ""
    to_sign = f"{method}\t{u.scheme}\t{u.netloc}\t{u.path}{'?' + u.query if u.query else ''}\t\t{content}\t{head}"
    key = base64.b64encode(hmac.new(client_secret.encode(), ts.encode(), hashlib.sha256).digest())
    return head + "signature=" + base64.b64encode(hmac.new(key, to_sign.encode(), hashlib.sha256).digest()).decode()


@pytest.mark.parametrize("method,body", [("GET", b""), ("POST", b'{"name":"x"}')])
def test_edgegrid_signature_matches_the_reference(method, body):
    args = dict(client_token="akab-c", client_secret=AK_SECRET, access_token="akab-a", method=method,
                url="https://akab-h.luna.akamaiapis.net/appsec/v1/configs/1/custom-rules?x=1", body=body)
    ts, nonce = "20261104T10:00:00+0000", "nonce-1"
    assert edgegrid_header(**args, timestamp=ts, nonce=nonce) == reference_edgegrid(**args, ts=ts, nonce=nonce)
    assert AK_SECRET not in edgegrid_header(**args)


class FakeAkamai:
    def __init__(self):
        self.calls: list[tuple[str, str]] = []
        self.rules: list[dict] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"].startswith("EG1-HMAC-SHA256 client_token=akab-c;")
        self.calls.append((request.method, request.url.path))
        p = request.url.path
        if p == "/appsec/v1/configs/77/custom-rules" and request.method == "GET":
            return httpx.Response(200, json={"customRules": self.rules})
        if p == "/appsec/v1/configs/77/custom-rules" and request.method == "POST":
            rule = {**json.loads(request.content), "id": 661}
            self.rules.append(rule)
            return httpx.Response(200, json=rule)
        if p == "/appsec/v1/activations":
            return httpx.Response(200, json={"activationId": 9001})
        if p == "/appsec/v1/configs/77/custom-rules/661" and request.method == "DELETE":
            self.rules = []
            return httpx.Response(204)
        return httpx.Response(200, json={})


def test_akamai_rule_is_created_attached_activated_and_removed(client, auth_headers):
    ak = FakeAkamai()
    client.app.state.vpatch_http_transport = httpx.MockTransport(ak.handler)
    creds = json.dumps({"host": "akab-h.luna.akamaiapis.net", "client_token": "akab-c", "client_secret": AK_SECRET,
                        "access_token": "akab-a"})
    vp = plan(client, auth_headers, add_site(client, auth_headers, "shop84"), "akamai",
              {"config_id": "77", "version": "4", "policy_id": "pol_1", "network": "production"}, creds).json()
    assert "not verified" in vp["plan"]["note"] and AK_SECRET not in json.dumps(vp)
    client.post(f"/api/virtual-patches/{vp['id']}/approve", headers=auth_headers)
    active = get(client, auth_headers, vp["id"])
    assert active["state"] == "active", active
    policy = "/appsec/v1/configs/77/versions/4/security-policies/pol_1/custom-rules/661"
    assert ak.calls == [("GET", "/appsec/v1/configs/77/custom-rules"), ("POST", "/appsec/v1/configs/77/custom-rules"),
                        ("PUT", policy), ("POST", "/appsec/v1/activations")]
    client.post(f"/api/virtual-patches/{vp['id']}/remove", headers=auth_headers)
    assert get(client, auth_headers, vp["id"])["state"] == "removed" and ak.rules == []


def test_akamai_host_must_be_an_akamai_api_host(client, auth_headers):
    creds = json.dumps({"host": "169.254.169.254", "client_token": "a", "client_secret": "b", "access_token": "c"})
    r = plan(client, auth_headers, add_site(client, auth_headers, "shop84"), "akamai",
             {"config_id": "77", "version": "4", "policy_id": "pol_1"}, creds)
    assert r.status_code == 422 and r.json()["error"] == "invalid_config"


# --- AWS WAF --------------------------------------------------------------------------

ACL = {"Name": "shop-acl", "Id": "a1b2c3", "ARN": "arn:aws:wafv2:eu-west-1:123456789012:regional/webacl/shop-acl/a1b2c3",
       "DefaultAction": {"Allow": {}},
       "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "shop-acl"},
       "Rules": [{"Name": "rate-limit", "Priority": 3, "Statement": {"RateBasedStatement": {"Limit": 1000,
                                                                                            "AggregateKeyType": "IP"}},
                  "Action": {"Block": {}}, "VisibilityConfig": {"SampledRequestsEnabled": True,
                                                                 "CloudWatchMetricsEnabled": True, "MetricName": "rl"}}],
       "Capacity": 2}
AWS_CONFIG = {"web_acl_name": "shop-acl", "web_acl_id": "a1b2c3", "region": "eu-west-1", "scope": "regional"}


@pytest.fixture
def waf():
    c = boto3.client("wafv2", region_name="eu-west-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    with Stubber(c) as stub:
        yield c, stub
        stub.assert_no_pending_responses()


def test_aws_waf_adds_the_managed_php_rules_and_a_block_rule(client, auth_headers, waf):
    c, stub = waf
    client.app.state.vpatch_aws_factory = lambda config, secret: c
    vp = plan(client, auth_headers, add_site(client, auth_headers, "shop84"), "aws_waf", AWS_CONFIG).json()
    assert vp["config"]["scope"] == "REGIONAL"
    tag = tag_for(vp["id"])
    expected = AwsWaf(AWS_CONFIG, "", lambda *_: c)._rules(tag, 4)
    assert expected[0]["Statement"]["ManagedRuleGroupStatement"]["Name"] == "AWSManagedRulesPHPRuleSet"
    get_args = {"Name": "shop-acl", "Scope": "REGIONAL", "Id": "a1b2c3"}
    stub.add_response("get_web_acl", {"WebACL": ACL, "LockToken": "lock-1"}, get_args)
    # botocore checks every field against the WAFv2 API model here.
    stub.add_response("update_web_acl", {"NextLockToken": "lock-2"},
                      {**get_args, "DefaultAction": {"Allow": {}}, "Rules": ACL["Rules"] + expected,
                       "VisibilityConfig": ACL["VisibilityConfig"], "LockToken": "lock-1"})
    client.post(f"/api/virtual-patches/{vp['id']}/approve", headers=auth_headers)
    assert get(client, auth_headers, vp["id"])["state"] == "active"

    stub.add_response("get_web_acl", {"WebACL": {**ACL, "Rules": ACL["Rules"] + expected}, "LockToken": "lock-2"}, get_args)
    stub.add_response("update_web_acl", {"NextLockToken": "lock-3"},
                      {**get_args, "DefaultAction": ANY, "Rules": ACL["Rules"], "VisibilityConfig": ANY,
                       "LockToken": "lock-2"})
    client.post(f"/api/virtual-patches/{vp['id']}/remove", headers=auth_headers)
    assert get(client, auth_headers, vp["id"])["state"] == "removed"


def test_aws_waf_apply_is_idempotent_and_a_lock_conflict_is_retried(client, auth_headers, waf):
    c, stub = waf
    client.app.state.vpatch_aws_factory = lambda config, secret: c
    vp = plan(client, auth_headers, add_site(client, auth_headers, "shop84"), "aws_waf", AWS_CONFIG).json()
    get_args = {"Name": "shop-acl", "Scope": "REGIONAL", "Id": "a1b2c3"}
    stub.add_response("get_web_acl", {"WebACL": ACL, "LockToken": "lock-1"}, get_args)
    stub.add_client_error("update_web_acl", "WAFOptimisticLockException", "changed")
    client.post(f"/api/virtual-patches/{vp['id']}/approve", headers=auth_headers)
    assert get(client, auth_headers, vp["id"])["state"] == "applying"  # will be retried

    ours = AwsWaf(AWS_CONFIG, "", lambda *_: c)._rules(tag_for(vp["id"]), 4)
    stub.add_response("get_web_acl", {"WebACL": {**ACL, "Rules": ACL["Rules"] + ours}, "LockToken": "lock-9"}, get_args)
    s = client.app.state
    run(service.run(s.sessionmaker, s.vault, s.demo_world, vp["id"], None, "apply", state=s))
    done = get(client, auth_headers, vp["id"])  # already there (another attempt got through): no second update
    assert done["state"] == "active"
