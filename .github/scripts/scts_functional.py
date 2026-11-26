#!/usr/bin/env python3
"""
scts_functional.py: exercise splunk_app_scdeploy on a real SCTS stack.

What the app does, and so what this checks:

  * Its UCC REST handlers store destinations (GitLab, GitHub, AWS SM,
    1Password) with the secret fields encrypted.
  * `| gendeploytoken` mints a Splunk auth token for the user the destination
    names, refuses callers outside the destination's `limit_role`, delivers the
    token to the destination and returns a result row with the token redacted.
  * The `token_cleaner` modular input deletes expired tokens.

Delivery is the part that is hard to observe without a real GitLab. The GitLab
destination posts its JSON payload (ACS_TOKEN, SPLUNK_SERVERNAME, ACS_STACK) to
`https://<hostname>/api/v4/projects/<id>/pipeline?ref=<branch>`. The hostname is
a free-text field, so the check points it back at the stack's own
`/services/receivers/simple` (credentials in the URL's userinfo, the GitLab
path pushed into a `#fragment` that is never sent). The payload is then indexed
on the same stack, the check searches it back, and the delivered token is used
to authenticate. The token never leaves the stack and this runner, and it is
registered with the log masker before anything else touches it.

Every check is reached by a route the app does not use to produce its answer:
the token list endpoint (the app only calls tokens/create), the index (the app
only writes there via HTTP), current-context with the delivered token as the
credential.

Self-test: `--expect-fail a,b` inverts the exit code so that the run passes only
if exactly those checks fail and every other one passes. The workflow uses it
after installing a deliberately broken build onto the same stack.

Stdlib only. Never prints a credential.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scts  # noqa: E402

APP = "splunk_app_scdeploy"
CHECKS: List[Tuple[str, Callable[["Ctx"], None]]] = []


def check(name: str):
    def deco(fn):
        CHECKS.append((name, fn))
        return fn
    return deco


class CheckFailed(Exception):
    pass


def require(cond: bool, message: str) -> None:
    if not cond:
        raise CheckFailed(message)


class Ctx:
    def __init__(self, access: Dict[str, str], run_tag: str) -> None:
        self.web_url = str(access["url"]).rstrip("/")
        self.host = urllib.parse.urlsplit(self.web_url).hostname
        self.mgmt = "https://{}:8089".format(self.host)
        self.user = str(access["username"])
        self.password = str(access["password"])
        scts.mask(self.password)
        self.tag = run_tag
        self.ctx = ssl.create_default_context()
        self.secrets_seen: List[str] = []
        self.state: Dict[str, Any] = {}

    def secret(self, value: str) -> str:
        scts.mask(value)
        self.secrets_seen.append(value)
        return value

    # -- HTTP -------------------------------------------------------------

    def rest(self, method: str, path: str, data: Optional[Dict[str, Any]] = None,
             bearer: Optional[str] = None, timeout: float = 120) -> Tuple[int, Any]:
        url = self.mgmt + path
        sep = "&" if "?" in url else "?"
        if "output_mode=" not in url:
            url += sep + "output_mode=json"
        body = None
        headers = {"User-Agent": "scdeploy-scts-functional"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        else:
            headers["Authorization"] = "Basic " + base64.b64encode(
                "{}:{}".format(self.user, self.password).encode()).decode()
        if data is not None:
            body = urllib.parse.urlencode(data, doseq=True).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        status, raw, _ = scts._request(method, url, headers, body, timeout=timeout, context=self.ctx)
        try:
            return status, json.loads(raw.decode("utf-8")) if raw else None
        except ValueError:
            return status, raw.decode("utf-8", "replace")

    def ns(self, path: str) -> str:
        return "/servicesNS/nobody/{}/{}".format(APP, path)

    def search(self, spl: str) -> Tuple[int, Any, str]:
        """Oneshot search in the app's namespace. Returns (status, json, raw text)."""
        status, data = self.rest("POST", "/servicesNS/{}/{}/search/jobs".format(
            urllib.parse.quote(self.user), APP),
            {"search": spl, "exec_mode": "oneshot", "count": 0, "output_mode": "json"},
            timeout=300)
        raw = json.dumps(data) if not isinstance(data, str) else data
        return status, data, raw

    def search_settled(self, spl: str) -> Tuple[int, Any, str]:
        """A destination written through one search head member reaches the
        others by replication, so a search on another member can briefly miss
        it. Retry only that specific miss, which happens before any token is
        minted."""
        for _ in range(12):
            status, data, raw = self.search(spl)
            if "Cannot find destination_name" not in raw:
                break
            time.sleep(10)
        return status, data, raw

    def tokens(self) -> List[Dict[str, Any]]:
        status, data = self.rest("GET", "/services/authorization/tokens?count=0")
        require(status == 200, "token list answered HTTP {}".format(status))
        return data.get("entry", [])

    def tokens_with_audience(self, aud: str) -> List[Dict[str, Any]]:
        return [t for t in self.tokens()
                if (t.get("content", {}).get("claims", {}) or {}).get("aud") == aud]

    def upsert(self, endpoint: str, name: str, fields: Dict[str, str]) -> None:
        status, data = self.rest("POST", self.ns(endpoint), dict(fields, name=name))
        # UCC wraps the 409 for an existing name in a 500.
        if status == 409 or "already in use" in json.dumps(data):
            status, data = self.rest("POST", self.ns("{}/{}".format(endpoint, name)), fields)
        require(status in (200, 201), "{} {} answered HTTP {}: {}".format(
            endpoint, name, status, _messages(data)))


def _messages(data: Any) -> str:
    if isinstance(data, dict):
        return " | ".join(str(m.get("text", "")) for m in data.get("messages", []))[:400]
    return str(data)[:400]


def _rows(data: Any) -> List[Dict[str, Any]]:
    return data.get("results", []) if isinstance(data, dict) else []


# ---------------------------------------------------------------------------
# Checks, in order. Later checks use state from earlier ones.
#
# Every object a check creates is named after the run tag. The stack is a
# search head cluster and an EDITED stanza reaches the other members lazily: a
# search on a stale member runs with the old settings (seen: a delivery sent to
# the previous run's receiver). A NEW stanza on a stale member is simply
# missing, which search_settled() retries.
# ---------------------------------------------------------------------------

@check("rest_handlers_load")
def _rest_handlers(c: Ctx) -> None:
    for ep in ("dest_gitlab", "dest_github", "dest_awssm", "dest_1password", "token_cleaner"):
        status, data = c.rest("GET", c.ns("{}_{}".format(APP, ep)))
        require(status == 200, "{}_{} answered HTTP {}: {}".format(APP, ep, status, _messages(data)))


@check("destination_secret_encrypted")
def _secret_encrypted(c: Ctx) -> None:
    sentinel = c.secret("scdeployci" + secrets.token_hex(12))
    c.upsert("{}_dest_gitlab".format(APP), "ci_secret_probe", {
        "hostname": "gitlab.invalid", "token": sentinel, "projectid": "1",
        "limit_role": "admin",
    })
    # Read the conf through the generic conf endpoint, not the app's handler.
    status, data = c.rest("GET", c.ns("configs/conf-{}_dest_gitlab/ci_secret_probe".format(APP)))
    require(status == 200, "conf read answered HTTP {}".format(status))
    stored = json.dumps(data.get("entry", [{}])[0].get("content", {}))
    require(sentinel not in stored, "the destination token is stored in clear text in the conf")


@check("missing_destination_reported")
def _missing(c: Ctx) -> None:
    status, data, raw = c.search(
        "| gendeploytoken destination_type=gitlab destination_name=aios_ci_missing_destination")
    require("Cannot find destination_name called aios_ci_missing_destination" in raw,
            "command did not report the missing destination (HTTP {}): {}".format(
                status, _messages(data) or raw[:300]))


def _receiver_userinfo(c: Ctx) -> str:
    """userinfo for the loopback receiver: a fresh throwaway user per run.

    A fresh user, because changing an existing user's password reaches the
    other search head members by replication, and a delivery landing on a
    member that has not caught up answers 401. Waits until the user
    authenticates on several load-balanced requests in a row.
    """
    if "rcv_userinfo" in c.state:
        return c.state["rcv_userinfo"]
    role = "scdeploy_ci_rcv"
    name = "scdeploy_ci_rcv_" + c.tag.lower()
    pw = c.secret("Rc" + secrets.token_hex(16) + "x9")
    c.rest("POST", "/services/authorization/roles", {
        "name": role, "capabilities": ["edit_tcp"], "srchIndexesAllowed": "main"})
    status, _ = c.rest("POST", "/services/authentication/users",
                       {"name": name, "password": pw, "roles": role, "force-change-pass": "0"})
    user, password = name, pw
    if status not in (200, 201):
        scts.log("Could not create a receiver user (HTTP {}); using the stack admin.".format(status))
        user, password = c.user, c.password
    else:
        auth = "Basic " + base64.b64encode("{}:{}".format(user, password).encode()).decode()
        good = 0
        for _ in range(40):
            st, _r, _h = scts._request("GET", c.mgmt + "/services/authentication/current-context",
                                       {"Authorization": auth}, timeout=60, context=c.ctx)
            good = good + 1 if st == 200 else 0
            if good >= 6:
                break
            time.sleep(3)
        require(good >= 6, "the receiver user never authenticated consistently")
    info = "{}:{}".format(urllib.parse.quote(user, safe=""), urllib.parse.quote(password, safe=""))
    c.secret(urllib.parse.quote(password, safe=""))
    c.state["rcv_userinfo"] = info
    return info


@check("command_mints_and_delivers")
def _deliver(c: Ctx) -> None:
    sourcetype = "scdeploy_ci_" + c.tag
    aud = "scdeployci_" + c.tag
    c.state["aud"] = aud
    # The stack cannot reach its own public load balancer (the connection
    # hairpins and times out), but a member's own FQDN works and its
    # certificate (*.<stack>.splunkcloud.com) verifies.
    status, info = c.rest("GET", "/services/server/info")
    require(status == 200, "server/info answered HTTP {}".format(status))
    member = info["entry"][0]["content"]["serverName"]
    hostname = "{}@{}:8089/services/receivers/simple?index=main&sourcetype={}&source=scts#".format(
        _receiver_userinfo(c), member, sourcetype)
    # The destination names the user, the SPL names another: the destination wins.
    roles = c.state.setdefault("my_roles", _my_roles(c))
    c.upsert("{}_dest_gitlab".format(APP), "ci_deliver_" + c.tag, {
        "hostname": hostname, "token": c.secret("glpat-ci-" + secrets.token_hex(8)),
        "projectid": "1", "user": c.user, "limit_role": "|".join(roles),
    })
    status, data, raw = c.search_settled(
        "| gendeploytoken destination_type=gitlab destination_name=ci_deliver_{} "
        "user=scdeploy_ci_not_this_user audience={} expires_on=+20m".format(c.tag, aud))
    c.state["deliver_raw"] = raw
    rows = _rows(data)
    require(status == 200 and len(rows) == 1,
            "expected one result row, got HTTP {} rows={} messages={}".format(
                status, len(rows), _messages(data)))
    row = rows[0]
    c.state["row"] = row
    require(row.get("error") in (None, ""), "command reported an error: {}".format(
        str(row.get("message"))[:300]))
    require(row.get("token") == "[REDACTED]", "result row token is not redacted")
    require(row.get("user") == c.user, "token was minted for user={!r}, not the destination's user".format(
        row.get("user")))
    require(row.get("tokenId"), "no tokenId in the result row")
    resp = str(row.get("gitlab_resp", ""))
    require('"bytes"' in resp or "bytes" in resp,
            "the loopback receiver did not accept the payload: {}".format(resp[:200]))


def _my_roles(c: Ctx) -> List[str]:
    status, data = c.rest("GET", "/services/authentication/current-context")
    require(status == 200, "current-context answered HTTP {}".format(status))
    return list(data["entry"][0]["content"].get("roles", []))


@check("minted_token_listed_for_user")
def _listed(c: Ctx) -> None:
    require("row" in c.state, "no result row from the delivery check")
    found = c.tokens_with_audience(c.state["aud"])
    require(len(found) == 1, "expected 1 token with the run's audience, found {}".format(len(found)))
    tok = found[0]
    require(tok.get("name") == c.state["row"].get("tokenId"),
            "the listed token id does not match the result row")
    require(tok["content"]["claims"].get("sub") == c.user,
            "the token subject is not the destination's user")


@check("delivered_payload_shape")
def _payload(c: Ctx) -> None:
    require("row" in c.state, "no result row from the delivery check")
    spl = 'search index=main sourcetype="scdeploy_ci_{}" earliest=-1h | head 5 | table _raw'.format(c.tag)
    raw_events: List[str] = []
    for _ in range(24):
        status, data, _r = c.search(spl)
        raw_events = [r.get("_raw", "") for r in _rows(data)]
        if raw_events:
            break
        time.sleep(10)
    require(len(raw_events) == 1, "expected 1 delivered event, found {}".format(len(raw_events)))
    try:
        body = json.loads(raw_events[0])
        variables = {v["key"]: v["value"] for v in body["variables"]}
    except (ValueError, KeyError, TypeError):
        raise CheckFailed("the delivered event is not the GitLab variables payload")
    token = variables.get("ACS_TOKEN", "")
    if token:
        c.secret(token)
    c.state["delivered_token"] = token
    require(token.count(".") == 2, "ACS_TOKEN is not a JWT")
    require(variables.get("SPLUNK_SERVERNAME"), "SPLUNK_SERVERNAME is empty")
    require(variables.get("ACS_STACK") not in (None, "", "Unknown"),
            "ACS_STACK is {!r}".format(variables.get("ACS_STACK")))


@check("delivered_token_authenticates")
def _auth(c: Ctx) -> None:
    token = c.state.get("delivered_token")
    require(bool(token), "no delivered token to try")
    status, data = c.rest("GET", "/services/authentication/current-context", bearer=token)
    require(status == 200, "the delivered token does not authenticate (HTTP {})".format(status))
    require(data["entry"][0]["content"].get("username") == c.user,
            "the delivered token authenticates as the wrong user")


@check("output_never_contains_token")
def _no_leak(c: Ctx) -> None:
    token = c.state.get("delivered_token")
    require(bool(token), "no delivered token to compare against")
    require(token not in c.state.get("deliver_raw", ""), "the search output contains the token")
    require(token.split(".")[1] not in c.state.get("deliver_raw", ""),
            "the search output contains the token's claims segment")


@check("limit_role_refuses")
def _refuse(c: Ctx) -> None:
    aud = "scdeployci_denied_" + c.tag
    c.upsert("{}_dest_gitlab".format(APP), "ci_denied_" + c.tag, {
        "hostname": "gitlab.invalid", "token": c.secret("glpat-ci-" + secrets.token_hex(8)),
        "projectid": "1", "limit_role": "scdeploy_ci_no_such_role",
    })
    status, data, raw = c.search_settled(
        "| gendeploytoken destination_type=gitlab destination_name=ci_denied_{} "
        "user={} audience={}".format(c.tag, c.user, aud))
    require("Unauthorised to run" in raw, "a caller outside limit_role was not refused: {}".format(
        _messages(data) or raw[:300]))
    # Positive control for this count is minted_token_listed_for_user, which
    # finds exactly one token through the same function.
    require(len(c.tokens_with_audience(aud)) == 0, "a token was minted for a refused caller")


@check("token_cleaner_removes_expired")
def _cleaner(c: Ctx) -> None:
    aud = "scdeployci_clean_" + c.tag
    ids = {}
    for label, expiry in (("expired1", "+5s"), ("expired2", "+5s"), ("live", "+2h")):
        status, data = c.rest("POST", "/services/authorization/tokens/create",
                              {"name": c.user, "audience": aud, "expires_on": expiry})
        require(status in (200, 201), "could not create a {} token (HTTP {})".format(label, status))
        content = data["entry"][0]["content"]
        c.secret(content.get("token", ""))
        ids[label] = content["id"]
    time.sleep(15)
    c.upsert("{}_token_cleaner".format(APP), "ci_cleaner_" + c.tag, {
        "min_expiry": "0", "interval": "20", "limit": "10"})
    remaining = set()
    deadline = time.time() + 300
    while time.time() < deadline:
        remaining = {t["name"] for t in c.tokens_with_audience(aud)}
        if ids["expired1"] not in remaining and ids["expired2"] not in remaining:
            break
        time.sleep(15)
    c.rest("DELETE", c.ns("{}_token_cleaner/ci_cleaner_{}".format(APP, c.tag)))
    require(ids["expired1"] not in remaining and ids["expired2"] not in remaining,
            "expired tokens were not removed within 5 minutes")
    require(ids["live"] in remaining, "the cleaner removed a token that has not expired")


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("stack_id")
    ap.add_argument("--tag", default=os.environ.get("GITHUB_RUN_ID", str(int(time.time()))))
    ap.add_argument("--only", default="", help="Comma list of checks to run.")
    ap.add_argument("--expect-fail", default="",
                    help="Comma list: pass only if exactly these checks fail.")
    args = ap.parse_args()

    detail = scts.Scts(os.environ.get(scts.TOKEN_ENV, "")).get(args.stack_id)
    access = detail.get("stackAccessDetails")
    if not access:
        scts.fail("Stack {} has no access details (state {}).".format(args.stack_id, detail.get("state")))
    c = Ctx(access, "".join(ch for ch in args.tag if ch.isalnum()))

    # The app mints Splunk auth tokens, which SCTS stacks ship with switched
    # off. A customer turns them on to use the app at all; do the same.
    status, _ = c.rest("POST", "/services/admin/token-auth/tokens_auth", {"disabled": "false"})
    scts.log("Token authentication enabled (HTTP {}).".format(status))

    only = {x for x in args.only.split(",") if x}
    failed: List[str] = []
    for name, fn in CHECKS:
        if only and name not in only:
            continue
        try:
            fn(c)
            scts.log("PASS {}".format(name))
        except CheckFailed as exc:
            failed.append(name)
            scts.log("FAIL {}: {}".format(name, exc))
        except Exception as exc:  # noqa: BLE001 - a crash is a failed check, with its type
            failed.append(name)
            scts.log("FAIL {}: {}: {}".format(name, type(exc).__name__, str(exc)[:300]))

    total = len(only) if only else len(CHECKS)
    scts.log("{} of {} checks failed: {}".format(len(failed), total, ",".join(failed) or "none"))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("\n#### Functional checks{}\n\n".format(
                " (mutant self-test)" if args.expect_fail else ""))
            for name, _ in CHECKS:
                if only and name not in only:
                    continue
                fh.write("- {} {}\n".format("FAIL" if name in failed else "pass", name))

    if args.expect_fail:
        want = {x for x in args.expect_fail.split(",") if x}
        if set(failed) == want:
            scts.log("Self-test passed: the mutant turned exactly {} red.".format(sorted(want)))
            return 0
        scts.log("Self-test FAILED: expected exactly {} to fail, got {}.".format(
            sorted(want), sorted(failed)))
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
