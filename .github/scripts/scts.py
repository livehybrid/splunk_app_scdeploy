#!/usr/bin/env python3
"""
scts.py — minimal client for the Splunk Cloud Testing Service (SCTS).

SCTS provisions short-lived Splunk stacks from an API, which is what makes it
useful in CI: a pipeline can stand up a real Splunk, install the add-on it just
built, prove the add-on actually loads, and tear the stack down again.

API: https://scts.dev.splunk.com/openapi.json
Auth: `Authorization: Bearer <Dev Portal API token>`

What the API does and does not do
---------------------------------
SCTS manages the *stack* lifecycle only. There are exactly five operations:

    POST   /v1/stacks            create
    GET    /v1/stacks            list
    GET    /v1/stacks/versions   available Splunk versions
    GET    /v1/stacks/{id}       detail, including access details
    DELETE /v1/stacks/{id}       delete

There is **no app-install endpoint**. Once a stack reaches RUNNING, SCTS hands
back `stackAccessDetails` (url, username, password) and installing an add-on is
then an ordinary Splunk operation against that stack, not an SCTS one. That is
what `install` below does.

Stdlib only, deliberately: this runs in CI on a bare Python and should not need
a pip step or a lockfile to stay reproducible.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import mimetypes
import re
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Dict, Optional, Tuple

DEFAULT_BASE_URL = "https://scts.dev.splunk.com"
TOKEN_ENV = "SCTS_API_TOKEN"

# Stack states from the OpenAPI schema.
STATE_CREATING = "CREATING"
STATE_RUNNING = "RUNNING"
STATE_STOPPING = "STOPPING"
STATE_ERROR = "ERROR"
TERMINAL_BAD = {STATE_ERROR, STATE_STOPPING}


# ---------------------------------------------------------------------------
# Output helpers. GitHub Actions-aware, but they degrade to plain text locally.
# ---------------------------------------------------------------------------

IN_ACTIONS = os.environ.get("GITHUB_ACTIONS") == "true"


def log(message: str) -> None:
    print(message, flush=True)


def mask(secret: str) -> None:
    """Register a value with the Actions log masker before it can be printed.

    Anything derived from a stack's access details has to go through this. A
    stack is short-lived, but a password in a public repo's build log is
    forever.
    """
    if secret and IN_ACTIONS:
        print("::add-mask::{}".format(secret), flush=True)


def set_output(name: str, value: str) -> None:
    out = os.environ.get("GITHUB_OUTPUT")
    if not out:
        return
    with open(out, "a", encoding="utf-8") as fh:
        # Heredoc form, so a value containing a newline cannot corrupt the file.
        delimiter = "ghadelim-{}".format(uuid.uuid4().hex)
        fh.write("{}<<{}\n{}\n{}\n".format(name, delimiter, value, delimiter))


def fail(message: str) -> "NoReturn":  # type: ignore[valid-type]
    if IN_ACTIONS:
        print("::error::{}".format(message), flush=True)
    else:
        print("ERROR: {}".format(message), file=sys.stderr, flush=True)
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _request(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[bytes] = None,
    timeout: float = 60.0,
    context: Optional[ssl.SSLContext] = None,
) -> Tuple[int, bytes, Dict[str, str]]:
    req = urllib.request.Request(url, data=body, method=method)
    for key, value in headers.items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers or {})


class Scts:
    """The five SCTS operations, and nothing else."""

    def __init__(self, token: str, base_url: str = DEFAULT_BASE_URL) -> None:
        if not token:
            fail(
                "No SCTS API token. Set {} (in CI: a repository secret, never a "
                "committed file).".format(TOKEN_ENV)
            )
        self._token = token
        self._base = base_url.rstrip("/")

    def _call(self, method: str, path: str, payload: Optional[Any] = None) -> Tuple[int, Any]:
        headers = {
            "Authorization": "Bearer {}".format(self._token),
            "Accept": "application/json",
            "User-Agent": "splunk-app-cicd-pattern/scts.py",
        }
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        status, raw, _ = _request(method, self._base + path, headers, body)
        if not raw:
            return status, None
        try:
            return status, json.loads(raw.decode("utf-8"))
        except ValueError:
            return status, raw.decode("utf-8", "replace")

    @staticmethod
    def _describe_error(status: int, data: Any) -> str:
        """SCTS returns {code, message} on error; fall back to the raw body."""
        if isinstance(data, dict) and "message" in data:
            return "HTTP {} {} — {}".format(status, data.get("code", ""), data["message"])
        return "HTTP {} — {}".format(status, str(data)[:300])

    # -- operations ---------------------------------------------------------

    def versions(self) -> list:
        status, data = self._call("GET", "/v1/stacks/versions")
        if status != 200:
            fail("listStackVersions failed: " + self._describe_error(status, data))
        return (data or {}).get("versions", [])

    def list_stacks(self) -> list:
        status, data = self._call("GET", "/v1/stacks")
        if status != 200:
            fail("listStacks failed: " + self._describe_error(status, data))
        return (data or {}).get("stacks", [])

    def create(self, splunk_version: Optional[str] = None) -> Tuple[int, Any]:
        """Returns (status, body); 202 is success, 409 means the quota is used."""
        # An empty object means "latest released", per the spec.
        payload: Dict[str, Any] = {}
        if splunk_version:
            payload["splunkVersion"] = splunk_version
        return self._call("POST", "/v1/stacks", payload)

    def get(self, stack_id: str) -> Dict[str, Any]:
        status, data = self._call("GET", "/v1/stacks/{}".format(urllib.parse.quote(stack_id)))
        if status != 200:
            fail("getStack failed: " + self._describe_error(status, data))
        return data

    def delete(self, stack_id: str, strict: bool = False) -> bool:
        status, data = self._call("DELETE", "/v1/stacks/{}".format(urllib.parse.quote(stack_id)))
        if status == 204:
            return True
        if status == 404:
            # Already gone. For teardown that is success, not failure.
            log("Stack {} already absent (404).".format(stack_id))
            return True
        message = "deleteStack failed: " + self._describe_error(status, data)
        if strict:
            fail(message)
        log("WARNING: " + message)
        return False

    # -- derived ------------------------------------------------------------

    def wait_until_running(self, stack_id: str, timeout_s: int, interval_s: int) -> Dict[str, Any]:
        """Poll getStack until RUNNING with access details, or give up.

        Access details are documented as "present only when the stack has access
        details available", so RUNNING alone is not enough to start installing:
        wait for the credentials too.
        """
        deadline = time.time() + timeout_s
        last_state = None
        errors = 0
        while time.time() < deadline:
            # A 75-minute poll will meet the odd transient failure; only a run of
            # them is fatal.
            try:
                status, detail = self._call(
                    "GET", "/v1/stacks/{}".format(urllib.parse.quote(stack_id)))
            except (urllib.error.URLError, OSError) as exc:
                status, detail = 0, str(exc)
            if status != 200 or not isinstance(detail, dict):
                errors += 1
                log("getStack answered {} ({} in a row).".format(status, errors))
                if errors >= 10:
                    fail("getStack kept failing: " + self._describe_error(status, detail))
                time.sleep(interval_s)
                continue
            errors = 0
            state = detail.get("state")
            if state != last_state:
                log("Stack {} state: {}".format(stack_id, state))
                last_state = state

            if state == STATE_RUNNING and detail.get("stackAccessDetails"):
                return detail
            if state in TERMINAL_BAD:
                fail(
                    "Stack {} reached {} before becoming usable. Nothing to install "
                    "into.".format(stack_id, state)
                )
            time.sleep(interval_s)

        fail(
            "Stack {} did not reach {} with access details within {}s (last state: "
            "{}).".format(stack_id, STATE_RUNNING, timeout_s, last_state)
        )


# ---------------------------------------------------------------------------
# Installing an add-on onto a stack
#
# SCTS has no install endpoint, so this talks to the stack's own Splunk. Two
# routes are tried, most-likely first, because what a stack exposes is a
# property of how SCTS provisions it rather than something the API promises:
#
#   1. Splunk Web app upload (POST /en-US/manager/appinstall/_upload). Works
#      wherever Splunk Web is reachable, which is exactly what SCTS hands back.
#   2. Management REST (POST /services/apps/local) on :8089, if it is exposed.
#
# `probe` reports which of these a stack actually answers on, so the first real
# run tells us which route is the supported one rather than us guessing.
# ---------------------------------------------------------------------------

def _tls_context(verify: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _multipart(fields: Dict[str, str], file_field: str, file_path: str,
               filename: Optional[str] = None) -> Tuple[bytes, str]:
    """Build a multipart/form-data body without pulling in requests."""
    boundary = "----sctsboundary{}".format(uuid.uuid4().hex)
    filename = filename or os.path.basename(file_path)
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"

    parts = []
    for name, value in fields.items():
        parts.append(
            ('--{b}\r\nContent-Disposition: form-data; name="{n}"\r\n\r\n{v}\r\n')
            .format(b=boundary, n=name, v=value).encode("utf-8")
        )
    with open(file_path, "rb") as fh:
        payload = fh.read()
    parts.append(
        ('--{b}\r\nContent-Disposition: form-data; name="{n}"; filename="{f}"\r\n'
         'Content-Type: {c}\r\n\r\n').format(b=boundary, n=file_field, f=filename, c=ctype)
        .encode("utf-8")
    )
    parts.append(payload)
    parts.append("\r\n--{b}--\r\n".format(b=boundary).encode("utf-8"))

    return b"".join(parts), "multipart/form-data; boundary={}".format(boundary)


class Stack:
    """A provisioned SCTS stack, addressed through its own Splunk endpoints."""

    def __init__(self, access: Dict[str, str], verify_tls: bool = True) -> None:
        self.web_url = str(access["url"]).rstrip("/")
        self.username = str(access["username"])
        self.password = str(access["password"])
        self._ctx = _tls_context(verify_tls)
        # A real cookie jar, not hand-rolled Set-Cookie parsing. A stack sits
        # behind an AWS load balancer whose AWSALB cookies carry `Expires=Sun,
        # 21 Sep ...`, and splitting that header on commas corrupts the jar. The
        # symptom is a flat HTTP 400 from the login POST.
        self._jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._jar),
            urllib.request.HTTPSHandler(context=self._ctx),
        )
        self._opener.addheaders = [("User-Agent", "splunk-app-cicd-pattern/scts.py")]
        # Everything derived from the stack password must be masked before any
        # of it can reach a log line.
        mask(self.password)

    @property
    def mgmt_url(self) -> str:
        """Management REST, on the conventional :8089 of the same host."""
        parts = urllib.parse.urlsplit(self.web_url)
        return "https://{}:8089".format(parts.hostname)

    def _cookie(self, name_prefix: str) -> str:
        return next(
            (c.value for c in self._jar if c.name.startswith(name_prefix)), "",
        )

    # -- probing ------------------------------------------------------------

    def probe(self) -> Dict[str, Any]:
        """Report which endpoints this stack actually answers on.

        Useful on a first run against an unfamiliar stack shape, and cheap
        enough to leave in the pipeline as a diagnostic.
        """
        result: Dict[str, Any] = {"web_url": self.web_url, "mgmt_url": self.mgmt_url}
        for key, url in (
            ("web_login", self.web_url + "/en-US/account/login"),
            ("mgmt_server_info", self.mgmt_url + "/services/server/info"),
        ):
            try:
                status, _, _ = _request(
                    "GET", url, {"User-Agent": "scts.py"}, timeout=30, context=self._ctx,
                )
                # 401 on the management URL is a positive result: splunkd answered.
                result[key] = status
            except Exception as exc:  # noqa: BLE001 - a probe reports, never raises
                result[key] = "unreachable: {}".format(exc)
        return result

    # -- install ------------------------------------------------------------

    def _web_login(self) -> str:
        """Log in to Splunk Web, returning the post-login CSRF form key.

        Splunk issues the CSRF token as a cookie (`cval` before login,
        `splunkweb_csrf_token_<port>` after) and expects it echoed back in the
        `X-Splunk-Form-Key` header. Miss that and every POST is a 403.
        """
        self._opener.open(self.web_url + "/en-US/account/login", timeout=60).read()
        cval = self._cookie("cval")

        payload = urllib.parse.urlencode({
            "username": self.username,
            "password": self.password,
            "cval": cval,
        }).encode("utf-8")
        request = urllib.request.Request(
            self.web_url + "/en-US/account/login", data=payload, method="POST",
        )
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        request.add_header("X-Splunk-Form-Key", cval)
        request.add_header("X-Requested-With", "XMLHttpRequest")
        try:
            response = self._opener.open(request, timeout=60)
        except urllib.error.HTTPError as exc:
            fail("Splunk Web login failed on {} (HTTP {}).".format(self.web_url, exc.code))
        if response.status not in (200, 302, 303):
            fail("Splunk Web login failed on {} (HTTP {}).".format(self.web_url, response.status))

        # The post-login token replaces cval for subsequent form posts.
        return self._cookie("splunkweb_csrf_token") or cval

    def install_via_web(self, package_path: str) -> None:
        """Upload an add-on package through the Splunk Web app installer.

        This is the route, not management REST: `POST /services/apps/local` does
        not parse a multipart body at all (it answers HTTP 500 `'name'`, a
        KeyError on the field it never read), and its `name` argument wants a
        path on the server, which a remote caller has no way to produce.
        """
        form_key = self._web_login()
        body, content_type = _multipart(
            {"force": "1", "appfile_url": "", "cval": form_key}, "appfile", package_path,
        )
        request = urllib.request.Request(
            self.web_url + "/en-US/manager/appinstall/_upload", data=body, method="POST",
        )
        request.add_header("Content-Type", content_type)
        request.add_header("X-Splunk-Form-Key", form_key)
        request.add_header("X-Requested-With", "XMLHttpRequest")
        request.add_header("Referer", self.web_url + "/en-US/manager/appinstall/_upload")
        try:
            response = self._opener.open(request, timeout=900)
        except urllib.error.HTTPError as exc:
            fail(
                "App upload rejected by Splunk Web (HTTP {}): {}".format(
                    exc.code, exc.read().decode("utf-8", "replace")[:400]
                )
            )
        log("Uploaded {} via Splunk Web (HTTP {}).".format(
            os.path.basename(package_path), response.status))

    def mgmt(self, method: str, path: str, data: Optional[Dict[str, str]] = None,
             timeout: float = 120, bearer: Optional[str] = None) -> Tuple[int, Any]:
        """Management REST on :8089 with the stack admin's credentials."""
        url = self.mgmt_url + path
        url += ("&" if "?" in url else "?") + "output_mode=json"
        headers = {
            "User-Agent": "scts.py",
            "Authorization": ("Bearer " + bearer) if bearer else _basic_auth(self.username, self.password),
        }
        body = None
        if data is not None:
            body = urllib.parse.urlencode(data).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        status, raw, _ = _request(method, url, headers, body, timeout=timeout, context=self._ctx)
        try:
            return status, json.loads(raw.decode("utf-8")) if raw else None
        except ValueError:
            return status, raw.decode("utf-8", "replace")

    def _page_form_key(self, path: str) -> str:
        html = self._opener.open(self.web_url + path, timeout=60).read().decode("utf-8", "replace")
        for pattern in (r'name="splunk_form_key"\s+value="([^"]+)"',
                        r'value="([^"]+)"\s+name="splunk_form_key"',
                        r'"FORM_KEY"\s*:\s*"([^"]+)"'):
            match = re.search(pattern, html)
            if match:
                return match.group(1)
        return ""

    def install_via_lookup(self, package_path: str, app_name: str) -> None:
        """Install through the lookup uploader, for stacks without the app uploader.

        Cloud 10.6+ removed /manager/appinstall/_upload. The lookup uploader still
        accepts a gzip file (Splunk sniffs the magic, so the name must end
        .csv.gz), which lands under etc/users/<user>/search/lookups/. apps/local
        then installs from that server-side path. No ACS and no AppInspect.
        """
        form_key = self._web_login()
        page = "/en-US/manager/search/data/lookup-table-files/_new"
        key = self._page_form_key(page) or form_key
        name = "{}-{}.csv.gz".format(app_name, uuid.uuid4().hex[:8])
        body, content_type = _multipart(
            {"splunk_form_key": key, "namespace": "search", "name": name,
             "action": "save"},
            "spl-ctrl_lookupfile", package_path, filename=name,
        )
        request = urllib.request.Request(self.web_url + page, data=body, method="POST")
        request.add_header("Content-Type", content_type)
        request.add_header("X-Splunk-Form-Key", key)
        request.add_header("Referer", self.web_url + page)
        try:
            resp = self._opener.open(request, timeout=600)
            text = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            fail("Lookup upload rejected (HTTP {}): {}".format(
                exc.code, exc.read().decode("utf-8", "replace")[:300]))
        # The page answers 200 with a JSON error body, so read the body.
        if text.lstrip().startswith("{"):
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = {}
            if parsed.get("status") == "ERROR" or parsed.get("messages") or parsed.get("error"):
                fail("Lookup upload failed: {}".format(text[:300]))

        log("Uploaded {} through the lookup uploader.".format(name))
        self.install_from_lookup_on_every_member(name, app_name)

    # -- search head cluster ----------------------------------------------
    #
    # An SCTS stack is a hidden three-member search head cluster behind one
    # load-balanced hostname (serverName changes between requests). apps/local
    # installs on the member that answers, and apps do not replicate between
    # members, so a single install leaves the app on one member in three and
    # every check becomes a lottery. The load balancer honours its AWSALB
    # cookie on :8089, so a cookie jar pins requests to one member; lookup files
    # DO replicate, so each member can install from the same uploaded file.

    def _member_opener(self, label: str, tries: int = 40):
        for _ in range(tries):
            jar = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(jar),
                urllib.request.HTTPSHandler(context=self._ctx),
            )
            status, data = self._pinned(opener, "GET", "/services/server/info")
            if status == 200 and data["entry"][0]["content"].get("serverName") == label:
                return opener
        fail("Could not pin a connection to member {}.".format(label))

    def _pinned(self, opener, method: str, path: str,
                data: Optional[Dict[str, str]] = None, timeout: float = 120) -> Tuple[int, Any]:
        url = self.mgmt_url + path
        url += ("&" if "?" in url else "?") + "output_mode=json"
        body = urllib.parse.urlencode(data).encode("utf-8") if data is not None else None
        request = urllib.request.Request(url, data=body, method=method)
        request.add_header("Authorization", _basic_auth(self.username, self.password))
        request.add_header("User-Agent", "scts.py")
        try:
            with opener.open(request, timeout=timeout) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read()
        try:
            return status, json.loads(raw.decode("utf-8")) if raw else None
        except ValueError:
            return status, raw.decode("utf-8", "replace")

    def members(self) -> list:
        status, data = self.mgmt("GET", "/services/shcluster/member/members?count=0")
        if status == 200 and data.get("entry"):
            return sorted(e["content"]["label"] for e in data["entry"])
        status, data = self.mgmt("GET", "/services/server/info")
        return [data["entry"][0]["content"]["serverName"]]

    def install_from_lookup_on_every_member(self, name: str, app_name: str) -> None:
        members = self.members()
        log("Search head members: {}".format(len(members)))
        for label in members:
            opener = self._member_opener(label)
            server_path = ""
            for _ in range(40):
                status, data = self._pinned(
                    opener, "GET", "/servicesNS/-/-/data/lookup-table-files/{}".format(
                        urllib.parse.quote(name)))
                if status == 200:
                    server_path = data["entry"][0]["content"].get("eai:data", "")
                    break
                time.sleep(15)
            if not server_path:
                fail("The uploaded package never replicated to {}.".format(label))
            status, data = self._pinned(opener, "POST", "/services/apps/local", {
                "name": server_path, "filename": "true", "update": "true"}, timeout=600)
            if status not in (200, 201):
                msgs = data.get("messages") if isinstance(data, dict) else data
                fail("apps/local install on {} failed (HTTP {}): {}".format(
                    label, status, str(msgs)[:300]))
            log("Installed {} on {} (HTTP {}).".format(app_name, label.split(".")[0], status))

    def member_versions(self, app_name: str) -> Dict[str, Optional[str]]:
        out: Dict[str, Optional[str]] = {}
        for label in self.members():
            opener = self._member_opener(label)
            status, data = self._pinned(opener, "GET", "/servicesNS/nobody/system/apps/local/{}".format(
                urllib.parse.quote(app_name)))
            out[label.split(".")[0]] = (
                data["entry"][0]["content"].get("version") if status == 200 else None)
        return out

    def install(self, package_path: str, app_name: str) -> None:
        """The lookup route. The app uploader page still renders (GET 200) on
        Cloud 10.8 but its POST answers 404, so probing it proves nothing."""
        self.install_via_lookup(package_path, app_name)

    def mint_token(self, audience: str, expires_on: str = "+30m") -> str:
        # SCTS stacks ship with token authentication off.
        self.mgmt("POST", "/services/admin/token-auth/tokens_auth", {"disabled": "false"})
        status, data = self.mgmt("POST", "/services/authorization/tokens/create", {
            "name": self.username, "audience": audience, "expires_on": expires_on})
        if status not in (200, 201):
            return ""
        token = data["entry"][0]["content"].get("token", "")
        mask(token)
        return token

    # -- verification -------------------------------------------------------

    def installed_version(self, app_name: str) -> Optional[str]:
        """Read the app's version back off the stack, through the mgmt API.

        This is the step that makes the whole exercise worth running. The build
        stamps the commit hash into app.conf, so the version read back here
        proves *which commit* is on the stack, not merely that something with
        the right name installed.
        """
        url = "{}/servicesNS/nobody/system/apps/local/{}?output_mode=json".format(
            self.mgmt_url, urllib.parse.quote(app_name),
        )
        try:
            status, raw, _ = _request(
                "GET", url,
                {"User-Agent": "scts.py", "Authorization": _basic_auth(self.username, self.password)},
                timeout=90, context=self._ctx,
            )
        except Exception as exc:  # noqa: BLE001
            log("Could not reach the management API to verify: {}".format(exc))
            return None
        if status == 404:
            log("{} is not present on the stack (HTTP 404).".format(app_name))
            return None
        if status != 200:
            log("Verification request returned HTTP {}.".format(status))
            return None
        try:
            return json.loads(raw.decode("utf-8"))["entry"][0]["content"].get("version")
        except (ValueError, KeyError, IndexError):
            return None


def _basic_auth(user: str, password: str) -> str:
    import base64
    return "Basic " + base64.b64encode("{}:{}".format(user, password).encode()).decode()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _client(args: argparse.Namespace) -> Scts:
    return Scts(os.environ.get(TOKEN_ENV, ""), args.base_url)


def cmd_versions(args: argparse.Namespace) -> None:
    for version in _client(args).versions():
        log("{status:<11} {build:<16} {name}".format(
            status=version.get("status", "?"),
            build=version.get("buildVersion", "?"),
            name=version.get("releaseName", ""),
        ))


def cmd_list(args: argparse.Namespace) -> None:
    stacks = _client(args).list_stacks()
    if not stacks:
        log("No active stacks.")
        return
    for stack in stacks:
        log("{id}  {state:<9} {version:<12} terminates {term}".format(
            id=stack.get("id"), state=stack.get("state"),
            version=stack.get("splunkVersion", "?"),
            term=stack.get("terminationDate", "?"),
        ))


OWNER_ARTIFACT_PREFIX = "scts-stack-"


def _created_by_this_workflow(stack_id: str) -> bool:
    """True only if a run of this repository recorded creating `stack_id`.

    SCTS has no name or tag field on create, so ownership cannot be read off the
    stack. Instead every run uploads an artefact named scts-stack-<id> the
    moment createStack answers, before it waits. A leftover stack whose id has
    such an artefact in this repository was created by this workflow; anything
    else (another repo, a local run, William poking by hand) is not ours to
    delete.
    """
    repo = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")
    if not repo or not token:
        log("No GITHUB_REPOSITORY/GITHUB_TOKEN, so ownership of {} cannot be shown.".format(stack_id))
        return False
    url = "https://api.github.com/repos/{}/actions/artifacts?per_page=10&name={}".format(
        repo, urllib.parse.quote(OWNER_ARTIFACT_PREFIX + stack_id))
    status, raw, _ = _request("GET", url, {
        "Authorization": "Bearer {}".format(token),
        "Accept": "application/vnd.github+json",
        "User-Agent": "scts.py",
    })
    if status != 200:
        log("Artefact lookup for {} answered HTTP {}; treating it as not ours.".format(stack_id, status))
        return False
    count = (json.loads(raw.decode("utf-8")) or {}).get("total_count", 0)
    return count > 0


def _resolve_conflict(client: Scts, reclaim: bool) -> bool:
    """Handle 409 MaxStacksLimitReached. Returns True if a retry is worthwhile."""
    stacks = client.list_stacks()
    if not stacks:
        log("409 but no stack is listed; it may be deleting. A retry may succeed.")
        return True
    retry = False
    for stack in stacks:
        sid = str(stack.get("id"))
        ours = _created_by_this_workflow(sid)
        log("Existing stack {} state={} created={} terminates={} created_by_this_workflow={}".format(
            sid, stack.get("state"), stack.get("createdAt"), stack.get("terminationDate"), ours))
        if ours and reclaim:
            log("Deleting leftover stack {} from an earlier run of this workflow.".format(sid))
            retry = client.delete(sid) or retry
        elif ours:
            log("Leftover stack {} is ours but --reclaim-own was not given; leaving it.".format(sid))
    if not retry:
        fail(
            "SCTS allows one stack at a time and one already exists. It was not created by "
            "this workflow (or reclaiming is off), so it has been left alone. Delete it by "
            "hand or wait for its termination date, then re-run."
        )
    return True


def cmd_create(args: argparse.Namespace) -> None:
    client = _client(args)
    status, stack = client.create(args.splunk_version)
    if status == 409:
        log("createStack: " + client._describe_error(status, stack))
        _resolve_conflict(client, args.reclaim_own)
        # A deleted stack can take a while to release the quota.
        for _ in range(20):
            time.sleep(30)
            status, stack = client.create(args.splunk_version)
            if status != 409:
                break
    if status != 202:
        fail("createStack failed: " + client._describe_error(status, stack))
    stack_id = stack["id"]
    # Emit the id before waiting: if the wait times out, the teardown step still
    # needs the id or the stack leaks until its termination date.
    set_output("stack_id", stack_id)
    log("Created stack {} ({}), terminates {}".format(
        stack_id, stack.get("splunkVersion", "?"), stack.get("terminationDate", "?"),
    ))

    if args.no_wait:
        return
    _wait(client, stack_id, args.timeout, args.interval)


def _wait(client: Scts, stack_id: str, timeout: int, interval: int) -> None:
    detail = client.wait_until_running(stack_id, timeout, interval)
    access = detail.get("stackAccessDetails") or {}
    mask(str(access.get("password", "")))
    set_output("stack_url", str(access.get("url", "")))
    set_output("splunk_version", str(detail.get("splunkVersion", "")))
    log("Stack {} is RUNNING at {} (Splunk {})".format(
        stack_id, access.get("url"), detail.get("splunkVersion")))


def cmd_wait(args: argparse.Namespace) -> None:
    _wait(_client(args), args.stack_id, args.timeout, args.interval)


def cmd_probe(args: argparse.Namespace) -> None:
    detail = _client(args).get(args.stack_id)
    access = detail.get("stackAccessDetails")
    if not access:
        fail("Stack {} has no access details yet (state {}).".format(
            args.stack_id, detail.get("state")))
    result = Stack(access, verify_tls=not args.insecure).probe()
    log(json.dumps(result, indent=2))


def cmd_install(args: argparse.Namespace) -> None:
    client = _client(args)
    detail = client.get(args.stack_id)
    access = detail.get("stackAccessDetails")
    if not access:
        fail("Stack {} has no access details (state {}).".format(
            args.stack_id, detail.get("state")))

    stack = Stack(access, verify_tls=not args.insecure)
    log("Install target: {} (Splunk {})".format(stack.web_url, detail.get("splunkVersion")))
    log("Probe: " + json.dumps(stack.probe()))

    if not os.path.isfile(args.package):
        fail("Package not found: {}".format(args.package))
    stack.install(args.package, args.app_name or "app")

    if args.app_name:
        version = None
        for _ in range(12):
            versions = stack.member_versions(args.app_name)
            log("Version per member: {}".format(versions))
            distinct = set(versions.values())
            version = distinct.pop() if len(distinct) == 1 else None
            if version and (not args.expect_version or version == args.expect_version):
                break
            version = None
            time.sleep(15)
        if version:
            log("Verified: {} is installed at version {}".format(args.app_name, version))
            set_output("installed_version", version)
            if args.expect_version and version != args.expect_version:
                fail(
                    "Version mismatch. Built {} but the stack reports {}. The artefact "
                    "on the stack is not the one this run produced.".format(
                        args.expect_version, version)
                )
        else:
            fail(
                "{} did not read back from the stack after upload. Treating that as a "
                "failed install rather than assuming success.".format(args.app_name)
            )


def _acs_call(url: str, token: str) -> Tuple[int, str]:
    try:
        status, raw, _ = _request("GET", url, {
            "Authorization": "Bearer " + token, "User-Agent": "scts.py"}, timeout=60)
    except Exception as exc:  # noqa: BLE001 - a probe reports, never raises
        return 0, "unreachable: {}".format(exc)
    text = raw.decode("utf-8", "replace")
    try:
        body = json.loads(text)
        # Keep codes and messages only, never anything token-shaped.
        if isinstance(body, dict):
            text = json.dumps({k: body[k] for k in ("code", "message", "status", "infraVersion")
                               if k in body})[:300]
        else:
            text = "json {}".format(type(body).__name__)
    except ValueError:
        text = text[:200]
    if token and token in text:
        text = "[withheld]"
    return status, text


def cmd_acs_probe(args: argparse.Namespace) -> None:
    """Does ACS (admin.splunk.com) answer for an SCTS stack? Reports, never fails."""
    detail = _client(args).get(args.stack_id)
    access = detail.get("stackAccessDetails")
    if not access:
        fail("Stack {} has no access details.".format(args.stack_id))
    stack = Stack(access, verify_tls=not args.insecure)
    host = urllib.parse.urlsplit(stack.web_url).hostname or ""
    names = [host.split(".")[0]]
    status, info = stack.mgmt("GET", "/services/server/info")
    if status == 200:
        server_name = info["entry"][0]["content"].get("serverName", "")
        log("serverName {}".format(server_name))
        if "." in server_name:
            names.append(server_name.split(".")[1])
    token = stack.mint_token("acs-probe")
    log("On-stack JWT minted: {}".format(bool(token)))
    results = {}
    for name in dict.fromkeys(names):
        base = "https://admin.splunk.com/{}/adminconfig/v2".format(name)
        for path in ("/status", "/apps/victoria?count=1", "/access/search-api/ipallowlists"):
            code, text = _acs_call(base + path, token)
            results["{}{}".format(name, path)] = code
            log("ACS {}{} -> HTTP {} {}".format(name, path, code, text))
    set_output("acs_results", json.dumps(results))
    # /status wants a different credential; the apps list is what deploying needs.
    ok = any(code == 200 for key, code in results.items() if "/apps/victoria" in key)
    log("ACS usable against this stack: {}".format(ok))
    set_output("acs_ok", "true" if ok else "false")


def cmd_delete(args: argparse.Namespace) -> None:
    if not args.stack_id:
        log("No stack id supplied; nothing to delete.")
        return
    ok = _client(args).delete(args.stack_id, strict=args.strict)
    log("Deleted stack {}".format(args.stack_id) if ok else "Stack not deleted.")


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="Splunk Cloud Testing Service client.")
    parser.add_argument("--base-url", default=os.environ.get("SCTS_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument(
        "--insecure", action="store_true",
        help="Skip TLS verification when talking to the stack (not to SCTS itself).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("versions", help="List available Splunk versions.").set_defaults(func=cmd_versions)
    sub.add_parser("list", help="List your active stacks.").set_defaults(func=cmd_list)

    p_create = sub.add_parser("create", help="Create a stack and wait for it.")
    p_create.add_argument("--splunk-version", default=None,
                          help="Build version to provision. Omit for latest released.")
    p_create.add_argument(
        "--timeout", type=int, default=5400,
        help="Seconds to wait for RUNNING. Observed provisioning time is ~75 min.",
    )
    p_create.add_argument("--interval", type=int, default=20, help="Poll interval in seconds.")
    p_create.add_argument("--no-wait", action="store_true")
    p_create.add_argument(
        "--reclaim-own", action="store_true",
        help="On 409, delete a leftover stack only if this repo's artefacts show this "
             "workflow created it. Stacks created elsewhere are never touched.",
    )
    p_create.set_defaults(func=cmd_create)

    p_wait = sub.add_parser("wait", help="Wait for a stack to be RUNNING with credentials.")
    p_wait.add_argument("stack_id")
    p_wait.add_argument("--timeout", type=int, default=7800)
    p_wait.add_argument("--interval", type=int, default=30)
    p_wait.set_defaults(func=cmd_wait)

    p_probe = sub.add_parser("probe", help="Report which endpoints a stack exposes.")
    p_probe.add_argument("stack_id")
    p_probe.set_defaults(func=cmd_probe)

    p_install = sub.add_parser("install", help="Install a built add-on onto a stack.")
    p_install.add_argument("stack_id")
    p_install.add_argument("--package", required=True, help="Path to the .tar.gz / .spl.")
    p_install.add_argument("--app-name", default=None, help="App id, to verify the install.")
    p_install.add_argument("--expect-version", default=None,
                           help="Fail unless the stack reports exactly this version.")
    p_install.set_defaults(func=cmd_install)

    p_acs = sub.add_parser("acs-probe", help="Check whether ACS answers for a stack.")
    p_acs.add_argument("stack_id")
    p_acs.set_defaults(func=cmd_acs_probe)

    p_delete = sub.add_parser("delete", help="Delete a stack.")
    p_delete.add_argument("stack_id", nargs="?", default="")
    p_delete.add_argument("--strict", action="store_true",
                          help="Exit non-zero if the delete fails.")
    p_delete.set_defaults(func=cmd_delete)

    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
