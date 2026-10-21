"""The gendeploytoken custom command loads and runs on this Splunk's Python.

commands.conf pins python.required = 3.13, so on Splunk 10.2+ the command runs
on Python 3.13 and on 10.0/10.1 on Python 3.9. Every import in the script
(splunklib, solnlib, boto3, the vendored native nacl/cffi wheels) happens at
module load, so a command that reaches its own "unknown destination" error
has imported everything on the interpreter Splunk chose for it.

The assertion reads the search job's messages from splunkd, which the command
never writes to directly: an import failure surfaces there as a generic
external-command error, a successful load as the command's own exception text.
"""
import json

from splunklib import binding

MISSING = "aios_ci_missing_destination"


def _search_messages(splunk, spl):
    conn = binding.connect(**splunk)
    try:
        resp = conn.post(
            "/services/search/jobs",
            search=spl,
            exec_mode="oneshot",
            output_mode="json",
        )
        body = resp.body.read().decode("utf-8", "replace")
    except binding.HTTPError as e:
        body = e.body.decode("utf-8", "replace") if isinstance(e.body, bytes) else str(e)
    try:
        msgs = json.loads(body).get("messages", [])
        return " | ".join(str(m.get("text", "")) for m in msgs) or body
    except ValueError:
        return body


def _ensure_github_conf(splunk):
    """A fresh install has no dest_github conf at all, so generate() would stop
    at a KeyError inside splunklib. One placeholder stanza makes the conf exist,
    so the command reaches its own destination lookup."""
    conn = binding.connect(**splunk)
    try:
        conn.post(
            "/servicesNS/nobody/splunk_app_scdeploy/configs/conf-splunk_app_scdeploy_dest_github",
            name="aios_ci_placeholder",
        )
    except binding.HTTPError as e:
        if e.status != 409:  # already exists from an earlier run
            raise


def test_gendeploytoken_loads_and_reaches_generate(splunk):
    _ensure_github_conf(splunk)
    text = _search_messages(
        splunk,
        f"| gendeploytoken destination_type=github destination_name={MISSING}",
    )
    print("search messages:", text)
    assert f"Cannot find destination_name called {MISSING}" in text, text
