"""The token_cleaner input honours its per-run `limit`.

Before the fix it logged "Stopping token remover as reached per-run
delete_limit" and then carried on (`continue`), deleting every expired token.

The test mints more expired tokens than the limit, creates one cleaner input
with a long interval (so it runs once, at creation) and counts, through
splunkd's own token listing, how many expired tokens disappeared. It counts
every expired token on the instance, not only the ones it minted, because the
cleaner is instance-wide by design: whichever tokens it picks, it must stop at
`limit`. A live token must survive.
"""
import json
import time
import uuid

import pytest
from splunklib import binding

APP = "splunk_app_scdeploy"
N_EXPIRED = 6
LIMIT = 2


def _conn(splunk):
    return binding.connect(**splunk)


def _json(resp):
    return json.loads(resp.body.read().decode("utf-8", "replace"))


def _tokens(conn):
    """{id: exp} for every token on the instance, from splunkd's listing."""
    data = _json(conn.get("/services/authorization/tokens", output_mode="json", count=0))
    return {e["name"]: int(e["content"]["claims"]["exp"]) for e in data.get("entry", [])}


def _mint(conn, audience, expires_on):
    data = _json(conn.post("/services/authorization/tokens/create", output_mode="json",
                           name="admin", audience=audience, expires_on=expires_on))
    return data["entry"][0]["content"]["id"]


def _wait_kvstore_ready(conn, timeout=420):
    """Token creation needs the KV store, which can still be starting after
    the container reports ready (seen on 10.2)."""
    deadline, last = time.time() + timeout, None
    while time.time() < deadline:
        try:
            data = _json(conn.get("/services/kvstore/status", output_mode="json"))
            last = data["entry"][0]["content"].get("current", {}).get("status")
            if str(last).lower() == "ready":
                return
        except binding.HTTPError as e:
            last = e.status
        if str(last).lower() == "failed":
            # Seen on this repo's 10.2 image only: the KV store never starts,
            # so no token can exist there. Say why, with splunkd's own words.
            pytest.skip(f"KV store status 'failed' on this instance; token tests cannot run. "
                        f"Recent KV store errors: {_kvstore_errors(conn)}")
        time.sleep(5)
    pytest.fail(f"KV store not ready within {timeout}s (last status {last!r})")


def _kvstore_errors(conn):
    try:
        resp = conn.post("/services/search/jobs", exec_mode="oneshot", output_mode="json", count=8,
                         search="search index=_internal (source=*mongod.log* OR component=KVStore*) "
                                "(ERROR OR error OR fatal OR Fatal OR fail*) earliest=-30m "
                                "| head 8 | table _raw")
        rows = _json(resp).get("results", [])
        return " || ".join(r.get("_raw", "")[:300] for r in rows) or "none found"
    except Exception as exc:  # diagnostics only
        return f"(search failed: {exc})"


@pytest.fixture
def token_auth(splunk):
    conn = _conn(splunk)
    _wait_kvstore_ready(conn)
    conn.post("/services/admin/token-auth/tokens_auth", disabled="false")
    return conn


def test_cleaner_stops_at_limit(token_auth):
    conn = token_auth
    tag = uuid.uuid4().hex[:8]
    audience = f"aios_ci_cleaner_{tag}"
    expired = {_mint(conn, audience, "+3s") for _ in range(N_EXPIRED)}
    live = _mint(conn, audience, "+2h")
    time.sleep(8)

    now = time.time()
    before = _tokens(conn)
    missing = len(expired - set(before))
    assert missing == 0, f"{missing} minted tokens missing from the listing"
    expired_before = {t for t, exp in before.items() if exp < now}
    assert len(expired_before) >= N_EXPIRED > LIMIT

    name = f"ci_cleaner_{tag}"
    conn.post(f"/servicesNS/nobody/{APP}/{APP}_token_cleaner", output_mode="json",
              name=name, min_expiry="0", limit=str(LIMIT), interval="86400")
    try:
        # Wait for the first deletion, then for the run to settle.
        deadline = time.time() + 240
        while time.time() < deadline:
            if expired_before - set(_tokens(conn)):
                break
            time.sleep(5)
        time.sleep(30)
        after = set(_tokens(conn))
    finally:
        conn.delete(f"/servicesNS/nobody/{APP}/{APP}_token_cleaner/{name}")
        for t in expired | {live}:
            try:
                conn.delete("/services/authorization/tokens/admin", id=t)
            except binding.HTTPError:
                pass

    # Counts only: token ids stay out of the CI log.
    n_removed = len(expired_before - after)
    n_expired = len(expired_before)
    live_kept = live in after
    assert n_removed > 0, "the cleaner removed nothing within 4 minutes (did it run?)"
    assert n_removed == LIMIT, f"limit={LIMIT} but {n_removed} of {n_expired} expired tokens were removed"
    assert live_kept, "the cleaner removed a token that has not expired"
