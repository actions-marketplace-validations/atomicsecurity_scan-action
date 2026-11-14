"""Tests for the Action's script.

Run standalone (no app deps): `python -m pytest github-action/test_atomic_scan.py`.

The decision helpers are tested directly. The orchestration in `main()` is run
against a real HTTP server on a loopback port that plays both the Atomic API and
the object storage from a script of answers, and records what it was sent; the
script's clock and sleep are injected, so nothing here waits.
"""

from __future__ import annotations

import http.server
import json
import pathlib
import sys
import threading
from typing import Any

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

import atomic_scan as a

# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def test_severity_rank_orders_and_handles_unknown() -> None:
    assert a._severity_rank("critical") > a._severity_rank("high") > a._severity_rank("medium")
    assert a._severity_rank("medium") > a._severity_rank("low") > a._severity_rank("info")
    assert a._severity_rank("CRITICAL") == a._severity_rank("critical")  # case-insensitive
    assert a._severity_rank("bogus") == -1


def test_is_terminal() -> None:
    for s in ("succeeded", "failed", "timeout", "cancelled", "SUCCEEDED"):
        assert a.is_terminal(s)
    for s in ("queued", "running", "pending_upload"):
        assert not a.is_terminal(s)


def test_gate_fails_on_or_above_threshold() -> None:
    findings = [
        {"kind": "vulnerability", "severity": "high", "false_positive": None},
        {"kind": "vulnerability", "severity": "low", "false_positive": None},
    ]
    failed, counts, blocking = a.gate_result(findings, "high")
    assert failed is True
    assert blocking == 1
    assert counts["high"] == 1 and counts["low"] == 1


def test_gate_passes_below_threshold() -> None:
    findings = [{"kind": "vulnerability", "severity": "medium", "false_positive": None}]
    failed, _counts, blocking = a.gate_result(findings, "high")
    assert failed is False and blocking == 0


def test_gate_ignores_observations_and_suppressed() -> None:
    findings = [
        {"kind": "observation", "severity": "critical", "false_positive": None},
        {"kind": "vulnerability", "severity": "critical", "false_positive": {"marked_at": "x"}},
    ]
    failed, _counts, blocking = a.gate_result(findings, "high")
    assert failed is False and blocking == 0


def test_gate_counts_all_severities_regardless_of_threshold() -> None:
    findings = [
        {"kind": "vulnerability", "severity": "critical", "false_positive": None},
        {"kind": "vulnerability", "severity": "info", "false_positive": None},
    ]
    failed, counts, blocking = a.gate_result(findings, "critical")
    assert failed is True and blocking == 1  # only the critical blocks
    assert counts["critical"] == 1 and counts["info"] == 1


def test_dashboard_url_is_the_app_not_the_api() -> None:
    sid = "0b9f7c52-4f0e-4c7a-9a43-5d0d6f1e2a10"
    assert a.dashboard_url("https://atomicsecurity.app/api", sid) == (
        f"https://atomicsecurity.app/dashboard/scans/{sid}"
    )
    assert a.dashboard_url("https://atomicsecurity.app/api/", sid) == (
        f"https://atomicsecurity.app/dashboard/scans/{sid}"
    )
    # a base that does not end in /api is left alone (a self-hosted API host)
    assert a.dashboard_url("http://localhost:8000", sid) == (
        f"http://localhost:8000/dashboard/scans/{sid}"
    )


@pytest.mark.parametrize(
    ("status", "needle"),
    [
        (401, "API key"),
        (402, "credits"),
        (403, "verify"),
        (404, "api-url"),
        (413, "too large for the plan"),
        (429, "in progress"),
        (503, "queue"),
    ],
)
def test_explain_says_what_to_do(status: int, needle: str) -> None:
    detail = {
        403: "Verify your email to run your free scan.",
        413: "too large for the plan",
    }.get(status, "detail from the API")
    text = a.explain(status, detail, "https://atomicsecurity.app")
    assert needle.lower() in text.lower()


def test_explain_keeps_the_apis_words_for_a_status_it_has_no_advice_for() -> None:
    assert "cannot start scan in state 'running'" in a.explain(
        409, "cannot start scan in state 'running'", "https://x"
    )
    assert "418" in a.explain(418, "", "https://x")


# --------------------------------------------------------------------------- #
# A server that plays the API and the storage
# --------------------------------------------------------------------------- #

SCAN_ID = "0b9f7c52-4f0e-4c7a-9a43-5d0d6f1e2a10"
KEY = "ask_live_abcdefghijklmnopqrstuvwxyz234567abcdefg"
APK = b"PK\x03\x04" + bytes(range(256)) * 300  # 76,804 bytes: more than one read block


class Fake:
    """Answers from a script: `on(method, path, *answers)`. Each request to that
    method and path takes the next answer; the last one repeats. An answer is
    `(status, body)` or `(status, body, headers)`; a body that is not bytes is
    sent as JSON. `"drop"` closes the connection without answering."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self._script: dict[tuple[str, str], list[Any]] = {}
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args: Any) -> None:  # keep test output clean
                pass

            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                path, _, query = self.path.partition("?")
                fake.requests.append(
                    {
                        "method": self.command,
                        "path": path,
                        "query": query,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                        "body": body,
                    }
                )
                answers = fake._script.get((self.command, path))
                if not answers:
                    answer: Any = (599, {"detail": f"unscripted {self.command} {path}"})
                else:
                    answer = answers.pop(0) if len(answers) > 1 else answers[0]
                if answer == "drop":
                    self.close_connection = True
                    self.connection.close()
                    return
                status, payload, *rest = answer
                headers = rest[0] if rest else {}
                if isinstance(payload, bytes):
                    data = payload
                    ctype = headers.get("Content-Type", "application/octet-stream")
                else:
                    data = json.dumps(payload).encode()
                    ctype = "application/json"
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                for k, v in headers.items():
                    if k != "Content-Type":
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = _serve  # noqa: N815

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        self._thread.start()

    def on(self, method: str, path: str, *answers: Any) -> None:
        self._script[(method, path)] = list(answers)

    def sent(self, method: str, path: str) -> list[dict[str, Any]]:
        return [r for r in self.requests if r["method"] == method and r["path"] == path]

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def finding(seq: int, severity: str, kind: str = "vulnerability", fp: Any = None) -> dict:
    return {
        "id": f"f-{seq}",
        "seq": seq,
        "kind": kind,
        "severity": severity,
        "title": f"finding {seq}",
        "false_positive": fp,
    }


def page(items: list[dict], cursor: int, status: str, error: str | None = None) -> dict:
    return {"items": items, "next_cursor": cursor, "scan_status": status, "error": error}


@pytest.fixture
def fake() -> Any:
    f = Fake()
    yield f
    f.close()


@pytest.fixture
def run(fake: Fake, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> Any:
    """Run `main()` against the fake with a happy-path script that a test
    overrides per route. Returns (exit code, printed text, sleeps)."""
    apk = tmp_path / "app-release.apk"
    apk.write_bytes(APK)
    fake.on(
        "POST",
        "/v1/scans",
        (
            201,
            {
                "scan_id": SCAN_ID,
                "status": "pending_upload",
                "upload_url": f"{fake.base}/storage/obj?X-Amz-Signature=abc",
                "upload_headers": {"Content-Type": "application/vnd.android.package-archive"},
            },
        ),
    )
    fake.on("PUT", "/storage/obj", (200, b""))
    fake.on("POST", f"/v1/scans/{SCAN_ID}/start", (200, {"id": SCAN_ID, "status": "queued"}))
    fake.on(
        "GET",
        f"/v1/scans/{SCAN_ID}/findings",
        (200, page([], 0, "queued")),
        (200, page([finding(1, "low"), finding(2, "medium")], 2, "running")),
        (200, page([finding(3, "info", kind="observation")], 3, "succeeded")),
    )
    fake.on(
        "GET",
        f"/v1/scans/{SCAN_ID}/export",
        (200, b'{"version": "2.1.0", "runs": []}', {"Content-Type": "application/json"}),
    )

    def _run(**overrides: str) -> tuple[int, str, list[float]]:
        env = {
            "ATOMIC_API_URL": fake.base,
            "ATOMIC_API_KEY": KEY,
            "ATOMIC_APK_PATH": str(apk),
            "ATOMIC_FAIL_ON": "high",
            "ATOMIC_WAIT_TIMEOUT": "1800",
            "ATOMIC_SARIF_OUTPUT": "",
        }
        env.update(overrides)
        now = [1000.0]
        sleeps: list[float] = []

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            now[0] += seconds

        code = a.main(env=env, sleep=sleep, clock=lambda: now[0])
        out = capsys.readouterr()
        return code, out.out + out.err, sleeps

    return _run


# --------------------------------------------------------------------------- #
# The run, end to end
# --------------------------------------------------------------------------- #


def test_a_clean_scan_passes(fake: Fake, run: Any) -> None:
    code, text, _sleeps = run()
    assert code == 0
    assert "passed" in text
    assert f"/dashboard/scans/{SCAN_ID}" in text
    assert "Traceback" not in text
    # the three calls, in order, then polling
    order = [(r["method"], r["path"]) for r in fake.requests]
    assert order[:3] == [
        ("POST", "/v1/scans"),
        ("PUT", "/storage/obj"),
        ("POST", f"/v1/scans/{SCAN_ID}/start"),
    ]
    created = json.loads(fake.sent("POST", "/v1/scans")[0]["body"])
    assert created == {"filename": "app-release.apk", "size_bytes": len(APK)}


def test_the_key_goes_to_the_api_and_never_to_the_storage(fake: Fake, run: Any) -> None:
    run()
    for r in fake.requests:
        if r["path"].startswith("/v1/"):
            assert r["headers"]["authorization"] == f"Bearer {KEY}"
        else:
            assert "authorization" not in r["headers"]


def test_the_upload_is_the_file_with_the_headers_the_api_named(fake: Fake, run: Any) -> None:
    run()
    put = fake.sent("PUT", "/storage/obj")[0]
    assert put["body"] == APK
    assert put["headers"]["content-length"] == str(len(APK))
    # the presigned URL's signature covers the content type: it must be this one
    assert put["headers"]["content-type"] == "application/vnd.android.package-archive"
    assert put["query"] == "X-Amz-Signature=abc"


def test_the_upload_content_type_has_a_default_for_an_api_that_names_none(
    fake: Fake, run: Any
) -> None:
    fake.on(
        "POST",
        "/v1/scans",
        (201, {"scan_id": SCAN_ID, "upload_url": f"{fake.base}/storage/obj"}),
    )
    assert run()[0] == 0
    put = fake.sent("PUT", "/storage/obj")[0]
    assert put["headers"]["content-type"] == "application/vnd.android.package-archive"


def test_polling_follows_the_cursor_and_keeps_every_finding(fake: Fake, run: Any) -> None:
    code, text, sleeps = run(ATOMIC_FAIL_ON="medium")
    polls = fake.sent("GET", f"/v1/scans/{SCAN_ID}/findings")
    assert [p["query"] for p in polls] == [
        "since=0&limit=200",
        "since=0&limit=200",
        "since=2&limit=200",
    ]
    assert code == 1  # the medium finding from the second page blocks
    assert "1 medium" in text and "1 low" in text
    assert sleeps == [5, 5]  # between polls, not after the last


def test_a_scan_that_ended_is_read_to_its_last_finding(run: Any, fake: Fake) -> None:
    """Found by review, 2026-11-14: the first poll that sees the scan finished may
    carry a full page, with more findings behind it. Stopping there judged the
    build on the first 200 findings only: a critical at number 201 passed."""
    first = [finding(i, "low") for i in range(1, 201)]  # a full page
    fake.on(
        "GET",
        f"/v1/scans/{SCAN_ID}/findings",
        (200, page(first, 200, "succeeded")),
        (200, page([finding(500, "critical")], 500, "succeeded")),
    )
    code, text, sleeps = run()
    assert code == 1
    assert "1 critical" in text and "200 low" in text
    polls = fake.sent("GET", f"/v1/scans/{SCAN_ID}/findings")
    assert [p["query"] for p in polls] == ["since=0&limit=200", "since=200&limit=200"]
    assert sleeps == []  # the scan is over: the rest is read at once, without waiting


def test_a_last_page_that_is_exactly_full_ends_on_the_empty_one(run: Any, fake: Fake) -> None:
    fake.on(
        "GET",
        f"/v1/scans/{SCAN_ID}/findings",
        (200, page([finding(i, "low") for i in range(1, 201)], 200, "succeeded")),
        (200, page([], 200, "succeeded")),
    )
    code, _text, _ = run()
    assert code == 0
    assert len(fake.sent("GET", f"/v1/scans/{SCAN_ID}/findings")) == 2


def test_a_full_page_that_never_advances_does_not_loop(run: Any, fake: Fake) -> None:
    """A server that keeps answering the same full page must not hold the build."""
    fake.on(
        "GET",
        f"/v1/scans/{SCAN_ID}/findings",
        (200, page([finding(i, "low") for i in range(1, 201)], 200, "succeeded")),
    )
    code, _text, _ = run()
    assert code == 0
    assert len(fake.sent("GET", f"/v1/scans/{SCAN_ID}/findings")) == 2


def test_the_rest_is_also_read_when_the_scan_ends_mid_stream(run: Any, fake: Fake) -> None:
    fake.on(
        "GET",
        f"/v1/scans/{SCAN_ID}/findings",
        (200, page([finding(1, "low")], 1, "running")),
        (200, page([finding(i, "low") for i in range(2, 202)], 201, "succeeded")),
        (200, page([finding(i, "low") for i in range(202, 402)], 401, "succeeded")),
        (200, page([finding(402, "high")], 402, "succeeded")),
    )
    code, text, _ = run()
    assert code == 1
    assert "1 high" in text and "401 low" in text


def test_the_gate_fails_the_build(run: Any, fake: Fake) -> None:
    fake.on(
        "GET",
        f"/v1/scans/{SCAN_ID}/findings",
        (200, page([finding(1, "critical"), finding(2, "high")], 2, "succeeded")),
    )
    code, text, _ = run()
    assert code == 1
    assert "2 finding(s) at or above 'high'" in text
    assert "::error::" in text


def test_a_suppressed_finding_does_not_fail_the_build(run: Any, fake: Fake) -> None:
    fake.on(
        "GET",
        f"/v1/scans/{SCAN_ID}/findings",
        (200, page([finding(1, "critical", fp={"marked_at": "2026-11-01"})], 1, "succeeded")),
    )
    assert run()[0] == 0


def test_an_unknown_fail_on_is_an_error_not_a_pass(run: Any, fake: Fake) -> None:
    code, text, _ = run(ATOMIC_FAIL_ON="hgih")
    assert code == 2
    assert "fail-on" in text and "hgih" in text
    assert fake.requests == []  # nothing was uploaded for a run that cannot be judged


def test_a_missing_apk_is_an_error_before_any_call(run: Any, fake: Fake) -> None:
    code, text, _ = run(ATOMIC_APK_PATH="/nonexistent/app.apk")
    assert code == 2
    assert "/nonexistent/app.apk" in text
    assert fake.requests == []


def test_sarif_is_written_from_the_code_scanning_profile(
    run: Any, fake: Fake, tmp_path: pathlib.Path
) -> None:
    out = tmp_path / "out" / "atomic.sarif"
    out.parent.mkdir()
    code, _text, _ = run(ATOMIC_SARIF_OUTPUT=str(out))
    assert code == 0
    assert json.loads(out.read_text())["version"] == "2.1.0"
    export = fake.sent("GET", f"/v1/scans/{SCAN_ID}/export")[0]
    assert export["query"] == "format=sarif&profile=code-scanning"


def test_sarif_is_written_even_when_the_gate_fails(
    run: Any, fake: Fake, tmp_path: pathlib.Path
) -> None:
    fake.on(
        "GET",
        f"/v1/scans/{SCAN_ID}/findings",
        (200, page([finding(1, "critical")], 1, "succeeded")),
    )
    out = tmp_path / "atomic.sarif"
    code, _text, _ = run(ATOMIC_SARIF_OUTPUT=str(out))
    assert code == 1
    assert out.exists()


# ----- what the API can say on create / start --------------------------------


@pytest.mark.parametrize(
    ("status", "detail", "needle"),
    [
        (401, "not authenticated", "API key"),
        (402, "No scan credits remaining. Top up to run more scans.", "/dashboard/billing"),
        (413, "file exceeds max APK size (524288000 bytes)", "exceeds max APK size"),
        (422, [{"loc": ["body", "size_bytes"], "msg": "Input should be >= 1"}], "size_bytes"),
    ],
)
def test_create_refused(run: Any, fake: Fake, status: int, detail: Any, needle: str) -> None:
    fake.on("POST", "/v1/scans", (status, {"detail": detail}))
    code, text, _ = run()
    assert code == 2
    assert needle in text
    assert "::error::" in text
    assert "Traceback" not in text
    assert fake.sent("PUT", "/storage/obj") == []


@pytest.mark.parametrize(
    ("status", "detail", "needle"),
    [
        (402, "No scan credits remaining. Top up to run more scans.", "credits"),
        (403, "Verify your email to run your free scan. Check your inbox.", "Verify your email"),
        (409, "upload not found in storage; PUT to upload_url first", "upload not found"),
    ],
)
def test_start_refused(run: Any, fake: Fake, status: int, detail: str, needle: str) -> None:
    fake.on("POST", f"/v1/scans/{SCAN_ID}/start", (status, {"detail": detail}))
    code, text, _ = run()
    assert code == 2
    assert needle in text
    assert "Traceback" not in text


def test_a_busy_workspace_is_waited_out(run: Any, fake: Fake) -> None:
    busy = (429, {"detail": "too many scans in progress (5); wait for one to finish"})
    created = fake._script[("POST", "/v1/scans")][0]
    fake.on("POST", "/v1/scans", busy, busy, created)
    code, text, sleeps = run()
    assert code == 0
    assert len(fake.sent("POST", "/v1/scans")) == 3
    assert sleeps[:2] == [30, 30]
    assert "waiting" in text


def test_retry_after_is_honoured_up_to_a_minute(run: Any, fake: Fake) -> None:
    created = fake._script[("POST", "/v1/scans")][0]
    fake.on(
        "POST",
        "/v1/scans",
        (503, {"detail": "the scan queue is full right now"}, {"Retry-After": "7"}),
        (503, {"detail": "the scan queue is full right now"}, {"Retry-After": "3600"}),
        created,
    )
    code, _text, sleeps = run()
    assert code == 0
    assert sleeps[:2] == [7, 60]


def test_a_workspace_that_stays_busy_ends_the_run(run: Any, fake: Fake) -> None:
    fake.on("POST", "/v1/scans", (429, {"detail": "too many scans in progress (5)"}))
    code, text, sleeps = run(ATOMIC_WAIT_TIMEOUT="100")
    assert code == 3
    assert "too many scans in progress" in text
    assert sum(sleeps) <= 100 + 30


# ----- the upload --------------------------------------------------------------


def test_a_rejected_upload_shows_what_the_storage_said(run: Any, fake: Fake) -> None:
    fake.on(
        "PUT",
        "/storage/obj",
        (
            403,
            b"<Error><Code>SignatureDoesNotMatch</Code><Message>nope</Message></Error>",
            {"Content-Type": "application/xml"},
        ),
    )
    code, text, _ = run()
    assert code == 2
    assert "SignatureDoesNotMatch" in text
    assert "403" in text
    assert fake.sent("POST", f"/v1/scans/{SCAN_ID}/start") == []


# ----- polling -----------------------------------------------------------------


def test_one_bad_answer_while_polling_is_ridden_out(run: Any, fake: Fake) -> None:
    fake.on(
        "GET",
        f"/v1/scans/{SCAN_ID}/findings",
        (200, page([finding(1, "low")], 1, "running")),
        (502, {"detail": "the API did not answer; try again in a moment"}),
        "drop",
        (200, page([], 1, "succeeded")),
    )
    code, text, _ = run()
    assert code == 0
    assert "1 low" in text


def test_bad_answers_that_are_not_in_a_row_do_not_add_up(run: Any, fake: Fake) -> None:
    bad = (503, {"detail": "unavailable"})
    running = (200, page([], 0, "running"))
    fake.on(
        "GET",
        f"/v1/scans/{SCAN_ID}/findings",
        *[bad] * 4,
        running,
        *[bad] * 4,
        running,
        *[bad] * 4,
        (200, page([], 0, "succeeded")),
    )
    assert run()[0] == 0


def test_five_bad_answers_in_a_row_end_the_run(run: Any, fake: Fake) -> None:
    fake.on(
        "GET",
        f"/v1/scans/{SCAN_ID}/findings",
        (200, page([], 0, "running")),
        (503, {"detail": "unavailable"}),
    )
    code, text, _ = run()
    assert code == 3
    assert len(fake.sent("GET", f"/v1/scans/{SCAN_ID}/findings")) == 6
    assert "Traceback" not in text


def test_a_key_revoked_mid_scan_ends_the_run_at_once(run: Any, fake: Fake) -> None:
    fake.on(
        "GET",
        f"/v1/scans/{SCAN_ID}/findings",
        (200, page([], 0, "running")),
        (401, {"detail": "not authenticated"}),
    )
    code, text, _ = run()
    assert code == 3
    assert "API key" in text
    assert len(fake.sent("GET", f"/v1/scans/{SCAN_ID}/findings")) == 2


@pytest.mark.parametrize("status", ["failed", "timeout", "cancelled"])
def test_a_scan_that_does_not_succeed_fails_the_step(run: Any, fake: Fake, status: str) -> None:
    fake.on(
        "GET",
        f"/v1/scans/{SCAN_ID}/findings",
        (200, page([], 0, status, error="sandbox exited 137")),
    )
    code, text, _ = run()
    assert code == 3
    assert status in text and "sandbox exited 137" in text


def test_a_scan_that_never_finishes_ends_at_the_deadline(run: Any, fake: Fake) -> None:
    fake.on("GET", f"/v1/scans/{SCAN_ID}/findings", (200, page([], 0, "running")))
    code, text, sleeps = run(ATOMIC_WAIT_TIMEOUT="60")
    assert code == 3
    assert "60s" in text
    assert 55 <= sum(sleeps) <= 65


# ----- what GitHub is told -------------------------------------------------------


def test_outputs_and_summary_on_github(run: Any, fake: Fake, tmp_path: pathlib.Path) -> None:
    fake.on(
        "GET",
        f"/v1/scans/{SCAN_ID}/findings",
        (200, page([finding(1, "high"), finding(2, "low")], 2, "succeeded")),
    )
    outputs = tmp_path / "gh_output"
    summary = tmp_path / "gh_summary"
    code, _text, _ = run(GITHUB_OUTPUT=str(outputs), GITHUB_STEP_SUMMARY=str(summary))
    assert code == 1
    lines = outputs.read_text().splitlines()
    assert f"scan-id={SCAN_ID}" in lines
    assert f"scan-url={fake.base}/dashboard/scans/{SCAN_ID}" in lines
    assert "blocking-findings=1" in lines
    md = summary.read_text()
    assert "| High | 1 |" in md and "| Low | 1 |" in md
    assert f"{fake.base}/dashboard/scans/{SCAN_ID}" in md


def test_nothing_is_written_outside_github(
    run: Any, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert run()[0] == 0
    assert [p.name for p in tmp_path.iterdir()] == ["app-release.apk"]


# ----- found against production on 2026-11-14 ---------------------------------


def test_every_request_names_the_client(run: Any, fake: Fake, tmp_path: pathlib.Path) -> None:
    """Cloudflare answers 403 "error code: 1010" to urllib's default
    `Python-urllib/3.x` user agent, so every call must carry our own."""
    run(ATOMIC_SARIF_OUTPUT=str(tmp_path / "x.sarif"))
    assert len(fake.requests) >= 6
    for r in fake.requests:
        assert r["headers"]["user-agent"].startswith("atomic-scan-action/"), r["path"]


def test_an_empty_key_is_an_error_before_any_call(run: Any, fake: Fake) -> None:
    code, text, _ = run(ATOMIC_API_KEY="  ")
    assert code == 2
    assert "api-key" in text
    assert fake.requests == []


def test_a_dropped_upload_is_tried_once_more(run: Any, fake: Fake) -> None:
    fake.on("PUT", "/storage/obj", "drop", (200, b""))
    code, _text, _ = run()
    assert code == 0
    puts = fake.sent("PUT", "/storage/obj")
    assert len(puts) == 2
    assert puts[1]["body"] == APK  # the second attempt sends the whole file again


def test_an_upload_that_keeps_dropping_is_an_error(run: Any, fake: Fake) -> None:
    fake.on("PUT", "/storage/obj", "drop")
    code, text, _ = run()
    assert code == 2
    assert "upload" in text.lower()
    assert "Traceback" not in text
    assert len(fake.sent("PUT", "/storage/obj")) == 2


def test_a_start_whose_answer_was_lost_is_not_started_twice(run: Any, fake: Fake) -> None:
    """The API may have queued the scan although its answer never arrived; the
    second try then gets 409 "cannot start scan in state 'queued'", which means
    it is running, not that something is wrong."""
    fake.on(
        "POST",
        f"/v1/scans/{SCAN_ID}/start",
        "drop",
        (409, {"detail": "cannot start scan in state 'queued'"}),
    )
    code, _text, _ = run()
    assert code == 0
    assert len(fake.sent("POST", f"/v1/scans/{SCAN_ID}/start")) == 2


def test_a_first_409_on_start_is_still_an_error(run: Any, fake: Fake) -> None:
    fake.on(
        "POST",
        f"/v1/scans/{SCAN_ID}/start",
        (409, {"detail": "upload not found in storage; PUT to upload_url first"}),
    )
    assert run()[0] == 2
