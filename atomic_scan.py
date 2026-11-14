#!/usr/bin/env python3
"""Atomic App Scanner: scan an APK from CI and gate the build on the result.

Creates a scan, uploads the APK straight to object storage, starts it, follows
the findings until the scan ends, and exits non-zero when a vulnerability meets
the `fail-on` severity. Optionally writes SARIF for GitHub code scanning.

One file, standard library only: it runs as a GitHub Action (see action.yml)
and in any other CI that has Python 3.9 or newer:

    ATOMIC_API_KEY=ask_live_... ATOMIC_APK_PATH=app-release.apk python3 atomic_scan.py

Environment: ATOMIC_API_KEY, ATOMIC_APK_PATH (required); ATOMIC_API_URL
(default https://atomicsecurity.app/api), ATOMIC_FAIL_ON (default high),
ATOMIC_WAIT_TIMEOUT (seconds, default 1800), ATOMIC_SARIF_OUTPUT (a path).

Exit codes: 0 passed; 1 the gate failed; 2 the scan could not be started (key,
credits, upload, inputs); 3 the scan did not finish or did not succeed.
"""

from __future__ import annotations

import http.client
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

DEFAULT_API_URL = "https://atomicsecurity.app/api"

# Low to high. Used for the fail-on threshold comparison.
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
_TERMINAL = {"succeeded", "failed", "timeout", "cancelled"}

EXIT_PASSED, EXIT_GATE, EXIT_NOT_STARTED, EXIT_NOT_FINISHED = 0, 1, 2, 3

_POLL_SECONDS = 5
_PAGE = 200  # findings per request
_BUSY_SECONDS = 30  # between tries while the workspace or the queue is full
_RETRY_AFTER_CAP = 60
_MAX_BAD_POLLS = 5  # bad answers in a row before giving up on a running scan
_START_TRIES = 3

# The upload URL is presigned for exactly this content type (and length); the
# API names it in `upload_headers`, this is the fallback for one that does not.
_APK_CONTENT_TYPE = "application/vnd.android.package-archive"
# Our own name on every request: the CDN in front of the API refuses urllib's
# default `Python-urllib/3.x` (HTTP 403, "error code: 1010").
_USER_AGENT = "atomic-scan-action/1 (+https://github.com/atomicsecurity/scan-action)"


class ApiError(Exception):
    """The API answered with an error status."""

    def __init__(self, status: int, detail: str, retry_after: int | None = None) -> None:
        super().__init__(f"HTTP {status}: {detail}")
        self.status = status
        self.detail = detail
        self.retry_after = retry_after


class TransientError(Exception):
    """No usable answer: the connection failed, timed out or was cut."""


class UploadError(Exception):
    def __init__(self, status: int, text: str) -> None:
        super().__init__(text)
        self.status = status
        self.text = text


# --------------------------------------------------------------------------- #
# Decisions (no I/O)
# --------------------------------------------------------------------------- #


def _severity_rank(sev: str) -> int:
    """Rank a severity (higher = worse); -1 for an unknown value."""
    try:
        return _SEVERITY_ORDER.index(sev.lower())
    except ValueError:
        return -1


def is_terminal(status: str) -> bool:
    """True once the scan has reached a terminal state (stop polling)."""
    return status.lower() in _TERMINAL


def gate_result(findings: list[dict[str, Any]], fail_on: str) -> tuple[bool, dict[str, int], int]:
    """Decide pass/fail from the collected findings.

    Counts only non-suppressed VULNERABILITY findings (observations are app
    inventory, not security issues; false-positive-marked findings are excluded).
    Returns (failed, counts_by_severity, blocking_count). `failed` is True when
    any counted finding is at or above `fail_on`."""
    threshold = _severity_rank(fail_on)
    counts = {s: 0 for s in _SEVERITY_ORDER}
    blocking = 0
    for f in findings:
        if f.get("kind") != "vulnerability":
            continue
        if f.get("false_positive"):  # suppressed: not build-blocking
            continue
        sev = str(f.get("severity", "")).lower()
        if sev in counts:
            counts[sev] += 1
        if threshold >= 0 and _severity_rank(sev) >= threshold:
            blocking += 1
    return blocking > 0, counts, blocking


def dashboard_url(api_url: str, scan_id: str) -> str:
    """The scan's page in the web app. The public API lives under `<app>/api`."""
    base = api_url.rstrip("/")
    if base.endswith("/api"):
        base = base[: -len("/api")]
    return f"{base}/dashboard/scans/{scan_id}"


def explain(status: int, detail: str, app_url: str) -> str:
    """What an API error means for the person reading the CI log."""
    if status == 401:
        return (
            f"Atomic rejected the API key ({detail or 'not authenticated'}). Create a key at "
            f"{app_url}/dashboard/settings/api-keys and pass it from a secret."
        )
    if status == 402:
        return (
            f"This workspace has no scan credits left ({detail or 'payment required'}). "
            f"Buy a scan or subscribe at {app_url}/dashboard/billing"
        )
    if status == 403:
        return detail or "Atomic refused the request (403)."
    if status == 404:
        return (
            f"Atomic answered 404 ({detail or 'not found'}). Check the api-url input: "
            f"it is {DEFAULT_API_URL} unless you were given another one."
        )
    if status == 429:
        return f"Too many scans in progress for this workspace: {detail}"
    if status == 503:
        return f"The scan queue is full right now: {detail}"
    return f"HTTP {status}: {detail}" if detail else f"HTTP {status}"


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #


def _detail_of(body: bytes) -> str:
    """The API's `detail`, whatever shape it has, as one line."""
    text = body.decode("utf-8", "replace").strip()
    try:
        detail = json.loads(text).get("detail")
    except (ValueError, AttributeError):
        return text[:300]
    if isinstance(detail, str):
        return detail
    if isinstance(detail, list):  # FastAPI validation errors
        parts = []
        for item in detail:
            if isinstance(item, dict):
                loc = ".".join(str(p) for p in item.get("loc", []) if p != "body")
                parts.append(f"{loc}: {item.get('msg', '')}" if loc else str(item.get("msg", "")))
            else:
                parts.append(str(item))
        return "; ".join(parts)
    return text[:300]


def _retry_after(headers: Any) -> int | None:
    try:
        return max(0, int(headers.get("Retry-After", "")))
    except (TypeError, ValueError):
        return None


def _open(req: urllib.request.Request, timeout: float) -> bytes:
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.read()
    except urllib.error.HTTPError as exc:
        raise ApiError(exc.code, _detail_of(exc.read()), _retry_after(exc.headers)) from None
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        raise TransientError(str(getattr(exc, "reason", exc)) or type(exc).__name__) from None


def _api(method: str, url: str, token: str, payload: dict | None = None) -> dict:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": _USER_AGENT,
    }
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, method=method, headers=headers, data=data)  # noqa: S310
    body = _open(req, timeout=60)
    if not body:
        return {}
    try:
        parsed = json.loads(body)
    except ValueError:
        raise TransientError("the answer was not JSON") from None
    return parsed if isinstance(parsed, dict) else {}


def _download(url: str, token: str) -> bytes:
    req = urllib.request.Request(  # noqa: S310
        url, headers={"Authorization": f"Bearer {token}", "User-Agent": _USER_AGENT}
    )
    return _open(req, timeout=180)


def _upload(path: str, url: str, size: int, headers: Mapping[str, str]) -> None:
    """PUT the file to the presigned URL, streamed. No Authorization header:
    the URL is the credential, and it is signed for these headers."""
    send = {"User-Agent": _USER_AGENT, **headers, "Content-Length": str(size)}
    last = ""
    for _attempt in range(2):  # a cut connection is worth one more try
        with open(path, "rb") as fh:
            req = urllib.request.Request(url, data=fh, method="PUT", headers=send)  # noqa: S310
            try:
                with urllib.request.urlopen(req, timeout=900) as resp:  # noqa: S310
                    resp.read()
                return
            except urllib.error.HTTPError as exc:
                text = exc.read(2000).decode("utf-8", "replace").strip()
                raise UploadError(exc.code, text) from None
            except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
                last = str(getattr(exc, "reason", exc)) or type(exc).__name__
    raise UploadError(0, last)


# --------------------------------------------------------------------------- #
# The run
# --------------------------------------------------------------------------- #


def _log(line: str) -> None:
    print(line, flush=True)


def _write_github(env: Mapping[str, str], scan_id: str, url: str, blocking: int) -> None:
    out = env.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"scan-id={scan_id}\nscan-url={url}\nblocking-findings={blocking}\n")


def _write_summary(env: Mapping[str, str], url: str, counts: dict[str, int], verdict: str) -> None:
    path = env.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    rows = "".join(f"| {s.capitalize()} | {counts[s]} |\n" for s in reversed(_SEVERITY_ORDER))
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(
            "### Atomic App Scanner\n\n"
            f"{verdict}\n\n"
            "| Severity | Vulnerabilities |\n|---|---|\n"
            f"{rows}\n"
            f"[Open the full report]({url})\n"
        )


def main(
    env: Mapping[str, str] = os.environ,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> int:
    api_url = (env.get("ATOMIC_API_URL") or DEFAULT_API_URL).rstrip("/")
    app_url = dashboard_url(api_url, "").rsplit("/dashboard/", 1)[0]
    token = (env.get("ATOMIC_API_KEY") or "").strip()
    apk_path = env.get("ATOMIC_APK_PATH") or ""
    fail_on = (env.get("ATOMIC_FAIL_ON") or "high").strip().lower()
    sarif_out = (env.get("ATOMIC_SARIF_OUTPUT") or "").strip()

    # Inputs first: nothing is uploaded for a run that cannot be judged.
    if fail_on not in _SEVERITY_ORDER:
        _log(f"::error::fail-on must be one of {', '.join(_SEVERITY_ORDER)}; got '{fail_on}'")
        return EXIT_NOT_STARTED
    try:
        wait_timeout = int(env.get("ATOMIC_WAIT_TIMEOUT") or "1800")
    except ValueError:
        _log("::error::wait-timeout must be a number of seconds")
        return EXIT_NOT_STARTED
    if not token:
        _log(
            "::error::The api-key input is empty. Store an Atomic API key as a secret; "
            "note that secrets are not passed to workflows triggered from forks."
        )
        return EXIT_NOT_STARTED
    if not os.path.isfile(apk_path):
        _log(f"::error::No APK at apk-path '{apk_path}'")
        return EXIT_NOT_STARTED

    size = os.path.getsize(apk_path)
    filename = os.path.basename(apk_path)
    deadline = clock() + wait_timeout

    # 1. Create. A full workspace or queue is waited out, not failed on: two
    #    pipelines that run at once should queue.
    while True:
        try:
            created = _api(
                "POST", f"{api_url}/v1/scans", token, {"filename": filename, "size_bytes": size}
            )
            break
        except ApiError as exc:
            if exc.status not in (429, 503):
                _log(f"::error::{explain(exc.status, exc.detail, app_url)}")
                return EXIT_NOT_STARTED
            wait = min(exc.retry_after or _BUSY_SECONDS, _RETRY_AFTER_CAP)
            why = explain(exc.status, exc.detail, app_url)
        except TransientError as exc:
            wait = _BUSY_SECONDS
            why = f"Atomic could not be reached ({exc})"
        if clock() + wait > deadline:
            _log(f"::error::{why}. Gave up after {wait_timeout}s.")
            return EXIT_NOT_FINISHED
        _log(f"::notice::{why}; waiting {wait}s")
        sleep(wait)

    scan_id = str(created["scan_id"])
    scan_url = dashboard_url(api_url, scan_id)
    _log(f"::notice::Atomic scan {scan_id} created, uploading {filename} ({size} bytes)")

    # 2. Upload, straight to storage.
    upload_headers = created.get("upload_headers") or {"Content-Type": _APK_CONTENT_TYPE}
    try:
        _upload(apk_path, created["upload_url"], size, upload_headers)
    except UploadError as exc:
        what = f"HTTP {exc.status}: {exc.text}" if exc.status else exc.text
        _log(f"::error::The APK upload failed ({what})")
        return EXIT_NOT_STARTED

    # 3. Start. If the answer to a first try is lost, the scan may be queued
    #    all the same; the next try then says 409, which is fine.
    for attempt in range(_START_TRIES):
        try:
            _api("POST", f"{api_url}/v1/scans/{scan_id}/start", token)
            break
        except ApiError as exc:
            if exc.status == 409 and attempt > 0:
                break
            _log(f"::error::{explain(exc.status, exc.detail, app_url)}")
            return EXIT_NOT_STARTED
        except TransientError as exc:
            if attempt == _START_TRIES - 1:
                _log(f"::error::Atomic could not be reached to start the scan ({exc})")
                return EXIT_NOT_STARTED
            sleep(_POLL_SECONDS)
    _log(f"::notice::Atomic scan started: {scan_url}")

    # 4. Follow the findings until the scan ends.
    cursor = 0
    findings: dict[int, dict] = {}
    page: dict[str, Any] = {}
    status = "queued"
    bad = 0
    while True:
        if clock() >= deadline:
            _log(f"::error::The scan did not finish within {wait_timeout}s: {scan_url}")
            return EXIT_NOT_FINISHED
        try:
            page = _api(
                "GET",
                f"{api_url}/v1/scans/{scan_id}/findings?since={cursor}&limit={_PAGE}",
                token,
            )
        except ApiError as exc:
            if exc.status not in (502, 503, 504):
                _log(f"::error::{explain(exc.status, exc.detail, app_url)}")
                return EXIT_NOT_FINISHED
            bad += 1
        except TransientError:
            bad += 1
        else:
            bad = 0
            items = page.get("items", [])
            for f in items:
                findings[f["seq"]] = f
            seen_up_to = cursor
            cursor = page.get("next_cursor", cursor)
            status = str(page.get("scan_status", status))
            if is_terminal(status):
                # The scan is over, but a full page may have more behind it: read
                # on at once until a page comes back short. (Judging the build on
                # the first page alone let a finding beyond it pass the gate.)
                if len(items) >= _PAGE and cursor != seen_up_to:
                    continue
                break
        if bad >= _MAX_BAD_POLLS:
            _log(f"::error::Lost contact with Atomic while the scan ran: {scan_url}")
            return EXIT_NOT_FINISHED
        sleep(_POLL_SECONDS)

    if status != "succeeded":
        _log(f"::error::The scan ended '{status}': {page.get('error') or 'no detail'}")
        _write_github(env, scan_id, scan_url, 0)
        return EXIT_NOT_FINISHED

    # 5. SARIF, before the verdict: a failing build still gets its alerts.
    if sarif_out:
        try:
            sarif = _download(
                f"{api_url}/v1/scans/{scan_id}/export?format=sarif&profile=code-scanning", token
            )
        except (ApiError, TransientError) as exc:
            _log(f"::warning::Could not fetch SARIF ({exc})")
        else:
            with open(sarif_out, "wb") as fh:
                fh.write(sarif)
            _log(f"::notice::SARIF written to {sarif_out}")

    # 6. The verdict.
    failed, counts, blocking = gate_result(list(findings.values()), fail_on)
    summary = ", ".join(f"{counts[s]} {s}" for s in reversed(_SEVERITY_ORDER) if counts[s])
    _log(f"::notice::Atomic found {summary or 'no vulnerabilities'}: {scan_url}")
    _write_github(env, scan_id, scan_url, blocking)
    if failed:
        verdict = f"{blocking} finding(s) at or above '{fail_on}'"
        _write_summary(env, scan_url, counts, f"**Failed:** {verdict}.")
        _log(f"::error::{verdict}, failing the build")
        return EXIT_GATE
    _write_summary(env, scan_url, counts, f"**Passed:** nothing at or above '{fail_on}'.")
    _log(f"Atomic scan passed: no findings at or above '{fail_on}'.")
    return EXIT_PASSED


if __name__ == "__main__":
    sys.exit(main())
