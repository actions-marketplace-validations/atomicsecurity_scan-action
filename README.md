# Atomic App Scanner for CI

Scan an Android APK with [Atomic App Scanner](https://atomicsecurity.app) on every build and
fail the build when a vulnerability reaches a severity you choose. One Python file, standard
library only: it runs as a GitHub Action and in any other CI.

## GitHub Actions

```yaml
- uses: atomicsecurity/scan-action@v1
  with:
    api-key: ${{ secrets.ATOMIC_API_KEY }}
    apk-path: app/build/outputs/apk/release/app-release.apk
    fail-on: critical # the default; info | low | medium | high | critical
```

Create the key in the app under **Settings, API keys** and store it as a repository or
organization secret. Each run uses one scan of your plan.

Most apps have findings at `high` on their first scan, many of them in bundled SDKs. Start at the default, mark what does not apply as a false positive in the app, then lower the threshold to `high`.

### Inputs

| Input          | Required | Default                          | Description                                                 |
| -------------- | -------- | -------------------------------- | ----------------------------------------------------------- |
| `api-key`      | yes      |                                  | Atomic API key (`ask_live_...`). Pass it from a secret.     |
| `apk-path`     | yes      |                                  | Path to the APK to scan.                                    |
| `fail-on`      | no       | `critical`                       | Lowest severity that fails the build.                       |
| `wait-timeout` | no       | `1800`                           | Seconds to wait for a free slot and for the scan to finish. |
| `sarif-output` | no       |                                  | If set, write SARIF to this path.                           |
| `api-url`      | no       | `https://atomicsecurity.app/api` | Leave the default unless you were given another one.        |

### Outputs

| Output              | Description                                         |
| ------------------- | --------------------------------------------------- |
| `scan-id`           | The id of the scan.                                 |
| `scan-url`          | The scan's report page.                             |
| `blocking-findings` | How many vulnerabilities are at or above `fail-on`. |

The job summary shows the counts per severity and a link to the full report.

### Alerts in the Security tab

Write SARIF and hand it to GitHub code scanning. Run the upload even when the gate failed the
build, or a failing build shows no alerts:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  # ... build the APK ...
  - uses: atomicsecurity/scan-action@v1
    with:
      api-key: ${{ secrets.ATOMIC_API_KEY }}
      apk-path: app/build/outputs/apk/release/app-release.apk
      sarif-output: atomic.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always() && hashFiles('atomic.sarif') != ''
    with:
      sarif_file: atomic.sarif
      category: atomic
```

Code scanning is free on public repositories. On a private one, GitHub accepts the upload
only with its paid Code Security add-on; without it, leave the upload step out: the gate and
the job summary work on their own.

The SARIF holds the open vulnerabilities only, without evidence: a hardcoded secret the scan
found is not copied to GitHub. Each alert links to the finding in Atomic, where the evidence
is. A scan of an APK has no source lines, so an alert names the class (as
`com/example/Login.java`) or the file inside the APK, at line 1. Several hits of one rule in one method are one alert.

## Any other CI

The script needs Python 3.9 or newer and four environment variables:

```sh
curl -fsSLO https://raw.githubusercontent.com/atomicsecurity/scan-action/v1/atomic_scan.py
ATOMIC_API_KEY="$ATOMIC_API_KEY" \
ATOMIC_APK_PATH=app/build/outputs/apk/release/app-release.apk \
ATOMIC_FAIL_ON=critical \
ATOMIC_SARIF_OUTPUT=atomic.sarif \
python3 atomic_scan.py
```

`ATOMIC_WAIT_TIMEOUT` (seconds, default 1800) and `ATOMIC_API_URL` are optional.

## Behaviour

The script creates a scan, uploads the APK straight to storage (it does not pass through the
API), starts the scan and follows it to the end. Then it counts the vulnerabilities that are
not marked as false positives. Observations (app inventory, posture notes) never block a
build.

| Exit code | Meaning                                                        |
| --------- | -------------------------------------------------------------- |
| `0`       | Passed: nothing at or above `fail-on`.                         |
| `1`       | The gate failed.                                               |
| `2`       | The scan could not be started: key, credits, upload or inputs. |
| `3`       | The scan did not finish in time or did not succeed.            |

If the workspace already runs its maximum of scans, or the queue is full, the script waits
and tries again until `wait-timeout`, so two pipelines that start together queue instead of
failing. A finding you mark as a false positive in the app stops blocking the next build.

## Troubleshooting

- **"The api-key input is empty"**: the secret is not set, or the workflow was triggered from
  a fork (GitHub does not pass secrets to those).
- **"no scan credits left"**: the workspace has used its scans. The message links to billing.
- **"Verify your email"**: a free workspace must verify its email address before its first
  scan.
- **HTTP 403 with "error code: 1010"** from your own client: the API's CDN refuses the default
  user agent of Python's `urllib`. Send your own `User-Agent` header (this script does).

## Development

```sh
python -m pip install pytest
python -m pytest -q
```

The tests run the script against a local HTTP server that plays the API and the storage.

## License

MIT, see [LICENSE](LICENSE).
