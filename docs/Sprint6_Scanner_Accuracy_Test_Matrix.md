# Sprint 6 Scanner Accuracy Test Matrix

**Assessment timestamp:** 2026-11-19 17:06 PST

**Source:** uploaded `CPSC-491-Project-main(2).zip`, GitHub `main` source archive

**Archive snapshot identifier:** `3b41cd0eff4d52fe9947968b716d8a6324f20312`
**Scope:** controlled `127.0.0.1` mock services and offline catalog only

The source archive did not include `.git`, so `git branch`, `git status`, and an independently queried `HEAD` are unavailable in the extracted copy. The archive's first line identifies its snapshot; GitHub displayed the repository's `main` branch when inspected. No merge state is inferred from this archive.

## Baseline

Runtime: Python 3.14.8, pytest 9.1.1, Linux. The three requested baseline suites passed on the new archive: **33 tests and 49 subtests**. The test run used approved host access because Scapy inspects local interfaces during import. See `Backend/sprint6-baseline.log`.

## Matrix

| Case | Controlled scenario | Expected result | Actual result | Status |
|---|---|---|---|---|
| ACC-01 | Mock Apache HTTP banner `2.4.49` | Two potential catalog matches: CVE-2021-41773 and CVE-2021-42013 | Both findings appear on the same TCP port in coordinator output and JSON | PASS |
| ACC-02 | Mock Apache HTTP banner `2.4.51` | No catalog matches | No findings | PASS |
| ACC-03 | Mock nginx HTTP banner `1.20.0` | One potential match: CVE-2021-23017 | One finding | PASS |
| ACC-04 | Mock nginx HTTP banner `1.20.1` | No catalog matches | No findings | PASS |
| ACC-05 | Generic HTTP response with no product/version evidence | Service `http`; product/version unset | Initially labeled product `connection` due broad cross-service signature fallback. Fixed by restricting fallback to passive unclassified banners; now HTTP with no product/version | PASS after fix |
| ACC-06 | Apache mock on OS-assigned high ephemeral port with no service hint | Identify Apache and version from HTTP response | Apache `2.4.58` identified | PASS |
| ACC-07 | Bound, non-listening TCP port on loopback | Do not report as open | Open-only scan returns no result | PASS |
| ACC-08 | Apache mock with misleading `ssh` service hint | HTTP banner determines service/product/version | Apache `2.4.58` identified as HTTP | PASS |
| ACC-09 | Apache `2.4.49` identity at confidence `0.89` | Suppress CVE matching below `0.90` | No software identity and no findings | PASS |
| ACC-10 | Silent UDP timeout | `open|filtered` / `udp_timeout`; do not claim open | Inconclusive state returned; legacy open-only API omits it | PASS |

ACC-01–04 use harmless synthetic banners. No vulnerable Apache or nginx implementation is installed or exercised. ACC-10 uses a deterministic socket timeout mock because UDP timeout classification can vary by host firewall and operating system.

## Controlled sample measurements

These are descriptive results for this small, deliberately selected regression set. They are not estimates of scanner performance on real networks.

| Layer | Cases included | Confusion counts | Accuracy |
|---|---:|---|---:|
| TCP port open/closed | ACC-01–08 | TP 7, FP 0, TN 1, FN 0 | 8/8 (100%) |
| Fingerprint product present/absent | ACC-01–06 and ACC-08; ACC-07 excluded because no service exists | TP 6, FP 0, TN 1, FN 0 | 7/7 (100%) |
| CVE label match | Three expected affected labels plus five expected negative labels across ACC-01–04 and ACC-09 | TP 3, FP 0, TN 5, FN 0 | 8/8 (100%) |

The UDP case is excluded from port accuracy because `open|filtered` is intentionally inconclusive. Exact service/version assertions are retained in the tests; the fingerprint table above only reports the product-present/absent confusion count to keep unlike product classes from being pooled into an unhelpful single accuracy number.

## Reproduction

Run from `Backend/`:

```bash
python3 -m pytest -v \
  test_scanner_tcp_fingerprint_accuracy.py \
  test_cve_reference_catalog.py \
  test_service_vulnerability_matcher.py \
  test_scanner_sprint6_accuracy.py
```

On Windows, use `python -m pytest -v` with the same test filenames. These tests open only ephemeral listeners bound to `127.0.0.1`; closed TCP and silent UDP conditions are locally controlled. The command and final result are recorded in `Backend/sprint6-final-tests.log`.

The frontend regression tests are in `frontend/src/services/scanMapper.test.ts` and `scanService.test.ts`. They were not run here because the archive has no `node_modules`; installing dependencies was not part of the approved test setup. Use `npm ci` followed by `npm test` in `frontend/` to run them on a configured Node environment.

## Newer project changes preserved

This archive includes frontend changes absent from the previous snapshot: real scan CVSS is represented as `null`, and recoverable backend errors are mapped to scan warnings. The Sprint 6 patch applies on top of these changes and leaves them intact.

## Limitations

- Only Linux was executed. Windows and macOS behavior remains unverified in this run.
- Ephemeral local sockets exercise scanner behavior, not NAT, host firewalls, proxies, TLS middleboxes, banner hiding, or production services.
- The curated catalog contains three CVE records and is intentionally incomplete; no finding is not evidence of safety.
- The sample is too small and intentionally constructed; percentages must not be generalized.
