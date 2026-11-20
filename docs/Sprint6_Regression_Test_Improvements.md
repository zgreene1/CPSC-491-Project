# Sprint 6 Regression Test Improvements

**Timestamp:** 2026-11-19 17:06 PST

## Changes

- Added `Backend/test_scanner_sprint6_accuracy.py` with localhost-only ACC-01 through ACC-10 coverage: affected/patched Apache and nginx versions, unknown HTTP, HTTP on an unusual ephemeral port, closed TCP, misleading service hint, low-confidence suppression, and silent UDP inconclusive classification.
- Added assertions for two Apache CVEs surviving coordinator JSON serialization, adapter preservation of fingerprint identity metadata, and API conversion of the `match_vulnerabilities` flag.
- Corrected the fingerprint fallback so generic HTTP headers cannot borrow unrelated low-confidence product signatures. Removed the `http`-as-product signature.
- Updated frontend mapper tests to verify both Apache CVEs remain attached to one port and TCP/UDP rows with the same host/port get distinct IDs.
- Added a frontend scan request test for `match_vulnerabilities: true` and corrected a stale test description that claimed CVE matching was absent.
- Applied and checked these changes against the newer 16:59 archive. Its existing `cvss: null` and recoverable-warning frontend updates remain intact.

## Test commands and result

From `Backend/`:

```bash
python3 -m pytest -q \
  test_scanner_tcp_fingerprint_accuracy.py \
  test_cve_reference_catalog.py \
  test_service_vulnerability_matcher.py \
  test_scanner_sprint6_accuracy.py
```

Result on Linux at 2026-11-19 17:05 PST against archive `3b41cd0eff4d52fe9947968b716d8a6324f20312`: **42 passed, 53 subtests passed**. The targeted command uses local fixtures/offline data; Scapy required the approved host-access path for local interface enumeration.

On Windows, use `python -m pytest -q` with the same filenames. On macOS/Linux, use `python3 -m pytest -q`.

The frontend tests were added but not executed because `frontend/node_modules` is absent. On a configured Node environment:

```bash
npm ci
npm test
```

## Files changed

- `Backend/scanner_Service_Fingerprint.py`
- `Backend/service_signatures.json`
- `Backend/test_scanner_sprint6_accuracy.py`
- `frontend/src/services/scanMapper.ts`
- `frontend/src/services/scanMapper.test.ts`
- `frontend/src/services/scanService.test.ts`

No CVSS scoring, severity logic, database schema, or persistence implementation was changed by this Sprint 6 patch. Existing CVSS-null and recoverable-warning frontend updates in the newer archive were preserved.
