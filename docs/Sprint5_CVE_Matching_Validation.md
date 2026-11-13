# Sprint 5 — Curated CVE Matching Verification

**Review date:** 2026-11-12

**Status:** Tested offline against a small, manually vetted subset of vendor/NVD records. **Not** a complete NVD integration.

## What was implemented

- `Backend/vulnerability_catalog.json` now includes three curated CVEs instead of an empty production catalog.
- Existing `service_vulnerability_matcher.py` checks exact allowlisted software identities, conservative numeric version bounds, `open/tcp` observations and high-confidence application-level fingerprint methods.
- The scanner coordinator's existing opt-in `MATCHING` stage consumes the curated catalog and serializes matches in `ScanResult.vulnerabilities`.
- The React frontend already passes `match_vulnerabilities: true` and can display associated potential CVE IDs, although it still groups ordinary open-port observations under its broader "vulnerabilities" UI type.
- Optional local mock HTTP services expose simulated *banner strings* for affected and patched versions; they do not execute the affected Apache/nginx software.

## Verified CVE data

| CVE | Software | Versions represented by catalog | Vendor / NVD evidence | Caveat |
| --- | --- | --- | --- | --- |
| CVE-2021-41773 | Apache HTTP Server | 2.4.49 only | https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773 | Requires vulnerable alias-path access configuration; potential match only. |
| CVE-2021-42013 | Apache HTTP Server | 2.4.49 and 2.4.50 | https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-42013 and https://nvd.nist.gov/vuln/detail/CVE-2021-42013 | Incomplete fix for earlier CVE; configuration affects exploitability. |
| CVE-2021-23017 | nginx | 0.6.18–1.20.0 | https://nginx.org/en/security_advisories.html and https://nvd.nist.gov/vuln/detail/CVE-2021-23017 | Requires `resolver` directive and conditions allowing forged DNS replies; versions 1.20.1 and 1.21.0 are fixed. |

All catalog entries use an inclusive lower and exclusive upper bound. They are local data reviewed against the linked source; there is no dynamic fetching from NVD. Updated vendor patches or backports cannot be inferred from a banner alone.

## Deterministic expected outcomes

| Product | Advertised version | Potential catalog matches |
| --- | --- | --- |
| Apache httpd | 2.4.48 | None from these three records |
| Apache httpd | 2.4.49 | CVE-2021-41773, CVE-2021-42013 |
| Apache httpd | 2.4.50 | CVE-2021-42013 |
| Apache httpd | 2.4.51 | None from these three records |
| nginx | 1.20.0 | CVE-2021-23017 |
| nginx | 1.20.1 | None from these three records |

Other versions and products may have unrelated CVEs not covered by this catalog. A zero-match result is **not** a clean bill of health.

## Run verification tests

From the `Backend` directory:

```sh
# Dependency-free record and mock-banner verification (Python 3.10+):
python -m unittest -v test_cve_reference_catalog

# Complete scanner integration verification (requires Backend/requirements.txt):
python -m pytest -q test_service_vulnerability_matcher.py test_cve_reference_catalog.py

# Complete scanner regression suite:
python -m pytest -q
```

Commands are identical in Windows PowerShell, Linux, and macOS when `python` resolves to Python 3; on systems where it does not, use `python3` instead. GitHub Actions already tests Linux, Windows, and macOS.

## Verification results from this evaluation

- **58 passed, 24 subtests passed:** independent regression tests covering CVE records, auth, persistence components, target validation, and TCP validation, using `pytest` without Scapy or Flask.
- **33 passed:** coordinator, CVE and TCP fingerprinting tests run with real loopback sockets. Because Scapy could not be installed in this environment, a narrow, temporary import-only stub was supplied *outside the repository*; all tested scan targets were explicitly specified as localhost and bypassed ARP discovery. This is not proof of full native Scapy compatibility.
- `python demo_service_cve.py` printed the expected affected/patched version matrix (two Apache matches for 2.4.49, one for 2.4.50, one nginx match for 1.20.0, none for the tested fixed versions).
- All changed Python files passed bytecode compilation. A full CI run including Flask, real Scapy discovery, and all three OSes is still required.

## Demo without a live scan

From `Backend`, run:

```sh
python demo_service_cve.py
```

This prints the expected CVE boundary matrix using synthetic `PortObservation` values and needs no elevated privileges or internet access.

## Live localhost demonstration with web UI

In a terminal in `Backend`:

```sh
python mock_services_lab.py --ports 18084,18085,18086,18087
```

Start the configured API/frontend in their own terminals. In **New Scan**, choose custom TCP target `127.0.0.1`, ports `18084-18087`, and start a scan. The frontend sends `match_vulnerabilities: true` automatically.

- Port 18084 advertises Apache 2.4.49: *potential* CVE-2021-41773 and CVE-2021-42013.
- Port 18085 advertises Apache 2.4.51: no match to these CVEs.
- Port 18086 advertises nginx 1.20.0: *potential* CVE-2021-23017.
- Port 18087 advertises nginx 1.20.1: no match to this CVE.

**Do not claim these synthetic banner servers are vulnerable or that finding a matching version confirms an exploitable issue.** The real server products, server configuration, vendor patches and applicability of CVEs are not actually tested here.

## Remaining limitations

1. Curated subset only; no NVD API ingestion, live syncing, CVSS scoring, or complete CPE/vulnerability analysis.
2. The matcher intentionally rejects non-numeric or packaged-version suffixes (for example `OpenSSH_9.6p1` and vendor-backport package tags) rather than making unsafe guesses.
3. UI currently presents open-port observations in a vulnerability-shaped table. Findings must remain labeled as *potential* and not counted as verified vulnerabilities.
4. Backend scan history still lives in memory and is not persisted across API restarts.
5. Cross-OS CI runs on GitHub Actions; local smoke verification on each target OS is still needed for a final release sign-off.
