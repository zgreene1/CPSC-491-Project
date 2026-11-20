# Sprint 6 Scanner Integration Gap Report

**Assessment timestamp:** 2026-11-19 17:06 PST

**Reviewed snapshot:** GitHub `main` source archive `3b41cd0eff4d52fe9947968b716d8a6324f20312`

**Method:** source trace plus local deterministic tests; no external network scanning

## Confirmed findings

| ID | Severity | Finding | Evidence and reproduction | Disposition |
|---|---|---|---|---|
| GAP-01 | P2, low impact | Generic HTTP headers could be mislabeled as another service's product. The service-specific signature pass could fail, then an unrestricted fallback matched `Connection: close` to the low-confidence product `connection`. | ACC-05: send a generic HTTP `HEAD` response with `Server: FixtureGateway` and no product version; fingerprint returned product `connection`. | Fixed in `Backend/scanner_Service_Fingerprint.py` by limiting cross-service search to passive banners that remain unclassified; removed the generic `http` product signature. Regression test now expects HTTP service with product/version unset. |
| GAP-02 | P2 | Frontend finding IDs collided for TCP and UDP observations with the same host and port, even though the API supports scanning both protocols. | Map a JSON result containing `127.0.0.1:5353/tcp` and `127.0.0.1:5353/udp`; old mapper produced the same `id` for both rows. | Fixed in `frontend/src/services/scanMapper.ts` by including protocol in the row ID; a mapper regression test asserts unique IDs. |

## Integration trace: host → port → fingerprint → CVE → JSON → frontend

1. Host targets are normalized in `scanner_coordinator.py`, then adapted from `Device` to `HostObservation` in `scanner_adapters.py`.
2. TCP port results become `PortObservation` records. The adapter keys retain host IP, port, and protocol.
3. `ScannerCoordinator.run()` fingerprints open TCP results, joins fingerprints by `(host_ip, port, protocol)`, and applies product, version, confidence, banner, detection method, and normalized software ID.
4. `match_vulnerabilities` defaults to `False` in `ScanConfiguration`; `api_server._build_configuration()` forwards the request value. The frontend's real scan request currently sends `match_vulnerabilities: true` in `scanService.ts`.
5. With matching enabled, the coordinator loads the local catalog. Apache `2.4.49` returns two distinct potential findings, nginx `1.20.0` returns one, and patched boundary versions return none.
6. `ScanResult.to_dict()` includes `configuration.match_vulnerabilities`, enriched port fields, and the full `vulnerabilities` list. The API returns that result JSON.
7. `scanMapper.ts` associates CVE records by host/port/protocol. Both Apache matches are kept in `matches`; the legacy single `cve` field contains the first match. The details UI renders `matches`, so the second Apache CVE is not dropped.

`Backend/test_scanner_sprint6_accuracy.py` checks the two Apache matches through coordinator JSON serialization, adapter metadata, and API configuration flag conversion. The frontend mapper test verifies both CVEs survive on a row. The frontend request test checks the flag is sent. The existing route is asynchronous; its broader API suite was not part of this targeted test run.

## Candidate integration gap

| ID | Severity | Candidate issue | Reproduction / impact | Suggested follow-up |
|---|---|---|---|---|
| GAP-C1 | P3 | The frontend API port type and view model do not retain backend `software_id`, `fingerprint_method`, `evidence_method`, or `state_reason`; port-level confidence is also not shown unless it accompanies a CVE match. | Compare `PortObservation.to_dict()` with `ApiPortObservation` in `frontend/src/services/scanMapper.ts`; map a port with those fields and observe they are not retained. This does not currently alter CVE matching because matching occurs before the API response. | Add a scanner evidence panel/model if the UI needs provenance and low-confidence diagnostic visibility. No need to change persistence for this assessment. |

## Confirmed boundaries and non-findings

- The catalog has exactly three curated entries in this snapshot, including both Apache CVEs. Its own note says it is incomplete and offline; broad NVD coverage is not implemented.
- `match_vulnerabilities` is disabled for backend callers that omit the flag; it is enabled by the current frontend `startScan()` request. This is a default-versus-opt-in behavior, not a lost flag.
- The newer archive represents real scan CVSS as `null` and maps recoverable backend errors into frontend warnings. Severity remains `unclassified`; this assessment did not change teammate-owned scoring behavior.
- The newer archive does not contain the Sprint 6 generic HTTP fingerprint fix, protocol-qualified frontend row ID, or added ACC matrix tests. The patch below targets this archive and preserves its newer CVSS/warning changes.
- UDP timeout classification is correctly inconclusive (`open|filtered`) and is omitted from the legacy open-only UDP return path.

## Scope limits

The newer archive was created at 16:59 and embeds snapshot identifier `3b41cd0eff4d52fe9947968b716d8a6324f20312`. It lacks `.git`, so local branch, HEAD, working-tree status, and merge ancestry cannot be independently checked. The backend files relevant to scanner accuracy are unchanged from the prior archive. Windows/macOS were not run. The accuracy sample is controlled and small and does not support general scanner accuracy claims.
