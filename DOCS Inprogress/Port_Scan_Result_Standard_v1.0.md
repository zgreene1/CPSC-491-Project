# Vulnerability Scanner — Port Scan Results and Classification Standard

**Technical reference:** PSRS-001  
**Version:** 1.0 (proposed standard; not yet fully implemented)  
**Issued:** October 15, 2026  
**Applies to:** CPSC 491-10 Vulnerability Scanner — scanner modules, shared contracts, backend API, persistence, reporting, and vulnerability correlation  
**Platform scope:** Linux, Windows, and macOS

## 1. Purpose, scope, and status

This document establishes a consistent technical standard for representing the outcomes of TCP and UDP port checks. Its purpose is to prevent false conclusions about port availability, distinguish observed facts from inference, preserve scan coverage information, and establish a stable interface for service fingerprinting and vulnerability correlation.

The terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** express proposed implementation requirements for this project. They do not assert that the current repository already satisfies them. “Current” refers to the reviewed `Project (2).zip` project snapshot; “proposed” identifies changes to be implemented and accepted by the team.

This standard applies to active TCP-connect and UDP application-probe results; it does not imply support for SYN, ACK, FIN, or other specialized Nmap techniques. Scanning MUST remain limited to authorized systems and networks. The specification does not guarantee complete vulnerability discovery merely because all TCP ports are checked.

### 1.1 Governing principles

- **Evidence before conclusion:** every confirmed open, closed, or filtered state MUST be supported by an applicable network observation.
- **Visibility is not certainty:** lack of response MUST NOT by itself mean “closed,” and an unattempted port MUST NOT be represented as scanned.
- **Separation of stages:** port detection, service hints, service identification, product/version fingerprinting, and CVE matching MUST remain distinguishable.
- **Stable contracts:** externally consumed results MUST use shared, JSON-compatible contracts and explicit backward-compatible schema changes.
- **Cross-platform correctness:** differences in socket, ICMP, and permission behavior on Linux, Windows, and macOS MUST be tested or documented.

## 2. Verified current implementation baseline

| Component | Verified existing behavior | Gap relative to this standard |
|---|---|---|
| `scanner_Port_Scanner.py` | TCP connect scanning returns `PortResult` only after a successful connection. Supports common, smart, custom, and `all` port selection. | Refused, timed-out, and error outcomes are collapsed into no result. Per-port state evidence is not returned. |
| `udp_port_scanner.py` | Returns `UDPPortResult(state="open")` when an application response is received. | Timeout and socket errors return no result. No persisted inconclusive classification. |
| Scanner CLI | Declares `--proto tcp`, `udp`, or `both`. | The reviewed CLI's execution branch still calls TCP-only scan functions; protocol dispatch must be implemented and tested. |
| `scanner_coordinator.py` | Coordinates TCP checks, scan progress, cancellation, and optional service fingerprinting. | UDP protocol selection is not represented in `ScanConfiguration` or executed by this coordinator. |
| `scanner_contracts.py` | Defines `PortObservation`, `ScanProgress`, `ScanResult`, and JSON serialization. | `state` is an unconstrained string; contract has no evidence-method or per-state outcome fields. |
| `scanner_adapters.py` | Converts open TCP results to `PortObservation`; applies fingerprint product, version, banner, and confidence. | The fingerprint `cpe` and `detection_method` are not retained in the shared port contract. |
| `scanner_Service_Fingerprint.py` | Internal `ServiceFingerprint` includes service, product, version, banner, CPE, confidence, and detection method. | Downstream consumers cannot directly use all provenance fields through `PortObservation`. |

**Compatibility rule:** the open-port-only return types MAY remain as a legacy convenience interface during migration. They MUST NOT be presented as full port-state inventories. Introduce detailed outcome records without silently changing the meaning of existing fields.

## 3. Port-state vocabulary and decision rules

The project SHALL adopt the following state names for future detailed observations. They align with the relevant Nmap port-state concepts, with `unknown` defined as a **project-specific diagnostic outcome**, not a standard Nmap port state.

| State | Definition | Sufficient evidence / use | Current status |
|---|---|---|---|
| `open` | Evidence indicates an application accepts the relevant connection or responds to the probe. | TCP connection succeeds; UDP response attributable to the probed endpoint. | Implemented for successful TCP and responding UDP checks. |
| `closed` | Evidence indicates the port is reachable but not accepting the requested service. | TCP connection refused; UDP ICMP destination port unreachable (type 3, code 3), if reliably attributable. | Proposed detailed outcome. |
| `filtered` | A network control is supported by explicit evidence. | Applicable administrative prohibition or a similarly conclusive filtered response. | Proposed detailed outcome. |
| `open\|filtered` | A UDP probe cannot distinguish a silent service from filtering. | UDP probe times out without a conclusive response. | Proposed UDP outcome. |
| `unknown` | A probe could not be classified reliably for an operational or observation reason. | Local socket error, unreachable route, interrupted check, ambiguous attribution, or other unclassified failure. | Proposed project extension. |

### 3.1 TCP-connect interpretation

- A completed TCP connect operation that succeeds MUST produce `open`.
- A refused TCP connection SHOULD produce `closed`, with the refusal category recorded.
- A TCP timeout MUST NOT, by itself, be labeled `closed` or definitively `filtered`; the standard diagnostic outcome is `unknown` with reason `timeout` unless stronger evidence exists.
- Local DNS, routing, socket, or platform errors MUST be recorded as errors or `unknown`; they MUST NOT be counted as confirmed port states.
- If a check is cancelled before completion, it MUST be counted as incomplete rather than assigned `closed`.

### 3.2 UDP interpretation

- A valid response attributable to the intended host and port MAY support `open`; source endpoint and response validity SHOULD be checked before classification.
- A reliably attributable ICMP destination-port-unreachable result MAY support `closed`.
- An explicit administrative-prohibition response MAY support `filtered` when the evidence is available and can be attributed.
- A silent UDP probe SHOULD be reported as `open|filtered`, not `closed`.
- When a platform cannot inspect ICMP details without extra privileges, the scanner MUST degrade conservatively and report the limitation rather than guessing.

**Important:** the current UDP implementation only returns positive responses. Implementing the remaining states requires new outcome handling, not a change to documentation alone.

## 4. Authoritative result contract

`PortObservation` in `scanner_contracts.py` remains the canonical public port-result model. The fields below represent the **current dataclass shape**; the standard adds validation and interpretation requirements, not an immediate incompatible rename.

| Field | Type | Requirement and semantics |
|---|---|---|
| `host_ip` | string | Required. IP address to which this observation pertains; the current implementation is IPv4-focused. |
| `port` | integer | Required. Scan target MUST be 1–65535; Boolean and non-integer inputs are invalid. |
| `protocol` | string | Required. Lowercase `tcp` or `udp` when that protocol was actually tested. |
| `state` | string | Required. Must come from the state vocabulary when detailed classification is supported. |
| `host_mac` | string or null | Optional host-layer metadata; absence must not invalidate a result. |
| `service_hint` | string or null | Optional port-number-based suggestion; not a confirmed service identity. |
| `service` | string or null | Optional service identified by probe or reliable response evidence. |
| `product` | string or null | Optional identified software product. |
| `version` | string or null | Optional software version supported by fingerprint evidence. |
| `banner` | string or null | Optional bounded, sanitized network response excerpt; avoid secrets and unbounded raw payloads. |
| `confidence` | number or null | Optional fingerprint confidence; if present, MUST be within 0.0–1.0. Not vulnerability probability. |
| `observed_at` | string or null | Optional timestamp. New producers SHOULD emit offset-aware ISO 8601 UTC timestamps. |

### 4.1 Proposed backward-compatible extensions

The following attributes are **not presently defined** in `PortObservation`. They SHOULD be introduced as optional and nullable fields, with consumers updated in a coordinated manner.

| Proposed field | Purpose |
|---|---|
| `state_reason` | Machine-readable classification cause, e.g., `tcp_connect_success`, `connection_refused`, `udp_timeout`, `icmp_port_unreachable`. |
| `evidence_method` | Technique that produced the state, e.g., `tcp_connect`, `udp_application_probe`, `icmp_response`. |
| `evidence_summary` | Sanitized, bounded description of response or error category supporting the observation. |
| `fingerprint_method` | Provenance of service detection; corresponds to internal `ServiceFingerprint.detection_method`. |
| `cpe` | Optional software identifier when sufficiently supported by fingerprinting evidence. |

Proposed additions MUST preserve existing field meanings. Adding fields does not mean every consumer must receive a non-null value. Consumers MUST tolerate absent optional fields. New producers SHOULD normalize timestamps to UTC while existing naive timestamps remain tolerated during migration.

### 4.2 Uniqueness and deterministic presentation

- The final consolidated per-scan view SHOULD contain at most one current observation per `(scan_id, host_ip, protocol, port)` key.
- If multiple probes are performed, raw attempts MAY be retained separately from the consolidated observation.
- Results SHOULD be sorted consistently by IP address, protocol, then port for reproducible tests and reports.
- `service_hint`, `service`, and `product` MUST NOT be conflated; null conveys unavailable evidence, not scan failure.

## 5. Scan selection and coverage standards

IANA registers transport service names and port-number allocations over 0–65535. For this project's scan-target validation, **port 0 is excluded** and selectable ports MUST lie in 1–65535. IANA assigns system ports 0–1023, user/registered ports 1024–49151, and dynamic/private ports 49152–65535; these categories do not establish which application is actually running on a port.

| Scan mode | Required interpretation | Coverage statement |
|---|---|---|
| `common` | Scan the project's defined common TCP port list. | Selective; not a full-port assessment. |
| `smart` | Scan high-probability ports and selectively expand based on observations or fallback logic. | Adaptive and potentially variable by host; not exhaustive. |
| `custom` | Scan the validated set or range supplied by the user. | Only requested ports are in scope. |
| `all` | Select every TCP destination port 1–65535 for each included host. | Full TCP port *selection*; completion must still be established from counters. |
| UDP selection | Use a defined UDP port list/explicit selection once the coordinator supports it. | MUST NOT assume UDP completeness from TCP mode names. |

**Completeness rule:** the report MUST differentiate *selected*, *attempted*, *completed*, and *not completed* port checks. An `all` scan cancelled halfway is not a full completed scan. Similarly, a completed smart scan is complete only with respect to its adaptive selected scope.

### 5.1 Proposed coverage summary fields

The current `ScanProgress` exposes `ports_completed`, `total_ports`, and percentage. Its `total_ports` effectively counts planned host/port checks, not a count of distinct port numbers. The next coverage contract SHOULD expose explicit counters:

- `checks_selected`: planned host/protocol/port combinations for the final resolved scope.
- `checks_attempted`: combinations on which a probe was actually initiated.
- `checks_completed`: combinations that reached a classified or inconclusive observation.
- `checks_incomplete`: scheduled combinations not completed (including cancellation).
- `outcome_counts`: counts per state, plus operational errors as applicable.
- `selection_mode`, `resolved_scope`, `protocols_requested`, `coverage_complete`: context needed to interpret results.

For fixed scopes, `checks_completed + checks_incomplete = checks_selected` SHOULD hold at finalization when each check is counted once. Smart scans MUST account for additional work appended during adaptive expansion. Any report presenting a percentage MUST clearly state what denominator is used.

## 6. Service identification and vulnerability correlation

A port is not a vulnerability. The system MUST represent the following levels separately:

1. **Network state**: observation supports `open`, `closed`, or an inconclusive classification.
2. **Service hint**: common port association suggests a protocol, without proof.
3. **Service identification**: application-layer evidence supports the service name.
4. **Product/version identification**: observed banner or signature supports a software identity and version.
5. **Vulnerability correlation**: compatible product/version identifiers are evaluated against vulnerability data with recorded match rationale and data provenance.

A mere open port or `service_hint` MUST NOT create a **confirmed CVE** finding. Even identified version strings may be incomplete, vendor-modified, or backported; vulnerability matching MUST retain uncertainty and MAY need additional evidence. `confidence` in `PortObservation` MUST be interpreted as fingerprint confidence, not a likelihood that a CVE is exploitable.

The fingerprinting adapter SHOULD eventually preserve the internal CPE identifier and detection method in the public result when supported. Vulnerability severity or CVSS values belong in a vulnerability-finding contract, not in `PortObservation` itself.

## 7. Serialization examples

### 7.1 Compatible current `PortObservation` example

This example uses only fields already present in the shared contract; example values are illustrative, not verified scan output.

```json
{
  "host_ip": "127.0.0.1",
  "port": 18081,
  "protocol": "tcp",
  "state": "open",
  "host_mac": null,
  "service_hint": "unknown",
  "service": "http",
  "product": "Apache httpd",
  "version": "2.4.58",
  "banner": "HTTP/1.1 200 OK",
  "confidence": 0.95,
  "observed_at": "2026-10-15T23:00:00+00:00"
}
```

### 7.2 Proposed detailed inconclusive UDP observation

This represents a **future extension** and is not emitted by the current UDP scanner.

```json
{
  "host_ip": "127.0.0.1",
  "port": 161,
  "protocol": "udp",
  "state": "open|filtered",
  "host_mac": null,
  "service_hint": "snmp",
  "service": null,
  "product": null,
  "version": null,
  "banner": null,
  "confidence": null,
  "observed_at": "2026-10-15T23:00:00+00:00",
  "state_reason": "udp_timeout",
  "evidence_method": "udp_application_probe",
  "evidence_summary": "No attributable response before the configured timeout"
}
```

### 7.3 Reporting rule

A user-facing report SHALL explicitly label which entries are confirmed-open findings and which represent closed, filtered, inconclusive, or failed checks. Reporting MUST NOT silently omit inconclusive counts when claiming coverage. Open-port-only result exports MAY remain available if accurately labeled as such.

## 8. Operational, safety, and cross-platform requirements

- **Scope authorization:** the scanner MUST only probe intended authorized targets; target and CIDR validation remain prerequisites.
- **Privileges:** raw ICMP interpretation or ARP may require elevated permissions or OS-specific support. Lack of privilege MUST NOT be hidden as “no open ports.”
- **Failure reporting:** scanner errors MUST use structured `ScannerError` or equivalent machine-readable diagnostics, distinct from a network port state.
- **Bounded probing:** timeouts, concurrency, retry policy, and output-size limits SHOULD be configurable and documented.
- **Data handling:** banners and error details SHOULD be bounded and sanitized before storage or web display.
- **Cross-OS tests:** deterministic socket-based tests MUST run where applicable on Linux, Windows, and macOS. Tests requiring privileged packets or external networks SHOULD be isolated from standard CI and documented separately.
- **Cancellation:** no new work SHOULD be scheduled after a cancellation request; queued/in-flight work and partial results MUST be accounted for honestly.

## 9. Verification and acceptance matrix

These criteria describe proposed acceptance tests. They are not claims of existing cross-platform success.

| ID | Test and expected outcome | Method | Priority |
|---|---|---|---|
| PS-01 | Deterministic localhost TCP listener is consistently reported `open`. | Automated; 10 repeats | Required |
| PS-02 | Refused TCP connection is not reported open; proposed detailed output reports `closed`. | Automated | Required |
| PS-03 | TCP timeout is not silently equated with `closed`; detailed output records `unknown`/reason. | Automated fault simulation | Required for new states |
| PS-04 | Inputs 0, 65536, reversed ranges, Boolean, string, and float ports are rejected. | Automated unit test | Required |
| PS-05 | `all` selects exactly 1–65535; common/custom/smart advertise actual scopes. | Automated | Required |
| PS-06 | Known responding UDP probe is reported `open`; silent UDP is not confirmed `closed`. | Automated | Required |
| PS-07 | Protocol selector invokes TCP, UDP, or both as requested once implemented. | Automated integration | Required before claiming UDP integration |
| PS-08 | Contract round-trip preserves required fields; optional additions do not break consumers. | Automated contract | Required |
| PS-09 | One consolidated record per scan/host/protocol/port; results sorted deterministically. | Automated | Required |
| PS-10 | Known service fixtures produce documented service/product/version matches; hints alone never create confirmed versions. | Automated + manual | Required |
| PS-11 | Matching stage cannot create confirmed CVEs solely from `open` or `service_hint`. | Automated fixture + manual review | Required when matcher exists |
| PS-12 | Cancellation distinguishes completed and incomplete work and preserves partial results. | Automated + manual | Required |
| PS-13 | CI runs applicable tests on Ubuntu, Windows, and macOS; authorized-network limitations recorded. | CI + manual | Required |
| PS-14 | Repeatable scan benchmark records scope, timeout, concurrency, duration, and resource use. | Automated measurement + manual review | Recommended |

For the deterministic TCP localhost acceptance fixture, the target is **10/10 successful open-port detections and zero false-open reports**. This is a controlled engineering acceptance threshold; it is not an asserted real-world detection rate. Real-network precision and recall SHALL be reported from an explicitly documented, authorized ground-truth dataset.

## 10. Implementation sequence and migration controls

| Phase | Deliverable | Dependencies and acceptance gate |
|---|---|---|
| 1 — Contract approval | Confirm states, result field semantics, and coverage vocabulary. | Agree on consumer compatibility and classification evidence rules. |
| 2 — Detailed probe outcomes | Add TCP/UDP classified outcomes and reasons while retaining open-only adapters. | Pass state-decision tests PS-01–PS-06. |
| 3 — Protocol integration | Wire TCP/UDP selection through CLI and coordinator/configuration. | Pass dispatch and contract tests PS-07–PS-09. |
| 4 — Identification provenance | Carry fingerprint method/CPE and separate hint from confirmation. | Pass fingerprint and matcher-gating tests PS-10–PS-11. |
| 5 — Coverage and reporting | Add scope/outcome counters, incomplete-work tracking, and truthful UI labels. | Pass cancellation, coverage, and final compatibility tests PS-12–PS-13. |
| 6 — Accuracy and performance | Publish controlled reference results, repeated-run reliability, and performance baseline. | Record PS-14 plus observed accuracy and known limitations. |

Schema changes MUST be reviewed against the frontend, API, persistence, and any existing JSON fixtures. Optional-field additions SHOULD be introduced before enabling new port states in downstream reports. Port-state semantics MUST be documented in API contracts and release notes.

## 11. Source references

**Reviewed project source (local repository snapshot):** `Project (2).zip` — `Backend/scanner_contracts.py`, `scanner_adapters.py`, `scanner_Port_Scanner.py`, `udp_port_scanner.py`, `scanner_coordinator.py`, `scanner_Service_Fingerprint.py`, and `S2-01 Shared Scanner Data Contracts.md`.

**External technical references:**

1. Nmap Project, *Port Scanning Basics*: https://nmap.org/book/man-port-scanning-basics.html — terminology for `open`, `closed`, `filtered`, and `open|filtered`. Nmap supports additional states not adopted by this project.
2. Internet Assigned Numbers Authority, *Service Name and Transport Protocol Port Number Registry*: https://www.iana.org/assignments/service-names-port-numbers/ — service names and port classifications.
3. IETF, *RFC 6335*: https://www.rfc-editor.org/rfc/rfc6335 — IANA service name and port-number registration policies.

**Interpretation note:** Nmap terminology and IANA registry information are external reference points. The specific evidence rules, schema extensions, coverage metrics, and acceptance thresholds above are proposed **project standards**, not requirements imposed by those external publications.
