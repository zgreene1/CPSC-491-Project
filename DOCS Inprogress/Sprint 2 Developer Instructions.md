# Sprint 2 Developer Instructions

## Sprint 2 Goal
Sprint 2 should turn the independent Sprint 1 scanner modules into a coordinated scanner pipeline with stable contracts across scanner, backend, persistence, frontend, and testing work. The target is not a finished vulnerability scanner. The target is a reliable orchestration foundation: shared scanner models, a scanner coordinator, lifecycle state, progress reporting, cancellation behavior, backend-facing interfaces, persistence-facing output, and enough tests/demo material to prove that the pieces work together.

## General Developer Guidance
- Reuse the existing host discovery and TCP port scanner modules. Do not rewrite their core behavior unless a defect blocks integration.
- Keep scanner internals separated from backend, frontend, and persistence contracts.
- Prefer small, testable models and service methods over large end-to-end functions.
- Treat service detection and vulnerability matching states as future-facing unless those implementations already exist.
- Validate inputs early and return predictable errors instead of allowing low-level exceptions to leak into the UI/API layer.
- Every implemented job should include a short note or test showing how another teammate can use the result.

## Jobs

### S2-01 - Define Shared Scanner Data Contracts
Objective: Create the common scanner objects used by scanner, backend, frontend, and persistence contributors.

Developer Instructions:
- Review the existing scanner modules and identify the data they already accept and return.
- Define the minimum shared structures needed for Sprint 2: scan configuration, host observation, port observation, scan progress, scan lifecycle state, scan result, and scanner error.
- Keep field names stable and plain so they can be serialized later.
- Document required fields, optional fields, default values, and field meaning.
- Avoid exposing module-specific implementation details in the shared contracts.

Acceptance Criteria:
- Shared contract definitions exist in one obvious location.
- Backend, frontend, and persistence contributors can understand the fields without reading scanner internals.
- The contracts include scan configuration, host observation, and port observation at minimum.

### S2-02 - Implement Scan Configuration Model
Objective: Represent all scanner input settings in one reusable structure.

Developer Instructions:
- Include target or network, scan mode, port selection, timeout, discovery options, and concurrency configuration.
- Add validation for missing targets, invalid ports, invalid timeout values, and unsupported scan modes.
- Make defaults explicit so scans behave predictably when optional values are omitted.
- Keep the structure usable by both manual scans and future scheduled scans.

Acceptance Criteria:
- Scanner modules can receive a single configuration object instead of loose parameters.
- Invalid configuration returns a clear validation error.
- Tests or examples cover valid and invalid configurations.

### S2-03 - Implement Host Observation Model
Objective: Standardize how discovered hosts are represented.

Developer Instructions:
- Include IP address, optional hostname, discovery source, and discovery status.
- Preserve enough source information to explain where the host came from, such as local interface, ARP scan, neighbor table, or manual target.
- Decide how duplicate hosts should be represented after normalization.
- Keep the model independent from OS-specific discovery details.

Acceptance Criteria:
- Host discovery output can be converted into host observations.
- Host observations are serializable and easy to store.
- The model supports local host, discovered host, and manually supplied target cases.

### S2-04 - Implement Port Observation Model
Objective: Standardize how port scan results are represented.

Developer Instructions:
- Include host, port, protocol, state, and optional service information.
- Use consistent values for protocol and state, such as TCP and open/closed/filtered/unknown.
- Leave service fields optional so Sprint 2 does not depend on Sprint 3 service identification.
- Include timing or raw response details only if they are already available and useful.

Acceptance Criteria:
- TCP scanner output can be converted into port observations.
- Port observations can be consumed by backend and persistence without needing scanner internals.
- The model can later carry service detection results without changing its core shape.

### S2-05 - Build Scanner Coordinator
Objective: Add one coordination layer that runs the scanner pipeline from configuration through result aggregation.

Developer Instructions:
- Create a coordinator that accepts a scan configuration and controls pipeline execution.
- The pipeline should follow this order: configuration validation, host discovery, target normalization, TCP port scanning, result aggregation.
- Keep each stage isolated so it can be tested independently.
- The coordinator should call existing modules rather than copying their code.
- Return structured scan results and structured errors.

Acceptance Criteria:
- One coordinator call can run the Sprint 2 pipeline.
- Existing host discovery and TCP scanner modules are reused.
- A basic scan produces a structured result object.

### S2-06 - Reuse Existing Host Discovery Module
Objective: Integrate current host discovery work into the coordinator without duplicating logic.

Developer Instructions:
- Identify the existing host discovery entry point and call it from the coordinator.
- Wrap or adapt the returned data into host observations.
- Preserve existing cross-platform behavior.
- Add a fallback path for configurations that skip discovery and use manual targets.

Acceptance Criteria:
- Coordinator can perform host discovery through the existing module.
- Discovery results are normalized into host observations.
- The integration does not break standalone host discovery use.

### S2-07 - Reuse Existing TCP Port Scanner Module
Objective: Integrate the current TCP scanner into the coordinator without duplicating logic.

Developer Instructions:
- Identify the existing TCP scanner entry point and call it for normalized targets.
- Convert scanner results into port observations.
- Respect configuration settings for ports, timeout, and concurrency where supported.
- Preserve existing scanner behavior for targeted port scanning.

Acceptance Criteria:
- Coordinator can scan normalized targets using the existing TCP scanner.
- Open port results are returned as port observations.
- Existing TCP scanner tests or usage remain valid.

### S2-08 - Add Target Normalization Step
Objective: Convert discovered hosts and user-provided targets into one consistent target list.

Developer Instructions:
- Accept targets from discovery, manual configuration, or both.
- Remove duplicates by IP/host identity while preserving useful source information.
- Validate IP addresses, hostnames, and network ranges before scanning.
- Decide how unreachable or invalid targets should be reported.

Acceptance Criteria:
- Manual and discovered targets flow into the same scanning path.
- Duplicate targets do not cause duplicate scan work.
- Invalid targets produce a clear error or skipped-target record.

### S2-09 - Add Result Aggregation Step
Objective: Combine scan configuration, lifecycle data, host observations, and port observations into one scan result.

Developer Instructions:
- Define the final scan result shape for Sprint 2.
- Include scan ID if available, configuration summary, timestamps, final lifecycle state, hosts, ports, errors, and progress summary.
- Keep the result suitable for storage and API response use.
- Do not include raw internal objects that cannot be serialized.

Acceptance Criteria:
- Completed scans produce one structured result object.
- Failed or cancelled scans still produce a useful partial result.
- Persistence and backend contributors can consume the result shape.

### S2-10 - Define Scanner Lifecycle States
Objective: Track scanner progress through clear states that reflect actual implementation.

Developer Instructions:
- Define lifecycle states: CREATED, DISCOVERING, SCANNING, IDENTIFYING, MATCHING, COMPLETED, FAILED, and CANCELLED.
- Mark IDENTIFYING and MATCHING as inactive or future states until those stages exist.
- Document what each state means and which transitions are allowed.
- Avoid ambiguous states that overlap with progress counters.

Acceptance Criteria:
- Lifecycle states are defined in a shared enum or equivalent structure.
- Each state has a documented meaning.
- Future states do not misrepresent work that is not yet implemented.

### S2-11 - Implement Lifecycle Transitions
Objective: Move scans through lifecycle states as work starts, progresses, completes, fails, or is cancelled.

Developer Instructions:
- Initialize scans in CREATED.
- Move to DISCOVERING during host discovery and SCANNING during port scanning.
- Move to COMPLETED only after aggregation succeeds.
- Move to FAILED on unrecoverable errors and CANCELLED when cancellation is accepted.
- Record timestamps or event history if this can be done simply.

Acceptance Criteria:
- State changes match actual pipeline execution.
- Failure and cancellation paths set final states correctly.
- Backend status lookup can report the current state.

### S2-12 - Expose Scanner Progress Fields
Objective: Provide progress data needed for UI and backend monitoring.

Developer Instructions:
- Track hosts discovered, hosts completed, ports completed, total ports, percent complete, current host, current port, elapsed time, and cancellation state.
- Make progress safe to read while a scan is running.
- Percent complete should be calculated consistently and should avoid division-by-zero errors.
- Keep progress reporting useful even when total work is not fully known yet.

Acceptance Criteria:
- Backend can request current progress for an active scan.
- Progress fields update during discovery and scanning.
- Progress output is serializable and frontend-friendly.

### S2-13 - Add Cancellation Support
Objective: Allow an active scan to be cancelled cleanly.

Developer Instructions:
- Add a cancellation flag, token, or equivalent signal the coordinator can check between units of work.
- Stop launching new work after cancellation is requested.
- Preserve partial results collected before cancellation.
- Set final lifecycle state to CANCELLED when the scan stops because of cancellation.

Acceptance Criteria:
- Cancellation can be requested for an active scan.
- The scan stops safely and does not report COMPLETED.
- Partial results and final cancellation state are available after cancellation.

### S2-14 - Define Scanner/Backend Interface
Objective: Create the contract the backend uses to start scans and read scan status/results.

Developer Instructions:
- Define start scan, get scan status, get scan progress, get scan result, and cancel scan operations.
- Specify request and response shapes for each operation.
- Keep scanner module details hidden behind the interface.
- Use the shared models from S2-01 through S2-04.

Acceptance Criteria:
- Backend contributors can implement API routes or services without reading scanner internals.
- Interface documents include success and error responses.
- The interface covers start, status, progress, result, and cancellation actions.

### S2-15 - Implement Backend Service Structure
Objective: Add the initial backend service shape for scan execution and status lookup.

Developer Instructions:
- Create or outline the scan execution service responsible for starting and tracking scans.
- Decide where active scan state is stored during runtime.
- Make room for persistence without requiring full database behavior in this job.
- Keep the service testable without a running web server where possible.

Acceptance Criteria:
- Backend has a clear service layer for scan operations.
- Active scans can be started, queried, and cancelled through that layer.
- The service delegates scanner behavior to the coordinator.

### S2-16 - Define Persistence Schema for Scan Data
Objective: Establish how Sprint 2 scan data will be stored.

Developer Instructions:
- Define storage needs for scan configuration, scan state, timestamps, host observations, port observations, errors, and final results.
- Separate data that belongs to one scan from reusable reference data.
- Keep the schema compatible with future vulnerability findings and remediation status.
- Include field names and basic types even if full persistence implementation comes later.

Acceptance Criteria:
- A schema or model draft exists for Sprint 2 scan data.
- It maps cleanly from the aggregated scan result.
- It leaves room for Sprint 3 vulnerability findings.

### S2-17 - Define Frontend/Backend Scan Contracts
Objective: Document request and response shapes needed by scan configuration and progress UI work.

Developer Instructions:
- Define the scan start request fields the frontend should send.
- Define scan status/progress response fields the frontend should display.
- Define result response fields needed for initial scan results.
- Include validation and error response examples.

Acceptance Criteria:
- Frontend contributors can build scan configuration and progress screens against the contract.
- Contract fields align with scanner/backend models.
- At least one example request and response is provided.

### S2-18 - Standardize Scanner Error Model
Objective: Normalize expected scanner and backend failures.

Developer Instructions:
- Define error categories such as validation error, discovery failure, scan failure, timeout, cancellation, unsupported platform, and internal error.
- Include machine-readable code, human-readable message, affected stage, and optional details.
- Ensure errors can be returned through backend/API responses.
- Do not expose sensitive local system details in user-facing messages.

Acceptance Criteria:
- Expected failure paths return consistent structured errors.
- Backend and frontend can distinguish validation, scan, cancellation, and internal errors.
- Tests or examples cover at least three error categories.

### S2-19 - Expand CI for Scanner Integration
Objective: Add automated checks that cover the scanner pipeline and integration points.

Developer Instructions:
- Add tests for module imports, configuration validation, coordinator execution, and basic integration behavior.
- Keep tests deterministic and avoid requiring access to external networks.
- Use localhost or mocked scanner modules for integration checks when needed.
- Make failures easy to diagnose from test output.

Acceptance Criteria:
- CI or automated test command includes Sprint 2 scanner integration coverage.
- Tests avoid unsafe or unauthorized network scanning.
- The test suite can run repeatedly with stable results.

### S2-20 - Write Initial Integration Tests
Objective: Verify that scanner, backend interface, and persistence-facing output work together.

Developer Instructions:
- Cover a basic successful scan path.
- Cover invalid configuration.
- Cover no-host or no-result behavior.
- Cover scan failure and cancellation behavior.
- Verify the final result can be serialized or mapped to persistence fields.

Acceptance Criteria:
- Integration tests exercise the coordinator through the backend-facing layer or a close equivalent.
- Tests verify success, validation, failure, empty result, and cancellation paths.
- Persistence-facing output shape is checked.

### S2-21 - Plan Deployment Environment Needs
Objective: Identify the environment requirements needed to run the scanner host and web interface together.

Developer Instructions:
- Document supported operating systems, runtime requirements, required permissions, network assumptions, and local/remote access expectations.
- Identify what is needed for development versus packaged deployment.
- Note any scanner behavior that may require elevated privileges or OS-specific handling.
- Keep this as an implementation checklist, not a full deployment guide.

Acceptance Criteria:
- A short environment checklist exists.
- The checklist covers scanner host, backend service, web UI, and local network access.
- Known risks or platform differences are called out.

### S2-22 - Prepare Sprint 2 Demo Path
Objective: Define a simple demonstration showing that Sprint 2 created a coordinated scanner pipeline.

Developer Instructions:
- Prepare a demo flow that starts a scan, shows lifecycle state, shows progress, and displays structured output.
- Use a safe target such as localhost or a controlled lab service.
- Include a fallback demo path if live network discovery is unavailable.
- Keep the demo short enough for a sprint review.

Acceptance Criteria:
- Demo steps are documented.
- Demo proves coordination rather than standalone module execution only.
- Expected output and fallback behavior are described.
