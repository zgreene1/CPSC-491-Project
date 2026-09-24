# Sprint 2 Lower-Level LLM Instructions

## Purpose
Use this document when giving Sprint 2 work to a smaller or lower-level model. It is intentionally literal. The model should make small, scoped changes, follow the listed order, and avoid inventing extra product features.

## Global Rules for the Model
- Work only on the job ID assigned.
- Preserve existing scanner behavior unless the assigned job explicitly requires a change.
- Reuse existing host discovery and TCP port scanner code.
- Do not add real vulnerability matching in Sprint 2 unless it already exists.
- Do not perform scans against public or unauthorized targets.
- Prefer localhost, mocks, fixtures, or controlled test services for examples and tests.
- Return clear files changed, behavior changed, and tests run.
- If code structure is unknown, inspect the repository first and follow existing naming and style.

## Output Format Required from the Model
For every assigned job, the model should finish with:
- Summary: one or two sentences.
- Changed files: list of files touched.
- Tests: list of checks run or explain why none were run.
- Notes: any known limitation or follow-up.

## Job Instructions

### S2-01 - Define Shared Scanner Data Contracts
Task:
1. Locate the existing scanner modules.
2. Identify current input and output data for host discovery and port scanning.
3. Create or update a shared contract location for scanner models.
4. Define scan configuration, host observation, port observation, scan progress, scan lifecycle state, scan result, and scanner error.
5. Write short field descriptions.

Do Not:
- Do not rewrite scanner logic.
- Do not add UI code.
- Do not add database code.

Required Result:
- A shared model or documentation location exists.
- The three required models are present: scan configuration, host observation, port observation.

### S2-02 - Implement Scan Configuration Model
Task:
1. Add a scan configuration structure.
2. Include target/network, scan mode, port selection, timeout, discovery options, and concurrency fields.
3. Add defaults for optional values.
4. Add validation for missing target, invalid port, invalid timeout, and unsupported scan mode.
5. Add a small test or usage example.

Do Not:
- Do not pass loose scanner arguments if the config object can be used.
- Do not silently accept invalid values.

Required Result:
- Scanner code can receive one configuration object.
- Invalid input produces a structured validation error.

### S2-03 - Implement Host Observation Model
Task:
1. Add a host observation structure.
2. Include IP address, optional hostname, discovery source, and discovery status.
3. Add conversion from existing host discovery output if needed.
4. Add a small test or example for local host, discovered host, and manual target.

Do Not:
- Do not store OS-specific details directly in the shared model unless they are optional metadata.
- Do not drop discovery source information.

Required Result:
- Host discovery output can become host observations.
- The object can be serialized or printed as plain data.

### S2-04 - Implement Port Observation Model
Task:
1. Add a port observation structure.
2. Include host, port, protocol, state, and optional service information.
3. Use consistent values for protocol and state.
4. Add conversion from TCP scanner output if needed.
5. Add a small test or example.

Do Not:
- Do not require service detection to be complete.
- Do not mix raw socket objects into the shared model.

Required Result:
- TCP scanner output can become port observations.
- Optional service fields can be empty in Sprint 2.

### S2-05 - Build Scanner Coordinator
Task:
1. Create a coordinator module or class.
2. Accept a scan configuration object.
3. Validate configuration.
4. Run host discovery when enabled.
5. Normalize targets.
6. Run TCP port scanning.
7. Aggregate results.
8. Return a structured scan result.

Do Not:
- Do not copy host discovery or TCP scanner logic into the coordinator.
- Do not make the coordinator depend on frontend code.

Required Result:
- One coordinator call runs the Sprint 2 pipeline.
- A safe test/demo can run against localhost or mocked targets.

### S2-06 - Reuse Existing Host Discovery Module
Task:
1. Find the existing host discovery entry point.
2. Call it from the coordinator.
3. Convert results into host observations.
4. Support a config path that skips discovery and uses manual targets.
5. Add or update tests for both paths.

Do Not:
- Do not replace the existing host discovery implementation.
- Do not remove cross-platform handling.

Required Result:
- Discovery results are available to the coordinator as host observations.

### S2-07 - Reuse Existing TCP Port Scanner Module
Task:
1. Find the existing TCP scanner entry point.
2. Call it from the coordinator for each normalized target.
3. Pass configured ports and timeout where supported.
4. Convert results into port observations.
5. Add or update tests using safe targets or mocks.

Do Not:
- Do not scan broad networks in tests.
- Do not rewrite the TCP scanner unless required for integration.

Required Result:
- Coordinator can produce port observations using the existing TCP scanner.

### S2-08 - Add Target Normalization Step
Task:
1. Accept targets from manual configuration and discovery results.
2. Validate targets.
3. Remove duplicates.
4. Preserve source information where possible.
5. Return one target list for the TCP scanner.

Do Not:
- Do not scan invalid targets.
- Do not allow duplicate targets to create duplicate work.

Required Result:
- Manual and discovered targets use the same scan path.

### S2-09 - Add Result Aggregation Step
Task:
1. Define the final Sprint 2 scan result structure.
2. Include configuration summary, lifecycle state, timestamps, hosts, ports, progress summary, and errors.
3. Include partial results for failed or cancelled scans.
4. Ensure the result can be serialized.

Do Not:
- Do not return raw internal objects.
- Do not discard useful partial results after an error.

Required Result:
- Every scan returns one structured result object.

### S2-10 - Define Scanner Lifecycle States
Task:
1. Add lifecycle states: CREATED, DISCOVERING, SCANNING, IDENTIFYING, MATCHING, COMPLETED, FAILED, CANCELLED.
2. Document each state.
3. Mark IDENTIFYING and MATCHING as future or inactive unless implemented.
4. Define allowed transitions if appropriate.

Do Not:
- Do not claim service identification or CVE matching is active if it is not implemented.

Required Result:
- Lifecycle states are available from a shared location.

### S2-11 - Implement Lifecycle Transitions
Task:
1. Set initial scan state to CREATED.
2. Set DISCOVERING during host discovery.
3. Set SCANNING during TCP scanning.
4. Set COMPLETED after successful aggregation.
5. Set FAILED on unrecoverable errors.
6. Set CANCELLED when cancellation stops the scan.
7. Add tests or examples for success, failure, and cancellation.

Do Not:
- Do not leave failed scans in SCANNING.
- Do not report cancelled scans as completed.

Required Result:
- Current scan state reflects the real pipeline stage.

### S2-12 - Expose Scanner Progress Fields
Task:
1. Add progress output with hosts discovered, hosts completed, ports completed, total ports, percent complete, current host, current port, elapsed time, and cancellation state.
2. Update progress during discovery and scanning.
3. Avoid division by zero.
4. Make progress serializable.

Do Not:
- Do not require frontend code.
- Do not use inconsistent field names across responses.

Required Result:
- Backend or tests can read current progress from an active or completed scan.

### S2-13 - Add Cancellation Support
Task:
1. Add a cancellation flag, token, or equivalent control.
2. Add a way to request cancellation for an active scan.
3. Check cancellation between units of work.
4. Stop launching new work after cancellation is requested.
5. Preserve partial results.
6. Set final state to CANCELLED.

Do Not:
- Do not abruptly kill the process if a cooperative stop is possible.
- Do not discard partial scan data.

Required Result:
- An active scan can be cancelled and reports CANCELLED.

### S2-14 - Define Scanner/Backend Interface
Task:
1. Define operations for start scan, get status, get progress, get result, and cancel scan.
2. Define request and response shapes.
3. Use shared scanner models.
4. Include success and error examples.

Do Not:
- Do not expose scanner internals through the backend contract.
- Do not require database completion for this interface.

Required Result:
- Backend developers can implement routes or services from the interface.

### S2-15 - Implement Backend Service Structure
Task:
1. Create or update a scan service layer.
2. Add methods to start, query, and cancel scans.
3. Store active scan state in a simple runtime-safe structure.
4. Delegate scanning to the coordinator.
5. Keep the service testable without a web server if possible.

Do Not:
- Do not put all scan logic inside API route handlers.
- Do not duplicate coordinator behavior.

Required Result:
- Backend has a service object or module for scan operations.

### S2-16 - Define Persistence Schema for Scan Data
Task:
1. List fields needed for scan configuration, scan state, timestamps, hosts, ports, errors, and final results.
2. Map fields from the aggregated scan result to persistence fields.
3. Leave room for future vulnerability findings.
4. Write the schema as code models, migration draft, or documentation depending on project structure.

Do Not:
- Do not block this job on a full database implementation.
- Do not include vulnerability finding fields as required Sprint 2 data.

Required Result:
- Persistence contributors know how Sprint 2 scan data should be stored.

### S2-17 - Define Frontend/Backend Scan Contracts
Task:
1. Define start scan request fields.
2. Define status and progress response fields.
3. Define result response fields.
4. Define validation and error response examples.
5. Keep names aligned with scanner/backend models.

Do Not:
- Do not build full UI in this job.
- Do not invent fields that the backend cannot produce.

Required Result:
- Frontend developers can build scan setup and progress views from the contract.

### S2-18 - Standardize Scanner Error Model
Task:
1. Define error categories: validation error, discovery failure, scan failure, timeout, cancellation, unsupported platform, internal error.
2. Include code, message, stage, and optional details.
3. Make errors serializable.
4. Add tests or examples for at least three categories.

Do Not:
- Do not expose sensitive local file paths or system details in user-facing messages.
- Do not return unrelated exception formats from different scanner stages.

Required Result:
- Scanner and backend failures use one consistent error shape.

### S2-19 - Expand CI for Scanner Integration
Task:
1. Add or update automated tests for imports, config validation, coordinator behavior, and basic integration.
2. Avoid external network dependencies.
3. Use localhost, mocks, or fixtures.
4. Make the test command clear in documentation.

Do Not:
- Do not add tests that scan public IPs.
- Do not require manual services unless clearly marked optional.

Required Result:
- Automated checks cover the Sprint 2 scanner pipeline.

### S2-20 - Write Initial Integration Tests
Task:
1. Test a basic successful scan path.
2. Test invalid configuration.
3. Test no-host or empty-result behavior.
4. Test scan failure.
5. Test cancellation.
6. Test that final output maps to persistence-facing fields.

Do Not:
- Do not rely on unstable external services.
- Do not make tests order-dependent.

Required Result:
- Integration tests prove scanner, backend-facing interface, and persistence-facing output can work together.

### S2-21 - Plan Deployment Environment Needs
Task:
1. Document supported OS targets.
2. Document runtime requirements.
3. Document network assumptions.
4. Document local and remote access expectations.
5. Note any elevated permission or OS-specific scanner concerns.

Do Not:
- Do not write a full production deployment guide.
- Do not assume Docker is required for normal deployment unless the project already decided that.

Required Result:
- A concise environment checklist exists for development and future packaging.

### S2-22 - Prepare Sprint 2 Demo Path
Task:
1. Write demo steps for starting a scan.
2. Show lifecycle state changes.
3. Show progress output.
4. Show structured final output.
5. Use localhost or a controlled lab target.
6. Add fallback steps using mocks or sample data if live scanning is unavailable.

Do Not:
- Do not require public network scanning.
- Do not demo only separate standalone modules if the coordinator exists.

Required Result:
- Sprint 2 demo shows a coordinated scanner pipeline with state, progress, and output.
