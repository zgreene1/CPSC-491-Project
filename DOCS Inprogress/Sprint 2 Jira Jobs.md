# Sprint 2 Jira Jobs

## Sprint 2 Goal
Sprint 2 focuses on turning the initial scanner components into a coordinated scanner pipeline with stable contracts between the scanner, backend, persistence, and frontend. The main outcome is a usable scanner orchestration layer with shared data models, lifecycle state, progress reporting, cancellation support, and early integration points for the rest of the application.

## Jira Jobs

| Jira ID | Job | Goal | Done When |
| --- | --- | --- | --- |
| S2-01 | Define shared scanner data contracts | Create the common scanner objects the backend, frontend, and persistence layers can rely on. | Scan configuration, host observation, and port observation fields are documented and agreed on. |
| S2-02 | Implement scan configuration model | Represent target/network, scan mode, port selection, timeout, discovery options, and concurrency settings in one reusable structure. | Scanner modules can receive one configuration object instead of separate ad hoc parameters. |
| S2-03 | Implement host observation model | Standardize how discovered hosts are represented. | Each discovered host can include IP address, optional hostname, discovery source, and discovery status. |
| S2-04 | Implement port observation model | Standardize how port scan results are represented. | Each result can include host, port, protocol, state, and optional service information. |
| S2-05 | Build scanner coordinator | Add a coordination layer that connects existing scanner modules into one pipeline. | A scan can flow through configuration, host discovery, target normalization, TCP port scanning, and result aggregation. |
| S2-06 | Reuse existing host discovery module | Integrate the current host discovery work without duplicating its logic. | The coordinator can call host discovery and receive normalized host observations. |
| S2-07 | Reuse existing TCP port scanner module | Integrate the current TCP scanner without duplicating its logic. | The coordinator can scan configured targets and receive normalized port observations. |
| S2-08 | Add target normalization step | Convert discovered hosts and user-provided targets into a consistent target list for scanning. | The scanner handles local discovery results and manual targets through the same pipeline. |
| S2-09 | Add result aggregation step | Combine host and port observations into a scan result structure usable by backend and persistence work. | One completed scan produces a single structured result object. |
| S2-10 | Define scanner lifecycle states | Track scanner progress with clear implementation-backed states. | Lifecycle states include CREATED, DISCOVERING, SCANNING, IDENTIFYING, MATCHING, COMPLETED, FAILED, and CANCELLED, with unused stages gated until implemented. |
| S2-11 | Implement lifecycle transitions | Move scans between lifecycle states as work starts, progresses, completes, fails, or is cancelled. | State changes match the actual scanner pipeline and can be observed by the backend. |
| S2-12 | Expose scanner progress fields | Provide progress data needed for UI and backend monitoring. | Progress includes hosts discovered, hosts completed, ports completed, total ports, percent complete, current host, current port, elapsed time, and cancellation state. |
| S2-13 | Add cancellation support | Allow an active scan to be cancelled cleanly. | Cancellation request is tracked, scan work stops safely, and final state becomes CANCELLED when appropriate. |
| S2-14 | Define scanner/backend interface | Create the contract the backend will use to start scans and read scan status/results. | Backend contributors can call the scanner pipeline without depending on scanner internals. |
| S2-15 | Implement backend service structure | Add the initial backend service shape for scan execution and status lookup. | Backend has a clear place to start scans, track active scans, and return scan progress. |
| S2-16 | Define persistence schema for scan data | Establish how scan configuration, scan status, host observations, and port observations will be stored. | Persistence contributors have a schema or model draft ready for implementation. |
| S2-17 | Define frontend/backend scan contracts | Document the request and response shapes needed by the scan configuration UI and scan progress UI. | Frontend contributors know what fields to send, display, and expect from the backend. |
| S2-18 | Standardize scanner error model | Normalize validation errors, discovery failures, scan failures, and cancellation responses. | Scanner and backend return consistent error codes/messages for expected failure paths. |
| S2-19 | Expand CI for scanner integration | Add automated checks that cover the scanner pipeline across the initial integration points. | CI runs module import, configuration, coordinator, and basic integration tests. |
| S2-20 | Write initial integration tests | Verify that scanner, backend interface, and persistence-facing output work together. | Tests cover a basic scan path, invalid configuration, no-host result, scan failure, and cancellation path. |
| S2-21 | Plan deployment environment needs | Identify environment requirements needed to run the scanner host and web interface together. | The team has a short environment checklist for local development and later packaging work. |
| S2-22 | Prepare Sprint 2 demo path | Define a simple demonstration showing scanner orchestration, lifecycle state, progress, and output. | The team can show a coordinated scan pipeline rather than separate standalone modules. |
