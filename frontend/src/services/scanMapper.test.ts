import { describe, expect, it } from "vitest";
import { mapApiProgress, mapApiResultToScanRecord, mapLifecycleState } from "./scanMapper";

describe("mapLifecycleState", () => {
  it.each([
    ["CREATED", "queued"],
    ["DISCOVERING", "running"],
    ["SCANNING", "running"],
    ["IDENTIFYING", "running"],
    ["MATCHING", "running"],
    ["COMPLETED", "completed"],
    ["FAILED", "failed"],
    ["CANCELLED", "cancelled"],
  ])("maps backend state %s to %s", (backendState, expected) => {
    expect(mapLifecycleState(backendState)).toBe(expected);
  });
});

describe("mapApiProgress", () => {
  it("maps snake_case backend fields to the frontend progress shape", () => {
    const mapped = mapApiProgress({
      scan_id: "scan-1",
      state: "SCANNING",
      hosts_discovered: 1,
      hosts_completed: 0,
      ports_completed: 2,
      total_ports: 10,
      percent_complete: 20,
      current_host: "10.0.1.12",
      current_port: 443,
      elapsed_seconds: 1.5,
      cancellation_requested: false,
    });

    expect(mapped).toEqual({
      scanId: "scan-1",
      status: "running",
      percentComplete: 20,
      hostsDiscovered: 1,
      hostsCompleted: 0,
      portsCompleted: 2,
      totalPorts: 10,
      currentHost: "10.0.1.12",
      currentPort: 443,
      elapsedSeconds: 1.5,
      cancellationRequested: false,
    });
  });
});

describe("mapApiResultToScanRecord", () => {
  it("marks every real port finding as unclassified since the backend has no CVE matching yet", () => {
    const record = mapApiResultToScanRecord({
      scan_id: "scan-2",
      configuration: { targets: ["127.0.0.1"] },
      state: "COMPLETED",
      started_at: "2026-10-01T00:00:00",
      completed_at: "2026-10-01T00:00:05",
      ports: [
        {
          host_ip: "127.0.0.1",
          host_mac: null,
          port: 22,
          protocol: "tcp",
          state: "open",
          service_hint: null,
          service: "ssh",
          product: "OpenSSH",
          version: "9.6p1",
          banner: "SSH-2.0-OpenSSH_9.6p1",
          confidence: 0.99,
          observed_at: "2026-10-01T00:00:03",
        },
      ],
      progress: {
        scan_id: "scan-2",
        state: "COMPLETED",
        hosts_discovered: 1,
        hosts_completed: 1,
        ports_completed: 1,
        total_ports: 1,
        percent_complete: 100,
        current_host: null,
        current_port: null,
        elapsed_seconds: 5,
        cancellation_requested: false,
      },
    });

    expect(record.id).toBe("scan-2");
    expect(record.status).toBe("completed");
    expect(record.vulnerabilities).toHaveLength(1);
    expect(record.vulnerabilities[0]).toMatchObject({
      severity: "unclassified",
      cve: "Not yet assessed",
      host: "127.0.0.1",
      port: 22,
      service: "OpenSSH 9.6p1",
    });
    expect(record.severityCounts.unclassified).toBe(1);
  });

  it("filters out closed/filtered ports", () => {
    const record = mapApiResultToScanRecord({
      scan_id: "scan-3",
      configuration: { targets: ["127.0.0.1"] },
      state: "COMPLETED",
      started_at: null,
      completed_at: null,
      ports: [
        {
          host_ip: "127.0.0.1",
          host_mac: null,
          port: 80,
          protocol: "tcp",
          state: "closed",
          service_hint: null,
          service: null,
          product: null,
          version: null,
          banner: null,
          confidence: null,
          observed_at: null,
        },
      ],
      progress: {
        scan_id: "scan-3",
        state: "COMPLETED",
        hosts_discovered: 1,
        hosts_completed: 1,
        ports_completed: 1,
        total_ports: 1,
        percent_complete: 100,
        current_host: null,
        current_port: null,
        elapsed_seconds: 1,
        cancellation_requested: false,
      },
    });

    expect(record.vulnerabilities).toHaveLength(0);
    expect(record.totalFindings).toBe(0);
  });
});
