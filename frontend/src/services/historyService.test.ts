import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mockScans } from "../mocks/scans";
import { getScanHistory } from "./historyService";
import { ScanApiError } from "./scanService";

describe("getScanHistory", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    globalThis.fetch = vi.fn();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("merges real scans with the seeded demo scans, newest first", async () => {
    vi.mocked(globalThis.fetch).mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        scans: [
          {
            scan_id: "scan-real-1",
            configuration: { targets: ["127.0.0.1"] },
            state: "COMPLETED",
            started_at: "2026-10-15T23:59:59",
            completed_at: "2026-10-16T00:00:00",
            ports: [],
            progress: {
              scan_id: "scan-real-1",
              state: "COMPLETED",
              hosts_discovered: 1,
              hosts_completed: 1,
              ports_completed: 0,
              total_ports: 0,
              percent_complete: 100,
              current_host: null,
              current_port: null,
              elapsed_seconds: 1,
              cancellation_requested: false,
            },
          },
        ],
      }),
    } as Response);

    const history = await getScanHistory();

    // The real scan is newer than every seeded demo scan, so it sorts first.
    expect(history[0].id).toBe("scan-real-1");
    expect(history[0].isDemo).toBe(false);

    // All 3 seeded demo scans are still present, each marked isDemo.
    const demoEntries = history.filter((scan) => scan.isDemo);
    expect(demoEntries).toHaveLength(mockScans.length);
    expect(history).toHaveLength(mockScans.length + 1);
  });

  it("still returns the demo scans when the backend has no real scans", async () => {
    vi.mocked(globalThis.fetch).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ scans: [] }),
    } as Response);

    const history = await getScanHistory();

    expect(history).toHaveLength(mockScans.length);
    expect(history.every((scan) => scan.isDemo)).toBe(true);
  });

  it("throws a connection error when the backend is unreachable", async () => {
    vi.mocked(globalThis.fetch).mockRejectedValueOnce(new TypeError("Failed to fetch"));

    await expect(getScanHistory()).rejects.toMatchObject({
      kind: "connection",
    } satisfies Partial<ScanApiError>);
  });

  it("throws a server error when the backend responds with a failure status", async () => {
    vi.mocked(globalThis.fetch).mockResolvedValueOnce({ ok: false, status: 500 } as Response);

    await expect(getScanHistory()).rejects.toThrow("Failed to load scan history.");
  });
});
