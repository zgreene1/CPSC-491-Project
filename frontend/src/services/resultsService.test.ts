import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mockScans } from "../mocks/scans";
import { getScanResults } from "./resultsService";
import { ScanApiError } from "./scanService";

describe("getScanResults", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    globalThis.fetch = vi.fn();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("returns the matching demo scan by id without calling the network", async () => {
    const target = mockScans[1];
    const result = await getScanResults(target.id);

    expect(result).toBe(target);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("never falls back to an unrelated demo scan for an unknown id", async () => {
    vi.mocked(globalThis.fetch).mockResolvedValueOnce({
      ok: false,
      status: 404,
    } as Response);

    const result = await getScanResults("scan-does-not-exist");

    expect(result).toBeUndefined();
    // Confirm it's genuinely undefined, not silently equal to any seeded scan.
    expect(mockScans.some((scan) => scan === result)).toBe(false);
  });

  it("fetches and maps a real scan for a non-demo id", async () => {
    vi.mocked(globalThis.fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        scan_id: "scan-real-123",
        configuration: { targets: ["10.0.5.5"] },
        state: "COMPLETED",
        started_at: "2026-10-15T00:00:00",
        completed_at: "2026-10-15T00:00:05",
        ports: [],
        progress: {
          scan_id: "scan-real-123",
          state: "COMPLETED",
          hosts_discovered: 1,
          hosts_completed: 1,
          ports_completed: 0,
          total_ports: 0,
          percent_complete: 100,
          current_host: null,
          current_port: null,
          elapsed_seconds: 5,
          cancellation_requested: false,
        },
      }),
    } as Response);

    const result = await getScanResults("scan-real-123");

    expect(result?.id).toBe("scan-real-123");
    expect(result?.target).toBe("10.0.5.5");
    expect(result?.isDemo).toBe(false);
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/scans/scan-real-123/results"),
    );
  });

  it("throws a connection error when the backend is unreachable", async () => {
    vi.mocked(globalThis.fetch).mockRejectedValueOnce(new TypeError("Failed to fetch"));

    await expect(getScanResults("scan-real-123")).rejects.toMatchObject({
      kind: "connection",
    } satisfies Partial<ScanApiError>);
  });

  it("throws when the scan hasn't finished yet", async () => {
    vi.mocked(globalThis.fetch).mockResolvedValueOnce({
      ok: false,
      status: 202,
    } as Response);

    await expect(getScanResults("scan-still-running")).rejects.toThrow(
      "hasn't finished yet",
    );
  });
});
