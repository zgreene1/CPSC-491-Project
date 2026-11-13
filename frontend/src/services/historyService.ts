import { mockScans } from "../mocks/scans";
import type { ScanRecord } from "../types/scan";
import { authFetch } from "./apiClient";
import { ScanApiError } from "./scanService";
import { mapApiResultToScanRecord, type ApiScanResult } from "./scanMapper";

/**
 * Returns every real scan from the backend plus the Sprint 1 seeded demo
 * scans, newest first. Each record's `isDemo` flag (see types/scan.ts) is
 * what lets the UI label rows "Live" vs "Demo" instead of blending them.
 */
export async function getScanHistory(): Promise<ScanRecord[]> {
  let response: Response;
  try {
    response = await authFetch("/api/scans");
  } catch {
    throw new ScanApiError(
      "Could not reach the scan service. Confirm the backend is running.",
      "connection",
    );
  }

  if (!response.ok) {
    throw new ScanApiError("Failed to load scan history.", "server");
  }

  const data = (await response.json()) as { scans: ApiScanResult[] };
  const realScans = data.scans.map(mapApiResultToScanRecord);

  return [...realScans, ...mockScans].sort(
    (a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime(),
  );
}
