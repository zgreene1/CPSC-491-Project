import { mockScans } from "../mocks/scans";
import type { ScanRecord } from "../types/scan";
import { ScanApiError } from "./scanService";
import { mapApiResultToScanRecord } from "./scanMapper";

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://localhost:8000";

/**
 * Sprint 1's seeded demo scans (Dashboard/History) still resolve from mock
 * data since they were never real backend scans. Any other id is treated as
 * a real scan started through the New Scan workflow and fetched from the
 * backend API.
 */
export async function getScanResults(scanId: string): Promise<ScanRecord | undefined> {
  const mockMatch = mockScans.find((scan) => scan.id === scanId);
  if (mockMatch) {
    return mockMatch;
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/scans/${scanId}/results`);
  } catch {
    throw new ScanApiError(
      "Could not reach the scan service. Confirm the backend is running.",
      "connection",
    );
  }

  if (response.status === 404) {
    return undefined;
  }
  if (response.status === 202) {
    throw new ScanApiError("This scan hasn't finished yet.", "server");
  }
  if (!response.ok) {
    throw new ScanApiError("Failed to load scan results.", "server");
  }

  return mapApiResultToScanRecord(await response.json());
}
