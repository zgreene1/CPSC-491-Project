import { mockScans } from "../mocks/scans";
import type { ScanRecord } from "../types/scan";
import { delay } from "./delay";

/**
 * Mocked for Sprint 1. Sprint 2 replaces the body with GET /api/scans/:id/results.
 */
export async function getScanResults(scanId: string): Promise<ScanRecord | undefined> {
  return delay(mockScans.find((scan) => scan.id === scanId), 500);
}
