import { mockScans } from "../mocks/scans";
import type { ScanSummary } from "../types/scan";
import { delay } from "./delay";

/**
 * Mocked for Sprint 1. Sprint 2 replaces the body with GET /api/scans/history.
 */
export async function getScanHistory(): Promise<ScanSummary[]> {
  return delay([...mockScans], 500);
}
