import type { RemediationRecord, RemediationStatus } from "../types/scan";

/**
 * Frontend-only remediation tracking, persisted in the browser's localStorage.
 * No backend endpoint or database table for this exists (checked — not in
 * api_server.py, not in Brian's scan-record SQLite schema), and per the
 * documented team boundary, storage/persistence is the backend team's domain
 * while this is purely a per-viewer UI tracking layer. It resets per
 * browser/device; it is not shared scan data.
 */

const STORAGE_PREFIX = "remediation:";
const DEFAULT_STATUS: RemediationStatus = "open";

export function buildRemediationKey(scanId: string, host: string, port: number, vulnerabilityId: string): string {
  return `${scanId}:${host}:${port}:${vulnerabilityId}`;
}

function defaultRecord(): RemediationRecord {
  return { status: DEFAULT_STATUS, notes: "", updatedAt: "" };
}

function isRemediationStatus(value: unknown): value is RemediationStatus {
  return value === "open" || value === "in-progress" || value === "resolved" || value === "accepted-risk";
}

function isRemediationRecord(value: unknown): value is RemediationRecord {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    isRemediationStatus(record.status) &&
    typeof record.notes === "string" &&
    typeof record.updatedAt === "string"
  );
}

/** Returns a default "open"/no-notes record when nothing is stored yet, or
 * when the stored value is missing/corrupt — never throws. */
export function getRemediation(key: string): RemediationRecord {
  try {
    const raw = localStorage.getItem(STORAGE_PREFIX + key);
    if (!raw) return defaultRecord();

    const parsed: unknown = JSON.parse(raw);
    return isRemediationRecord(parsed) ? parsed : defaultRecord();
  } catch {
    return defaultRecord();
  }
}

export function setRemediation(
  key: string,
  update: { status: RemediationStatus; notes: string },
): RemediationRecord {
  const record: RemediationRecord = {
    status: update.status,
    notes: update.notes,
    updatedAt: new Date().toISOString(),
  };

  try {
    localStorage.setItem(STORAGE_PREFIX + key, JSON.stringify(record));
  } catch {
    // localStorage can throw in private browsing / storage-full cases.
    // The UI already reflects the new value via its own state, so this is a
    // silent best-effort persist rather than a user-facing failure.
  }

  return record;
}
