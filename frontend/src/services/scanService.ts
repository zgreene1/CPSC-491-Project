import { latestScan, mockScans } from "../mocks/scans";
import type { ScanConfig, ScanRecord } from "../types/scan";
import { delay } from "./delay";

const IPV4_PATTERN =
  /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;
const HOSTNAME_PATTERN = /^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const CIDR_PATTERN = /^(\d{1,3}\.){3}\d{1,3}\/(\d|[1-2]\d|3[0-2])$/;
const PORT_RANGE_PATTERN = /^\d{1,5}(-\d{1,5})?$/;

export interface ValidationError {
  field: "target" | "portRange";
  message: string;
}

/**
 * Client-side validation mirrors the target/port-range rules the backend
 * team defined (see target_validation.py). Sprint 2 additionally validates
 * server-side and surfaces those errors through the same shape.
 */
export function validateScanConfig(config: ScanConfig): ValidationError[] {
  const errors: ValidationError[] = [];
  const target = config.target.trim();

  if (!target) {
    errors.push({ field: "target", message: "Target IP or hostname is required." });
  } else if (
    !IPV4_PATTERN.test(target) &&
    !HOSTNAME_PATTERN.test(target) &&
    !CIDR_PATTERN.test(target)
  ) {
    errors.push({
      field: "target",
      message: "Enter a valid IPv4 address, CIDR range, or hostname.",
    });
  }

  const portRange = config.portRange.trim();
  if (!portRange) {
    errors.push({ field: "portRange", message: "Port range is required." });
  } else if (!PORT_RANGE_PATTERN.test(portRange)) {
    errors.push({ field: "portRange", message: "Use a single port (443) or a range (1-1024)." });
  } else {
    const [start, end] = portRange.split("-").map(Number);
    if (start < 1 || start > 65535 || (end !== undefined && (end < 1 || end > 65535))) {
      errors.push({ field: "portRange", message: "Ports must be between 1 and 65535." });
    } else if (end !== undefined && end < start) {
      errors.push({ field: "portRange", message: "Range end must be greater than or equal to the start." });
    }
  }

  return errors;
}

/**
 * Mocked for Sprint 1 — resolves with a freshly "started" scan record.
 * Sprint 2 replaces this with POST /api/scans and returns the accepted scan id.
 */
export async function startScan(config: ScanConfig): Promise<ScanRecord> {
  const errors = validateScanConfig(config);
  if (errors.length > 0) {
    throw new Error(errors[0].message);
  }

  const scan: ScanRecord = {
    ...latestScan,
    id: `scan-${Math.floor(1000 + Math.random() * 9000)}`,
    target: config.target,
    startedAt: new Date().toISOString(),
    status: "running",
    config,
  };

  return delay(scan, 500);
}

export async function getScanById(scanId: string): Promise<ScanRecord | undefined> {
  return delay(mockScans.find((scan) => scan.id === scanId) ?? latestScan, 400);
}
