import type { ScanConfig } from "../types/scan";
import { mapApiProgress } from "./scanMapper";
import type { ScanProgressState } from "../types/scan";

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://localhost:8000";

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
 * Client-side validation mirrors the rules the backend enforces in
 * scanner_contracts.ScanConfiguration.validation_errors(), so the UI can give
 * instant feedback before a network round trip. The backend remains the
 * source of truth — see handleApiError below for how server-side validation
 * errors are surfaced if they ever diverge.
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
  if (config.scanType === "custom" && !portRange) {
    errors.push({ field: "portRange", message: "Port range is required for a custom scan." });
  } else if (portRange && !PORT_RANGE_PATTERN.test(portRange)) {
    errors.push({ field: "portRange", message: "Use a single port (443) or a range (1-1024)." });
  } else if (portRange) {
    const [start, end] = portRange.split("-").map(Number);
    if (start < 1 || start > 65535 || (end !== undefined && (end < 1 || end > 65535))) {
      errors.push({ field: "portRange", message: "Ports must be between 1 and 65535." });
    } else if (end !== undefined && end < start) {
      errors.push({ field: "portRange", message: "Range end must be greater than or equal to the start." });
    }
  }

  return errors;
}

export type ScanApiErrorKind = "validation" | "connection" | "server";

export class ScanApiError extends Error {
  readonly kind: ScanApiErrorKind;

  constructor(message: string, kind: ScanApiErrorKind) {
    super(message);
    this.name = "ScanApiError";
    this.kind = kind;
  }
}

function buildScanRequestPayload(config: ScanConfig) {
  const scanModeMap: Record<ScanConfig["scanType"], string> = {
    quick: "common",
    full: "all",
    custom: "custom",
  };

  // Depth maps to timeout per host/port check: shallower scans fail fast on
  // unresponsive ports, deeper scans wait longer to confirm a true negative.
  const timeoutByDepth: Record<ScanConfig["scanDepth"], number> = {
    light: 0.5,
    standard: 1.0,
    deep: 2.5,
  };

  return {
    targets: [config.target.trim()],
    scan_mode: scanModeMap[config.scanType],
    port_spec: config.scanType === "custom" ? config.portRange.trim() : null,
    timeout_seconds: timeoutByDepth[config.scanDepth],
    discovery_enabled: false,
  };
}

async function parseErrorMessage(response: Response): Promise<string> {
  try {
    const data = await response.json();
    return data?.errors?.[0]?.message ?? data?.error ?? "The server rejected this request.";
  } catch {
    return "The server rejected this request.";
  }
}

/**
 * Starts a real scan against the backend API (see Backend/api_server.py).
 * Throws ScanApiError with a `kind` of "validation" (bad config, HTTP 400),
 * "connection" (backend unreachable), or "server" (unexpected failure) so
 * callers can show the right message for each case.
 */
export async function startScan(config: ScanConfig): Promise<{ scanId: string }> {
  const clientErrors = validateScanConfig(config);
  if (clientErrors.length > 0) {
    throw new ScanApiError(clientErrors[0].message, "validation");
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/scans`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildScanRequestPayload(config)),
    });
  } catch {
    throw new ScanApiError(
      "Could not reach the scan service. Confirm the backend is running.",
      "connection",
    );
  }

  if (response.status === 400) {
    throw new ScanApiError(await parseErrorMessage(response), "validation");
  }
  if (!response.ok) {
    throw new ScanApiError(await parseErrorMessage(response), "server");
  }

  const data = await response.json();
  return { scanId: data.scan_id as string };
}

export async function getScanProgress(scanId: string): Promise<ScanProgressState> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/scans/${scanId}/progress`);
  } catch {
    throw new ScanApiError("Lost connection to the scan service.", "connection");
  }

  if (!response.ok) {
    throw new ScanApiError(await parseErrorMessage(response), "server");
  }

  return mapApiProgress(await response.json());
}
