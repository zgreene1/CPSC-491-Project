import { describe, expect, it } from "vitest";
import { validateScanConfig } from "./scanService";
import type { ScanConfig } from "../types/scan";

const baseConfig: ScanConfig = {
  target: "10.0.1.12",
  portRange: "1-1024",
  scanType: "quick",
  scanDepth: "standard",
};

describe("validateScanConfig", () => {
  it("passes for a valid IPv4 target and port range", () => {
    expect(validateScanConfig(baseConfig)).toEqual([]);
  });

  it("passes for a valid hostname target", () => {
    expect(validateScanConfig({ ...baseConfig, target: "scanme.example.com" })).toEqual([]);
  });

  it("passes for a valid CIDR target", () => {
    expect(validateScanConfig({ ...baseConfig, target: "10.0.1.0/24" })).toEqual([]);
  });

  it("flags an empty target", () => {
    const errors = validateScanConfig({ ...baseConfig, target: "" });
    expect(errors).toContainEqual({ field: "target", message: "Target IP or hostname is required." });
  });

  it("flags a malformed target", () => {
    const errors = validateScanConfig({ ...baseConfig, target: "not a host!!" });
    expect(errors.some((e) => e.field === "target")).toBe(true);
  });

  it("flags an out-of-range port", () => {
    const errors = validateScanConfig({ ...baseConfig, portRange: "70000" });
    expect(errors.some((e) => e.field === "portRange")).toBe(true);
  });

  it("flags a reversed port range", () => {
    const errors = validateScanConfig({ ...baseConfig, portRange: "1024-1" });
    expect(errors.some((e) => e.field === "portRange")).toBe(true);
  });

  it("flags an empty port range", () => {
    const errors = validateScanConfig({ ...baseConfig, portRange: "" });
    expect(errors).toContainEqual({ field: "portRange", message: "Port range is required." });
  });
});
