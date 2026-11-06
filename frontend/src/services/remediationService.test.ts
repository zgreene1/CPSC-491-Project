import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildRemediationKey, getRemediation, setRemediation } from "./remediationService";

describe("buildRemediationKey", () => {
  it("builds a stable, unique key per scan/host/port/vulnerability", () => {
    expect(buildRemediationKey("scan-1", "10.0.1.12", 443, "CVE-2024-3094")).toBe(
      "scan-1:10.0.1.12:443:CVE-2024-3094",
    );
  });
});

describe("remediationService", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it("defaults to Open with empty notes when nothing is stored yet", () => {
    const record = getRemediation("scan-1:10.0.1.12:443:CVE-2024-3094");
    expect(record.status).toBe("open");
    expect(record.notes).toBe("");
  });

  it("round-trips a status/notes update through localStorage", () => {
    const key = "scan-1:10.0.1.12:443:CVE-2024-3094";
    setRemediation(key, { status: "in-progress", notes: "Patching this weekend." });

    const record = getRemediation(key);
    expect(record.status).toBe("in-progress");
    expect(record.notes).toBe("Patching this weekend.");
    expect(record.updatedAt).not.toBe("");
  });

  it("keeps separate findings independent", () => {
    setRemediation("scan-1:10.0.1.12:443:CVE-A", { status: "resolved", notes: "Fixed." });

    expect(getRemediation("scan-1:10.0.1.12:443:CVE-B").status).toBe("open");
  });

  it("falls back to the default record when stored JSON is corrupt", () => {
    const key = "scan-1:10.0.1.12:443:CVE-2024-3094";
    localStorage.setItem(`remediation:${key}`, "{not valid json");

    const record = getRemediation(key);
    expect(record.status).toBe("open");
    expect(record.notes).toBe("");
  });

  it("falls back to the default record when stored data has the wrong shape", () => {
    const key = "scan-1:10.0.1.12:443:CVE-2024-3094";
    localStorage.setItem(`remediation:${key}`, JSON.stringify({ status: "not-a-real-status" }));

    const record = getRemediation(key);
    expect(record.status).toBe("open");
  });

  it("degrades gracefully when localStorage itself throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });

    expect(() => getRemediation("any-key")).not.toThrow();
    expect(getRemediation("any-key").status).toBe("open");
    expect(() => setRemediation("any-key", { status: "resolved", notes: "" })).not.toThrow();
  });
});
