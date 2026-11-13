import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../context/AuthContext";
import { ScanHistory } from "./ScanHistory";
import * as historyService from "../services/historyService";
import type { ScanRecord } from "../types/scan";

function renderScanHistory() {
  return render(
    <MemoryRouter initialEntries={["/history"]}>
      <AuthProvider>
        <Routes>
          <Route path="/history" element={<ScanHistory />} />
          <Route path="/scans/:scanId/results" element={<div>Results page</div>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

function scan(overrides: Partial<ScanRecord> = {}): ScanRecord {
  return {
    id: "scan-1",
    target: "10.0.1.12",
    startedAt: "2026-10-15T17:00:00Z",
    status: "completed",
    totalFindings: 2,
    severityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unclassified: 2 },
    isDemo: false,
    config: { target: "10.0.1.12", portRange: "", scanType: "custom", scanDepth: "standard" },
    vulnerabilities: [],
    ...overrides,
  };
}

describe("ScanHistory", () => {
  beforeEach(() => {
    vi.spyOn(historyService, "getScanHistory");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders every returned scan with its source label", async () => {
    vi.mocked(historyService.getScanHistory).mockResolvedValue([
      scan({ id: "scan-live", target: "127.0.0.1", isDemo: false }),
      scan({ id: "scan-demo", target: "10.0.1.0/24", isDemo: true }),
    ]);

    renderScanHistory();

    expect(await screen.findByText("127.0.0.1")).toBeInTheDocument();
    expect(screen.getByText("10.0.1.0/24")).toBeInTheDocument();
    expect(screen.getByText("Live")).toBeInTheDocument();
    expect(screen.getByText("Demo")).toBeInTheDocument();
  });

  it("navigates to a scan's results when a row is clicked", async () => {
    vi.mocked(historyService.getScanHistory).mockResolvedValue([scan({ id: "scan-42" })]);
    const user = userEvent.setup();

    renderScanHistory();

    await user.click(await screen.findByText("10.0.1.12"));
    expect(await screen.findByText("Results page")).toBeInTheDocument();
  });

  it("shows the empty state when there are no scans", async () => {
    vi.mocked(historyService.getScanHistory).mockResolvedValue([]);

    renderScanHistory();

    expect(await screen.findByText("No previous scans have been performed")).toBeInTheDocument();
  });

  it("shows an error state with retry when loading history fails", async () => {
    vi.mocked(historyService.getScanHistory)
      .mockRejectedValueOnce(new Error("backend down"))
      .mockResolvedValueOnce([scan()]);
    const user = userEvent.setup();

    renderScanHistory();

    expect(
      await screen.findByText("Failed to load scan history. The backend may be unavailable."),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("10.0.1.12")).toBeInTheDocument();
  });
});
