import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../context/AuthContext";
import { ScanProgress } from "./ScanProgress";
import * as scanService from "../services/scanService";

function renderScanProgress(scanId = "scan-abc") {
  return render(
    <MemoryRouter initialEntries={[`/scans/${scanId}/progress`]}>
      <AuthProvider>
        <Routes>
          <Route path="/scans/:scanId/progress" element={<ScanProgress />} />
          <Route path="/scans/:scanId/results" element={<div>Results page</div>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("ScanProgress", () => {
  beforeEach(() => {
    vi.spyOn(scanService, "getScanProgress");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders progress once the backend responds", async () => {
    vi.mocked(scanService.getScanProgress).mockResolvedValue({
      scanId: "scan-abc",
      status: "running",
      percentComplete: 40,
      hostsDiscovered: 1,
      hostsCompleted: 0,
      portsCompleted: 2,
      totalPorts: 5,
      currentHost: "10.0.1.12",
      currentPort: 443,
      elapsedSeconds: 3,
      cancellationRequested: false,
    });

    renderScanProgress();

    expect(await screen.findByText("40%")).toBeInTheDocument();
    expect(screen.getByText("10.0.1.12")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "View Results" })).toBeDisabled();
  });

  it("enables View Results once the scan completes", async () => {
    vi.mocked(scanService.getScanProgress).mockResolvedValue({
      scanId: "scan-abc",
      status: "completed",
      percentComplete: 100,
      hostsDiscovered: 1,
      hostsCompleted: 1,
      portsCompleted: 5,
      totalPorts: 5,
      currentHost: null,
      currentPort: null,
      elapsedSeconds: 8,
      cancellationRequested: false,
    });

    renderScanProgress();

    expect(await screen.findByText("Completed")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "View Results" })).toBeEnabled();
  });

  it("shows a distinct Failed state and keeps View Results disabled when the scan fails", async () => {
    vi.mocked(scanService.getScanProgress).mockResolvedValue({
      scanId: "scan-abc",
      status: "failed",
      percentComplete: 40,
      hostsDiscovered: 1,
      hostsCompleted: 0,
      portsCompleted: 2,
      totalPorts: 5,
      currentHost: null,
      currentPort: null,
      elapsedSeconds: 4,
      cancellationRequested: false,
    });

    renderScanProgress();

    // The badge renders the raw status value lowercase and capitalizes it
    // only visually via CSS (see StatusBadge in ScanProgress.tsx).
    expect(await screen.findByText("failed")).toBeInTheDocument();
    expect(screen.queryByText("Completed")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "View Results" })).toBeDisabled();
    expect(
      screen.getByText("This scan did not complete successfully (status: failed)."),
    ).toBeInTheDocument();
  });

  it("shows a backend-unavailable error when the progress request fails to connect", async () => {
    vi.mocked(scanService.getScanProgress).mockRejectedValue(
      new scanService.ScanApiError(
        "Lost connection to the scan service.",
        "connection",
      ),
    );

    renderScanProgress();

    expect(await screen.findByText("Backend unavailable")).toBeInTheDocument();
    expect(screen.getByText("Lost connection to the scan service.")).toBeInTheDocument();
  });
});
