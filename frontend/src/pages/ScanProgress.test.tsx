import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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

  it("shows a Cancel Scan button while running and calls cancelScan when clicked", async () => {
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
    const cancelSpy = vi.spyOn(scanService, "cancelScan").mockResolvedValue(undefined);
    const user = userEvent.setup();

    renderScanProgress();

    const cancelButton = await screen.findByRole("button", { name: "Cancel Scan" });
    await user.click(cancelButton);

    expect(cancelSpy).toHaveBeenCalledWith("scan-abc");
  });

  it("shows a Cancel Scan button while queued, before the scan starts running", async () => {
    vi.mocked(scanService.getScanProgress).mockResolvedValue({
      scanId: "scan-abc",
      status: "queued",
      percentComplete: 0,
      hostsDiscovered: 0,
      hostsCompleted: 0,
      portsCompleted: 0,
      totalPorts: 0,
      currentHost: null,
      currentPort: null,
      elapsedSeconds: 0,
      cancellationRequested: false,
    });

    renderScanProgress();

    expect(await screen.findByRole("button", { name: "Cancel Scan" })).toBeInTheDocument();
  });

  it("hides the Cancel Scan button once the scan is terminal", async () => {
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

    await screen.findByText("Completed");
    expect(screen.queryByRole("button", { name: "Cancel Scan" })).not.toBeInTheDocument();
  });

  it("shows a waiting message and hides Cancel once cancellation has been requested", async () => {
    vi.mocked(scanService.getScanProgress).mockResolvedValue({
      scanId: "scan-abc",
      status: "running",
      percentComplete: 60,
      hostsDiscovered: 1,
      hostsCompleted: 0,
      portsCompleted: 3,
      totalPorts: 5,
      currentHost: null,
      currentPort: null,
      elapsedSeconds: 4,
      cancellationRequested: true,
    });

    renderScanProgress();

    expect(await screen.findByText("Cancellation requested — waiting for the scan to stop…")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Cancel Scan" })).not.toBeInTheDocument();
  });

  it("shows an error when cancelling fails", async () => {
    vi.mocked(scanService.getScanProgress).mockResolvedValue({
      scanId: "scan-abc",
      status: "running",
      percentComplete: 40,
      hostsDiscovered: 1,
      hostsCompleted: 0,
      portsCompleted: 2,
      totalPorts: 5,
      currentHost: null,
      currentPort: null,
      elapsedSeconds: 3,
      cancellationRequested: false,
    });
    vi.spyOn(scanService, "cancelScan").mockRejectedValue(
      new scanService.ScanApiError("Lost connection to the scan service.", "connection"),
    );
    const user = userEvent.setup();

    renderScanProgress();

    await user.click(await screen.findByRole("button", { name: "Cancel Scan" }));

    expect(await screen.findByText("Could not cancel scan")).toBeInTheDocument();
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
