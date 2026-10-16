import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../context/AuthContext";
import { ScanResults } from "./ScanResults";
import * as resultsService from "../services/resultsService";
import type { ScanRecord } from "../types/scan";

function renderScanResults(scanId = "scan-1") {
  return render(
    <MemoryRouter initialEntries={[`/scans/${scanId}/results`]}>
      <AuthProvider>
        <Routes>
          <Route path="/scans/:scanId/results" element={<ScanResults />} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

const twoFindingScan: ScanRecord = {
  id: "scan-1",
  target: "10.0.1.0/24",
  startedAt: "2026-09-15T14:32:00Z",
  status: "completed",
  totalFindings: 2,
  severityCounts: { critical: 1, high: 0, medium: 0, low: 1, info: 0, unclassified: 0 },
  isDemo: true,
  config: { target: "10.0.1.0/24", portRange: "1-1024", scanType: "full", scanDepth: "deep" },
  vulnerabilities: [
    {
      id: "vuln-1",
      cve: "CVE-2021-44228",
      severity: "critical",
      host: "10.0.1.31",
      port: 8080,
      service: "Apache Log4j 2.14.1",
      cvss: 10.0,
      description: "Log4Shell — unauthenticated remote code execution.",
      remediation: "Upgrade Log4j to 2.17.1+.",
    },
    {
      id: "vuln-2",
      cve: "N/A",
      severity: "low",
      host: "10.0.1.45",
      port: 21,
      service: "FTP (anonymous login enabled)",
      cvss: 3.1,
      description: "Anonymous FTP login is enabled.",
      remediation: "Disable anonymous authentication.",
    },
  ],
};

describe("ScanResults", () => {
  beforeEach(() => {
    vi.spyOn(resultsService, "getScanResults");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders every vulnerability in the results table", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue(twoFindingScan);

    renderScanResults();

    expect(await screen.findByText("CVE-2021-44228")).toBeInTheDocument();
    expect(screen.getByText("N/A")).toBeInTheDocument();
  });

  it("filters by severity", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue(twoFindingScan);
    const user = userEvent.setup();

    renderScanResults();
    await screen.findByText("CVE-2021-44228");

    await user.click(screen.getByRole("button", { name: "low" }));

    expect(screen.queryByText("CVE-2021-44228")).not.toBeInTheDocument();
    expect(screen.getByText("N/A")).toBeInTheDocument();
  });

  it("sorts by a column when its header is clicked", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue(twoFindingScan);
    const user = userEvent.setup();

    renderScanResults();
    await screen.findByText("CVE-2021-44228");

    await user.click(screen.getByRole("button", { name: /sort by cvss/i }));
    let rows = screen.getAllByRole("row").slice(1); // drop header row
    expect(rows[0]).toHaveTextContent("10.0"); // switching columns defaults to descending

    await user.click(screen.getByRole("button", { name: /sort by cvss/i }));
    rows = screen.getAllByRole("row").slice(1);
    expect(rows[0]).toHaveTextContent("3.1"); // clicking the same column again toggles ascending
  });

  it("searches by CVE, host, or service", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue(twoFindingScan);
    const user = userEvent.setup();

    renderScanResults();
    await screen.findByText("CVE-2021-44228");

    await user.type(screen.getByPlaceholderText("Search CVE, host, or service"), "ftp");

    expect(screen.queryByText("CVE-2021-44228")).not.toBeInTheDocument();
    expect(screen.getByText("N/A")).toBeInTheDocument();
  });

  it("opens the CVE detail panel when a row is selected", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue(twoFindingScan);
    const user = userEvent.setup();

    renderScanResults();
    await user.click(await screen.findByText("CVE-2021-44228"));

    expect(screen.getByText("Log4Shell — unauthenticated remote code execution.")).toBeInTheDocument();
    expect(screen.getByText("Upgrade Log4j to 2.17.1+.")).toBeInTheDocument();
  });

  it("shows an empty state for a scan with zero vulnerabilities", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue({
      ...twoFindingScan,
      totalFindings: 0,
      vulnerabilities: [],
    });

    renderScanResults();

    expect(await screen.findByText("No known vulnerabilities were detected")).toBeInTheDocument();
  });

  it("shows an error message when the scan cannot be found", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue(undefined);

    renderScanResults("scan-does-not-exist");

    expect(await screen.findByText("This scan could not be found.")).toBeInTheDocument();
  });
});
