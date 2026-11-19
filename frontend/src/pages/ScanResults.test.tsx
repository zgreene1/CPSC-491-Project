import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../context/AuthContext";
import { ScanResults } from "./ScanResults";
import * as resultsService from "../services/resultsService";
import { ScanApiError } from "../services/scanService";
import type { ScanRecord } from "../types/scan";

function renderScanResults(scanId = "scan-1") {
  return render(
    <MemoryRouter initialEntries={[`/scans/${scanId}/results`]}>
      <AuthProvider>
        <Routes>
          <Route path="/scans/:scanId/results" element={<ScanResults />} />
          <Route path="/scans/:scanId/progress" element={<div>Progress page</div>} />
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
      matches: [],
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
      matches: [],
    },
  ],
  warnings: [],
};

function manyFindingScan(count: number): ScanRecord {
  return {
    ...twoFindingScan,
    id: "scan-large",
    vulnerabilities: Array.from({ length: count }, (_, i) => ({
      id: `vuln-${i}`,
      cve: `CVE-0000-${String(i).padStart(4, "0")}`,
      severity: "unclassified",
      host: "10.0.0.1",
      port: 1024 + i,
      service: "unknown",
      cvss: 0,
      description: "Open port detected.",
      remediation: "No automated remediation guidance available yet.",
      matches: [],
    })),
  };
}

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

  it("does not show a warning banner when the scan has no warnings", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue(twoFindingScan);

    renderScanResults();

    await screen.findByText("CVE-2021-44228");
    expect(screen.queryByText("Scan completed with a warning")).not.toBeInTheDocument();
  });

  it("shows a non-fatal warning banner when the backend reports a recoverable scan error", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue({
      ...twoFindingScan,
      warnings: [
        {
          code: "VULNERABILITY_CATALOG_ERROR",
          message: "Vulnerability matching was unavailable; port results were preserved.",
          stage: "matching",
        },
      ],
    });

    renderScanResults();

    expect(await screen.findByText("Scan completed with a warning")).toBeInTheDocument();
    expect(
      screen.getByText("Vulnerability matching was unavailable; port results were preserved."),
    ).toBeInTheDocument();
    // The underlying port/finding data is still shown — a warning doesn't hide results.
    expect(screen.getByText("CVE-2021-44228")).toBeInTheDocument();
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

  it("opens the detail panel at Level 1 showing only CVE and severity", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue(twoFindingScan);
    const user = userEvent.setup();

    renderScanResults();
    await user.click(await screen.findByText("CVE-2021-44228"));

    expect(screen.getByRole("button", { name: "Show more detail →" })).toBeInTheDocument();
    expect(screen.queryByText("Log4Shell — unauthenticated remote code execution.")).not.toBeInTheDocument();
    expect(screen.queryByText("Upgrade Log4j to 2.17.1+.")).not.toBeInTheDocument();
  });

  it("reveals CVSS, affected service, and description at Level 2", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue(twoFindingScan);
    const user = userEvent.setup();

    renderScanResults();
    await user.click(await screen.findByText("CVE-2021-44228"));
    await user.click(screen.getByRole("button", { name: "Show more detail →" }));

    const detailPanel = screen.getByText("CVSS Score").closest("div")!.parentElement!;
    expect(within(detailPanel).getByText("10.0")).toBeInTheDocument();
    expect(screen.getByText("Log4Shell — unauthenticated remote code execution.")).toBeInTheDocument();
    expect(screen.queryByText("Upgrade Log4j to 2.17.1+.")).not.toBeInTheDocument();
  });

  it("reveals remediation guidance at Level 3", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue(twoFindingScan);
    const user = userEvent.setup();

    renderScanResults();
    await user.click(await screen.findByText("CVE-2021-44228"));
    await user.click(screen.getByRole("button", { name: "Show more detail →" }));
    await user.click(screen.getByRole("button", { name: "Show more detail →" }));

    expect(screen.getByText("Upgrade Log4j to 2.17.1+.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Show more detail →" })).not.toBeInTheDocument();
  });

  it("resets to Level 1 when a different vulnerability is selected", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue(twoFindingScan);
    const user = userEvent.setup();

    renderScanResults();
    await user.click(await screen.findByText("CVE-2021-44228"));
    await user.click(screen.getByRole("button", { name: "Show more detail →" }));
    await user.click(screen.getByRole("button", { name: "Show more detail →" }));
    expect(screen.getByText("Upgrade Log4j to 2.17.1+.")).toBeInTheDocument();

    await user.click(screen.getByText("N/A"));

    expect(screen.queryByText("Anonymous FTP login is enabled.")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Show more detail →" })).toBeInTheDocument();
  });

  it("shows real catalog matches and reference links when present", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue({
      ...twoFindingScan,
      vulnerabilities: [
        {
          ...twoFindingScan.vulnerabilities[0],
          matches: [
            {
              vulnerabilityId: "CVE-2021-44228",
              status: "potential",
              summary: "Log4j JNDI lookup RCE.",
              sourceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
              confidence: 0.9,
            },
          ],
        },
      ],
    });
    const user = userEvent.setup();

    renderScanResults();
    await user.click(await screen.findByText("CVE-2021-44228"));
    await user.click(screen.getByRole("button", { name: "Show more detail →" }));

    expect(screen.getByText("CVE-2021-44228 — Log4j JNDI lookup RCE.")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Show more detail →" }));

    expect(screen.getByRole("link", { name: "CVE-2021-44228 source" })).toHaveAttribute(
      "href",
      "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    );
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

  it("offers a Retry button on error instead of a dead end", async () => {
    vi.mocked(resultsService.getScanResults)
      .mockRejectedValueOnce(new Error("Failed to load scan results."))
      .mockResolvedValue(twoFindingScan);
    const user = userEvent.setup();

    renderScanResults();

    await screen.findByText("Failed to load scan results.");
    await user.click(screen.getByRole("button", { name: "Retry" }));

    expect(await screen.findByText("CVE-2021-44228")).toBeInTheDocument();
  });

  it("shows a friendly still-running state instead of an error when the scan hasn't finished", async () => {
    vi.mocked(resultsService.getScanResults).mockRejectedValue(
      new ScanApiError("This scan hasn't finished yet.", "in_progress"),
    );
    const user = userEvent.setup();

    renderScanResults("scan-still-running");

    expect(await screen.findByText("This scan is still running")).toBeInTheDocument();
    expect(screen.queryByText("This scan hasn't finished yet.")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "View scan progress" }));
    expect(await screen.findByText("Progress page")).toBeInTheDocument();
  });

  it("does not show pagination for a small result set", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue(twoFindingScan);

    renderScanResults();

    await screen.findByText("CVE-2021-44228");
    expect(screen.queryByText(/Showing \d+/)).not.toBeInTheDocument();
  });

  it("paginates a large result set instead of rendering every row at once", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue(manyFindingScan(60));

    renderScanResults();

    expect(await screen.findByText("Showing 1–25 of 60 findings")).toBeInTheDocument();
    expect(screen.getByText("CVE-0000-0000")).toBeInTheDocument();
    expect(screen.queryByText("CVE-0000-0025")).not.toBeInTheDocument();
  });

  it("navigates to the next page and shows the next slice of findings", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue(manyFindingScan(60));
    const user = userEvent.setup();

    renderScanResults();
    await screen.findByText("CVE-0000-0000");

    await user.click(screen.getByRole("button", { name: "Next page" }));

    expect(await screen.findByText("Showing 26–50 of 60 findings")).toBeInTheDocument();
    expect(screen.queryByText("CVE-0000-0000")).not.toBeInTheDocument();
    expect(screen.getByText("CVE-0000-0025")).toBeInTheDocument();
  });

  it("resets to page 1 when the severity filter changes", async () => {
    vi.mocked(resultsService.getScanResults).mockResolvedValue(manyFindingScan(60));
    const user = userEvent.setup();

    renderScanResults();
    await screen.findByText("CVE-0000-0000");
    await user.click(screen.getByRole("button", { name: "Next page" }));
    await screen.findByText("Showing 26–50 of 60 findings");

    await user.click(screen.getByRole("button", { name: "unclassified" }));

    expect(await screen.findByText("Showing 1–25 of 60 findings")).toBeInTheDocument();
  });
});
