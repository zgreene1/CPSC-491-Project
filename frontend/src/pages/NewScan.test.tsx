import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../context/AuthContext";
import { NewScan } from "./NewScan";

function renderNewScan() {
  return render(
    <MemoryRouter initialEntries={["/scans/new"]}>
      <AuthProvider>
        <Routes>
          <Route path="/scans/new" element={<NewScan />} />
          <Route path="/scans/:scanId/progress" element={<div>Progress page</div>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("NewScan", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    globalThis.fetch = vi.fn();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("shows a validation error when the target is empty", async () => {
    const user = userEvent.setup();
    renderNewScan();

    await user.click(screen.getByRole("button", { name: "Start Scan" }));

    expect(await screen.findByText("Target IP or hostname is required.")).toBeInTheDocument();
    expect(screen.queryByText("Progress page")).not.toBeInTheDocument();
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("shows a validation error for an invalid target", async () => {
    const user = userEvent.setup();
    renderNewScan();

    await user.type(screen.getByLabelText("Target IP / Hostname"), "not a valid host!!");
    await user.click(screen.getByRole("button", { name: "Start Scan" }));

    expect(
      await screen.findByText("Enter a valid IPv4 address, CIDR range, or hostname."),
    ).toBeInTheDocument();
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("navigates to the scan progress page after the backend accepts the scan", async () => {
    vi.mocked(globalThis.fetch).mockResolvedValueOnce({
      ok: true,
      status: 202,
      json: async () => ({ scan_id: "scan-abc123" }),
    } as Response);

    const user = userEvent.setup();
    renderNewScan();

    await user.type(screen.getByLabelText("Target IP / Hostname"), "10.0.1.12");
    await user.click(screen.getByRole("button", { name: "Start Scan" }));

    expect(await screen.findByText("Progress page")).toBeInTheDocument();
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/scans"),
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("shows a connection error when the backend is unreachable", async () => {
    vi.mocked(globalThis.fetch).mockRejectedValueOnce(new TypeError("Failed to fetch"));

    const user = userEvent.setup();
    renderNewScan();

    await user.type(screen.getByLabelText("Target IP / Hostname"), "10.0.1.12");
    await user.click(screen.getByRole("button", { name: "Start Scan" }));

    expect(await screen.findByText("Backend unavailable")).toBeInTheDocument();
    expect(
      screen.getByText("Could not reach the scan service. Confirm the backend is running."),
    ).toBeInTheDocument();
  });

  it("surfaces a server-side validation error (HTTP 400) under the target field", async () => {
    vi.mocked(globalThis.fetch).mockResolvedValueOnce({
      ok: false,
      status: 400,
      json: async () => ({ errors: [{ message: "Unsupported scan mode." }] }),
    } as Response);

    const user = userEvent.setup();
    renderNewScan();

    await user.type(screen.getByLabelText("Target IP / Hostname"), "10.0.1.12");
    await user.click(screen.getByRole("button", { name: "Start Scan" }));

    expect(await screen.findByText("Unsupported scan mode.")).toBeInTheDocument();
    expect(screen.queryByText("Progress page")).not.toBeInTheDocument();
  });
});
