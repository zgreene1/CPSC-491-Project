import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";
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
  it("shows a validation error when the target is empty", async () => {
    const user = userEvent.setup();
    renderNewScan();

    await user.click(screen.getByRole("button", { name: "Start Scan" }));

    expect(await screen.findByText("Target IP or hostname is required.")).toBeInTheDocument();
    expect(screen.queryByText("Progress page")).not.toBeInTheDocument();
  });

  it("shows a validation error for an invalid target", async () => {
    const user = userEvent.setup();
    renderNewScan();

    await user.type(screen.getByLabelText("Target IP / Hostname"), "not a valid host!!");
    await user.click(screen.getByRole("button", { name: "Start Scan" }));

    expect(
      await screen.findByText("Enter a valid IPv4 address, CIDR range, or hostname."),
    ).toBeInTheDocument();
  });

  it("navigates to the scan progress page after a valid submission", async () => {
    const user = userEvent.setup();
    renderNewScan();

    await user.type(screen.getByLabelText("Target IP / Hostname"), "10.0.1.12");
    await user.click(screen.getByRole("button", { name: "Start Scan" }));

    expect(await screen.findByText("Progress page")).toBeInTheDocument();
  });
});
