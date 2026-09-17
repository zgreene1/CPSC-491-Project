import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { Sidebar } from "./Sidebar";

describe("Sidebar", () => {
  it("renders a navigation link for every primary section", () => {
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>,
    );

    const nav = screen.getByRole("navigation", { name: "Primary" });
    for (const label of ["Dashboard", "New Scan", "Scan History", "Reports", "Settings"]) {
      expect(within(nav).getByText(label)).toBeInTheDocument();
    }
  });
});
