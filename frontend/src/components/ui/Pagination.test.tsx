import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Pagination } from "./Pagination";

describe("Pagination", () => {
  it("shows the correct item range and page count", () => {
    render(<Pagination page={2} pageSize={25} totalItems={60} onPageChange={() => {}} itemLabel="findings" />);

    expect(screen.getByText("Showing 26–50 of 60 findings")).toBeInTheDocument();
    expect(screen.getByText("2 / 3")).toBeInTheDocument();
  });

  it("disables Previous on the first page and Next on the last page", () => {
    const { rerender } = render(
      <Pagination page={1} pageSize={25} totalItems={60} onPageChange={() => {}} />,
    );
    expect(screen.getByRole("button", { name: "Previous page" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next page" })).toBeEnabled();

    rerender(<Pagination page={3} pageSize={25} totalItems={60} onPageChange={() => {}} />);
    expect(screen.getByRole("button", { name: "Previous page" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Next page" })).toBeDisabled();
  });

  it("calls onPageChange with the adjacent page when Previous/Next is clicked", async () => {
    const onPageChange = vi.fn();
    const user = userEvent.setup();
    render(<Pagination page={2} pageSize={25} totalItems={60} onPageChange={onPageChange} />);

    await user.click(screen.getByRole("button", { name: "Next page" }));
    expect(onPageChange).toHaveBeenCalledWith(3);

    await user.click(screen.getByRole("button", { name: "Previous page" }));
    expect(onPageChange).toHaveBeenCalledWith(1);
  });

  it("shows a single page of 1 for an empty result set without dividing by zero", () => {
    render(<Pagination page={1} pageSize={25} totalItems={0} onPageChange={() => {}} />);

    expect(screen.getByText("Showing 0–0 of 0 items")).toBeInTheDocument();
    expect(screen.getByText("1 / 1")).toBeInTheDocument();
  });
});
