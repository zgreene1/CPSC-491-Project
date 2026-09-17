import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Table, type Column } from "./Table";

interface Row {
  id: string;
  name: string;
}

const columns: Column<Row>[] = [
  { key: "name", header: "Name", sortable: true, render: (row) => row.name },
];

describe("Table", () => {
  it("renders a row per item", () => {
    render(
      <Table columns={columns} rows={[{ id: "1", name: "Alpha" }, { id: "2", name: "Beta" }]} rowKey={(r) => r.id} />,
    );
    expect(screen.getByText("Alpha")).toBeInTheDocument();
    expect(screen.getByText("Beta")).toBeInTheDocument();
  });

  it("renders the empty state when there are no rows", () => {
    render(
      <Table columns={columns} rows={[]} rowKey={(r) => r.id} emptyState={<p>Nothing here</p>} />,
    );
    expect(screen.getByText("Nothing here")).toBeInTheDocument();
  });

  it("calls onSort when a sortable header is clicked", () => {
    const onSort = vi.fn();
    render(
      <Table columns={columns} rows={[{ id: "1", name: "Alpha" }]} rowKey={(r) => r.id} onSort={onSort} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /sort by name/i }));
    expect(onSort).toHaveBeenCalledWith("name");
  });

  it("calls onRowClick when a row is clicked", () => {
    const onRowClick = vi.fn();
    const row = { id: "1", name: "Alpha" };
    render(<Table columns={columns} rows={[row]} rowKey={(r) => r.id} onRowClick={onRowClick} />);
    fireEvent.click(screen.getByText("Alpha"));
    expect(onRowClick).toHaveBeenCalledWith(row);
  });
});
