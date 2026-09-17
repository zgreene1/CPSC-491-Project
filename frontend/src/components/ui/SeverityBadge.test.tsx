import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Severity } from "../../types/scan";
import { SeverityBadge } from "./SeverityBadge";

describe("SeverityBadge", () => {
  const cases: Array<[Severity, string]> = [
    ["critical", "Critical"],
    ["high", "High"],
    ["medium", "Medium"],
    ["low", "Low"],
    ["info", "Info"],
  ];

  it.each(cases)("renders the %s label for severity=%s", (severity, label) => {
    render(<SeverityBadge severity={severity} />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });
});
