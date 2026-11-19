import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { WarningBanner } from "./WarningBanner";

describe("WarningBanner", () => {
  it("renders its children inside a status region", () => {
    render(
      <WarningBanner>
        <p>Your session has expired.</p>
      </WarningBanner>,
    );

    expect(screen.getByRole("status")).toHaveTextContent("Your session has expired.");
  });
});
