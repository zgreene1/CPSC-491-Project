import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Button } from "./Button";

describe("Button", () => {
  it("renders its label", () => {
    render(<Button>Start Scan</Button>);
    expect(screen.getByRole("button", { name: "Start Scan" })).toBeInTheDocument();
  });

  it("calls onClick when clicked", () => {
    const onClick = vi.fn();
    render(<Button onClick={onClick}>Click me</Button>);
    fireEvent.click(screen.getByRole("button", { name: "Click me" }));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it("does not call onClick when disabled", () => {
    const onClick = vi.fn();
    render(
      <Button onClick={onClick} disabled>
        Disabled
      </Button>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Disabled" }));
    expect(onClick).not.toHaveBeenCalled();
  });

  it("shows a loading indicator and disables the button when isLoading", () => {
    render(<Button isLoading>Loading</Button>);
    const button = screen.getByRole("button", { name: "Loading" });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("aria-busy", "true");
  });
});
