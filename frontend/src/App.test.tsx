import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { App } from "./App";
import { renderWithProviders } from "./test/utils";

describe("App routing", () => {
  it("redirects an unauthenticated visitor to the login page", () => {
    renderWithProviders(<App />, { route: "/dashboard" });
    expect(screen.getByRole("heading", { name: "Sentry" })).toBeInTheDocument();
    expect(screen.getByLabelText("Username")).toBeInTheDocument();
  });

  it("navigates to the dashboard after a successful login", async () => {
    const user = userEvent.setup();
    renderWithProviders(<App />, { route: "/login" });

    await user.type(screen.getByLabelText("Username"), "analyst");
    await user.type(screen.getByLabelText("Password"), "hunter2");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
  });
});
