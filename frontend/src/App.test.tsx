import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import * as authService from "./services/authService";
import { renderWithProviders } from "./test/utils";

describe("App routing", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("redirects an unauthenticated visitor to the login page", () => {
    renderWithProviders(<App />, { route: "/dashboard" });
    expect(screen.getByRole("heading", { name: "Sentry" })).toBeInTheDocument();
    expect(screen.getByLabelText("Username")).toBeInTheDocument();
  });

  it("navigates to the dashboard after a successful login", async () => {
    // authService.login has a real network-simulating delay (see authService.ts).
    // Stubbing it here keeps this test deterministic instead of racing RTL's
    // default assertion timeout against a real timer, which was flaky on
    // slower/loaded CI runners.
    vi.spyOn(authService, "login").mockResolvedValue({
      user: { username: "analyst", displayName: "analyst" },
      token: "mock-token",
    });

    const user = userEvent.setup();
    renderWithProviders(<App />, { route: "/login" });

    await user.type(screen.getByLabelText("Username"), "analyst");
    await user.type(screen.getByLabelText("Password"), "hunter2");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
  });
});
