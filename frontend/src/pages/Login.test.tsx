import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Login } from "./Login";
import * as authService from "../services/authService";
import { renderWithProviders } from "../test/utils";

const TOKEN_STORAGE_KEY = "sentry.auth.token";

describe("Login", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    sessionStorage.clear();
  });

  it("shows no session notice on a plain, first-time visit", async () => {
    renderWithProviders(<Login />, { route: "/login" });

    expect(screen.getByLabelText("Username")).toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("explains why the user landed here after an invalidated session, instead of a silent redirect", async () => {
    sessionStorage.setItem(TOKEN_STORAGE_KEY, "a-stale-or-tampered-token");
    vi.spyOn(authService, "getCurrentUser").mockRejectedValue(new Error("Session is invalid or expired."));

    renderWithProviders(<Login />, { route: "/login" });

    expect(
      await screen.findByText("Your session is no longer valid. Please sign in again."),
    ).toBeInTheDocument();
  });
});
