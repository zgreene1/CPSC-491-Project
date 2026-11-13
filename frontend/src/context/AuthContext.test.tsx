import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider, useAuth } from "./AuthContext";
import * as authService from "../services/authService";
import { invalidateSession } from "../services/authSession";

const TOKEN_STORAGE_KEY = "sentry.auth.token";

function renderAuth() {
  return renderHook(() => useAuth(), { wrapper: AuthProvider });
}

describe("AuthContext", () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("starts initializing with no user when sessionStorage is empty", async () => {
    const { result } = renderAuth();

    await waitFor(() => expect(result.current.isInitializing).toBe(false));
    expect(result.current.isAuthenticated).toBe(false);
  });

  it("restores a session only after verifying the stored token against the server", async () => {
    sessionStorage.setItem(TOKEN_STORAGE_KEY, "a-real-token");
    vi.spyOn(authService, "getCurrentUser").mockResolvedValue({
      username: "analyst",
      displayName: "analyst",
    });

    const { result } = renderAuth();

    expect(result.current.isInitializing).toBe(true);
    await waitFor(() => expect(result.current.isInitializing).toBe(false));
    expect(result.current.isAuthenticated).toBe(true);
    expect(result.current.user?.username).toBe("analyst");
  });

  it("never grants access from a fabricated sessionStorage token that fails verification", async () => {
    sessionStorage.setItem(TOKEN_STORAGE_KEY, "fabricated-garbage-token");
    vi.spyOn(authService, "getCurrentUser").mockRejectedValue(new Error("Session is invalid or expired."));

    const { result } = renderAuth();

    await waitFor(() => expect(result.current.isInitializing).toBe(false));
    expect(result.current.isAuthenticated).toBe(false);
    expect(sessionStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
  });

  it("logs out and clears the stored token when login succeeds and logout is called", async () => {
    vi.spyOn(authService, "login").mockResolvedValue({
      user: { username: "analyst", displayName: "analyst" },
      token: "fresh-token",
    });
    vi.spyOn(authService, "logout").mockResolvedValue(undefined);

    const { result } = renderAuth();
    await waitFor(() => expect(result.current.isInitializing).toBe(false));

    await act(async () => {
      await result.current.login("analyst", "correct-password");
    });
    expect(result.current.isAuthenticated).toBe(true);
    expect(sessionStorage.getItem(TOKEN_STORAGE_KEY)).toBe("fresh-token");

    act(() => {
      result.current.logout();
    });
    expect(result.current.isAuthenticated).toBe(false);
    expect(sessionStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
  });

  it("logs out automatically when any API call invalidates the session (e.g. a 401)", async () => {
    vi.spyOn(authService, "login").mockResolvedValue({
      user: { username: "analyst", displayName: "analyst" },
      token: "fresh-token",
    });

    const { result } = renderAuth();
    await waitFor(() => expect(result.current.isInitializing).toBe(false));

    await act(async () => {
      await result.current.login("analyst", "correct-password");
    });
    expect(result.current.isAuthenticated).toBe(true);

    act(() => {
      invalidateSession();
    });

    expect(result.current.isAuthenticated).toBe(false);
    expect(sessionStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
  });
});
