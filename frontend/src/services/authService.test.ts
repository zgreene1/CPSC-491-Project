import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getCurrentUser, login, logout } from "./authService";
import { getToken } from "./authSession";

describe("authService", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    globalThis.fetch = vi.fn();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  describe("login", () => {
    it("rejects empty credentials without calling the network", async () => {
      await expect(login("", "")).rejects.toThrow("Username and password are required.");
      expect(globalThis.fetch).not.toHaveBeenCalled();
    });

    it("stores the token and returns the user on a successful login", async () => {
      vi.mocked(globalThis.fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ token: "real-token-abc", username: "analyst", expires_at: 123 }),
      } as Response);

      const result = await login("analyst", "correct-password");

      expect(result).toEqual({
        user: { username: "analyst", displayName: "analyst" },
        token: "real-token-abc",
      });
      expect(getToken()).toBe("real-token-abc");
    });

    it("throws the server's error message on invalid credentials", async () => {
      vi.mocked(globalThis.fetch).mockResolvedValueOnce({
        ok: false,
        json: async () => ({ error: "Invalid username or password." }),
      } as Response);

      await expect(login("analyst", "wrong")).rejects.toThrow("Invalid username or password.");
    });

    it("throws a connection error when the backend is unreachable", async () => {
      vi.mocked(globalThis.fetch).mockRejectedValueOnce(new TypeError("Failed to fetch"));

      await expect(login("analyst", "correct-password")).rejects.toThrow(
        "Could not reach the authentication service",
      );
    });
  });

  describe("getCurrentUser", () => {
    it("returns the verified user for a valid token", async () => {
      vi.mocked(globalThis.fetch).mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ username: "analyst" }),
      } as Response);

      const user = await getCurrentUser("some-token");

      expect(user).toEqual({ username: "analyst", displayName: "analyst" });
    });

    it("throws for an invalid or expired token", async () => {
      vi.mocked(globalThis.fetch).mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ error: "Session has expired." }),
      } as Response);

      await expect(getCurrentUser("stale-token")).rejects.toThrow("Session is invalid or expired.");
    });
  });

  describe("logout", () => {
    it("clears the stored token even if the server call fails", async () => {
      vi.mocked(globalThis.fetch).mockRejectedValueOnce(new TypeError("Failed to fetch"));

      await logout();

      expect(getToken()).toBeNull();
    });
  });
});
