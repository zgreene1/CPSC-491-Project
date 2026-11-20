import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { authFetch } from "./apiClient";
import { getToken, onSessionInvalidated, setToken } from "./authSession";

describe("authFetch", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    setToken(null);
    vi.unstubAllGlobals();
  });

  it("attaches the current token as a Bearer header when one is set", async () => {
    setToken("a-real-token");
    vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 200 }));

    await authFetch("/api/scans");

    const [, init] = vi.mocked(fetch).mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(headers.get("Authorization")).toBe("Bearer a-real-token");
  });

  it("sends no Authorization header when there is no token", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 200 }));

    await authFetch("/api/scans");

    const [, init] = vi.mocked(fetch).mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(headers.has("Authorization")).toBe(false);
  });

  it("invalidates the session on a 401 response", async () => {
    setToken("a-real-token");
    vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 401 }));
    const listener = vi.fn();
    onSessionInvalidated(listener);

    await authFetch("/api/scans");

    expect(listener).toHaveBeenCalledWith("Your session has expired. Please sign in again.");
    expect(getToken()).toBeNull();
  });

  it("leaves the session untouched on a non-401 error response", async () => {
    setToken("a-real-token");
    vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 500 }));
    const listener = vi.fn();
    onSessionInvalidated(listener);

    await authFetch("/api/scans");

    expect(listener).not.toHaveBeenCalled();
    expect(getToken()).toBe("a-real-token");
  });

  it("returns the response unchanged so callers keep handling status codes themselves", async () => {
    const response = new Response(JSON.stringify({ ok: true }), { status: 200 });
    vi.mocked(fetch).mockResolvedValue(response);

    const result = await authFetch("/api/scans");

    expect(result).toBe(response);
  });
});
