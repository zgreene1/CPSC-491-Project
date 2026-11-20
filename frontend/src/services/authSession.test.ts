import { afterEach, describe, expect, it, vi } from "vitest";
import { getToken, invalidateSession, onSessionInvalidated, setToken } from "./authSession";

describe("authSession", () => {
  afterEach(() => {
    setToken(null);
  });

  it("round-trips a token through setToken/getToken", () => {
    expect(getToken()).toBeNull();
    setToken("a-real-token");
    expect(getToken()).toBe("a-real-token");
  });

  it("notifies every subscriber with the given reason when invalidated", () => {
    setToken("a-real-token");
    const first = vi.fn();
    const second = vi.fn();
    onSessionInvalidated(first);
    onSessionInvalidated(second);

    invalidateSession("Your session has expired. Please sign in again.");

    expect(first).toHaveBeenCalledWith("Your session has expired. Please sign in again.");
    expect(second).toHaveBeenCalledWith("Your session has expired. Please sign in again.");
    expect(getToken()).toBeNull();
  });

  it("notifies subscribers with no reason for an explicit logout", () => {
    const listener = vi.fn();
    onSessionInvalidated(listener);

    invalidateSession();

    expect(listener).toHaveBeenCalledWith(undefined);
  });

  it("stops notifying a listener once it unsubscribes", () => {
    const listener = vi.fn();
    const unsubscribe = onSessionInvalidated(listener);
    unsubscribe();

    invalidateSession("Session expired.");

    expect(listener).not.toHaveBeenCalled();
  });
});
