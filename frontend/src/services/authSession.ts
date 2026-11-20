/**
 * Holds the current auth token in memory and notifies subscribers when a
 * session becomes invalid (logout, or a 401 from any API call). Kept
 * separate from AuthContext so plain service functions (not just React
 * components) can trigger a logout — e.g. apiClient.ts on a 401 response.
 */

type Listener = (reason?: string) => void;

let currentToken: string | null = null;
const listeners = new Set<Listener>();

export function getToken(): string | null {
  return currentToken;
}

export function setToken(token: string | null): void {
  currentToken = token;
}

export function onSessionInvalidated(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/**
 * Clears the token and notifies subscribers. `reason` is omitted for an
 * explicit, user-initiated logout (nothing to explain), and set for any
 * unexpected invalidation — an expired/tampered token, a 401 mid-session,
 * or a stored token that failed server verification — so the UI can tell
 * the user why they landed back on the login page instead of redirecting
 * in silence.
 */
export function invalidateSession(reason?: string): void {
  currentToken = null;
  listeners.forEach((listener) => listener(reason));
}
