/**
 * Holds the current auth token in memory and notifies subscribers when a
 * session becomes invalid (logout, or a 401 from any API call). Kept
 * separate from AuthContext so plain service functions (not just React
 * components) can trigger a logout — e.g. apiClient.ts on a 401 response.
 */

type Listener = () => void;

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

export function invalidateSession(): void {
  currentToken = null;
  listeners.forEach((listener) => listener());
}
