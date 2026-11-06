import { API_BASE_URL, authFetch } from "./apiClient";
import { setToken } from "./authSession";

export interface AuthUser {
  username: string;
  displayName: string;
}

export interface LoginResult {
  user: AuthUser;
  token: string;
}

async function parseErrorMessage(response: Response): Promise<string> {
  try {
    const data = await response.json();
    return data?.error ?? "Invalid username or password.";
  } catch {
    return "Invalid username or password.";
  }
}

/**
 * Real request to POST /api/auth/login (see Backend/auth.py). Uses plain
 * fetch rather than authFetch — there's no session token yet to attach, and
 * a 401 here means "wrong credentials," not "an existing session expired,"
 * so it shouldn't trigger authFetch's invalidate-session side effect.
 */
export async function login(username: string, password: string): Promise<LoginResult> {
  if (!username.trim() || !password.trim()) {
    throw new Error("Username and password are required.");
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
  } catch {
    throw new Error("Could not reach the authentication service. Confirm the backend is running.");
  }

  if (!response.ok) {
    throw new Error(await parseErrorMessage(response));
  }

  const data = await response.json();
  setToken(data.token as string);
  return { user: { username: data.username, displayName: data.username }, token: data.token };
}

/**
 * Best-effort: the local token is always cleared, even if the server-side
 * blocklist call fails (e.g. the backend is unreachable), since the user's
 * intent to sign out should never be blocked by a network error.
 */
export async function logout(): Promise<void> {
  try {
    await authFetch("/api/auth/logout", { method: "POST" });
  } catch {
    // Local token clearing below still happens regardless.
  } finally {
    setToken(null);
  }
}

/**
 * Verifies a previously stored token against GET /api/auth/me. Used on app
 * mount so a restored session is never trusted without server confirmation.
 */
export async function getCurrentUser(token: string): Promise<AuthUser> {
  setToken(token);
  const response = await authFetch("/api/auth/me");
  if (!response.ok) {
    throw new Error("Session is invalid or expired.");
  }
  const data = await response.json();
  return { username: data.username, displayName: data.username };
}
