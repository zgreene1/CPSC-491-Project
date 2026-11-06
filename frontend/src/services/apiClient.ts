import { getToken, invalidateSession } from "./authSession";

export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://localhost:8000";

/**
 * Shared fetch wrapper for every authenticated API call: attaches the
 * current session token (if any) as a Bearer header, and invalidates the
 * session on a 401 response so AuthContext can react (logout + redirect)
 * no matter which service triggered the call.
 */
export async function authFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const token = getToken();
  const headers = new Headers(init.headers);
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE_URL}${path}`, { ...init, headers });

  if (response.status === 401) {
    invalidateSession();
  }

  return response;
}
