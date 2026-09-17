import { delay } from "./delay";

export interface AuthUser {
  username: string;
  displayName: string;
}

export interface LoginResult {
  user: AuthUser;
  token: string;
}

/**
 * Mocked for Sprint 1. Sprint 2 replaces the body with a real API request
 * (e.g. POST /api/auth/login) while keeping this call signature.
 */
export async function login(username: string, password: string): Promise<LoginResult> {
  if (!username.trim() || !password.trim()) {
    throw new Error("Username and password are required.");
  }

  return delay({
    user: { username, displayName: username },
    token: "mock-token",
  });
}

export async function logout(): Promise<void> {
  return delay(undefined, 200);
}
