export type UserResponse = {
  id: string;
  email: string;
  email_verified: boolean;
  name: string | null;
  image: string | null;
  is_admin: boolean;
  two_factor_enabled: boolean;
  created_at: string;
};

export type SessionResponse = {
  id: string;
  token: string;
  expires_at: string;
};

export type AuthResponse = {
  user: UserResponse;
  session: SessionResponse;
  skip_2fa_setup?: boolean;
};

export type SignInResponse = Partial<AuthResponse> & {
  twoFactorRequired?: boolean;
  twoFactorToken?: string;
};

let sessionCache: { promise: Promise<AuthResponse | null>; timestamp: number } | null = null;
const SESSION_CACHE_MS = 5_000;

function responseError(body: unknown): Error {
  const error = body as {
    detail?: string;
    message?: string;
    error?: string;
    title?: string;
  };
  return new Error(error.detail || error.message || error.error || error.title || "Request failed");
}

async function authRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    credentials: "include",
    headers: init?.body
      ? { "Content-Type": "application/json", ...init.headers }
      : init?.headers,
  });
  const body: unknown = await response.json();
  if (!response.ok) throw responseError(body);
  return body as T;
}

export function clearSessionCache() {
  sessionCache = null;
}

export async function getSession(): Promise<AuthResponse | null> {
  const now = Date.now();
  if (sessionCache && now - sessionCache.timestamp < SESSION_CACHE_MS) {
    return sessionCache.promise;
  }

  const promise = authRequest<unknown>("/api/auth/get-session")
    .then((body) => {
      if (!body || typeof body !== "object" || !("user" in body)) return null;
      return body as AuthResponse;
    })
    .catch(() => null);
  sessionCache = { promise, timestamp: now };
  return promise;
}

export async function signIn(email: string, password: string): Promise<SignInResponse> {
  return authRequest<SignInResponse>("/api/auth/sign-in", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function signUp(
  email: string,
  password: string,
  name: string,
  inviteCode: string,
): Promise<AuthResponse> {
  return authRequest<AuthResponse>("/api/auth/sign-up", {
    method: "POST",
    body: JSON.stringify({ email, password, name, invite_code: inviteCode }),
  });
}

export async function signOut(): Promise<{ success: boolean }> {
  clearSessionCache();
  return authRequest<{ success: boolean }>("/api/auth/sign-out", { method: "POST" });
}
