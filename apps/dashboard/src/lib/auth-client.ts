// Go auth API client — replaces Better Auth
const API_BASE = "/api/auth";

interface AuthResult<T = any> {
  data?: T;
  error?: { message: string; status: number };
}

async function authFetch<T>(path: string, options?: RequestInit): Promise<AuthResult<T>> {
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      ...options,
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...options?.headers,
      },
    });

    if (res.status === 429) {
      const retryAfter = res.headers.get("retry-after");
      const message = retryAfter
        ? `Too many requests. Please try again in ${retryAfter} seconds.`
        : "Too many requests. Please try again later.";
      return { error: { message, status: 429 } };
    }

    const text = await res.text();
    let data: any;
    try {
      data = JSON.parse(text);
    } catch {
      return { error: { message: "Invalid server response", status: res.status } };
    }

    if (!res.ok) {
      return { error: { message: data.message || data.error || "Request failed", status: res.status } };
    }

    return { data };
  } catch (err) {
    return { error: { message: err instanceof Error ? err.message : "Network error", status: 0 } };
  }
}

export const authClient = {
  signIn: {
    email: ({ email, password }: { email: string; password: string }) =>
      authFetch("/sign-in", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      }),
  },
  signUp: {
    email: ({ email, password, name }: { email: string; password: string; name: string }) =>
      authFetch("/sign-up", {
        method: "POST",
        body: JSON.stringify({ email, password, name }),
      }),
  },
  sendVerificationEmail: ({ email }: { email: string; callbackURL?: string }) =>
    authFetch("/send-verification-email", {
      method: "POST",
      body: JSON.stringify({ email }),
    }),
  requestPasswordReset: ({ email, redirectTo }: { email: string; redirectTo?: string }) =>
    authFetch("/forget-password", {
      method: "POST",
      body: JSON.stringify({ email, redirectTo }),
    }),
  resetPassword: ({ newPassword, token }: { newPassword: string; token: string }) =>
    authFetch("/reset-password", {
      method: "POST",
      body: JSON.stringify({ newPassword, token }),
    }),
  twoFactor: {
    enable: () => authFetch("/two-factor/enable", { method: "POST" }),
    verify: ({ code }: { code: string }) =>
      authFetch("/two-factor/verify", { method: "POST", body: JSON.stringify({ code }) }),
    validate: ({ code, token }: { code: string; token: string }) =>
      authFetch("/two-factor/validate", { method: "POST", body: JSON.stringify({ code, token }) }),
    disable: () => authFetch("/two-factor/disable", { method: "POST" }),
  },
  listSessions: () => authFetch("/list-sessions", { method: "GET" }),
  revokeSession: ({ token }: { token: string }) =>
    authFetch("/revoke-session", {
      method: "POST",
      body: JSON.stringify({ token }),
    }),
  changePassword: ({ currentPassword, newPassword }: { currentPassword: string; newPassword: string }) =>
    authFetch("/change-password", {
      method: "POST",
      body: JSON.stringify({ currentPassword, newPassword }),
    }),
  deleteAccount: () => authFetch("/delete-account", { method: "POST" }),
  updateUser: ({ name, image }: { name?: string; image?: string }) =>
    authFetch("/update-user", {
      method: "POST",
      body: JSON.stringify({ name, image }),
    }),
};

export async function signOut() {
  await fetch(`${API_BASE}/sign-out`, { method: "POST", credentials: "include" });
}

// useSession is not needed on client - session is loaded server-side in beforeLoad
// Export a stub that returns null to avoid breaking imports during transition
export function useSession() {
  return { data: null, isPending: false };
}

export const signIn = authClient.signIn;
export const signUp = authClient.signUp;
