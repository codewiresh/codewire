/**
 * React Native auth client with secure token storage
 */
import type { AuthConfig, AuthSession } from "./index";
import { DEFAULT_AUTH_CONFIG } from "./index";

// Token storage interface - implement with expo-secure-store
export interface TokenStorage {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  deleteItem(key: string): Promise<void>;
}

const TOKEN_KEY = "codewire_auth_token";
const SESSION_KEY = "codewire_session";

export class NativeAuthClient {
  private config: AuthConfig;
  private storage: TokenStorage;

  constructor(storage: TokenStorage, config?: AuthConfig) {
    this.storage = storage;
    this.config = { ...DEFAULT_AUTH_CONFIG, ...config };
  }

  async getSession(): Promise<AuthSession | null> {
    try {
      const sessionData = await this.storage.getItem(SESSION_KEY);
      if (!sessionData) return null;
      return JSON.parse(sessionData);
    } catch {
      return null;
    }
  }

  async signIn(email: string, password: string): Promise<AuthSession> {
    const response = await fetch(`${this.config.baseURL}/api/auth/sign-in/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.message || "Sign in failed");
    }

    const data = await response.json();
    await this.storage.setItem(TOKEN_KEY, data.token);
    await this.storage.setItem(SESSION_KEY, JSON.stringify(data));
    return data;
  }

  async signUp(email: string, password: string, name?: string): Promise<AuthSession> {
    const response = await fetch(`${this.config.baseURL}/api/auth/sign-up/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, name }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.message || "Sign up failed");
    }

    const data = await response.json();
    await this.storage.setItem(TOKEN_KEY, data.token);
    await this.storage.setItem(SESSION_KEY, JSON.stringify(data));
    return data;
  }

  async signOut(): Promise<void> {
    const token = await this.storage.getItem(TOKEN_KEY);
    if (token) {
      await fetch(`${this.config.baseURL}/api/auth/sign-out`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
      }).catch(() => {});
    }
    await this.storage.deleteItem(TOKEN_KEY);
    await this.storage.deleteItem(SESSION_KEY);
  }

  async getAuthHeaders(): Promise<Record<string, string>> {
    const token = await this.storage.getItem(TOKEN_KEY);
    if (!token) return {};
    return { Authorization: `Bearer ${token}` };
  }
}

/**
 * Create a native auth client with expo-secure-store
 * Usage:
 * ```
 * import * as SecureStore from 'expo-secure-store';
 * const authClient = createNativeAuthClient({
 *   getItem: SecureStore.getItemAsync,
 *   setItem: SecureStore.setItemAsync,
 *   deleteItem: SecureStore.deleteItemAsync,
 * });
 * ```
 */
export function createNativeAuthClient(storage: TokenStorage, config?: AuthConfig) {
  return new NativeAuthClient(storage, config);
}
