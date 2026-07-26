/**
 * @codewire/auth
 * Shared authentication for the Codewire platform
 */

export interface AuthConfig {
  baseURL?: string;
}

export interface AuthSession {
  user: {
    id: string;
    email: string;
    name: string | null;
    image: string | null;
    emailVerified: boolean;
  };
  session: {
    id: string;
    expiresAt: Date;
  };
}

export const DEFAULT_AUTH_CONFIG: AuthConfig = {
  baseURL: process.env.API_URL || "http://localhost:5173",
};
