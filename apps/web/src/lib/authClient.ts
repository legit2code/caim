/**
 * Enterprise Client-side Authentication & Token Management Service
 * Manages JWT Access Tokens, Refresh Tokens, automatic silent refresh, and authenticatedFetch wrapper.
 */

export interface AuthenticatedUser {
  principal_id: string;
  email: string;
  roles: string[];
  tenant_id?: string | null;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: 'Bearer';
  expires_in: number;
  principal: AuthenticatedUser;
}

const ACCESS_TOKEN_KEY = 'caim_access_token';
const REFRESH_TOKEN_KEY = 'caim_refresh_token';
const USER_KEY = 'caim_user_profile';
const TOKEN_EXPIRY_TIME_KEY = 'caim_access_token_expires_at';

class AuthClient {
  private refreshPromise: Promise<string | null> | null = null;
  private authStateListeners: Array<(user: AuthenticatedUser | null) => void> = [];

  public getAccessToken(): string | null {
    return localStorage.getItem(ACCESS_TOKEN_KEY);
  }

  public getRefreshToken(): string | null {
    return localStorage.getItem(REFRESH_TOKEN_KEY);
  }

  public getUser(): AuthenticatedUser | null {
    const raw = localStorage.getItem(USER_KEY);
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  public isAuthenticated(): boolean {
    return Boolean(this.getAccessToken() && this.getUser());
  }

  public subscribe(listener: (user: AuthenticatedUser | null) => void): () => void {
    this.authStateListeners.push(listener);
    return () => {
      this.authStateListeners = this.authStateListeners.filter(l => l !== listener);
    };
  }

  private notify(user: AuthenticatedUser | null) {
    for (const listener of this.authStateListeners) {
      try {
        listener(user);
      } catch (err) {
        console.error('[AuthClient] Listener error:', err);
      }
    }
  }

  public saveSession(response: LoginResponse): void {
    const expiresAt = Date.now() + (response.expires_in || 900) * 1000;
    localStorage.setItem(ACCESS_TOKEN_KEY, response.access_token);
    localStorage.setItem(REFRESH_TOKEN_KEY, response.refresh_token);
    localStorage.setItem(USER_KEY, JSON.stringify(response.principal));
    localStorage.setItem(TOKEN_EXPIRY_TIME_KEY, expiresAt.toString());
    this.notify(response.principal);
  }

  public clearSession(): void {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    localStorage.removeItem(TOKEN_EXPIRY_TIME_KEY);
    this.notify(null);
  }

  public isTokenExpiringSoon(): boolean {
    const expiresAtStr = localStorage.getItem(TOKEN_EXPIRY_TIME_KEY);
    if (!expiresAtStr) return true;
    const expiresAt = parseInt(expiresAtStr, 10);
    // If less than 60 seconds remaining
    return Date.now() >= expiresAt - 60000;
  }

  /**
   * Performs real login with email & password against POST /api/auth/login
   */
  public async login(email: string, password: string): Promise<LoginResponse> {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email: email.trim(), password }),
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `Authentication failed with HTTP ${res.status}`);
    }

    const data: LoginResponse = await res.json();
    this.saveSession(data);
    return data;
  }

  /**
   * Performs silent refresh via POST /api/auth/refresh
   */
  public async refreshAccessToken(): Promise<string | null> {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    const refreshToken = this.getRefreshToken();
    if (!refreshToken) {
      this.clearSession();
      return null;
    }

    this.refreshPromise = (async () => {
      try {
        const res = await fetch('/api/auth/refresh', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ refresh_token: refreshToken }),
        });

        if (!res.ok) {
          this.clearSession();
          return null;
        }

        const data: LoginResponse = await res.json();
        this.saveSession(data);
        return data.access_token;
      } catch (err) {
        console.warn('[AuthClient] Silent refresh failed:', err);
        this.clearSession();
        return null;
      } finally {
        this.refreshPromise = null;
      }
    })();

    return this.refreshPromise;
  }

  /**
   * Performs logout
   */
  public async logout(): Promise<void> {
    const refreshToken = this.getRefreshToken();
    if (refreshToken) {
      try {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: refreshToken }),
        });
      } catch {
        // Ignore network errors during logout
      }
    }
    this.clearSession();
  }

  /**
   * Universal authenticated fetch wrapper that attaches Authorization: Bearer <token>
   * and automatically refreshes tokens if expired or on 401 response.
   */
  public async fetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
    let token = this.getAccessToken();

    // Check if token is near expiration and refresh proactively
    if (token && this.isTokenExpiringSoon()) {
      const refreshedToken = await this.refreshAccessToken();
      if (refreshedToken) {
        token = refreshedToken;
      }
    }

    const headers = new Headers(init.headers || {});
    // Ensure x-bypass-auth is never sent
    headers.delete('x-bypass-auth');
    headers.delete('X-Bypass-Auth');

    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    const modifiedInit: RequestInit = {
      ...init,
      headers,
    };

    let response = await fetch(input, modifiedInit);

    // If 401 Unauthorized, attempt one silent refresh and retry
    if (response.status === 401 && this.getRefreshToken()) {
      const newToken = await this.refreshAccessToken();
      if (newToken) {
        headers.set('Authorization', `Bearer ${newToken}`);
        response = await fetch(input, {
          ...init,
          headers,
        });
      }
    }

    return response;
  }

  /**
   * Performs authenticated password rotation via POST /api/auth/change-password.
   */
  public async changePassword(currentPassword: string, newPassword: string): Promise<{ success: boolean; message: string }> {
    const res = await this.fetch('/api/auth/change-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error || `Password change failed with HTTP ${res.status}`);
    }

    return data;
  }
}

export const authClient = new AuthClient();
export const authenticatedFetch = authClient.fetch.bind(authClient);
