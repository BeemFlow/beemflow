import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type { ReactNode } from 'react';
import { api } from '../lib/api';
import type { User, Organization, LoginRequest, RegisterRequest } from '../types/beemflow';

interface AuthState {
  user: User | null;
  organization: Organization | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  error: string | null;
}

interface AuthContextValue extends AuthState {
  login: (credentials: LoginRequest) => Promise<void>;
  register: (data: RegisterRequest) => Promise<void>;
  logout: () => Promise<void>;
  switchOrganization: (organizationId: string) => void;
  refreshUser: () => Promise<void>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [state, setState] = useState<AuthState>({
    user: null,
    organization: null,
    isLoading: true,
    isAuthenticated: false,
    error: null,
  });

  const clearError = useCallback(() => {
    setState((prev) => ({ ...prev, error: null }));
  }, []);

  const refreshUser = useCallback(async () => {
    try {
      if (!api.isAuthenticated()) {
        setState({
          user: null,
          organization: null,
          isLoading: false,
          isAuthenticated: false,
          error: null,
        });
        return;
      }

      const [user, organization] = await Promise.all([
        api.getCurrentUser(),
        api.getCurrentOrganization(),
      ]);

      setState({
        user,
        organization,
        isLoading: false,
        isAuthenticated: true,
        error: null,
      });
    } catch (error) {
      // If refresh fails, user is not authenticated
      setState({
        user: null,
        organization: null,
        isLoading: false,
        isAuthenticated: false,
        error: error instanceof Error ? error.message : 'Failed to refresh user',
      });
    }
  }, []);

  const login = useCallback(async (credentials: LoginRequest) => {
    try {
      setState((prev) => ({ ...prev, isLoading: true, error: null }));
      const response = await api.login(credentials);

      setState({
        user: response.user,
        organization: response.organization,
        isLoading: false,
        isAuthenticated: true,
        error: null,
      });
    } catch (error) {
      setState((prev) => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error ? error.message : 'Login failed',
      }));
      throw error;
    }
  }, []);

  const register = useCallback(async (data: RegisterRequest) => {
    try {
      setState((prev) => ({ ...prev, isLoading: true, error: null }));
      const response = await api.register(data);

      setState({
        user: response.user,
        organization: response.organization,
        isLoading: false,
        isAuthenticated: true,
        error: null,
      });
    } catch (error) {
      setState((prev) => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error ? error.message : 'Registration failed',
      }));
      throw error;
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setState({
        user: null,
        organization: null,
        isLoading: false,
        isAuthenticated: false,
        error: null,
      });
    }
  }, []);

  const switchOrganization = useCallback((organizationId: string) => {
    // Update API client header (no server call needed!)
    api.setOrganization(organizationId);

    // Refresh user data to get new organization info
    refreshUser();
  }, [refreshUser]);

  // Auto-refresh user on mount if authenticated
  useEffect(() => {
    refreshUser();
  }, [refreshUser]);

  const value: AuthContextValue = {
    ...state,
    login,
    register,
    logout,
    switchOrganization,
    refreshUser,
    clearError,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
