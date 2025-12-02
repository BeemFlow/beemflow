import { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react';
import type { ReactNode } from 'react';
import { api } from '../lib/api';
import { hasPermission as checkPermission, safeExtractRole } from '../lib/permissions';
import type { User, Organization, LoginRequest, RegisterRequest, Role, Permission } from '../types/beemflow';

interface AuthState {
  user: User | null;
  organization: Organization | null;
  /**
   * User's role in the current organization
   * Extracted from organization.role for convenience
   */
  role: Role | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  error: string | null;
}

interface AuthContextValue extends AuthState {
  login: (credentials: LoginRequest) => Promise<void>;
  register: (data: RegisterRequest) => Promise<void>;
  logout: () => Promise<void>;
  /**
   * Switch to a different organization
   * @param organizationId - ID of organization to switch to
   * @returns Promise that resolves when the switch is complete
   */
  switchOrganization: (organizationId: string) => Promise<void>;
  refreshUser: () => Promise<void>;
  clearError: () => void;
  /**
   * Check if the current user has a specific permission
   * @param permission - Permission to check
   * @returns true if user has the permission
   */
  hasPermission: (permission: Permission) => boolean;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [state, setState] = useState<AuthState>({
    user: null,
    organization: null,
    role: null,
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
          role: null,
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
        // Validate role from API response to prevent runtime errors
        // If backend returns invalid role, fall back to null (no permissions)
        role: safeExtractRole(organization.role),
        isLoading: false,
        isAuthenticated: true,
        error: null,
      });
    } catch (error) {
      // If refresh fails, user is not authenticated
      setState({
        user: null,
        organization: null,
        role: null,
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
        role: safeExtractRole(response.organization.role),
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
        role: safeExtractRole(response.organization.role),
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
        role: null,
        isLoading: false,
        isAuthenticated: false,
        error: null,
      });
    }
  }, []);

  const switchOrganization = useCallback(async (organizationId: string) => {
    // Update API client header for subsequent requests
    api.setOrganization(organizationId);

    // Refresh user data to get new organization info
    // IMPORTANT: Must await to prevent race conditions with stale role data
    await refreshUser();
  }, [refreshUser]);

  // Auto-refresh user on mount if authenticated
  useEffect(() => {
    refreshUser();
  }, [refreshUser]);

  /**
   * Memoized permission checker to avoid unnecessary recalculations
   * Only recomputes when the user's role changes
   */
  const hasPermissionMemo = useMemo(
    () => (permission: Permission) => checkPermission(state.role, permission),
    [state.role]
  );

  const value: AuthContextValue = {
    ...state,
    login,
    register,
    logout,
    switchOrganization,
    refreshUser,
    clearError,
    hasPermission: hasPermissionMemo,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
