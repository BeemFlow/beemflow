import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import { ProtectedRoute } from './components/auth/ProtectedRoute';
import { LoginPage } from './pages/auth/LoginPage';
import { RegisterPage } from './pages/auth/RegisterPage';
import { Layout } from './components/common/Layout';
import { Dashboard } from './components/dashboard/Dashboard';
import { FlowEditor } from './components/editor/FlowEditor';
import { ExecutionView } from './components/execution/ExecutionView';
import { OAuthProvidersList } from './components/oauth/OAuthProvidersList';
import { OAuthSuccessPage } from './components/oauth/OAuthSuccessPage';
import { SettingsLayout } from './pages/settings/SettingsLayout';
import { ProfilePage } from './pages/settings/ProfilePage';
import { OrganizationPage } from './pages/settings/OrganizationPage';
import { TeamPage } from './pages/settings/TeamPage';

// Create a client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 10, // 10 seconds
      retry: 1,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            {/* Public routes */}
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />

            {/* Protected routes */}
            <Route element={<ProtectedRoute />}>
              <Route path="/" element={<Layout />}>
                <Route index element={<Dashboard />} />
                <Route path="flows">
                  <Route index element={<Navigate to="/" replace />} />
                  <Route path="new" element={<FlowEditor />} />
                  <Route path=":name" element={<FlowEditor />} />
                </Route>
                <Route path="runs">
                  <Route index element={<Navigate to="/" replace />} />
                  <Route path=":id" element={<ExecutionView />} />
                </Route>
                <Route path="oauth">
                  <Route index element={<OAuthProvidersList />} />
                  <Route path="success" element={<OAuthSuccessPage />} />
                </Route>
                <Route path="settings" element={<SettingsLayout />}>
                  <Route index element={<Navigate to="/settings/profile" replace />} />
                  <Route path="profile" element={<ProfilePage />} />
                  <Route path="organization" element={<OrganizationPage />} />
                  <Route path="team" element={<TeamPage />} />
                </Route>
                <Route path="*" element={<Navigate to="/" replace />} />
              </Route>
            </Route>
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
