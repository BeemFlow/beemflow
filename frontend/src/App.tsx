import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/common/Layout';
import { Dashboard } from './components/dashboard/Dashboard';
import { FlowEditor } from './components/editor/FlowEditor';
import { ExecutionView } from './components/execution/ExecutionView';

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
      <BrowserRouter>
        <Routes>
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
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
