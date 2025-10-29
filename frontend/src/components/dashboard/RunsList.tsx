import { Link } from 'react-router-dom';
import { useRuns } from '../../hooks/useRuns';
import { formatDistanceToNow } from 'date-fns';

export function RunsList() {
  const { data, isLoading, error } = useRuns({ limit: 10 });

  if (isLoading) {
    return (
      <div className="bg-white rounded-lg shadow">
        <div className="p-6 space-y-4">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="animate-pulse">
              <div className="h-4 bg-gray-200 rounded w-1/4 mb-2"></div>
              <div className="h-3 bg-gray-200 rounded w-1/2"></div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-4">
        <p className="text-red-800">Failed to load runs: {String(error)}</p>
      </div>
    );
  }

  const runs = data?.runs || [];

  if (runs.length === 0) {
    return (
      <div className="bg-white rounded-lg shadow p-8 text-center">
        <div className="text-6xl mb-4">🏃</div>
        <h3 className="text-lg font-semibold text-gray-900 mb-2">No runs yet</h3>
        <p className="text-gray-600">
          Execution history will appear here once you run a flow
        </p>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow overflow-hidden">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Run ID
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Flow
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Status
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Started
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Duration
            </th>
            <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
              Actions
            </th>
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200">
          {runs.map((run) => (
            <tr key={run.id} className="hover:bg-gray-50">
              <td className="px-6 py-4 whitespace-nowrap">
                <Link
                  to={`/runs/${run.id}`}
                  className="text-sm font-mono text-primary-600 hover:text-primary-800"
                >
                  {run.id.substring(0, 8)}...
                </Link>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <Link
                  to={`/flows/${run.flow_name}`}
                  className="text-sm text-gray-900 hover:text-primary-600"
                >
                  {run.flow_name}
                </Link>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <StatusBadge status={run.status} />
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                {formatDistanceToNow(new Date(run.started_at), {
                  addSuffix: true,
                })}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                {run.duration_ms
                  ? `${(run.duration_ms / 1000).toFixed(2)}s`
                  : run.status === 'running'
                  ? '⏱️ Running...'
                  : '-'}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                <Link
                  to={`/runs/${run.id}`}
                  className="text-primary-600 hover:text-primary-900"
                >
                  View →
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  // Normalize status to lowercase for consistent styling
  const normalizedStatus = status.toLowerCase();

  const styles = {
    completed: 'bg-green-100 text-green-800',
    succeeded: 'bg-green-100 text-green-800',
    failed: 'bg-red-100 text-red-800',
    running: 'bg-blue-100 text-blue-800 animate-pulse',
    awaiting_event: 'bg-yellow-100 text-yellow-800',
    pending: 'bg-gray-100 text-gray-800',
    cancelled: 'bg-gray-100 text-gray-800',
  };

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
        styles[normalizedStatus as keyof typeof styles] || styles.pending
      }`}
    >
      {status}
    </span>
  );
}
