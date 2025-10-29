import { Link } from 'react-router-dom';
import { useFlows, useDeleteFlow, useDeployFlow } from '../../hooks/useFlows';
import { useStartRun } from '../../hooks/useRuns';
import { formatDistanceToNow } from 'date-fns';

export function FlowsList() {
  const { data: flows, isLoading, error } = useFlows();
  const deleteFlow = useDeleteFlow();
  const deployFlow = useDeployFlow();
  const startRun = useStartRun();

  const handleDelete = async (name: string, e: React.MouseEvent) => {
    e.preventDefault();
    if (confirm(`Are you sure you want to delete flow "${name}"?`)) {
      try {
        await deleteFlow.mutateAsync(name);
      } catch (error) {
        alert(`Failed to delete flow: ${error}`);
      }
    }
  };

  const handleDeploy = async (name: string, e: React.MouseEvent) => {
    e.preventDefault();
    try {
      await deployFlow.mutateAsync(name);
      alert(`Flow "${name}" deployed successfully!`);
    } catch (error) {
      alert(`Failed to deploy flow: ${error}`);
    }
  };

  const handleRun = async (name: string, e: React.MouseEvent) => {
    e.preventDefault();
    try {
      const result = await startRun.mutateAsync({ flow_name: name });
      alert(`Run started: ${result.run_id}`);
    } catch (error) {
      alert(`Failed to start run: ${error}`);
    }
  };

  if (isLoading) {
    return (
      <div className="bg-white rounded-lg shadow">
        <div className="p-6 space-y-4">
          {[...Array(3)].map((_, i) => (
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
        <p className="text-red-800">Failed to load flows: {String(error)}</p>
      </div>
    );
  }

  if (!flows || flows.length === 0) {
    return (
      <div className="bg-white rounded-lg shadow p-8 text-center">
        <div className="text-6xl mb-4">📋</div>
        <h3 className="text-lg font-semibold text-gray-900 mb-2">No flows yet</h3>
        <p className="text-gray-600 mb-4">
          Create your first workflow to get started
        </p>
        <Link
          to="/flows/new"
          className="inline-block px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
        >
          Create Flow
        </Link>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow overflow-hidden">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Name
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Description
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Version
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Last Run
            </th>
            <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
              Actions
            </th>
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200">
          {flows.map((flow) => (
            <tr key={flow.name} className="hover:bg-gray-50">
              <td className="px-6 py-4 whitespace-nowrap">
                <Link
                  to={`/flows/${flow.name}`}
                  className="text-sm font-medium text-primary-600 hover:text-primary-800"
                >
                  {flow.name}
                </Link>
              </td>
              <td className="px-6 py-4">
                <div className="text-sm text-gray-900 max-w-md truncate">
                  {flow.description || '-'}
                </div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <span className="text-sm text-gray-600">{flow.version || '-'}</span>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                {flow.last_run ? (
                  <div className="flex items-center space-x-2">
                    <StatusBadge status={flow.last_run.status} />
                    <span className="text-xs text-gray-500">
                      {formatDistanceToNow(new Date(flow.last_run.timestamp), {
                        addSuffix: true,
                      })}
                    </span>
                  </div>
                ) : (
                  <span className="text-sm text-gray-400">Never run</span>
                )}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                <div className="flex items-center justify-end space-x-2">
                  <button
                    onClick={(e) => handleRun(flow.name, e)}
                    className="text-green-600 hover:text-green-900"
                    title="Run"
                  >
                    ▶️
                  </button>
                  <Link
                    to={`/flows/${flow.name}`}
                    className="text-primary-600 hover:text-primary-900"
                    title="Edit"
                  >
                    ✏️
                  </Link>
                  <button
                    onClick={(e) => handleDeploy(flow.name, e)}
                    className="text-blue-600 hover:text-blue-900"
                    title="Deploy"
                  >
                    🚀
                  </button>
                  <button
                    onClick={(e) => handleDelete(flow.name, e)}
                    className="text-red-600 hover:text-red-900"
                    title="Delete"
                  >
                    🗑️
                  </button>
                </div>
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
    running: 'bg-blue-100 text-blue-800',
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
