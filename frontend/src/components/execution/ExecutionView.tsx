import { useParams } from 'react-router-dom';
import { useRun } from '../../hooks/useRuns';
import { formatDistanceToNow } from 'date-fns';

export function ExecutionView() {
  const { id } = useParams<{ id: string }>();
  const { data: run, isLoading, error } = useRun(id, { refetchInterval: 2000 });

  if (isLoading) {
    return (
      <div className="bg-white rounded-lg shadow p-8">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-gray-200 rounded w-1/3"></div>
          <div className="h-4 bg-gray-200 rounded w-1/2"></div>
          <div className="h-32 bg-gray-200 rounded"></div>
        </div>
      </div>
    );
  }

  if (error || !run) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-8">
        <h2 className="text-xl font-semibold text-red-800 mb-2">Run not found</h2>
        <p className="text-red-700">Failed to load run: {String(error)}</p>
      </div>
    );
  }

  const duration = run.completed_at
    ? new Date(run.completed_at).getTime() - new Date(run.started_at).getTime()
    : Date.now() - new Date(run.started_at).getTime();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center justify-between mb-4">
          <h1 className="text-2xl font-bold text-gray-900">Run Details</h1>
          <StatusBadge status={run.status} />
        </div>

        <dl className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <dt className="text-sm font-medium text-gray-500">Run ID</dt>
            <dd className="mt-1 text-sm font-mono text-gray-900">{run.id}</dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500">Flow</dt>
            <dd className="mt-1 text-sm text-gray-900">{run.flow_name}</dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500">Started</dt>
            <dd className="mt-1 text-sm text-gray-900">
              {formatDistanceToNow(new Date(run.started_at), { addSuffix: true })}
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500">Duration</dt>
            <dd className="mt-1 text-sm text-gray-900">
              {(duration / 1000).toFixed(2)}s
            </dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500">Current Step</dt>
            <dd className="mt-1 text-sm text-gray-900">{run.current_step || '-'}</dd>
          </div>
          {run.resume_token && (
            <div>
              <dt className="text-sm font-medium text-gray-500">Resume Token</dt>
              <dd className="mt-1 text-sm font-mono text-gray-900">
                {run.resume_token}
              </dd>
            </div>
          )}
        </dl>

        {run.error && (
          <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg">
            <h3 className="text-sm font-semibold text-red-800 mb-2">Error</h3>
            <pre className="text-xs text-red-700 whitespace-pre-wrap">
              {run.error}
            </pre>
          </div>
        )}
      </div>

      {/* Step Outputs */}
      {run.step_outputs && Object.keys(run.step_outputs).length > 0 && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Step Outputs</h2>
          <div className="space-y-4">
            {Object.entries(run.step_outputs).map(([stepId, output]) => (
              <div key={stepId} className="border border-gray-200 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-700 mb-2">{stepId}</h3>
                <pre className="text-xs bg-gray-50 p-3 rounded overflow-x-auto">
                  {JSON.stringify(output, null, 2)}
                </pre>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Context & Vars */}
      {(run.vars || run.context) && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Context</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {run.vars && (
              <div>
                <h3 className="text-sm font-semibold text-gray-700 mb-2">Variables</h3>
                <pre className="text-xs bg-gray-50 p-3 rounded overflow-x-auto">
                  {JSON.stringify(run.vars, null, 2)}
                </pre>
              </div>
            )}
            {run.context && (
              <div>
                <h3 className="text-sm font-semibold text-gray-700 mb-2">Context</h3>
                <pre className="text-xs bg-gray-50 p-3 rounded overflow-x-auto">
                  {JSON.stringify(run.context, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      <p className="text-sm text-gray-500 text-center">
        Visual execution view with flow graph will be added in Phase 4.
      </p>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const styles = {
    completed: 'bg-green-100 text-green-800',
    failed: 'bg-red-100 text-red-800',
    running: 'bg-blue-100 text-blue-800 animate-pulse',
    awaiting_event: 'bg-yellow-100 text-yellow-800',
    pending: 'bg-gray-100 text-gray-800',
    cancelled: 'bg-gray-100 text-gray-800',
  };

  return (
    <span
      className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${
        styles[status as keyof typeof styles] || styles.pending
      }`}
    >
      {status}
    </span>
  );
}
