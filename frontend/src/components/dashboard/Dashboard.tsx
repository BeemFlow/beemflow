import { FlowsList } from './FlowsList';
import { RunsList } from './RunsList';
import { DashboardStats } from './DashboardStats';

export function Dashboard() {
  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
        <p className="mt-2 text-gray-600">
          Manage your workflows and monitor executions
        </p>
      </div>

      {/* Stats */}
      <DashboardStats />

      {/* Flows List */}
      <section>
        <h2 className="text-2xl font-semibold text-gray-900 mb-4">Flows</h2>
        <FlowsList />
      </section>

      {/* Recent Runs */}
      <section>
        <h2 className="text-2xl font-semibold text-gray-900 mb-4">Recent Runs</h2>
        <RunsList />
      </section>
    </div>
  );
}
