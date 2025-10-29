import { useDashboardStats } from '../../hooks/useDashboard';

export function DashboardStats() {
  const { data: stats, isLoading, error } = useDashboardStats();

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="bg-white rounded-lg shadow p-6 animate-pulse">
            <div className="h-4 bg-gray-200 rounded w-1/2 mb-2"></div>
            <div className="h-8 bg-gray-200 rounded w-3/4"></div>
          </div>
        ))}
      </div>
    );
  }

  if (error) {
    return null; // Silently fail for stats
  }

  const statCards = [
    {
      label: 'Total Flows',
      value: stats?.total_flows ?? 0,
      icon: '📋',
      color: 'text-blue-600',
    },
    {
      label: 'Active Runs',
      value: stats?.active_runs ?? 0,
      icon: '▶️',
      color: 'text-green-600',
    },
    {
      label: 'Awaiting Events',
      value: stats?.awaiting_events ?? 0,
      icon: '⏸️',
      color: 'text-yellow-600',
    },
    {
      label: 'Success Rate',
      value: `${((stats?.success_rate ?? 0) * 100).toFixed(1)}%`,
      icon: '📊',
      color: 'text-purple-600',
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
      {statCards.map((stat) => (
        <div key={stat.label} className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 font-medium">{stat.label}</p>
              <p className={`text-3xl font-bold ${stat.color} mt-2`}>
                {stat.value}
              </p>
            </div>
            <div className="text-4xl">{stat.icon}</div>
          </div>
        </div>
      ))}
    </div>
  );
}
