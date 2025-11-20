import { useState } from 'react';
import type { FormEvent } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { api } from '../../lib/api';

export function OrganizationPage() {
  const { organization, refreshUser } = useAuth();
  const [isEditing, setIsEditing] = useState(false);
  const [name, setName] = useState(organization?.name || '');
  const [slug, setSlug] = useState(organization?.slug || '');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setIsEditing(true);

    try {
      await api.updateOrganization({ name, slug });
      await refreshUser();
      setSuccess('Organization updated successfully');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update organization');
    } finally {
      setIsEditing(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-medium text-gray-900 mb-4">Organization Details</h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          {error && (
            <div className="rounded-md bg-red-50 p-4">
              <p className="text-sm text-red-800">{error}</p>
            </div>
          )}
          {success && (
            <div className="rounded-md bg-green-50 p-4">
              <p className="text-sm text-green-800">{success}</p>
            </div>
          )}

          <div>
            <label htmlFor="org-name" className="block text-sm font-medium text-gray-700">
              Organization Name
            </label>
            <input
              type="text"
              id="org-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
            />
          </div>

          <div>
            <label htmlFor="org-slug" className="block text-sm font-medium text-gray-700">
              Organization Slug
            </label>
            <input
              type="text"
              id="org-slug"
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              required
              pattern="[a-z0-9-]+"
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
            />
            <p className="mt-1 text-xs text-gray-500">Lowercase letters, numbers, and hyphens only</p>
          </div>

          <div>
            <button
              type="submit"
              disabled={isEditing}
              className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50"
            >
              {isEditing ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </form>
      </div>

      {/* Organization Info */}
      <div className="pt-6 border-t border-gray-200">
        <h3 className="text-sm font-medium text-gray-900 mb-4">Plan & Limits</h3>
        <dl className="space-y-3">
          <div className="flex justify-between">
            <dt className="text-sm text-gray-600">Plan</dt>
            <dd className="text-sm font-medium text-gray-900 capitalize">{organization?.plan}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-sm text-gray-600">Max Users</dt>
            <dd className="text-sm font-medium text-gray-900">{organization?.max_users}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-sm text-gray-600">Max Flows</dt>
            <dd className="text-sm font-medium text-gray-900">{organization?.max_flows}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-sm text-gray-600">Max Runs per Month</dt>
            <dd className="text-sm font-medium text-gray-900">{organization?.max_runs_per_month.toLocaleString()}</dd>
          </div>
        </dl>
      </div>
    </div>
  );
}
