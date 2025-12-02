import { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { api } from '../../lib/api';
import { Permission } from '../../types/beemflow';
import type { Role, OrganizationMember } from '../../types/beemflow';
import { getAssignableRoles, canAssignRole, getRoleLabel } from '../../lib/permissions';

export function TeamPage() {
  const { user, role, hasPermission } = useAuth();
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');

  // Invite member state
  const [showInviteForm, setShowInviteForm] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<Role>('member');
  const [isInviting, setIsInviting] = useState(false);

  // Permission checks
  const canManage = hasPermission(Permission.MembersInvite);
  const assignableRoles = getAssignableRoles(role);

  useEffect(() => {
    loadMembers();
  }, []);

  const loadMembers = async () => {
    try {
      setIsLoading(true);
      const data = await api.listMembers();
      setMembers(data);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load members');
    } finally {
      setIsLoading(false);
    }
  };

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsInviting(true);
    setError('');

    try {
      await api.inviteMember(inviteEmail, inviteRole);
      await loadMembers();
      setShowInviteForm(false);
      setInviteEmail('');
      setInviteRole('member');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to invite member');
    } finally {
      setIsInviting(false);
    }
  };

  const handleChangeRole = async (userId: string, newRole: string) => {
    // Security checks to prevent privilege escalation

    // 1. Prevent users from changing their own role
    if (userId === user?.id) {
      setError('You cannot change your own role');
      return;
    }

    // 2. Validate the new role is one the current user can assign
    if (!canAssignRole(role, newRole as Role)) {
      setError(`You do not have permission to assign the ${newRole} role`);
      return;
    }

    try {
      await api.updateMemberRole(userId, newRole);
      await loadMembers();
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update role');
    }
  };

  const handleRemove = async (userId: string) => {
    if (!confirm('Are you sure you want to remove this member?')) {
      return;
    }

    try {
      await api.removeMember(userId);
      await loadMembers();
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove member');
    }
  };

  if (isLoading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-lg font-medium text-gray-900">Team Members</h2>
          {role && (
            <p className="text-sm text-gray-500 mt-1">
              Your role: <span className="font-medium capitalize">{role}</span>
            </p>
          )}
        </div>
        {canManage && (
          <button
            onClick={() => setShowInviteForm(!showInviteForm)}
            className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
          >
            Invite Member
          </button>
        )}
      </div>

      {error && (
        <div className="rounded-md bg-red-50 p-4">
          <p className="text-sm text-red-800">{error}</p>
        </div>
      )}

      {/* Invite Form */}
      {showInviteForm && canManage && (
        <form onSubmit={handleInvite} className="bg-gray-50 p-4 rounded-md space-y-4">
          <div>
            <label htmlFor="invite-email" className="block text-sm font-medium text-gray-700">
              Email Address
            </label>
            <input
              type="email"
              id="invite-email"
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              required
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
            />
          </div>

          <div>
            <label htmlFor="invite-role" className="block text-sm font-medium text-gray-700">
              Role
            </label>
            <select
              id="invite-role"
              value={inviteRole}
              onChange={(e) => setInviteRole(e.target.value as Role)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
            >
              {assignableRoles.map((r) => (
                <option key={r} value={r}>
                  {getRoleLabel(r)}
                </option>
              ))}
            </select>
            {assignableRoles.length === 0 && (
              <p className="mt-1 text-xs text-red-500">You do not have permission to invite members</p>
            )}
          </div>

          <div className="flex space-x-2">
            <button
              type="submit"
              disabled={isInviting}
              className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50"
            >
              {isInviting ? 'Inviting...' : 'Send Invite'}
            </button>
            <button
              type="button"
              onClick={() => {
                setShowInviteForm(false);
                setInviteEmail('');
              }}
              className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* Members List */}
      <div className="bg-white overflow-hidden shadow-sm ring-1 ring-gray-200 rounded-md">
        <ul className="divide-y divide-gray-200">
          {members.map((member) => (
            <li key={member.user.id} className="px-6 py-4">
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 rounded-full bg-primary-600 flex items-center justify-center text-white font-semibold">
                      {member.user.name?.[0]?.toUpperCase() || member.user.email[0].toUpperCase()}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-900">
                        {member.user.name || member.user.email}
                        {member.user.id === user?.id && (
                          <span className="ml-2 text-xs text-gray-500">(you)</span>
                        )}
                      </p>
                      <p className="text-sm text-gray-500">{member.user.email}</p>
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-3">
                  {canManage && assignableRoles.length > 0 && member.user.id !== user?.id ? (
                    <select
                      value={member.role}
                      onChange={(e) => handleChangeRole(member.user.id, e.target.value)}
                      className="text-sm border-gray-300 rounded-md focus:ring-primary-500 focus:border-primary-500"
                    >
                      {assignableRoles.map((r) => (
                        <option key={r} value={r}>
                          {getRoleLabel(r)}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 capitalize">
                      {member.role}
                      {member.user.id === user?.id && (
                        <span className="ml-1 text-gray-500">(you)</span>
                      )}
                    </span>
                  )}

                  {canManage && member.user.id !== user?.id && member.role !== 'owner' && (
                    <button
                      onClick={() => handleRemove(member.user.id)}
                      className="text-sm text-red-600 hover:text-red-900"
                    >
                      Remove
                    </button>
                  )}
                </div>
              </div>
            </li>
          ))}
        </ul>
      </div>

      {members.length === 0 && (
        <div className="text-center py-12 text-gray-500">
          No team members yet
        </div>
      )}
    </div>
  );
}
