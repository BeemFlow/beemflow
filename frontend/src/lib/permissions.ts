/**
 * RBAC (Role-Based Access Control) Permission Utilities
 *
 * This module implements the permission checking logic that matches
 * the backend implementation in src/auth/mod.rs:84-162
 *
 * Permission model:
 * - Owner: Full control over organization (all permissions)
 * - Admin: Nearly full control (all permissions except OrgDelete)
 * - Member: Can create/edit flows, trigger runs, read members
 * - Viewer: Read-only access to flows, runs, members, tools
 *
 * @module permissions
 */

import type { Role, Permission } from '../types/beemflow';
import { Permission as PermissionValues } from '../types/beemflow';

/**
 * Member permissions - allowed actions for users with 'member' role
 * Matches backend logic from src/auth/mod.rs:107-118
 */
const MEMBER_PERMISSIONS: ReadonlySet<Permission> = new Set([
  PermissionValues.FlowsRead,
  PermissionValues.FlowsCreate,
  PermissionValues.FlowsUpdate,
  PermissionValues.RunsRead,
  PermissionValues.RunsTrigger,
  PermissionValues.RunsCancel,
  PermissionValues.OAuthConnect,
  PermissionValues.MembersRead,
  PermissionValues.ToolsRead,
] as const);

/**
 * Viewer permissions - read-only access
 * Matches backend logic from src/auth/mod.rs:121
 */
const VIEWER_PERMISSIONS: ReadonlySet<Permission> = new Set([
  PermissionValues.FlowsRead,
  PermissionValues.RunsRead,
  PermissionValues.MembersRead,
  PermissionValues.ToolsRead,
] as const);

/**
 * Check if a role has a specific permission
 *
 * This function implements the exact same logic as the backend
 * Role::has_permission method from src/auth/mod.rs:96-123
 *
 * @param role - User's role in the organization (undefined for unauthenticated)
 * @param permission - Permission to check
 * @returns true if the role has the permission, false otherwise
 *
 * @example
 * ```ts
 * hasPermission('owner', Permission.FlowsCreate) // true
 * hasPermission('viewer', Permission.FlowsCreate) // false
 * hasPermission('member', Permission.FlowsDeploy) // false
 * hasPermission(undefined, Permission.FlowsRead) // false
 * ```
 */
export function hasPermission(
  role: Role | undefined | null,
  permission: Permission
): boolean {
  // Unauthenticated users have no permissions
  if (!role) {
    return false;
  }

  // Switch statement provides exhaustiveness checking without weird patterns
  switch (role) {
    case 'owner':
      // Owner has all permissions
      return true;

    case 'admin':
      // Admin has all permissions except OrgDelete
      return permission !== PermissionValues.OrgDelete;

    case 'member':
      // Member has limited permissions
      return MEMBER_PERMISSIONS.has(permission);

    case 'viewer':
      // Viewer has read-only permissions
      return VIEWER_PERMISSIONS.has(permission);

    default:
      // TypeScript will error here if we add a new role and forget to handle it
      // This is exhaustiveness checking without the `never` pattern
      return false;
  }
}

/**
 * Get all permissions granted to a specific role
 *
 * Useful for debugging, permission audits, and UI displays
 * Matches backend logic from src/auth/mod.rs:126-162
 *
 * @param role - User's role in the organization
 * @returns Array of permissions granted to this role
 *
 * @example
 * ```ts
 * getRolePermissions('member')
 * // Returns: [Permission.FlowsRead, Permission.FlowsCreate, ...]
 * ```
 */
export function getRolePermissions(role: Role | undefined | null): ReadonlyArray<Permission> {
  if (!role) {
    return [];
  }

  // Get all possible permissions
  const allPermissions = Object.values(PermissionValues);

  // Filter to only permissions this role has
  return allPermissions.filter((permission) => hasPermission(role, permission));
}

/**
 * Get list of roles that the current user can assign to other users
 *
 * Permission rules:
 * - Owner: Can assign any role (owner, admin, member, viewer)
 * - Admin: Can assign admin, member, viewer (but NOT owner)
 * - Member: Cannot assign any roles
 * - Viewer: Cannot assign any roles
 *
 * @param currentUserRole - Role of the user performing the assignment
 * @returns Array of roles that can be assigned
 *
 * @example
 * ```ts
 * getAssignableRoles('owner') // ['owner', 'admin', 'member', 'viewer']
 * getAssignableRoles('admin') // ['admin', 'member', 'viewer']
 * getAssignableRoles('member') // []
 * ```
 */
export function getAssignableRoles(
  currentUserRole: Role | undefined | null
): ReadonlyArray<Role> {
  if (!currentUserRole) {
    return [];
  }

  if (currentUserRole === 'owner') {
    return ['owner', 'admin', 'member', 'viewer'] as const;
  }

  if (currentUserRole === 'admin') {
    // Admins cannot assign owner role (prevents privilege escalation)
    return ['admin', 'member', 'viewer'] as const;
  }

  // Members and viewers cannot assign roles
  return [];
}

/**
 * Check if a role can be assigned by the current user
 *
 * Convenience function for validating role assignments
 *
 * @param currentUserRole - Role of the user performing the assignment
 * @param targetRole - Role being assigned
 * @returns true if the current user can assign the target role
 *
 * @example
 * ```ts
 * canAssignRole('admin', 'owner') // false (privilege escalation prevented)
 * canAssignRole('owner', 'admin') // true
 * canAssignRole('member', 'viewer') // false (members can't manage roles)
 * ```
 */
export function canAssignRole(
  currentUserRole: Role | undefined | null,
  targetRole: Role
): boolean {
  const assignableRoles = getAssignableRoles(currentUserRole);
  return assignableRoles.includes(targetRole);
}

/**
 * Check if user can manage members (invite, update roles, remove)
 *
 * Convenience function for common permission check
 * Equivalent to: hasPermission(role, Permission.MembersInvite)
 *
 * @param role - User's role in the organization
 * @returns true if user can manage members
 */
export function canManageMembers(role: Role | undefined | null): boolean {
  return hasPermission(role, PermissionValues.MembersInvite);
}

/**
 * Check if user can update organization settings
 *
 * Convenience function for common permission check
 * Equivalent to: hasPermission(role, Permission.OrgUpdate)
 *
 * @param role - User's role in the organization
 * @returns true if user can update organization
 */
export function canUpdateOrganization(role: Role | undefined | null): boolean {
  return hasPermission(role, PermissionValues.OrgUpdate);
}

/**
 * Check if user can delete the organization
 *
 * Only owners can delete organizations
 * Convenience function for common permission check
 *
 * @param role - User's role in the organization
 * @returns true if user can delete organization
 */
export function canDeleteOrganization(role: Role | undefined | null): boolean {
  return hasPermission(role, PermissionValues.OrgDelete);
}

/**
 * Get a human-readable label for a role
 *
 * Capitalizes the first letter of the role
 *
 * @param role - User's role
 * @returns Capitalized role name
 *
 * @example
 * ```ts
 * getRoleLabel('owner') // 'Owner'
 * getRoleLabel('admin') // 'Admin'
 * ```
 */
export function getRoleLabel(role: Role): string {
  return role.charAt(0).toUpperCase() + role.slice(1);
}

/**
 * Check if a role is at least as privileged as another role
 *
 * Hierarchy: Owner > Admin > Member > Viewer
 *
 * @param role - Role to check
 * @param minimumRole - Minimum required role
 * @returns true if role is at least as privileged as minimumRole
 *
 * @example
 * ```ts
 * isAtLeastRole('owner', 'admin') // true
 * isAtLeastRole('member', 'admin') // false
 * isAtLeastRole('admin', 'admin') // true
 * ```
 */
export function isAtLeastRole(
  role: Role | undefined | null,
  minimumRole: Role
): boolean {
  if (!role) {
    return false;
  }

  const roleHierarchy: Record<Role, number> = {
    owner: 4,
    admin: 3,
    member: 2,
    viewer: 1,
  };

  return roleHierarchy[role] >= roleHierarchy[minimumRole];
}

/**
 * Type guard to check if a role is 'owner'
 *
 * Useful for type narrowing in TypeScript
 *
 * @param role - Role to check
 * @returns true if role is 'owner'
 */
export function isOwner(role: Role | undefined | null): role is 'owner' {
  return role === 'owner';
}

/**
 * Type guard to check if a role is 'admin'
 *
 * @param role - Role to check
 * @returns true if role is 'admin'
 */
export function isAdmin(role: Role | undefined | null): role is 'admin' {
  return role === 'admin';
}

/**
 * Type guard to check if a role is 'member'
 *
 * @param role - Role to check
 * @returns true if role is 'member'
 */
export function isMember(role: Role | undefined | null): role is 'member' {
  return role === 'member';
}

/**
 * Type guard to check if a role is 'viewer'
 *
 * @param role - Role to check
 * @returns true if role is 'viewer'
 */
export function isViewer(role: Role | undefined | null): role is 'viewer' {
  return role === 'viewer';
}

/**
 * Runtime validation: Check if a string is a valid Role
 *
 * Use this to validate API responses before using role values
 * Prevents runtime errors from invalid role strings
 *
 * @param value - String value to validate
 * @returns true if value is a valid Role
 *
 * @example
 * ```ts
 * const roleFromAPI = response.role; // Could be any string!
 * if (isValidRole(roleFromAPI)) {
 *   // Now TypeScript knows it's a Role
 *   hasPermission(roleFromAPI, Permission.FlowsRead);
 * }
 * ```
 */
export function isValidRole(value: unknown): value is Role {
  return (
    typeof value === 'string' &&
    (value === 'owner' || value === 'admin' || value === 'member' || value === 'viewer')
  );
}

/**
 * Safely extract role from API response with fallback
 *
 * Use this when consuming API responses that should contain a role
 * Returns null if role is missing or invalid
 *
 * @param role - Role value from API (could be any type)
 * @returns Validated Role or null
 *
 * @example
 * ```ts
 * const role = safeExtractRole(apiResponse.organization.role);
 * // role is now Role | null, never invalid
 * ```
 */
export function safeExtractRole(role: unknown): Role | null {
  return isValidRole(role) ? role : null;
}
