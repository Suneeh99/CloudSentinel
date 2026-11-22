import type { Membership } from '../../schemas/src/identity.js';
export type Permission = 'overview:read' | 'audit:read' | 'members:write' | 'connections:write';
const permissions: Record<Membership['role'], readonly Permission[]> = {
  owner: ['overview:read', 'audit:read', 'connections:write'],
  analyst: ['overview:read'],
  viewer: ['overview:read'],
};
export function allowed(
  membership: Membership,
  tenantId: string,
  permission: Permission,
  elevated = false,
) {
  return (
    membership.active &&
    (permission !== 'connections:write' || elevated) &&
    membership.tenantId === tenantId &&
    Object.prototype.hasOwnProperty.call(permissions, membership.role) &&
    permissions[membership.role].includes(permission)
  );
}
