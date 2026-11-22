import { describe, it, expect } from 'vitest';
import { allowed } from '../../packages/authorization/src/index.js';
import type { Membership } from '../../packages/schemas/src/identity.js';
describe('deny-by-default permissions', () => {
  const member: Membership = { tenantId: 'one', userId: 'alice', role: 'owner', active: true };
  it('requires a matching tenant and active membership', () => {
    expect(allowed(member, 'one', 'overview:read')).toBe(true);
    expect(allowed(member, 'two', 'overview:read')).toBe(false);
    expect(allowed({ ...member, active: false }, 'one', 'overview:read')).toBe(false);
  });
  it('keeps privileged mutations closed until MFA ships', () => {
    expect(allowed(member, 'one', 'connections:write')).toBe(false);
    expect(allowed(member, 'one', 'members:write')).toBe(false);
  });
  it('rejects unknown roles and inherited property names', () => {
    expect(
      allowed({ ...member, role: 'toString' as Membership['role'] }, 'one', 'overview:read'),
    ).toBe(false);
    expect(allowed({ ...member, role: 'viewer' }, 'one', 'audit:read')).toBe(false);
  });
});
