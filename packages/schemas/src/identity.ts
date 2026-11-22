import { z } from 'zod';
export const emailSchema = z.string().trim().toLowerCase().email().max(254);
export const registrationSchema = z
  .object({
    email: emailSchema,
    password: z.string().min(15).max(128),
    name: z.string().trim().min(1).max(80),
    organization: z.string().trim().min(2).max(80),
  })
  .strict();
export const loginSchema = z
  .object({
    email: emailSchema,
    password: z.string().min(1).max(128),
    code: z
      .string()
      .regex(/^\d{6}$/)
      .optional(),
  })
  .strict();
export type User = {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  tenantId: string;
  disabled: boolean;
  createdAt: number;
};
export type Membership = {
  userId: string;
  tenantId: string;
  role: 'owner' | 'analyst' | 'viewer';
  active: boolean;
};
export type Session = {
  id: string;
  verifier: string;
  userId: string;
  tenantId: string;
  createdAt: number;
  lastSeen: number;
  idleExpiresAt: number;
  expiresAt: number;
  elevatedUntil?: number;
};
export type Organization = { id: string; name: string; createdAt: number };
