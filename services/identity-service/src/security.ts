import argon2 from 'argon2';
import QRCode from 'qrcode';
import { z } from 'zod';
import type { Session, User } from '../../../packages/schemas/src/identity.js';
import { Store, isConditional } from '../../../packages/shared-utils/src/store.js';
import { newAuthenticator, encryptSecret, decryptSecret, counter, type Mfa } from './mfa.js';
import { CloudError } from '../../findings-service/src/cloud.js';
const passwordSchema = z.object({ password: z.string().min(1).max(128) }).strict();
const codeSchema = z.object({ code: z.string().regex(/^\d{6}$/) }).strict();
export function securityService(store: Store, encryptionKey?: string) {
  if (encryptionKey && !/^[a-f0-9]{64}$/i.test(encryptionKey))
    throw new Error('Invalid MFA_ENCRYPTION_KEY');
  const get = (userId: string) => store.get<Mfa>(`USER#${userId}`, 'MFA');
  const secret = (record: Mfa, userId: string) => {
    if (!encryptionKey)
      throw new CloudError(503, 'MFA encryption is not configured. Contact the operator.');
    return decryptSecret(record.secret, encryptionKey, userId);
  };
  function consume(userId: string, value: number) {
    return {
      Update: {
        TableName: store.table,
        Key: { pk: `USER#${userId}`, sk: 'MFA' },
        UpdateExpression: 'SET lastCounter = :value',
        ConditionExpression: 'attribute_exists(pk) AND lastCounter < :value',
        ExpressionAttributeValues: { ':value': value },
      },
    };
  }
  return {
    get,
    async loginProof(user: User, code: string | undefined, now: number) {
      const record = await get(user.id);
      if (!record) return [];
      const value = counter(secret(record, user.id), code ?? '', now, record.lastCounter);
      if (value === null)
        throw new CloudError(
          401,
          'Email, password, or authenticator code is incorrect. Use a fresh code.',
        );
      return [consume(user.id, value)];
    },
    async handle(
      path: string,
      method: string,
      input: unknown,
      user: User,
      session: Session,
      now: number,
      event: (action: string) => ReturnType<Store['put']>,
    ) {
      const record = await get(user.id);
      if (path === '/api/auth/security' && method === 'GET')
        return {
          configured: !!encryptionKey,
          mfaEnabled: !!record,
          elevatedUntil: session.elevatedUntil ?? 0,
        };
      if (!encryptionKey)
        throw new CloudError(503, 'MFA encryption is not configured. Contact the operator.');
      const elevated = {
        Update: {
          TableName: store.table,
          Key: { pk: `SESSION#${session.verifier}`, sk: 'SESSION' },
          UpdateExpression: 'SET elevatedUntil = :until',
          ConditionExpression: 'attribute_exists(pk) AND expiresAt > :now AND idleExpiresAt > :now',
          ExpressionAttributeValues: {
            ':until': Math.min(now + 600, session.expiresAt),
            ':now': now,
          },
        },
      };
      if (path === '/api/auth/mfa/enroll' && method === 'POST') {
        if (record) throw new CloudError(409, 'An authenticator is already enrolled.');
        const data = passwordSchema.parse(input);
        if (!(await argon2.verify(user.passwordHash, data.password)))
          throw new CloudError(403, 'Password is incorrect. Try again.');
        const totp = newAuthenticator(user.email);
        await store.transact([
          store.put(
            {
              pk: `USER#${user.id}`,
              sk: `MFA_PENDING#${session.id}`,
              secret: encryptSecret(totp.secret.base32, encryptionKey, user.id),
              expiresAt: now + 600,
            },
            false,
          ),
        ]);
        return {
          secret: totp.secret.base32,
          uri: totp.toString(),
          qrCode: await QRCode.toDataURL(totp.toString(), { width: 220, margin: 2 }),
        };
      }
      if (path === '/api/auth/mfa/confirm' && method === 'POST') {
        const data = codeSchema.parse(input);
        const pending = await store.get<Mfa & { expiresAt: number }>(
          `USER#${user.id}`,
          `MFA_PENDING#${session.id}`,
        );
        if (record || !pending || pending.expiresAt <= now)
          throw new CloudError(
            409,
            'Enrollment expired or already completed. Start enrollment again.',
          );
        const value = counter(secret(pending, user.id), data.code, now);
        if (value === null)
          throw new CloudError(
            403,
            'Authenticator code is incorrect or expired. Try a fresh code.',
          );
        try {
          await store.transact([
            store.put({
              pk: `USER#${user.id}`,
              sk: 'MFA',
              secret: pending.secret,
              lastCounter: value,
            }),
            store.delete(`USER#${user.id}`, `MFA_PENDING#${session.id}`),
            elevated,
            event('identity.mfa_enabled'),
          ]);
        } catch (error) {
          if (isConditional(error))
            throw new CloudError(409, 'Enrollment changed. Refresh and retry.');
          throw error;
        }
        return {
          message: 'Authenticator enabled. Cloud actions are approved for 10 minutes.',
          elevatedUntil: Math.min(now + 600, session.expiresAt),
        };
      }
      if (path === '/api/auth/reauthenticate' && method === 'POST') {
        const data = passwordSchema.extend({ code: z.string().regex(/^\d{6}$/) }).parse(input);
        if (!record || !(await argon2.verify(user.passwordHash, data.password)))
          throw new CloudError(403, 'Password or authenticator code is incorrect.');
        const value = counter(secret(record, user.id), data.code, now, record.lastCounter);
        if (value === null)
          throw new CloudError(
            403,
            'Authenticator code is incorrect or already used. Wait for a fresh code.',
          );
        try {
          await store.transact([
            consume(user.id, value),
            elevated,
            event('identity.reauthenticated'),
          ]);
        } catch (error) {
          if (isConditional(error))
            throw new CloudError(
              403,
              'Code already used or session expired. Wait for a fresh code.',
            );
          throw error;
        }
        return {
          message: 'Cloud actions are approved for 10 minutes.',
          elevatedUntil: Math.min(now + 600, session.expiresAt),
        };
      }
      throw new CloudError(404, 'Security endpoint not found.');
    },
  };
}
