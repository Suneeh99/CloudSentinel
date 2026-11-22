import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { TOTP, Secret } from 'otpauth';

export type Mfa = { secret: string; lastCounter: number };
function key(value: string) {
  if (!/^[a-f0-9]{64}$/i.test(value)) throw new Error('MFA encryption key must be 32 bytes of hex');
  return Buffer.from(value, 'hex');
}
export function encryptSecret(secret: string, encryptionKey: string, userId: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key(encryptionKey), iv);
  cipher.setAAD(Buffer.from(userId));
  return Buffer.concat([iv, cipher.update(secret), cipher.final(), cipher.getAuthTag()]).toString(
    'base64',
  );
}
export function decryptSecret(secret: string, encryptionKey: string, userId: string) {
  const data = Buffer.from(secret, 'base64');
  const cipher = createDecipheriv('aes-256-gcm', key(encryptionKey), data.subarray(0, 12));
  cipher.setAAD(Buffer.from(userId));
  cipher.setAuthTag(data.subarray(-16));
  return Buffer.concat([cipher.update(data.subarray(12, -16)), cipher.final()]).toString();
}
export function authenticator(secret: string, label: string) {
  return new TOTP({
    issuer: 'CloudSentinel',
    label,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(secret),
  });
}
export function newAuthenticator(label: string) {
  return authenticator(new Secret({ size: 20 }).base32, label);
}
export function counter(secret: string, code: string, now: number, lastCounter = -1) {
  if (!/^\d{6}$/.test(code)) return null;
  const delta = authenticator(secret, '').validate({
    token: code,
    timestamp: now * 1000,
    window: 1,
  });
  const value = delta === null ? null : Math.floor(now / 30) + delta;
  return value !== null && value > lastCounter ? value : null;
}
