import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { CreateTableCommand, DeleteTableCommand } from '@aws-sdk/client-dynamodb';
import { ScanCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { createApp, hash } from '../../services/identity-service/src/app.js';
import { database, Store } from '../../packages/shared-utils/src/store.js';
import type { Session, User } from '../../packages/schemas/src/identity.js';
const client = database(true),
  table = `cloudsentinel-test-${randomUUID()}`,
  store = new Store(client, table);
let app: Awaited<ReturnType<typeof createApp>>,
  now = 1800000000;
const origin = 'http://localhost:3000',
  password = 'Synthetic test passphrase!';
let ip = 0;
function request(
  path: string,
  method = 'GET',
  data?: unknown,
  cookie?: string,
  csrf?: string,
  extra: Record<string, string> = {},
) {
  const headers: Record<string, string> = { origin, 'content-type': 'application/json', ...extra };
  if (cookie) headers.cookie = cookie;
  if (csrf) headers['x-csrf-token'] = csrf;
  return app.handle(
    new Request(`${origin}/api${path}`, {
      method,
      headers,
      body: data === undefined ? undefined : JSON.stringify(data),
    }),
    `test-${++ip}`,
  );
}
async function register(email = `${randomUUID()}@example.test`) {
  const response = await request('/auth/register', 'POST', {
    email,
    password,
    name: 'Test Analyst',
    organization: 'Test Organization',
  });
  expect(response.status).toBe(202);
  return email;
}
async function login(email: string) {
  const response = await request('/auth/login', 'POST', { email, password });
  expect(response.status).toBe(200);
  const cookie = response.headers.get('set-cookie')!.split(';')[0];
  const { csrfToken } = await response.json();
  const me = await (await request('/auth/me', 'GET', undefined, cookie)).json();
  return { cookie, csrfToken: csrfToken as string, me, response };
}
beforeAll(async () => {
  await client.send(
    new CreateTableCommand({
      TableName: table,
      BillingMode: 'PAY_PER_REQUEST',
      KeySchema: [
        { AttributeName: 'pk', KeyType: 'HASH' },
        { AttributeName: 'sk', KeyType: 'RANGE' },
      ],
      AttributeDefinitions: [
        { AttributeName: 'pk', AttributeType: 'S' },
        { AttributeName: 'sk', AttributeType: 'S' },
      ],
    }),
  );
  app = await createApp(store, { origin, local: true, now: () => now, logging: false });
});
afterAll(async () => {
  await client.send(new DeleteTableCommand({ TableName: table }));
  client.destroy();
});
describe('DynamoDB-backed identity and authorization', () => {
  it('registers atomically, hashes passwords with unique salts, and avoids account enumeration', async () => {
    const email = await register('MixedCase@EXAMPLE.test');
    const duplicate = await request('/auth/register', 'POST', {
      email: email.toLowerCase(),
      password,
      name: 'Duplicate',
      organization: 'Duplicate',
    });
    expect(duplicate.status).toBe(202);
    const lookup = await store.get<{ userId: string }>(
      `EMAIL#${hash(email.toLowerCase())}`,
      'LOOKUP',
    );
    const user = await store.get<User>(`USER#${lookup!.userId}`, 'PROFILE');
    expect(user!.name).toBe('Test Analyst');
    expect(user!.passwordHash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    const other = await register();
    const otherLookup = await store.get<{ userId: string }>(`EMAIL#${hash(other)}`, 'LOOKUP');
    expect(
      (await store.get<User>(`USER#${otherLookup!.userId}`, 'PROFILE'))!.passwordHash,
    ).not.toBe(user!.passwordHash);
  });
  it('enforces uniqueness under concurrent registrations without orphan organizations', async () => {
    const email = `${randomUUID()}@example.test`,
      data = { email, password, name: 'Race', organization: 'Race tenant' };
    const results = await Promise.all([
      request('/auth/register', 'POST', data),
      request('/auth/register', 'POST', data),
    ]);
    expect(results.map((r) => r.status)).toEqual([202, 202]);
    const rows = await client.send(new ScanCommand({ TableName: table }));
    expect(rows.Items!.filter((r) => r.sk === 'PROFILE' && r.name === 'Race tenant')).toHaveLength(
      1,
    );
  });
  it('returns a protected identity, opaque cookie, CSRF token and no-store responses', async () => {
    const email = await register(),
      auth = await login(email);
    expect(auth.response.headers.get('set-cookie')).toContain('HttpOnly; SameSite=Strict; Path=/');
    expect(auth.response.headers.get('cache-control')).toBe('no-store');
    expect(auth.me.user.email).toBe(email);
    expect(auth.me.role).toBe('owner');
    expect(auth.me.user.passwordHash).toBeUndefined();
    const raw = auth.cookie.split('=')[1];
    expect(raw).toHaveLength(43);
    const row = await store.get<Session>(`SESSION#${hash(raw)}`, 'SESSION');
    expect(row!.verifier).toBe(hash(raw));
    const rows = await client.send(new ScanCommand({ TableName: table }));
    expect(JSON.stringify(rows.Items)).not.toContain(raw);
    const overview = await request(
      `/organizations/${auth.me.organization.id}/overview`,
      'GET',
      undefined,
      auth.cookie,
    );
    expect(overview.status).toBe(200);
    expect((await overview.json()).assets).toBeNull();
  });
  it('uses generic failed-login responses and rejects unauthenticated direct API requests', async () => {
    const email = await register();
    for (const target of [email, 'does-not-exist@example.test']) {
      const r = await request('/auth/login', 'POST', { email: target, password: 'incorrect' });
      expect(r.status).toBe(401);
      expect((await r.json()).error).toBe('Email or password is incorrect.');
    }
    expect((await request('/auth/me')).status).toBe(401);
    expect(
      (
        await request('/organizations/forged/overview', 'GET', undefined, undefined, undefined, {
          'x-user-id': 'owner',
          'x-tenant-id': 'forged',
        })
      ).status,
    ).toBe(401);
  });
  it('denies cross-tenant overview and audit access even with a valid session', async () => {
    const a = await login(await register()),
      b = await login(await register());
    for (const resource of ['overview', 'audit'])
      expect(
        (
          await request(
            `/organizations/${b.me.organization.id}/${resource}`,
            'GET',
            undefined,
            a.cookie,
          )
        ).status,
      ).toBe(403);
    expect(
      (await request(`/organizations/${a.me.organization.id}/audit`, 'GET', undefined, a.cookie))
        .status,
    ).toBe(200);
  });
  it('rejects origin forgery, missing CSRF and cross-session CSRF; logout revokes server-side', async () => {
    const email = await register(),
      a = await login(email),
      b = await login(email);
    expect(
      (
        await request('/auth/logout', 'POST', {}, a.cookie, a.csrfToken, {
          origin: 'https://evil.test',
        })
      ).status,
    ).toBe(403);
    expect((await request('/auth/logout', 'POST', {}, a.cookie)).status).toBe(403);
    expect((await request('/auth/logout', 'POST', {}, a.cookie, b.csrfToken)).status).toBe(403);
    expect((await request('/auth/logout', 'POST', {}, a.cookie, a.csrfToken)).status).toBe(200);
    expect((await request('/auth/me', 'GET', undefined, a.cookie)).status).toBe(401);
    expect((await request('/auth/me', 'GET', undefined, b.cookie)).status).toBe(200);
  });
  it('lists sessions without verifiers, revokes another session and denies foreign session revocation', async () => {
    const email = await register(),
      a = await login(email),
      b = await login(email),
      foreign = await login(await register());
    const list = await (await request('/auth/sessions', 'GET', undefined, a.cookie)).json();
    expect(list.sessions).toHaveLength(2);
    expect(JSON.stringify(list)).not.toContain('verifier');
    const target = list.sessions.find((s: { current: boolean }) => !s.current);
    expect(
      (
        await request(
          `/auth/sessions/${target.id}`,
          'DELETE',
          undefined,
          foreign.cookie,
          foreign.csrfToken,
        )
      ).status,
    ).toBe(404);
    expect(
      (await request(`/auth/sessions/${target.id}`, 'DELETE', undefined, a.cookie, a.csrfToken))
        .status,
    ).toBe(200);
    expect((await request('/auth/me', 'GET', undefined, b.cookie)).status).toBe(401);
  });
  it('enforces idle expiration without waiting for DynamoDB TTL deletion', async () => {
    const a = await login(await register());
    now += 1800;
    expect((await request('/auth/me', 'GET', undefined, a.cookie)).status).toBe(401);
    expect(await store.get(`SESSION#${hash(a.cookie.split('=')[1])}`, 'SESSION')).toBeDefined();
  });
  it('slides idle expiry but never extends absolute expiry', async () => {
    const a = await login(await register());
    for (let i = 0; i < 43; i++) {
      now += 1000;
      expect((await request('/auth/me', 'GET', undefined, a.cookie)).status).toBe(200);
    }
    now += 201;
    expect((await request('/auth/me', 'GET', undefined, a.cookie)).status).toBe(401);
  });
  it('rechecks disabled users, membership revocation and changed roles', async () => {
    const a = await login(await register());
    const update = async (pk: string, sk: string, key: string, value: unknown) =>
      client.send(
        new UpdateCommand({
          TableName: table,
          Key: { pk, sk },
          UpdateExpression: 'SET #k = :v',
          ExpressionAttributeNames: { '#k': key },
          ExpressionAttributeValues: { ':v': value },
        }),
      );
    await update(`TENANT#${a.me.organization.id}`, `MEMBER#${a.me.user.id}`, 'role', 'viewer');
    expect(
      (await request(`/organizations/${a.me.organization.id}/audit`, 'GET', undefined, a.cookie))
        .status,
    ).toBe(403);
    expect(
      (await request(`/organizations/${a.me.organization.id}/overview`, 'GET', undefined, a.cookie))
        .status,
    ).toBe(200);
    await update(`TENANT#${a.me.organization.id}`, `MEMBER#${a.me.user.id}`, 'active', false);
    expect((await request('/auth/me', 'GET', undefined, a.cookie)).status).toBe(401);
    const b = await login(await register());
    await update(`USER#${b.me.user.id}`, 'PROFILE', 'disabled', true);
    expect((await request('/auth/me', 'GET', undefined, b.cookie)).status).toBe(401);
  });
  it('rate limits account attempts across different source IPs', async () => {
    const email = `${randomUUID()}@example.test`;
    for (let i = 0; i < 10; i++)
      expect((await request('/auth/login', 'POST', { email, password })).status).toBe(401);
    const blocked = await request('/auth/login', 'POST', { email, password });
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get('retry-after')).toBe('900');
  });
  it('rejects weak input, overposting, unsupported content types and oversized requests', async () => {
    expect(
      (
        await request('/auth/register', 'POST', {
          email: 'test@example.test',
          password: 'short',
          name: 'X',
          organization: 'Test',
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await request('/auth/register', 'POST', {
          email: 'test@example.test',
          password,
          name: 'X',
          organization: 'Test',
          role: 'owner',
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await request('/auth/login', 'POST', {}, undefined, undefined, {
          'content-type': 'text/plain',
        })
      ).status,
    ).toBe(415);
    expect((await request('/auth/login', 'POST', { huge: 'a'.repeat(9000) })).status).toBe(413);
    const noOrigin = await app.handle(
      new Request(`${origin}/api/auth/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      }),
      'no-origin',
    );
    expect(noOrigin.status).toBe(403);
  });
  it('uses Secure host cookies in HTTPS configuration and fails invalid production configuration', async () => {
    await expect(createApp(store, { origin, local: false })).rejects.toThrow(
      'Invalid application origin',
    );
    const production = await createApp(store, {
      origin: 'https://security.example.test',
      local: false,
      logging: false,
      now: () => now,
    });
    const email = await register();
    const response = await production.handle(
      new Request('https://security.example.test/api/auth/login', {
        method: 'POST',
        headers: { origin: 'https://security.example.test', 'content-type': 'application/json' },
        body: JSON.stringify({ email, password }),
      }),
      'production-test',
    );
    expect(response.status).toBe(200);
    expect(response.headers.get('set-cookie')).toMatch(/^__Host-cloudsentinel=.*; Secure$/);
    expect(response.headers.get('set-cookie')).not.toContain('Domain=');
  });
});
