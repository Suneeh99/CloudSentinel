import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { CreateTableCommand, DeleteTableCommand } from '@aws-sdk/client-dynamodb';
import { UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { createApp, hash } from '../../services/identity-service/src/app.js';
import { database, Store } from '../../packages/shared-utils/src/store.js';
import { authenticator } from '../../services/identity-service/src/mfa.js';
import { groupChecks } from '../../services/connector-worker/src/aws.js';
import type { ScanResult } from '../../packages/schemas/src/cloud.js';
const client = database(true),
  table = `cloudsentinel-test-${randomUUID()}`,
  store = new Store(client, table);
const origin = 'http://localhost:3000',
  password = 'Synthetic cloud test passphrase!';
let now = 1800000000,
  ip = 0;
const verify = vi.fn(async () => {});
const scan = vi.fn(async (): Promise<ScanResult> => ({
  status: 'completed',
  resources: 1,
  errors: [],
  checks: groupChecks(
    'sg-internet',
    [{ IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }] }],
    'us-east-1',
  ),
}));
let app: Awaited<ReturnType<typeof createApp>>;
type Auth = {
  cookie: string;
  csrf: string;
  userId: string;
  tenantId: string;
  email: string;
  secret?: string;
};
function request(path: string, method = 'GET', input?: unknown, auth?: Auth, csrf = true) {
  return app.handle(
    new Request(`${origin}/api${path}`, {
      method,
      headers: {
        origin,
        'content-type': 'application/json',
        ...(auth ? { cookie: auth.cookie, ...(csrf ? { 'x-csrf-token': auth.csrf } : {}) } : {}),
      },
      body: input === undefined ? undefined : JSON.stringify(input),
    }),
    `cloud-${++ip}`,
  );
}
async function account(): Promise<Auth> {
  const email = `${randomUUID()}@example.test`;
  expect(
    (
      await request('/auth/register', 'POST', {
        email,
        password,
        name: 'Cloud Owner',
        organization: 'Cloud Security Lab',
      })
    ).status,
  ).toBe(202);
  const result = await request('/auth/login', 'POST', { email, password });
  const cookie = result.headers.get('set-cookie')!.split(';')[0],
    { csrfToken } = await result.json();
  const auth = { cookie, csrf: csrfToken, email, userId: '', tenantId: '' };
  const me = await (await request('/auth/me', 'GET', undefined, auth)).json();
  return { ...auth, userId: me.user.id, tenantId: me.organization.id };
}
function code(auth: Auth) {
  return authenticator(auth.secret!, auth.email).generate({ timestamp: now * 1000 });
}
async function enroll(auth: Auth) {
  const result = await request('/auth/mfa/enroll', 'POST', { password }, auth);
  expect(result.status).toBe(200);
  auth.secret = (await result.json()).secret;
  expect((await request('/auth/mfa/confirm', 'POST', { code: code(auth) }, auth)).status).toBe(200);
}
async function prepare(auth: Auth) {
  const result = await request(
    `/organizations/${auth.tenantId}/connections`,
    'POST',
    { name: 'AWS test account', region: 'us-east-1' },
    auth,
  );
  expect(result.status).toBe(200);
  return (await result.json()).connection;
}
async function connect(auth: Auth) {
  const c = await prepare(auth);
  expect(
    (
      await request(
        `/organizations/${auth.tenantId}/connections/${c.id}/verify`,
        'POST',
        { roleArn: 'arn:aws:iam::123456789012:role/CloudSentinelReadOnly' },
        auth,
      )
    ).status,
  ).toBe(200);
  return c;
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
  app = await createApp(store, {
    origin,
    local: true,
    now: () => now,
    logging: false,
    encryptionKey: 'ab'.repeat(32),
    cloud: { principalArn: 'arn:aws:iam::111111111111:role/Runtime', gateway: { verify, scan } },
  });
});
afterAll(async () => {
  await client.send(new DeleteTableCommand({ TableName: table }));
  client.destroy();
});
describe('organization AWS configuration assessments', () => {
  it('requires CSRF, owner membership, MFA and recent approval; isolates cloud records by organization', async () => {
    const a = await account(),
      b = await account();
    const path = `/organizations/${a.tenantId}/connections`;
    expect((await request(path, 'POST', { name: 'AWS', region: 'us-east-1' }, a)).status).toBe(403);
    await enroll(a);
    await enroll(b);
    expect(
      (await request(path, 'POST', { name: 'AWS', region: 'us-east-1' }, a, false)).status,
    ).toBe(403);
    const c = await connect(a);
    for (const resource of ['connections', 'scans'])
      expect(
        (await request(`/organizations/${a.tenantId}/${resource}`, 'GET', undefined, b)).status,
      ).toBe(403);
    expect(
      (
        await request(
          `/organizations/${b.tenantId}/connections/${c.id}/verify`,
          'POST',
          { roleArn: 'arn:aws:iam::123456789012:role/Test' },
          b,
        )
      ).status,
    ).toBe(404);
    const list = await (await request(path, 'GET', undefined, a)).json();
    expect(list.connections[0].externalId).toBe(c.externalId);
    expect(
      list.connections[0].trustPolicy.Statement[0].Condition.StringEquals['sts:ExternalId'],
    ).toBe(c.externalId);
    const other = await prepare(b);
    expect(other.externalId).not.toBe(c.externalId);
    await client.send(
      new UpdateCommand({
        TableName: table,
        Key: { pk: `TENANT#${a.tenantId}`, sk: `MEMBER#${a.userId}` },
        UpdateExpression: 'SET #role = :role',
        ExpressionAttributeNames: { '#role': 'role' },
        ExpressionAttributeValues: { ':role': 'viewer' },
      }),
    );
    expect((await request(path, 'POST', { name: 'Denied', region: 'us-east-1' }, a)).status).toBe(
      403,
    );
    const viewer = await (await request(path, 'GET', undefined, a)).json();
    expect(viewer.connections[0].externalId).toBeUndefined();
  });
  it('persists actual scan evidence and metrics, then disconnects without deleting history', async () => {
    const auth = await account();
    await enroll(auth);
    const c = await connect(auth);
    const base = `/organizations/${auth.tenantId}`;
    const result = await request(`${base}/connections/${c.id}/scans`, 'POST', undefined, auth);
    expect(result.status).toBe(200);
    const body = await result.json();
    expect(body.scan.status).toBe('completed');
    expect(body.scan.checks.filter((c: { status: string }) => c.status === 'fail')).toHaveLength(3);
    const history = await (await request(`${base}/scans`, 'GET', undefined, auth)).json();
    expect(history.scans[0].id).toBe(body.scan.id);
    expect(history.scans[0].pk).toBeUndefined();
    const overview = await (await request(`${base}/overview`, 'GET', undefined, auth)).json();
    expect(overview).toMatchObject({
      assessment: 'assessed',
      assets: 1,
      findings: 3,
      criticalFindings: 1,
      incidents: null,
    });
    const audit = await (await request(`${base}/audit`, 'GET', undefined, auth)).json();
    expect(audit.events.some((e: { action: string }) => e.action === 'cloud.scan_completed')).toBe(
      true,
    );
    expect((await request(`${base}/connections/${c.id}`, 'DELETE', undefined, auth)).status).toBe(
      200,
    );
    expect(
      (await request(`${base}/connections/${c.id}/scans`, 'POST', undefined, auth)).status,
    ).toBe(409);
    expect(
      (await (await request(`${base}/scans`, 'GET', undefined, auth)).json()).scans,
    ).toHaveLength(1);
    expect(
      (await (await request(`${base}/overview`, 'GET', undefined, auth)).json()).assets,
    ).toBeNull();
  });
  it('persists partial/failed results, enforces scan quotas and prevents concurrent scans', async () => {
    const auth = await account();
    await enroll(auth);
    const c = await connect(auth);
    const base = `/organizations/${auth.tenantId}/connections/${c.id}`;
    let release!: () => void;
    scan.mockImplementationOnce(async () => {
      await new Promise<void>((resolve) => {
        release = resolve;
      });
      return { status: 'partial', resources: 0, checks: [], errors: ['Inventory truncated'] };
    });
    const first = request(`${base}/scans`, 'POST', undefined, auth);
    await vi.waitFor(() => expect(release).toBeTypeOf('function'));
    expect((await request(`${base}/scans`, 'POST', undefined, auth)).status).toBe(409);
    expect((await request(base, 'DELETE', undefined, auth)).status).toBe(409);
    release();
    expect((await (await first).json()).scan.status).toBe('partial');
    scan.mockRejectedValueOnce(
      Object.assign(new Error('AWS SECRET MUST NOT LEAK'), { name: 'AccessDenied' }),
    );
    const failure = await (await request(`${base}/scans`, 'POST', undefined, auth)).json();
    expect(failure.scan.status).toBe('failed');
    expect(JSON.stringify(failure)).not.toContain('SECRET');
    for (let i = 0; i < 2; i++)
      expect((await request(`${base}/scans`, 'POST', undefined, auth)).status).toBe(200);
    expect((await request(`${base}/scans`, 'POST', undefined, auth)).status).toBe(429);
  });
  it('expires approval, rejects replay and requires MFA at subsequent login', async () => {
    const auth = await account();
    await enroll(auth);
    expect(
      (await request('/auth/reauthenticate', 'POST', { password, code: code(auth) }, auth)).status,
    ).toBe(403);
    now += 601;
    expect(
      (
        await request(
          `/organizations/${auth.tenantId}/connections`,
          'POST',
          { name: 'AWS', region: 'us-east-1' },
          auth,
        )
      ).status,
    ).toBe(403);
    expect((await request('/auth/login', 'POST', { email: auth.email, password })).status).toBe(
      401,
    );
    expect(
      (await request('/auth/reauthenticate', 'POST', { password, code: code(auth) }, auth)).status,
    ).toBe(200);
    expect(
      (await request('/auth/login', 'POST', { email: auth.email, password, code: code(auth) }))
        .status,
    ).toBe(401);
    now += 30;
    expect(
      (await request('/auth/login', 'POST', { email: auth.email, password, code: code(auth) }))
        .status,
    ).toBe(200);
    const mfa = await store.get<{ secret: string }>(`USER#${auth.userId}`, 'MFA');
    expect(mfa?.secret).not.toContain(auth.secret);
    const session = await store.get<{ elevatedUntil: number }>(
      `SESSION#${hash(auth.cookie.split('=')[1])}`,
      'SESSION',
    );
    expect(session!.elevatedUntil).toBeGreaterThan(now);
  });
  it('prevents duplicate account/region connections and releases the claim on disconnect', async () => {
    const auth = await account();
    await enroll(auth);
    const first = await connect(auth),
      second = await prepare(auth);
    const base = `/organizations/${auth.tenantId}/connections`;
    const input = { roleArn: 'arn:aws:iam::123456789012:role/CloudSentinelReadOnly' };
    expect((await request(`${base}/${second.id}/verify`, 'POST', input, auth)).status).toBe(409);
    expect((await request(`${base}/${first.id}`, 'DELETE', undefined, auth)).status).toBe(200);
    expect((await request(`${base}/${second.id}/verify`, 'POST', input, auth)).status).toBe(200);
    expect((await request(`${base}/${first.id}`, 'DELETE', undefined, auth)).status).toBe(200);
    const third = await prepare(auth);
    expect((await request(`${base}/${third.id}/verify`, 'POST', input, auth)).status).toBe(409);
  });
  it('rejects overposting, arbitrary regions and invalid role ARNs without AWS calls', async () => {
    const auth = await account();
    await enroll(auth);
    const c = await prepare(auth);
    const before = verify.mock.calls.length;
    const base = `/organizations/${auth.tenantId}/connections`;
    expect(
      (
        await request(
          base,
          'POST',
          { name: 'AWS', region: 'http://localhost', tenantId: 'other' },
          auth,
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await request(
          `${base}/${c.id}/verify`,
          'POST',
          { roleArn: 'arn:aws:iam::123456789012:root', externalId: 'overridden' },
          auth,
        )
      ).status,
    ).toBe(400);
    expect(verify.mock.calls.length).toBe(before);
  });
});
