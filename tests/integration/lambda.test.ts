import { beforeAll, afterAll, it, expect, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { CreateTableCommand, DeleteTableCommand } from '@aws-sdk/client-dynamodb';
import type { APIGatewayProxyEventV2, APIGatewayRequestAuthorizerEventV2 } from 'aws-lambda';
import { database } from '../../packages/shared-utils/src/store.js';
vi.mock('../../packages/shared-utils/src/store.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../packages/shared-utils/src/store.js')>();
  return { ...actual, database: () => actual.database(true) };
});
const client = database(),
  table = `cloudsentinel-adapter-test-${randomUUID()}`;
const origin = 'https://app.example.test';
let handler: (typeof import('../../services/identity-service/src/lambda.js'))['handler'];
let authorizer: (typeof import('../../services/identity-service/src/lambda.js'))['authorizer'];
function event(path: string, method = 'GET', body?: unknown, cookies?: string[], base64 = false) {
  const raw = body ? JSON.stringify(body) : undefined;
  return {
    version: '2.0',
    rawPath: path,
    rawQueryString: '',
    headers: { origin, 'content-type': 'application/json', 'x-user-id': 'forged' },
    cookies,
    body: raw && base64 ? Buffer.from(raw).toString('base64') : raw,
    isBase64Encoded: base64,
    requestContext: {
      http: { method, sourceIp: '127.0.0.2' },
      authorizer: { lambda: { userId: 'forged', tenantId: 'forged' } },
    },
  } as unknown as APIGatewayProxyEventV2;
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
  process.env.IDENTITY_TABLE = table;
  process.env.APP_ORIGIN = origin;
  ({ handler, authorizer } = await import('../../services/identity-service/src/lambda.js'));
});
afterAll(async () => {
  await client.send(new DeleteTableCommand({ TableName: table }));
  client.destroy();
  delete process.env.IDENTITY_TABLE;
  delete process.env.APP_ORIGIN;
});
it('rejects forged authorizer context and unauthenticated direct Gateway requests', async () => {
  const r = await handler(event('/api/auth/me'));
  expect(r.statusCode).toBe(401);
  expect(
    await authorizer(event('/api/auth/me') as unknown as APIGatewayRequestAuthorizerEventV2),
  ).toEqual({ isAuthorized: false });
});
it('adapts base64 bodies and HTTP API cookie arrays, then revalidates after logout', async () => {
  const email = 'lambda@example.test',
    password = 'Synthetic lambda passphrase';
  expect(
    (
      await handler(
        event(
          '/api/auth/register',
          'POST',
          { email, password, name: 'Adapter', organization: 'Lambda Test' },
          undefined,
          true,
        ),
      )
    ).statusCode,
  ).toBe(202);
  const login = await handler(event('/api/auth/login', 'POST', { email, password }));
  expect(login.statusCode).toBe(200);
  expect(login.cookies![0]).toContain('; Secure');
  expect(login.headers!['set-cookie']).toBeUndefined();
  const cookies = [login.cookies![0].split(';')[0]],
    csrf = JSON.parse(login.body!).csrfToken;
  const authenticated = event('/api/auth/me', 'GET', undefined, cookies);
  expect((await handler(authenticated)).statusCode).toBe(200);
  expect(
    (await authorizer(authenticated as unknown as APIGatewayRequestAuthorizerEventV2)).isAuthorized,
  ).toBe(true);
  const logout = event('/api/auth/logout', 'POST', undefined, cookies);
  logout.headers['x-csrf-token'] = csrf;
  expect((await handler(logout)).statusCode).toBe(200);
  expect(
    (await authorizer(authenticated as unknown as APIGatewayRequestAuthorizerEventV2)).isAuthorized,
  ).toBe(false);
  expect((await handler(authenticated)).statusCode).toBe(401);
});
