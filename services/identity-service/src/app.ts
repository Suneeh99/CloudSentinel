import { cloudService, CloudError, type CloudConfig } from '../../findings-service/src/cloud.js';
import { securityService } from './security.js';
import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import argon2 from 'argon2';
import { ZodError } from 'zod';
import {
  registrationSchema,
  loginSchema,
  type User,
  type Membership,
  type Session,
  type Organization,
} from '../../../packages/schemas/src/identity.js';
import { allowed, type Permission } from '../../../packages/authorization/src/index.js';
import { Store, isConditional } from '../../../packages/shared-utils/src/store.js';
import { log } from '../../../packages/observability/src/index.js';

export const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const random = () => randomBytes(32).toString('base64url');
const csrf = (token: string) =>
  createHmac('sha256', token).update('cloudsentinel-csrf-v1').digest('base64url');
const passwordOptions = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
} as const;
const IDLE = 30 * 60,
  ABSOLUTE = 12 * 60 * 60;
class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}
export type Config = {
  origin: string;
  local: boolean;
  now?: () => number;
  logging?: boolean;
  encryptionKey?: string;
  cloud?: CloudConfig;
};
type Principal = { user: User; session: Session; membership: Membership; token: string };

export async function createApp(store: Store, config: Config) {
  const cloud = cloudService(store, config.cloud);
  const security = securityService(store, config.encryptionKey);
  const origin = new URL(config.origin);
  if (
    origin.origin !== config.origin ||
    (!config.local && origin.protocol !== 'https:') ||
    (config.local && !['localhost', '127.0.0.1'].includes(origin.hostname))
  )
    throw new Error('Invalid application origin');
  const cookieName = config.local ? 'cloudsentinel_dev' : '__Host-cloudsentinel';
  const clock = config.now ?? (() => Math.floor(Date.now() / 1000));
  // Equal Argon2 cost for unknown identities; no random secret is logged or persisted.
  const dummyHash = await argon2.hash(random(), passwordOptions);
  function cookie(token: string, age = ABSOLUTE) {
    return `${cookieName}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}${config.local ? '' : '; Secure'}`;
  }
  function tokenOf(request: Request) {
    const values = (request.headers.get('cookie') ?? '')
      .split(';')
      .map((v) => v.trim())
      .filter((v) => v.startsWith(`${cookieName}=`));
    if (values.length !== 1) throw new HttpError(401, 'Sign in to continue.');
    const token = values[0].slice(cookieName.length + 1);
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new HttpError(401, 'Sign in to continue.');
    return token;
  }
  function audit(tenantId: string, actorId: string, action: string, now = clock()) {
    return {
      pk: `TENANT#${tenantId}`,
      sk: `AUDIT#${now.toString().padStart(12, '0')}#${randomUUID()}`,
      id: randomUUID(),
      actorId,
      action,
      createdAt: now,
    };
  }
  async function principal(request: Request): Promise<Principal> {
    const token = tokenOf(request),
      verifier = hash(token),
      now = clock();
    const session = await store.get<Session>(`SESSION#${verifier}`, 'SESSION');
    if (!session || session.expiresAt <= now || session.idleExpiresAt <= now)
      throw new HttpError(401, 'Your session has expired. Sign in again.');
    const [user, membership] = await Promise.all([
      store.get<User>(`USER#${session.userId}`, 'PROFILE'),
      store.get<Membership>(`TENANT#${session.tenantId}`, `MEMBER#${session.userId}`),
    ]);
    if (
      !user ||
      user.disabled ||
      !membership?.active ||
      membership.userId !== user.id ||
      membership.tenantId !== session.tenantId
    )
      throw new HttpError(401, 'Sign in to continue.');
    // Conditional refresh prevents a concurrent logout from resurrecting the session.
    try {
      await store.transact([
        {
          Update: {
            TableName: store.table,
            Key: { pk: `SESSION#${verifier}`, sk: 'SESSION' },
            UpdateExpression: 'SET lastSeen = :now, idleExpiresAt = :idle',
            ConditionExpression:
              'attribute_exists(pk) AND expiresAt > :now AND idleExpiresAt > :now',
            ExpressionAttributeValues: {
              ':now': now,
              ':idle': Math.min(now + IDLE, session.expiresAt),
            },
          },
        },
      ]);
    } catch (e) {
      if (isConditional(e)) throw new HttpError(401, 'Sign in to continue.');
      throw e;
    }
    return { user, membership, session, token };
  }
  function authorize(p: Principal, tenantId: string, permission: Permission) {
    if (!allowed(p.membership, tenantId, permission))
      throw new HttpError(403, 'You do not have permission to access this resource.');
  }
  function checkCsrf(request: Request, token: string) {
    const a = Buffer.from(request.headers.get('x-csrf-token') ?? ''),
      b = Buffer.from(csrf(token));
    if (a.length !== b.length || !timingSafeEqual(a, b))
      throw new HttpError(403, 'Security check failed. Refresh the page and try again.');
  }
  async function body(request: Request) {
    if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/json'))
      throw new HttpError(415, 'Use application/json.');
    const text = await request.text();
    if (Buffer.byteLength(text) > 8192) throw new HttpError(413, 'Request is too large.');
    try {
      return JSON.parse(text);
    } catch {
      throw new HttpError(400, 'Request must contain valid JSON.');
    }
  }
  async function throttle(scope: string, maximum: number) {
    if (!(await store.limit(hash(scope), clock(), maximum)))
      throw new HttpError(429, 'Too many attempts. Try again in 15 minutes.');
  }
  function json(data: unknown, status = 200, headers: Record<string, string> = {}) {
    return Response.json(data, { status, headers });
  }
  async function route(request: Request, ip: string) {
    const path = new URL(request.url).pathname.replace(/\/$/, ''),
      method = request.method;
    if (!['GET', 'POST', 'DELETE'].includes(method))
      throw new HttpError(405, 'Method not allowed.');
    if (method !== 'GET' && request.headers.get('origin') !== config.origin)
      throw new HttpError(403, 'Request origin is not allowed.');
    if (request.headers.get('sec-fetch-site') === 'cross-site')
      throw new HttpError(403, 'Cross-site requests are not allowed.');
    if (path === '/api/health' && method === 'GET')
      return json({ status: 'ok', service: 'identity', version: '0.1.0' });
    if (path === '/api/auth/register' && method === 'POST') {
      await throttle(`register:ip:${ip}`, 10);
      const input = registrationSchema.parse(await body(request));
      const now = clock(),
        id = randomUUID(),
        tenantId = randomUUID();
      const passwordHash = await argon2.hash(input.password, passwordOptions);
      try {
        await store.transact([
          store.put({ pk: `EMAIL#${hash(input.email)}`, sk: 'LOOKUP', userId: id }),
          store.put({
            pk: `USER#${id}`,
            sk: 'PROFILE',
            id,
            name: input.name,
            email: input.email,
            passwordHash,
            tenantId,
            disabled: false,
            createdAt: now,
          }),
          store.put({
            pk: `TENANT#${tenantId}`,
            sk: 'PROFILE',
            id: tenantId,
            name: input.organization,
            createdAt: now,
          }),
          store.put({
            pk: `TENANT#${tenantId}`,
            sk: `MEMBER#${id}`,
            userId: id,
            tenantId,
            role: 'owner',
            active: true,
          }),
          store.put(audit(tenantId, id, 'identity.registered', now)),
        ]);
      } catch (e) {
        if (!isConditional(e)) throw e;
      }
      // Same response for existing and new email; no session issued on registration.
      return json(
        {
          message:
            'If these details can be registered, your workspace is ready. Sign in to continue.',
        },
        202,
      );
    }
    if (path === '/api/auth/login' && method === 'POST') {
      await throttle(`login:ip:${ip}`, 30);
      const input = loginSchema.parse(await body(request));
      await throttle(`login:account:${input.email}`, 10);
      const lookup = await store.get<{ userId: string }>(`EMAIL#${hash(input.email)}`, 'LOOKUP');
      const user = lookup ? await store.get<User>(`USER#${lookup.userId}`, 'PROFILE') : undefined;
      const valid = await argon2.verify(user?.passwordHash ?? dummyHash, input.password);
      if (!valid || !user || user.disabled) {
        if (user)
          await store.transact([store.put(audit(user.tenantId, user.id, 'identity.login_failed'))]);
        throw new HttpError(401, 'Email or password is incorrect.');
      }
      const member = await store.get<Membership>(`TENANT#${user.tenantId}`, `MEMBER#${user.id}`);
      if (!member?.active) throw new HttpError(401, 'Email or password is incorrect.');
      const proof = await security.loginProof(user, input.code, clock());
      const token = random(),
        verifier = hash(token),
        now = clock();
      const session: Session = {
        id: randomUUID(),
        verifier,
        userId: user.id,
        tenantId: user.tenantId,
        createdAt: now,
        lastSeen: now,
        idleExpiresAt: now + IDLE,
        expiresAt: now + ABSOLUTE,
      };
      try {
        await store.transact([
          ...proof,
          store.put({ pk: `SESSION#${verifier}`, sk: 'SESSION', ...session }),
          store.put({ pk: `USER#${user.id}`, sk: `SESSION#${verifier}`, ...session }),
          store.put(audit(user.tenantId, user.id, 'identity.login', now)),
        ]);
      } catch (error) {
        if (isConditional(error))
          throw new HttpError(401, 'Authenticator code already used. Wait for a fresh code.');
        throw error;
      }
      return json({ csrfToken: csrf(token) }, 200, { 'set-cookie': cookie(token) });
    }
    const p = await principal(request);
    if (method !== 'GET') checkCsrf(request, p.token);
    if (
      [
        '/api/auth/security',
        '/api/auth/mfa/enroll',
        '/api/auth/mfa/confirm',
        '/api/auth/reauthenticate',
      ].includes(path)
    ) {
      if (method !== 'GET') await throttle(`mfa:${p.user.id}`, 10);
      const input = method === 'GET' ? undefined : await body(request);
      return json(
        await security.handle(path, method, input, p.user, p.session, clock(), (action) =>
          store.put(audit(p.session.tenantId, p.user.id, action)),
        ),
      );
    }
    const cloudPath = path.match(/^\/api\/organizations\/([^/]+)\/(connections|scans)(?:\/(.*))?$/);
    if (cloudPath) {
      const tenantId = cloudPath[1];
      authorize(p, tenantId, 'overview:read');
      if (method === 'GET' && !cloudPath[3])
        return json(
          cloudPath[2] === 'connections'
            ? await cloud.list(tenantId, p.membership.role === 'owner')
            : await cloud.history(tenantId),
        );
      const elevated =
        (p.session.elevatedUntil ?? 0) > clock() && !!(await security.get(p.user.id));
      if (!allowed(p.membership, tenantId, 'connections:write', elevated))
        throw new HttpError(
          403,
          'Only organization owners with MFA and a recent security approval can manage cloud connections or run scans.',
        );
      if (cloudPath[2] !== 'connections') throw new HttpError(404, 'Endpoint not found.');
      await throttle(`cloud-action:${p.user.id}`, 30);
      const action = cloudPath[3] ? cloudPath[3].split('/') : [];
      const input =
        method === 'POST' && !(action.length === 2 && action[1] === 'scans')
          ? await body(request)
          : undefined;
      return json(await cloud.mutate(tenantId, p.user.id, request, action, input, clock()));
    }
    if (path === '/api/auth/me' && method === 'GET') {
      const organization = await store.get<Organization>(`TENANT#${p.session.tenantId}`, 'PROFILE');
      if (!organization) throw new HttpError(403, 'Organization is unavailable.');
      return json({
        user: { id: p.user.id, name: p.user.name, email: p.user.email },
        organization: { id: organization.id, name: organization.name },
        role: p.membership.role,
        csrfToken: csrf(p.token),
        security: {
          mfa: (await security.get(p.user.id)) ? 'enabled' : 'not_enrolled',
          emailVerified: false,
        },
        environment: config.local ? 'local' : 'aws',
      });
    }
    if (path === '/api/auth/logout' && method === 'POST') {
      await store.transact([
        store.delete(`SESSION#${p.session.verifier}`, 'SESSION'),
        store.delete(`USER#${p.user.id}`, `SESSION#${p.session.verifier}`),
        store.put(audit(p.session.tenantId, p.user.id, 'identity.logout')),
      ]);
      return json({ message: 'Signed out.' }, 200, { 'set-cookie': cookie('', 0) });
    }
    if (path === '/api/auth/sessions' && method === 'GET') {
      const indexed = await store.query<Session>(`USER#${p.user.id}`, 'SESSION#', 100);
      const sessions = await Promise.all(
        indexed.map((s) => store.get<Session>(`SESSION#${s.verifier}`, 'SESSION')),
      );
      return json({
        sessions: sessions
          .filter((s): s is Session => !!s && s.expiresAt > clock() && s.idleExpiresAt > clock())
          .map((s) => ({
            id: s.id,
            createdAt: s.createdAt,
            lastSeen: s.lastSeen,
            expiresAt: s.expiresAt,
            current: s.id === p.session.id,
          })),
        limited: indexed.length === 100,
      });
    }
    if (path.startsWith('/api/auth/sessions/') && method === 'DELETE') {
      const id = path.slice('/api/auth/sessions/'.length);
      const sessions = await store.query<Session>(`USER#${p.user.id}`, 'SESSION#', 100);
      const target = sessions.find((s) => s.id === id);
      if (!target) throw new HttpError(404, 'Session not found.');
      await store.transact([
        store.delete(`SESSION#${target.verifier}`, 'SESSION'),
        store.delete(`USER#${p.user.id}`, `SESSION#${target.verifier}`),
        store.put(audit(p.session.tenantId, p.user.id, 'identity.session_revoked')),
      ]);
      return json(
        { message: 'Session revoked.' },
        200,
        target.id === p.session.id ? { 'set-cookie': cookie('', 0) } : {},
      );
    }
    const overview = path.match(/^\/api\/organizations\/([^/]+)\/overview$/);
    if (overview && method === 'GET') {
      authorize(p, overview[1], 'overview:read');
      return json({
        tenantId: overview[1],
        ...(await cloud.summary(overview[1])),
      });
    }
    const auditPath = path.match(/^\/api\/organizations\/([^/]+)\/audit$/);
    if (auditPath && method === 'GET') {
      authorize(p, auditPath[1], 'audit:read');
      const events = await store.query<{
        id: string;
        action: string;
        createdAt: number;
        actorId: string;
      }>(`TENANT#${auditPath[1]}`, 'AUDIT#', 25);
      return json({
        events: events.map(({ id, action, createdAt, actorId }) => ({
          id,
          action,
          createdAt,
          actorId,
        })),
        limit: 25,
      });
    }
    throw new HttpError(404, 'Endpoint not found.');
  }
  return {
    async validate(request: Request) {
      const p = await principal(request);
      return { userId: p.user.id, tenantId: p.session.tenantId };
    },
    async handle(request: Request, ip = 'unknown') {
      const requestId = randomUUID(),
        start = Date.now();
      let response: Response;
      try {
        response = await route(request, ip);
      } catch (e) {
        const status =
          e instanceof HttpError || e instanceof CloudError
            ? e.status
            : e instanceof ZodError
              ? 400
              : 503;
        const message =
          e instanceof HttpError || e instanceof CloudError
            ? e.message
            : e instanceof ZodError
              ? 'Check the required fields, input formats, and password length (15–128 characters for registration).'
              : 'The service is temporarily unavailable. Try again shortly.';
        response = json(
          { error: message, requestId },
          status,
          status === 429 ? { 'retry-after': '900' } : {},
        );
      }
      response.headers.set('cache-control', 'no-store');
      response.headers.set('x-content-type-options', 'nosniff');
      response.headers.set('x-request-id', requestId);
      response.headers.set('referrer-policy', 'no-referrer');
      if (config.logging !== false)
        log({
          requestId,
          method: request.method,
          status: response.status,
          durationMs: Date.now() - start,
          event: response.status >= 500 ? 'request.failed' : 'request.completed',
        });
      return response;
    },
  };
}
