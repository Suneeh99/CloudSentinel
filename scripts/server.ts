import { mkdir, open } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { AwsGateway } from '../services/connector-worker/src/aws.js';
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';
import { createApp } from '../services/identity-service/src/app.js';
import { database, Store } from '../packages/shared-utils/src/store.js';
const port = Number(process.env.PORT ?? 3000);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT');
const host = process.env.HOST ?? '127.0.0.1';
if (!['127.0.0.1', '0.0.0.0'].includes(host)) throw new Error('Invalid HOST');
const mode = process.env.APP_ENV ?? 'local';
if (!['local', 'aws'].includes(mode)) throw new Error('APP_ENV must be local or aws');
const local = mode === 'local';
const origin = process.env.APP_ORIGIN ?? (local ? `http://localhost:${port}` : '');
const table = local
  ? (process.env.LOCAL_IDENTITY_TABLE ?? 'cloudsentinel-local-identity')
  : process.env.IDENTITY_TABLE;
if (!table || (local && !/^cloudsentinel-local-(identity|e2e-[a-f0-9-]+)$/.test(table)))
  throw new Error('Invalid or missing identity table');
if (!local && process.env.DYNAMODB_LOCAL_ENDPOINT)
  throw new Error('AWS mode cannot use a local database endpoint');
let encryptionKey = process.env.MFA_ENCRYPTION_KEY;
if (!local && !encryptionKey) throw new Error('AWS mode requires MFA_ENCRYPTION_KEY');
if (local && !encryptionKey) {
  // Local-only key file. Deployed replicas must share the externally managed key.
  await mkdir('.local', { recursive: true, mode: 0o700 });
  try {
    const file = await open('.local/mfa.key', 'wx', 0o600);
    try {
      await file.writeFile(randomBytes(32).toString('hex'));
    } finally {
      await file.close();
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
  }
  encryptionKey = (await readFile('.local/mfa.key', 'utf8')).trim();
}
const store = new Store(database(local), table);
const app = await createApp(store, {
  origin,
  local,
  encryptionKey,
  cloud: process.env.CLOUDSENTINEL_AWS_PRINCIPAL_ARN
    ? { principalArn: process.env.CLOUDSENTINEL_AWS_PRINCIPAL_ARN, gateway: new AwsGateway() }
    : undefined,
});
let draining = false;
const root = resolve('apps/dashboard/out');
const mime: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css',
  '.js': 'text/javascript',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain',
};
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', origin);
    if (url.pathname === '/api/ready' && req.method === 'GET') {
      try {
        if (draining) throw new Error('Draining');
        await store.get('HEALTH', 'READINESS', AbortSignal.timeout(2000));
        res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end('{"status":"ready"}');
      } catch {
        res.writeHead(503, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end('{"status":"unavailable"}');
      }
      return;
    }
    if (url.pathname.startsWith('/api/')) {
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 8192) {
          res.writeHead(413, { 'cache-control': 'no-store' });
          res.end('Request too large');
          return;
        }
        chunks.push(chunk);
      }
      const headers = new Headers();
      for (const [key, value] of Object.entries(req.headers))
        if (value) headers.set(key, Array.isArray(value) ? value.join('; ') : value);
      const response = await app.handle(
        new Request(url, {
          method: req.method,
          headers,
          body: chunks.length ? Buffer.concat(chunks) : undefined,
        }),
        req.socket.remoteAddress ?? 'unknown',
      );
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(await response.text());
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405);
      res.end();
      return;
    }
    let file = resolve(root, `.${decodeURIComponent(url.pathname)}`);
    if (file !== root && !file.startsWith(root + sep)) {
      res.writeHead(403);
      res.end();
      return;
    }
    try {
      if ((await stat(file)).isDirectory()) file = resolve(file, 'index.html');
    } catch {
      res.writeHead(404);
      res.end('Not found. Run npm run build if the frontend is missing.');
      return;
    }
    // Static Next uses inline bootstrap scripts. Hash each exported page's scripts; no unsafe-inline script policy.
    const content = await readFile(file);
    const { createHash } = await import('node:crypto');
    const hashes =
      extname(file) === '.html'
        ? [...content.toString().matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)]
            .filter((m) => m[1])
            .map((m) => `'sha256-${createHash('sha256').update(m[1]).digest('base64')}'`)
            .join(' ')
        : '';
    res.writeHead(200, {
      'content-type': mime[extname(file)] ?? 'application/octet-stream',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'x-frame-options': 'DENY',
      'permissions-policy': 'camera=(), microphone=(), geolocation=()',
      'cache-control': 'no-cache',
      'content-security-policy': `default-src 'self'; script-src 'self' ${hashes}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'`,
    });
    res.end(req.method === 'HEAD' ? undefined : content);
  } catch {
    res.writeHead(500, { 'cache-control': 'no-store' });
    res.end('Local server error.');
  }
});
server.listen(port, host, () =>
  console.log(
    `CloudSentinel: ${origin} (${mode} mode; AWS scanning ${process.env.CLOUDSENTINEL_AWS_PRINCIPAL_ARN ? 'configured' : 'not configured'})`,
  ),
);
for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.once(signal, () => {
    draining = true;
    const deadline = setTimeout(() => process.exit(1), 30000);
    deadline.unref();
    server.close(() => {
      store.client.destroy();
      clearTimeout(deadline);
      process.exit(0);
    });
  });
}
