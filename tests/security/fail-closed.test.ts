import { it, expect, vi } from 'vitest';
import { createApp } from '../../services/identity-service/src/app.js';
import { Store, database } from '../../packages/shared-utils/src/store.js';
it('returns a redacted failure with no session when storage is unavailable', async () => {
  const store = new Store(database(true), 'unused-test-table');
  vi.spyOn(store, 'limit').mockRejectedValue(new Error('internal credentials should never escape'));
  const app = await createApp(store, {
    local: true,
    origin: 'http://localhost:3000',
    logging: false,
  });
  const response = await app.handle(
    new Request('http://localhost:3000/api/auth/login', {
      method: 'POST',
      headers: { origin: 'http://localhost:3000', 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'nobody@example.test', password: 'Synthetic passphrase' }),
    }),
    'test',
  );
  expect(response.status).toBe(503);
  expect(response.headers.get('set-cookie')).toBeNull();
  const body = await response.text();
  expect(body).not.toContain('credentials');
  expect(body).not.toContain('Error:');
  store.client.destroy();
});
