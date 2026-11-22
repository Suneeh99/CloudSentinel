import { defineConfig, devices } from '@playwright/test';
if (!process.env.LOCAL_IDENTITY_TABLE?.startsWith('cloudsentinel-local-e2e-'))
  throw new Error('Run npm run test:e2e for isolated test storage');
export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  use: {
    baseURL: 'http://localhost:3100',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    launchOptions: { channel: 'chromium' },
  },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile', use: { ...devices['Pixel 7'] } },
  ],
  webServer: {
    command: 'npx tsx scripts/server.ts',
    url: 'http://localhost:3100/api/health',
    reuseExistingServer: false,
    env: { PORT: '3100', APP_ORIGIN: 'http://localhost:3100' },
    timeout: 30000,
  },
});
