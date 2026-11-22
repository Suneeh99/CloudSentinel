import { randomUUID } from 'node:crypto';
import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { authenticator } from '../../services/identity-service/src/mfa.js';
import {
  groupChecks,
  readPolicy,
  trustPolicy,
  rules,
} from '../../services/connector-worker/src/aws.js';
import type { Connection, Scan } from '../../packages/schemas/src/cloud.js';
async function signIn(page: Page) {
  const email = `aws-browser-${randomUUID()}@example.test`,
    password = 'Synthetic browser cloud password!';
  await page.goto('/');
  await page.getByRole('tab', { name: 'Register', exact: true }).click();
  await page.getByLabel('Full name').fill('Cloud Owner');
  await page.getByLabel('Organization name').fill('Cloud Assessment Lab');
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Create workspace' }).click();
  await expect(page.getByRole('status')).toContainText('Sign in to continue');
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Sign in to workspace' }).click();
  await expect(page.getByRole('heading', { name: 'Security overview' })).toBeVisible();
  return { email, password };
}
test('enrolls a real authenticator and persists approval across reloads', async ({ page }) => {
  const { email, password } = await signIn(page);
  await page.getByRole('tab', { name: 'Cloud accounts', exact: true }).click();
  await page.getByLabel('Confirm your password').fill(password);
  await page.getByRole('button', { name: 'Set up authenticator' }).click();
  const secret = await page.locator('.setup-key').innerText();
  expect(secret).toMatch(/^[A-Z2-7]+$/);
  await page
    .getByLabel('Authenticator code', { exact: true })
    .fill(authenticator(secret, email).generate());
  await page.getByRole('button', { name: 'Enable authenticator' }).click();
  await expect(page.getByText(/Cloud actions approved until/)).toBeVisible();
  await page.reload();
  await expect(page.getByText(/Cloud actions approved until/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Generate IAM policies' })).toBeDisabled();
  expect((await page.request.get('/api/auth/security')).ok()).toBe(true);
  const audit = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
    .analyze();
  expect(audit.violations).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
test('connects a role and reviews scan findings using explicitly stubbed cloud API responses', async ({
  page,
}) => {
  await signIn(page);
  let connection: Connection | undefined;
  let scans: Scan[] = [];
  const policies = {
    trustPolicy: trustPolicy(
      'arn:aws:iam::111111111111:role/Runtime',
      'browser-unique-external-id',
    ),
    readPolicy,
  };
  await page.route('**/api/auth/security', (route) =>
    route.fulfill({
      json: { configured: true, mfaEnabled: true, elevatedUntil: Date.now() / 1000 + 600 },
    }),
  );
  await page.route('**/api/organizations/*/scans', (route) => route.fulfill({ json: { scans } }));
  await page.route('**/api/organizations/*/connections**', async (route) => {
    const request = route.request(),
      path = new URL(request.url()).pathname;
    if (request.method() === 'GET')
      return route.fulfill({
        json: {
          configured: true,
          regions: ['us-east-1'],
          rules,
          connections: connection ? [{ ...connection, ...policies }] : [],
        },
      });
    if (path.endsWith('/connections')) {
      connection = {
        id: 'browser-connection',
        tenantId: 'browser-tenant',
        name: request.postDataJSON().name,
        region: 'us-east-1',
        roleArn: '',
        accountId: '',
        externalId: 'browser-unique-external-id',
        createdAt: Date.now() / 1000,
        status: 'pending',
      };
      return route.fulfill({ json: { connection: { ...connection, ...policies } } });
    }
    if (path.endsWith('/verify')) {
      connection = {
        ...connection!,
        roleArn: request.postDataJSON().roleArn,
        accountId: '123456789012',
        status: 'connected',
      };
      return route.fulfill({ json: { message: 'Verified' } });
    }
    if (path.endsWith('/scans')) {
      const scan: Scan = {
        id: 'browser-scan',
        connectionId: connection!.id,
        connectionName: connection!.name,
        accountId: '123456789012',
        region: 'us-east-1',
        startedAt: Date.now() / 1000,
        status: 'partial',
        resources: 1,
        checks: groupChecks(
          'sg-browser-public',
          [{ IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }] }],
          'us-east-1',
        ),
        errors: ['S3 inventory: AWS denied access. Review the role permissions.'],
      };
      scans = [scan];
      return route.fulfill({ json: { scan } });
    }
    return route.fulfill({ status: 404, json: { error: 'Unexpected test request' } });
  });
  await page.getByRole('tab', { name: 'Cloud accounts', exact: true }).click();
  await page.getByLabel('Connection name').fill('Production AWS');
  await page.getByRole('button', { name: 'Generate IAM policies' }).click();
  await expect(page.getByRole('heading', { name: 'Production AWS' })).toBeVisible();
  await expect(page.getByLabel('Role trust policy JSON')).toContainText(
    'browser-unique-external-id',
  );
  await page
    .getByLabel('AWS IAM role ARN')
    .fill('arn:aws:iam::123456789012:role/CloudSentinelReadOnly');
  await page.getByRole('button', { name: 'Verify and connect AWS account' }).click();
  await page.getByRole('button', { name: 'Run predefined scan' }).click();
  await expect(page.getByText('Scan partial. 3 findings recorded.')).toBeVisible();
  await expect(
    page.getByRole('heading', { name: 'All traffic open to the internet', exact: true }),
  ).toBeVisible();
  await expect(page.getByText(/Coverage is incomplete/)).toBeVisible();
  await page.getByRole('article').first().getByText('Remediation & rule details').click();
  await expect(page.getByText(/Restrict inbound TCP port 22/)).toBeVisible();
  const audit = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
    .analyze();
  expect(audit.violations).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
