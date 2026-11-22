import AxeBuilder from '@axe-core/playwright';
import { test, expect } from '@playwright/test';
import { randomUUID } from 'node:crypto';
test('register, sign in, inspect protected overview and audit, revoke session, sign out', async ({
  page,
}) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const email = `browser-${randomUUID()}@example.test`;
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Sign in', exact: true })).toBeVisible();
  await page.getByRole('tab', { name: 'Register', exact: true }).click();
  await page.getByLabel('Full name').fill('Browser Analyst');
  await page.getByLabel('Organization name').fill('Browser Security Lab');
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password', { exact: true }).fill('Browser synthetic passphrase!');
  await page.getByRole('button', { name: 'Create workspace' }).click();
  await expect(page.getByRole('status')).toContainText('Sign in to continue');
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password', { exact: true }).fill('Browser synthetic passphrase!');
  await page.getByRole('button', { name: 'Sign in to workspace' }).click();
  await expect(page.getByRole('heading', { name: 'Security overview' })).toBeVisible();
  await expect(page.getByText('Not assessed', { exact: true })).toBeVisible();
  await expect(page.getByText('Workspace created', { exact: true })).toBeVisible();
  const cookies = await page.context().cookies();
  const sessionCookie = cookies.find((c) => c.name === 'cloudsentinel_dev')!;
  expect(sessionCookie.httpOnly).toBe(true);
  expect(sessionCookie.sameSite).toBe('Strict');
  expect(await page.evaluate(() => document.cookie)).not.toContain('cloudsentinel_dev');
  const dashboardAudit = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
    .analyze();
  expect(dashboardAudit.violations).toEqual([]);
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Security overview' })).toBeVisible();
  await page.getByRole('tab', { name: 'Audit activity' }).click();
  await expect(page.getByRole('heading', { name: 'Identity event history' })).toBeVisible();
  await page.getByRole('tab', { name: /Active sessions/ }).click();
  await expect(page.getByRole('heading', { name: 'This browser session' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
  await page.getByRole('article').getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Sign in', exact: true })).toBeVisible();
  expect((await page.request.get('/api/auth/me')).status()).toBe(401);
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Sign in', exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});
test('displays server errors without exposing protected content', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('Email address').fill('unknown@example.test');
  await page.getByLabel('Password', { exact: true }).fill('Incorrect synthetic password');
  await page.getByRole('button', { name: 'Sign in to workspace' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Email or password' })).toContainText(
    'Email or password is incorrect',
  );
  await expect(page.getByRole('heading', { name: 'Security overview' })).not.toBeVisible();
});

test('sign-in accessibility and keyboard tab navigation', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Sign in', exact: true })).toBeVisible();
  const audit = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
    .analyze();
  expect(audit.violations).toEqual([]);
  await page.getByRole('tab', { name: 'Sign in', exact: true }).focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('tab', { name: 'Register', exact: true })).toBeFocused();
  await expect(page.getByLabel('Full name')).toBeVisible();
});
