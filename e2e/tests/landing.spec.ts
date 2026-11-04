import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import { leaveSplash, watch } from './helpers';

test.describe('landing page', () => {
  test('shows the loading stage, then the page, without a single console problem or third-party request', async ({
    page,
  }) => {
    const problems = watch(page);
    await page.goto('/');
    await expect(page.locator('#splash')).toBeVisible();
    await leaveSplash(page);
    await expect(page.getByRole('heading', { level: 1 })).toContainText('Know when you are being attacked');
    await expect(page.getByRole('link', { name: /Open the lab/ }).first()).toBeVisible();
    expect(problems).toEqual([]);
  });

  test('the tour tabs swap in recorded output that really came from the service', async ({ page }) => {
    await page.goto('/');
    await leaveSplash(page);
    const tabs = page.getByRole('group', { name: 'Explore the product' });
    const output = page.getByRole('region', { name: 'Example output' });
    await tabs.getByRole('button', { name: /Audit/ }).click();
    await expect(output).toContainText('row_hash_mismatch');
    await expect(output).toContainText('seq_gap');
    await expect(output).toContainText('head_mismatch');
    await tabs.getByRole('button', { name: /Traps/ }).click();
    await expect(output).toContainText('honeytoken_trip');
    await expect(output).toContainText('this address is blocked');
    await tabs.getByRole('button', { name: /Humans/ }).click();
    await expect(output).toContainText('step_up_required');
    await expect(output).toContainText('operator_locked');
    await tabs.getByRole('button', { name: /Guards/ }).click();
    await expect(output).toContainText('non_public_address');
    await expect(output).toContainText('the signature did not verify');
    await tabs.getByRole('button', { name: /Analyst/ }).click();
    // placeholders are text, not tags: a transcript inserted as HTML must not swallow "<id>"
    await expect(output).toContainText('/v1/alice/proposals/<id>/approve');
    await expect(output).toContainText('not_pending');
    await expect(tabs.getByRole('button', { name: /Analyst/ })).toHaveAttribute('aria-pressed', 'true');
  });

  test('every hard part offers a recipe and a link that opens the lab on that tab', async ({ page }) => {
    await page.goto('/#hard-parts');
    await leaveSplash(page);
    const list = page.getByRole('group', { name: 'Hard parts to try' });
    const names = [
      'Edit the log',
      'Touch a trap',
      'Use a stolen key',
      'Fetch something forbidden',
      'Whisper to the analyst',
      'Travel faster than a plane',
      'Wait it out',
    ];
    for (const name of names) {
      await list.getByRole('button', { name }).click();
      await expect(page.getByText('You should see', { exact: true })).toBeVisible();
      await expect(page.getByRole('link', { name: 'Try it in the lab' })).toHaveAttribute('href', /lab\.html(#\w+)?$/);
    }
  });

  test('the theme switch is applied, remembered across reloads, and nothing leaves the page', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' });
    await page.goto('/');
    await leaveSplash(page);
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await page.getByRole('button', { name: 'Use the dark theme' }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await page.reload();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  });

  test('works with reduced motion and still reveals every section', async ({ browser }) => {
    const context = await browser.newContext({ reducedMotion: 'reduce' });
    const page = await context.newPage();
    await page.goto('/');
    await leaveSplash(page);
    await page.locator('#faq').scrollIntoViewIfNeeded();
    await expect(page.getByRole('heading', { name: /Asked often/ })).toBeVisible();
    await context.close();
  });

  test('has no horizontal scroll on a phone', async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 360, height: 740 } });
    const page = await context.newPage();
    await page.goto('/');
    await leaveSplash(page);
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow).toBeLessThanOrEqual(0);
    await context.close();
  });
});

for (const scheme of ['light', 'dark'] as const) {
  test(`accessibility: the landing page has no WCAG A/AA violations (${scheme})`, async ({ browser }) => {
    const context = await browser.newContext({ colorScheme: scheme, reducedMotion: 'reduce' });
    const page = await context.newPage();
    await page.goto('/');
    await leaveSplash(page);
    const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
    expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(' | ')}`)).toEqual([]);
    await context.close();
  });
}
