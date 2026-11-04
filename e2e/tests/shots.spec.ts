import { type Page, test } from '@playwright/test';
import { leaveSplash, play, resetLab, signIn, tab } from './helpers';

// Only with SHOTS=1 (`make screenshots`): these are the pictures in the README, taken from the real stack.
test.skip(process.env.SHOTS !== '1', 'screenshots are taken on request');
test.use({ viewport: { width: 1360, height: 860 }, colorScheme: 'light', contextOptions: { reducedMotion: 'reduce' } });

const OUT = '../docs/img';
const settle = async (page: Page) => {
  await page.evaluate(() => window.scrollTo(0, 0)); // clicking scrolled the page; the picture starts at the top
  await page.waitForTimeout(5000); // let the confirmation toast leave
};

test('landing', async ({ page }) => {
  await page.goto('/');
  await leaveSplash(page);
  await page.screenshot({ path: `${OUT}/landing.png` });
});

test('lab: a trap and what it set off', async ({ page, request }) => {
  await resetLab(request);
  await signIn(page);
  await play(page, 'Honeytoken');
  await page.locator('#v-ip').fill('203.0.113.88');
  await page.getByRole('button', { name: 'Request the resource' }).click();
  await page.setViewportSize({ width: 1360, height: 1400 });
  await settle(page);
  await page.screenshot({ path: `${OUT}/lab-attack.png` });
});

test('lab: the rewrite that only a receipt exposes', async ({ page, request }) => {
  await resetLab(request);
  await signIn(page);
  await play(page, 'Credential stuffing');
  await tab(page, 'Audit').click();
  await page.getByRole('button', { name: 'Take a receipt' }).click();
  await page.getByRole('button', { name: 'Rewrite with the key' }).click();
  await page.getByRole('button', { name: 'Verify', exact: true }).click();
  await page.getByRole('button', { name: 'Verify against the receipt' }).click();
  await page.setViewportSize({ width: 1360, height: 2100 }); // tall enough to show the verdicts under the chain
  await settle(page);
  await page.screenshot({ path: `${OUT}/lab-audit.png` });
});

test('lab: a proposal waiting for a person', async ({ page, request }) => {
  await resetLab(request);
  await signIn(page);
  await play(page, 'Probing');
  await tab(page, 'Analyst').click();
  await page.getByRole('button', { name: 'Analyse' }).click();
  await page
    .locator('.trace li')
    .filter({ hasText: 'block ip' })
    .getByRole('button', { name: 'Show the rows it cites' })
    .click();
  await settle(page);
  await page.screenshot({ path: `${OUT}/lab-analyst.png` });
});
