import { type APIRequestContext, type Page, expect } from '@playwright/test';

const BASE = new URL(process.env.E2E_BASE_URL ?? 'http://localhost:8000');
const KEY = { 'x-api-key': process.env.E2E_API_KEY ?? 'change-me' };

/** Collects what would make a reviewer frown: console errors, page errors (CSP violations land here) and third-party calls. */
export function watch(page: Page, { allowStatus = [] as number[] } = {}): string[] {
  const problems: string[] = [];
  page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() !== 'error' && m.type() !== 'warning') return;
    // Chromium logs every non-2xx fetch as an error. The lab provokes some on purpose; allow only the listed ones.
    const status = /status of (\d{3})/.exec(m.text());
    if (status && allowStatus.includes(Number(status[1]))) return;
    problems.push(`console ${m.type()}: ${m.text()}`);
  });
  page.on('request', (r) => {
    const url = new URL(r.url());
    if (url.protocol !== 'data:' && url.protocol !== 'blob:' && url.host !== BASE.host) {
      problems.push(`third-party request: ${r.url()}`);
    }
  });
  return problems;
}

export async function leaveSplash(page: Page): Promise<void> {
  await expect(page.locator('#splash')).toHaveCount(0, { timeout: 10_000 });
}

export async function signIn(page: Page): Promise<void> {
  await page.goto('/lab.html');
  await leaveSplash(page);
  await page.getByRole('button', { name: 'Enter the lab' }).last().click();
  await expect(page.getByRole('tab', { name: 'Attack' })).toBeVisible();
}

/** The service keeps its state in PostgreSQL and Redis, so every test starts from the lab's own "start over". */
export async function resetLab(request: APIRequestContext): Promise<void> {
  const res = await request.post('/v1/lab/reset', { headers: KEY });
  expect(res.ok()).toBeTruthy();
}

export const tab = (page: Page, name: string) => page.getByRole('tab', { name });

/** The tab panel that is open. Panels that were visited and left stay in the page, hidden, so every locator starts here. */
export const active = (page: Page) => page.locator('[role="tabpanel"]:not([hidden])');

/** The answer and result cards in the open tab, newest first. */
export const cards = (page: Page) => active(page).locator('.box.arrive');

/** The newest answer from the service in the open tab. A scenario's own report ("Played: …") is not an answer. */
export const latest = (page: Page) => cards(page).filter({ hasNotText: 'Played:' }).first();

/** A scenario button in the Attack tab. */
export async function play(page: Page, title: string): Promise<void> {
  await tab(page, 'Attack').click();
  await page.getByRole('button', { name: title, exact: true }).click();
  await expect(cards(page).filter({ hasText: `Played: ${title}` })).toBeVisible();
}

/** "Start over" empties the service and every open tab; wait for its confirmation before doing anything else. */
export async function startOver(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Start over' }).click();
  await expect(page.getByText('Back to a clean slate.')).toBeVisible();
}
