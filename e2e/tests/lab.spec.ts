import AxeBuilder from '@axe-core/playwright';
import { type Page, expect, test } from '@playwright/test';
import { active, cards, latest, leaveSplash, play, resetLab, signIn, startOver, tab, watch } from './helpers';

const box = (page: Page, heading: string | RegExp) =>
  active(page)
    .locator('.box')
    .filter({ has: page.getByRole('heading', { name: heading }) });
const REFUSALS = [401, 403, 423, 503];

async function fillCode(page: Page, id: string): Promise<void> {
  await page.getByRole('button', { name: 'Fill in the current code' }).click();
  await expect(page.locator(`#${id}-code`)).toHaveValue(/^\d{6}$/);
}

test.describe('lab', () => {
  test.beforeEach(async ({ request }) => {
    await resetLab(request);
  });

  test('refuses a wrong key and says so', async ({ page }) => {
    await page.goto('/lab.html');
    await leaveSplash(page);
    await page.getByLabel('API key').fill('definitely-not-the-key');
    await page.getByRole('button', { name: 'Enter the lab' }).last().click();
    await expect(page.getByText('That key was not accepted.')).toBeVisible();
    await expect(tab(page, 'Attack')).toHaveCount(0);
  });

  test('edit the log: the edit names the row, the rewrite passes alone and is exposed by the receipt', async ({
    page,
  }) => {
    const problems = watch(page);
    await signIn(page);
    await play(page, 'Credential stuffing');
    await tab(page, 'Audit').click();
    await page.getByRole('button', { name: 'Take a receipt' }).click();
    await page.getByRole('button', { name: 'Edit a row' }).click();
    await expect(latest(page)).toContainText('changed the address in entry');
    await page.getByRole('button', { name: 'Verify', exact: true }).click();
    const verdict = cards(page).filter({ hasText: 'damage found' }).first();
    await expect(verdict).toContainText('row_hash_mismatch');
    await expect(verdict).toContainText('written to the chain');

    // The worst case: the same attack, now with the signing key.
    await startOver(page);
    await play(page, 'Credential stuffing');
    await tab(page, 'Audit').click();
    await page.getByRole('button', { name: 'Take a receipt' }).click();
    await page.getByRole('button', { name: 'Rewrite with the key' }).click();
    await expect(latest(page)).toContainText('recomputed every hash after it');
    await page.getByRole('button', { name: 'Verify', exact: true }).click();
    await expect(cards(page).filter({ hasText: 'intact' }).first()).toBeVisible();
    await page.getByRole('button', { name: 'Verify against the receipt' }).click();
    const exposed = cards(page).filter({ hasText: 'Verify against the receipt' }).first();
    await expect(exposed).toContainText('damage found');
    await expect(exposed).toContainText('anchor_mismatch');
    expect(problems).toEqual([]);
  });

  test('deleting a row from the middle and cutting off the end each leave a different mark', async ({ page }) => {
    await signIn(page);
    await play(page, 'Credential stuffing');
    await tab(page, 'Audit').click();
    await page.getByRole('button', { name: 'Delete a row from the middle' }).click();
    await page.getByRole('button', { name: 'Verify', exact: true }).click();
    await expect(cards(page).filter({ hasText: 'damage found' }).first()).toContainText('seq_gap');
    await startOver(page);
    await play(page, 'Credential stuffing');
    await tab(page, 'Audit').click();
    await page.getByRole('button', { name: 'Cut off the last row' }).click();
    await page.getByRole('button', { name: 'Verify', exact: true }).click();
    await expect(cards(page).filter({ hasText: 'damage found' }).first()).toContainText('head_mismatch');
  });

  test('tampering with an empty chain is refused with a reason, not a crash', async ({ page }) => {
    await signIn(page);
    await tab(page, 'Audit').click();
    await page.getByRole('button', { name: 'Edit a row' }).click();
    await expect(latest(page)).toContainText('not enough history');
  });

  test('touch a trap: one address falls, another is untouched, and the chain says why', async ({ page }) => {
    const problems = watch(page, { allowStatus: REFUSALS });
    await signIn(page);
    await play(page, 'Honeytoken');
    await page.locator('#v-ip').fill('203.0.113.88');
    await page.getByRole('button', { name: 'Request the resource' }).click();
    await expect(latest(page)).toContainText('403');
    await expect(latest(page)).toContainText('this address is blocked');
    await page.locator('#v-ip').fill('203.0.113.9');
    await page.getByRole('button', { name: 'Request the resource' }).click();
    await expect(latest(page)).toContainText('quarterly-report');
    await expect(box(page, 'What the engine believes now')).toContainText('203.0.113.88');
    await tab(page, 'Audit').click();
    await expect(box(page, /1 · The chain/)).toContainText('honeytoken_trip');
    await expect(box(page, /1 · The chain/)).toContainText('ip_blocked');
    expect(problems).toEqual([]);
  });

  test('a canary record blocks whoever reads it, and answers like any other record first', async ({ page }) => {
    const problems = watch(page, { allowStatus: REFUSALS });
    await signIn(page);
    await page.locator('#v-ip').fill('203.0.113.89');
    await page.locator('#v-record-preset').selectOption({ label: 'A record no screen links to' });
    await page.getByRole('button', { name: 'Read the record' }).click();
    await expect(latest(page)).toContainText('a fictional record');
    await page.getByRole('button', { name: 'Request the resource' }).click();
    await expect(latest(page)).toContainText('403');
    expect(problems).toEqual([]);
  });

  test('use a stolen key: the network first, then the code, then a lockout that renaming cannot dodge', async ({
    page,
  }) => {
    const problems = watch(page, { allowStatus: REFUSALS });
    await signIn(page);
    await tab(page, 'Humans').click();
    const block = page.getByRole('button', { name: 'Block', exact: true });

    await page.locator('#hu-net').selectOption('outsider');
    await fillCode(page, 'hu');
    await block.click();
    await expect(latest(page)).toContainText('403');
    await expect(latest(page)).toContainText('ip_not_allowed');

    await page.locator('#hu-net').selectOption('operator');
    await page.locator('#hu-code').fill('');
    await block.click();
    await expect(latest(page)).toContainText('step_up_required');

    await page.locator('#hu-code').fill('000000');
    await block.click();
    await expect(latest(page)).toContainText('step_up_invalid');
    await expect(latest(page)).toContainText('"remaining": 2');
    await block.click();
    await expect(latest(page)).toContainText('"remaining": 1');
    await block.click();
    await expect(latest(page)).toContainText('423');
    await expect(latest(page)).toContainText('operator_locked');
    await expect(box(page, 'What the engine believes now')).toContainText('locked out');

    await page.locator('#hu-label').fill('someone-new');
    await fillCode(page, 'hu');
    await block.click();
    await expect(latest(page)).toContainText('operator_locked');

    await page.getByRole('button', { name: 'Release lockout' }).click();
    await expect(box(page, 'What the engine believes now')).toContainText('open');
    await fillCode(page, 'hu');
    await block.click();
    await expect(latest(page)).toContainText('"ok": true');
    await expect(box(page, 'What the engine believes now')).toContainText('203.0.113.9');
    expect(problems).toEqual([]);
  });

  test('fetch something forbidden: disguised addresses are refused for what they are, a typo is not an attack', async ({
    page,
  }) => {
    await signIn(page);
    await tab(page, 'Guards').click();
    const rows = box(page, 'What the chain recorded').locator('.trace li');

    await page.locator('#g-url').fill('http://2130706433/');
    await page.getByRole('button', { name: 'Check URL' }).click();
    await expect(latest(page)).toContainText('non_public_address');
    await expect(latest(page)).toContainText('127.0.0.1');

    await page.locator('#g-url').fill('http://169.254.169.254/latest/meta-data/');
    await page.getByRole('button', { name: 'Check URL' }).click();
    await expect(latest(page)).toContainText('169.254.169.254');
    await expect(rows).toHaveCount(2);

    await page.locator('#g-url').fill('not a url');
    await page.getByRole('button', { name: 'Check URL' }).click();
    await expect(latest(page)).toContainText(/invalid_url|unresolvable/);
    await expect(rows).toHaveCount(2);

    await page.locator('#g-redirect').fill('//evil.example.test/login');
    await page.getByRole('button', { name: 'Check redirect' }).click();
    await expect(latest(page)).toContainText('origin');
    await expect(rows).toHaveCount(3);
    await expect(box(page, 'What the chain recorded')).toContainText('ssrf_attempt');
    await expect(box(page, 'What the chain recorded')).toContainText('open_redirect_attempt');
  });

  test('whisper to the analyst: injected text never reaches a model, probing becomes one proposal a person approves', async ({
    page,
  }) => {
    const problems = watch(page, { allowStatus: REFUSALS });
    await signIn(page);
    await play(page, 'Prompt injection');
    await expect(cards(page).filter({ hasText: 'Played: Prompt injection' })).toContainText('never reaches a model');
    await play(page, 'Probing');
    await tab(page, 'Analyst').click();
    await page.getByRole('button', { name: 'Analyse' }).click();
    // Probing and the injected text come from two addresses, so there are two proposals; this test follows the first.
    await expect(active(page).locator('.trace li').filter({ hasText: 'block ip' })).toHaveCount(2);
    const proposal = active(page)
      .locator('.trace li')
      .filter({ hasText: 'block ip' })
      .filter({ hasText: '198.51.100.200' });
    await expect(proposal).toHaveCount(1);
    await expect(proposal).toContainText('pending');

    await proposal.getByRole('button', { name: 'Show the rows it cites' }).click();
    await expect(proposal).toContainText('ssrf_attempt');

    // Not blocked yet: the analyst proposed, nobody decided.
    await tab(page, 'Attack').click();
    await page.locator('#v-ip').fill('198.51.100.200');
    await page.getByRole('button', { name: 'Request the resource' }).click();
    await expect(latest(page)).toContainText('quarterly-report');

    await tab(page, 'Analyst').click();
    await fillCode(page, 'an');
    await proposal.getByRole('button', { name: 'Approve', exact: true }).click();
    await expect(proposal).toContainText('executed');

    await tab(page, 'Attack').click();
    await page.getByRole('button', { name: 'Request the resource' }).click();
    await expect(latest(page)).toContainText('403');
    expect(problems).toEqual([]);
  });

  test('a rejected proposal needs only the network, and is not proposed again without newer evidence', async ({
    page,
  }) => {
    await signIn(page);
    await play(page, 'Probing');
    await tab(page, 'Analyst').click();
    await page.getByRole('button', { name: 'Analyse' }).click();
    const proposal = active(page).locator('.trace li').filter({ hasText: 'block ip' });
    await proposal.getByRole('button', { name: 'Reject', exact: true }).click();
    await expect(proposal).toContainText('rejected');
    await page.getByRole('button', { name: 'Analyse' }).click();
    await expect(box(page, /1 · Ask the analyst/)).toContainText('you rejected the same thing');
    await expect(active(page).locator('.trace li').filter({ hasText: 'pending' })).toHaveCount(0);
  });

  test('travel faster than a plane: flagged with both numbers, suspended only after a person approves', async ({
    page,
  }) => {
    const problems = watch(page, { allowStatus: REFUSALS });
    await signIn(page);
    await play(page, 'Impossible travel');
    await expect(cards(page).filter({ hasText: 'Played: Impossible travel' })).toContainText('Tokyo');
    await tab(page, 'Analyst').click();
    await page.getByRole('button', { name: 'Analyse' }).click();
    // A single impossible journey is critical in the playbook, so the analyst also proposes a lockdown. A person
    // approves the proportionate step and turns the sledgehammer down.
    await expect(active(page).locator('.trace li').filter({ hasText: 'lockdown' })).toHaveCount(1);
    const proposal = active(page).locator('.trace li').filter({ hasText: 'suspend subject' });
    await expect(proposal).toContainText('ana@example.test');

    await tab(page, 'Attack').click();
    await page.locator('#v-ip').fill('203.0.113.5');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(latest(page)).toContainText('200'); // not suspended yet

    await tab(page, 'Analyst').click();
    await fillCode(page, 'an');
    await proposal.getByRole('button', { name: 'Approve', exact: true }).click();
    await expect(proposal).toContainText('executed');

    await tab(page, 'Attack').click();
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(latest(page)).toContainText('suspended');
    expect(problems).toEqual([]);
  });

  test('wait it out: a block expires when the clock passes it, without waiting', async ({ page }) => {
    const problems = watch(page, { allowStatus: REFUSALS });
    await signIn(page);
    await play(page, 'Credential stuffing');
    await tab(page, 'Time').click();
    await page.getByRole('button', { name: 'Request the resource' }).click();
    await expect(latest(page)).toContainText('403');
    await page.getByRole('button', { name: '+61 minutes' }).click();
    await page.getByRole('button', { name: 'Request the resource' }).click();
    await expect(latest(page)).toContainText('quarterly-report');
    expect(problems).toEqual([]);
  });

  test('lockdown refuses the protected application and nothing else', async ({ page }) => {
    const problems = watch(page, { allowStatus: REFUSALS });
    await signIn(page);
    await tab(page, 'Humans').click();
    await fillCode(page, 'hu');
    await page.getByRole('button', { name: 'Lockdown on' }).click();
    await expect(latest(page)).toContainText('"ok": true');
    await expect(box(page, 'What the engine believes now')).toContainText('on');
    await tab(page, 'Attack').click();
    await page.getByRole('button', { name: 'Request the resource' }).click();
    await expect(latest(page)).toContainText('503');
    await expect(latest(page)).toContainText('lockdown');
    // The lab (and the SOC API behind the key) is still reachable.
    await expect(box(page, 'What the engine believes now')).toBeVisible();
    expect(problems).toEqual([]);
  });

  test('starting over empties the chain, the blocks and the clock', async ({ page }) => {
    await signIn(page);
    await play(page, 'Credential stuffing');
    await expect(box(page, 'What the engine believes now')).toContainText('203.0.113.77');
    await startOver(page);
    await expect(box(page, 'What the engine believes now')).toContainText('no address');
    await expect(box(page, 'What the engine believes now')).toContainText('0 entries');
  });
});

// Every tab, with something on it, in both themes.
for (const scheme of ['light', 'dark'] as const) {
  for (const name of ['Attack', 'Audit', 'Humans', 'Analyst', 'Guards', 'Time']) {
    test(`accessibility: the ${name} tab has no WCAG A/AA violations (${scheme})`, async ({ browser, request }) => {
      await resetLab(request);
      const context = await browser.newContext({ colorScheme: scheme, reducedMotion: 'reduce' });
      const page = await context.newPage();
      await signIn(page);
      await play(page, 'Probing');
      await tab(page, name).click();
      if (name === 'Analyst') await page.getByRole('button', { name: 'Analyse' }).click();
      await page.waitForTimeout(300);
      const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
      expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(' | ')}`)).toEqual(
        [],
      );
      await context.close();
    });
  }
}
