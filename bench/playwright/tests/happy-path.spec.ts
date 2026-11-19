import { test, expect, Page } from '@playwright/test';
import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';

// Legitimate-user happy path through OWASP Juice Shop: register, log in,
// search, add to basket, check out. It behaves like a person in a browser
// (static assets, cookies, the Angular app's own API calls) so the recorded
// corpus looks like real traffic.
//
// Every value typed in is fake and generated per run. They are written to
// RESULTS_DIR/typed-values-<run>.json so the lab can check that none of them
// reached the stored corpus unredacted.

const run = randomBytes(4).toString('hex');
const user = {
  email: `shopper.${run}@lab.test`,
  password: `Shop-${randomBytes(6).toString('hex')}-Pw`,
  answer: `Answer${randomBytes(3).toString('hex')}`,
  name: `Lab Shopper ${run}`,
  mobile: '5550104242',
  zip: '10115',
  street: `${run} Example Street`,
  city: 'Labtown',
  state: 'Labstate',
  country: 'Labland',
  card: '4111111111111111', // well-known test number, passes Luhn
  cardName: `Lab Cardholder ${run}`,
};

function saveTypedValues() {
  const dir = process.env.RESULTS_DIR ?? 'out';
  mkdirSync(dir, { recursive: true });
  writeFileSync(`${dir}/typed-values-${run}.json`, JSON.stringify(user, null, 2));
}

async function dismissOverlays(page: Page) {
  const welcome = page.getByRole('button', { name: 'Close Welcome Banner' });
  if (await welcome.isVisible().catch(() => false)) await welcome.click();
  const cookies = page.getByRole('button', { name: 'dismiss cookie message' });
  if (await cookies.isVisible().catch(() => false)) await cookies.click();
}

// Checkout pages list choices as table rows with a radio button. Pick the
// row containing text, or the first selectable row.
async function selectRow(page: Page, text?: string) {
  let rows = page.getByRole('row').filter({ has: page.getByRole('radio') });
  if (text) rows = rows.filter({ hasText: text });
  await rows.first().getByRole('radio').click();
}

// Each checkout page ends with a button to the next step.
async function nextStep(page: Page) {
  await page.getByRole('button', { name: /^(Continue|Proceed)/ }).first().click();
}

test('register, log in, search, add to basket, check out', async ({ page }) => {
  saveTypedValues();

  await test.step('open the shop', async () => {
    await page.goto('/');
    await expect(page.getByRole('button', { name: 'Close Welcome Banner' })).toBeVisible();
    await dismissOverlays(page);
  });

  await test.step('register', async () => {
    await page.goto('/#/register');
    await page.locator('#emailControl').fill(user.email);
    await page.locator('#passwordControl').fill(user.password);
    await page.locator('#repeatPasswordControl').fill(user.password);
    await page.getByRole('combobox', { name: 'Selection list for the security question' }).click();
    await page.getByRole('option').first().click();
    await page.locator('#securityAnswerControl').fill(user.answer);
    await page.locator('#registerButton').click();
    await expect(page).toHaveURL(/#\/login/);
  });

  await test.step('log in', async () => {
    await page.locator('#email').fill(user.email);
    await page.locator('#password').fill(user.password);
    await page.locator('#loginButton').click();
    await expect(page).toHaveURL(/#\/search/);
  });

  await test.step('search', async () => {
    await page.locator('#searchQuery').click();
    await page.locator('#searchQuery input').fill('apple');
    await page.locator('#searchQuery input').press('Enter');
    await expect(page).toHaveURL(/q=apple/);
    await expect(page.locator('mat-card').first()).toBeVisible();
  });

  await test.step('add to basket', async () => {
    await page.getByRole('button', { name: 'Add to Basket' }).first().click();
    await expect(page.locator('.fa-layers-counter')).toHaveText('1');
  });

  await test.step('check out', async () => {
    await page.getByRole('button', { name: 'Show the shopping cart' }).click();
    await expect(page).toHaveURL(/#\/basket/);
    await page.locator('#checkoutButton').click();

    // Address
    await expect(page).toHaveURL(/#\/address\/select/);
    await page.getByRole('button', { name: 'Add New Address' }).click();
    await page.getByPlaceholder('Please provide a country.').fill(user.country);
    await page.getByPlaceholder('Please provide a name.').fill(user.name);
    await page.getByPlaceholder('Please provide a mobile number.').fill(user.mobile);
    await page.getByPlaceholder('Please provide a ZIP code.').fill(user.zip);
    await page.locator('#address').fill(user.street);
    await page.getByPlaceholder('Please provide a city.').fill(user.city);
    await page.getByPlaceholder('Please provide a state.').fill(user.state);
    await page.locator('#submitButton').click();
    await selectRow(page, user.name);
    await nextStep(page);

    // Delivery
    await expect(page).toHaveURL(/#\/delivery-method/);
    await selectRow(page);
    await nextStep(page);

    // Payment: add a card, select it
    await expect(page).toHaveURL(/#\/payment\/shop/);
    await page.getByText('Add new card').click();
    await page.getByLabel('Name').fill(user.cardName);
    await page.getByLabel('Card Number').fill(user.card);
    await page.getByLabel('Expiry Month').selectOption('12');
    await page.getByLabel('Expiry Year').selectOption({ index: 5 });
    await page.locator('#submitButton').click();
    await selectRow(page, '1111');
    await nextStep(page);

    // Review and place the order
    await expect(page).toHaveURL(/#\/order-summary/);
    await page.locator('#checkoutButton').click();
    await expect(page).toHaveURL(/#\/order-completion\//);
    await expect(page.getByText('Thank you for your purchase!')).toBeVisible();
  });
});
