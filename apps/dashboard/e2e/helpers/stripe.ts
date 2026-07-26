import { Page, expect } from "@playwright/test";

/**
 * Fills in Stripe Checkout page with a test card and submits.
 * Must be called when page is on checkout.stripe.com.
 *
 * On Stripe Checkout (full page), card fields are regular textboxes
 * on the page — NOT inside iframes like embedded Stripe Elements.
 *
 * Test cards:
 *   4242424242424242 — always succeeds
 *   4000000000000002 — always declines
 */
export async function fillStripeCheckout(
  page: Page,
  opts: {
    cardNumber?: string;
    email?: string;
  } = {},
) {
  const cardNumber = opts.cardNumber ?? "4242424242424242";

  // Wait for Stripe Checkout to load
  await page.waitForURL(/checkout\.stripe\.com/, { timeout: 30000 });

  // Wait for the card number field to be visible (page fully loaded)
  const cardField = page.getByRole("textbox", { name: "Card number" });
  await cardField.waitFor({ state: "visible", timeout: 15000 });

  // If email field is visible and empty, fill it
  const emailField = page.getByRole("textbox", { name: "Email" });
  if (await emailField.isVisible({ timeout: 3000 }).catch(() => false)) {
    const emailValue = await emailField.inputValue();
    if (!emailValue && opts.email) {
      await emailField.fill(opts.email);
    }
  }

  // Card number — regular textbox on Stripe Checkout page
  await cardField.fill(cardNumber);

  // Expiry
  await page.getByRole("textbox", { name: "Expiration" }).fill("12/30");

  // CVC
  await page.getByRole("textbox", { name: "CVC" }).fill("123");

  // Cardholder name (if visible)
  const nameField = page.getByRole("textbox", { name: "Cardholder name" });
  if (await nameField.isVisible({ timeout: 2000 }).catch(() => false)) {
    await nameField.fill("E2E Billing");
  }

  // Submit — button text varies: "Start trial", "Subscribe", "Pay"
  await page.getByRole("button", { name: /start trial|subscribe|pay/i }).click();
}

/**
 * Waits for Stripe Checkout to show a decline error.
 * Stripe shows "Your card was declined" or similar text.
 */
export async function expectStripeDecline(page: Page) {
  // Stripe shows an inline error when card is declined — match by text or error selectors
  await expect(
    page.getByText(/declined|failed|not completed|unable to process/i).first(),
  ).toBeVisible({ timeout: 30000 });
}
