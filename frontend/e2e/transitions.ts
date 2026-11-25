import type { Page } from "@playwright/test";

// Contrast checks should evaluate the settled theme while keeping real transitions enabled.
export async function waitForUiTransitions(page: Page) {
  await page.evaluate(async () => {
    await Promise.all(
      document
        .getAnimations()
        .filter((animation) => animation instanceof CSSTransition)
        .map((animation) => animation.finished.catch(() => undefined)),
    );
  });
}
