import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("Telegram assistant verifies the bot, selects a chat and tracks the test on mobile", async ({
  page,
}) => {
  const connectors: object[] = [];
  const bot = { id: "123456", username: "relay_test_bot", name: "News bot" };
  await page.route("**/api/config/connectors", async (route) => {
    if (route.request().method() === "POST") {
      const document = route.request().postDataJSON();
      expect(document.token_env).toBe("TELEGRAM_NEWS_BOT_TOKEN");
      expect(document.chat_id).toBe("42");
      const saved = { id: "wizard-connector", ...document };
      connectors.push(saved);
      await route.fulfill({ status: 201, json: saved });
    } else await route.fulfill({ json: connectors });
  });
  await page.route("**/api/telegram/setup/probe", (route) => {
    expect(route.request().postDataJSON().token_env).toBe(
      "TELEGRAM_NEWS_BOT_TOKEN",
    );
    return route.fulfill({
      json: {
        ok: true,
        bot,
        webhook_active: false,
        chats:
          route.request().postDataJSON().mode === "chats"
            ? [{ id: "42", name: "Operator", type: "private" }]
            : [],
      },
    });
  });
  await page.route("**/api/connectors/wizard-connector/test", (route) =>
    route.fulfill({ status: 202, json: { queued: "wizard-test" } }),
  );
  await page.route("**/api/deliveries/wizard-test", (route) =>
    route.fulfill({ json: { id: "wizard-test", state: "sent" } }),
  );
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await page.getByRole("button", { name: "Connectors", exact: true }).click();
  await page
    .getByRole("button", { name: "Set up Telegram", exact: true })
    .click();
  const assistant = page.getByRole("region", {
    name: "Telegram setup assistant",
  });
  await assistant
    .getByLabel("Token environment variable")
    .fill("TELEGRAM_NEWS_BOT_TOKEN");
  await assistant
    .getByRole("button", { name: "Check bot", exact: true })
    .click();
  await expect(
    assistant.getByRole("link", { name: "open this bot in Telegram" }),
  ).toHaveAttribute(
    "href",
    "https://t.me/relay_test_bot?start=vulnrelay_setup",
  );
  await assistant
    .getByRole("button", { name: "Find chats", exact: true })
    .click();
  await assistant
    .getByRole("combobox", { name: "Recent chats" })
    .selectOption("42");
  await assistant
    .getByRole("button", { name: "Continue", exact: true })
    .click();
  const accessibility = await new AxeBuilder({ page })
    .include(".telegram-setup")
    .analyze();
  expect(accessibility.violations).toEqual([]);
  await assistant
    .getByRole("button", { name: "Save connector and send test" })
    .click();
  await expect(
    assistant.getByText("Telegram accepted the test message."),
  ).toBeVisible();
  expect(connectors).toHaveLength(1);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBeTruthy();
  await assistant.screenshot({
    path: "test-results/telegram-setup-mobile.png",
  });
  await assistant
    .getByRole("button", { name: "Finish setup", exact: true })
    .click();
  await expect(assistant).toHaveCount(0);
});
