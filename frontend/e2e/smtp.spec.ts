import { expect, test } from "@playwright/test";

test("configure an email connector using environment references", async ({
  page,
  request,
}) => {
  let id = "";
  try {
    await page.goto("/");
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "Connectors", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Add connector", exact: true })
      .click();
    await page.getByLabel("Name", { exact: true }).fill("E2E email");
    await page.getByLabel("Connector type").selectOption("smtp");
    await page.getByLabel("Sender email address").fill("alerts@example.org");
    await page.getByLabel("Recipient email address").fill("team@example.org");
    await expect(
      page.getByLabel("SMTP password environment variable"),
    ).toHaveValue("VULNRELAY_SMTP_PASSWORD");
    await expect(
      page.getByText(/STARTTLS and a valid server certificate are required/),
    ).toBeVisible();
    const response = page.waitForResponse(
      (r) =>
        r.url().endsWith("/api/config/connectors") &&
        r.request().method() === "POST",
    );
    await page
      .getByRole("button", { name: "Save connector", exact: true })
      .click();
    const saved = await (await response).json();
    id = saved.id;
    expect(saved).toMatchObject({
      kind: "smtp",
      smtp_to: "team@example.org",
      smtp_password_env: ["VULNRELAY", "SMTP", "PASSWORD"].join("_"),
    });
    await expect(page.getByText("E2E email", { exact: true })).toBeVisible();
  } finally {
    if (id)
      await request.delete(`/api/config/connectors/${id}`, {
        headers: { "x-vulnrelay-request": "1" },
      });
  }
});
