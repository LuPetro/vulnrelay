import { expect, test } from "@playwright/test";

test("add an exact package version without contacting OSV", async ({
  page,
  request,
}) => {
  let assetId = "";
  try {
    await page.goto("/");
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "Assets", exact: true })
      .click();
    await page.getByRole("button", { name: "Add asset", exact: true }).click();
    await page.getByLabel("Name", { exact: true }).fill("E2E Django package");
    await page.getByLabel("Match by").selectOption("package");
    await page.getByLabel("Package ecosystem").selectOption("PyPI");
    await page.getByLabel("Package name").fill("django");
    await page.getByLabel("Exact installed version").fill("5.1.2");
    await expect(
      page.getByText(/package identity and version are sent to OSV.dev/),
    ).toBeVisible();
    const response = page.waitForResponse(
      (r) =>
        r.url().endsWith("/api/config/assets") &&
        r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Save asset", exact: true }).click();
    const saved = await (await response).json();
    assetId = saved.id;
    expect(saved).toMatchObject({
      kind: "package",
      ecosystem: "PyPI",
      package: "django",
      version: "5.1.2",
    });
    await expect(
      page.getByText("E2E Django package", { exact: true }),
    ).toBeVisible();
    await expect(page.getByText(/PyPI django 5.1.2/)).toBeVisible();
  } finally {
    if (assetId)
      await request.delete(`/api/config/assets/${assetId}`, {
        headers: { "x-vulnrelay-request": "1" },
      });
  }
});
