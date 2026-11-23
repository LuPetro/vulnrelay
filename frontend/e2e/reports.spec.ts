import { expect, test } from "@playwright/test";

test("configure and preview a scheduled personal report", async ({
  page,
  request,
}) => {
  const headers = { "x-vulnrelay-request": "1" };
  const connector = await (
    await request.post("/api/config/connectors", {
      headers,
      data: { name: "E2E report channel", chat_id: "-123456" },
    })
  ).json();
  let reportId = "";
  try {
    await page.goto("/");
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "Reports", exact: true })
      .click();
    await page.getByRole("button", { name: "Add report" }).click();
    await page.getByLabel("Report name").fill("Weekly team report");
    await page
      .getByRole("combobox", { name: "Coverage" })
      .selectOption("relevant");
    await page.getByRole("combobox", { name: "Weekday" }).selectOption("4");
    await page.getByLabel("Local time").fill("17:00");
    await page.getByLabel("IANA timezone").fill("Europe/Vienna");
    await page.getByLabel("E2E report channel").check();
    const response = page.waitForResponse(
      (r) =>
        r.url().endsWith("/api/digests") && r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Save report" }).click();
    const created = await (await response).json();
    reportId = created.id;
    expect(created).toMatchObject({
      scope: "relevant",
      frequency: "weekly",
      weekday: 4,
      timezone: "Europe/Vienna",
      time: "17:00",
    });
    await expect(
      page.getByText("Weekly team report", { exact: true }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Preview" }).click();
    await expect(
      page.getByRole("heading", {
        name: "Report preview · Weekly team report",
      }),
    ).toBeVisible();
    await expect(page.getByText(/Coverage can be incomplete/)).toBeVisible();
    await page.reload();
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "Reports", exact: true })
      .click();
    await expect(
      page.getByText("Weekly team report", { exact: true }),
    ).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBeTruthy();
  } finally {
    if (reportId) await request.delete(`/api/digests/${reportId}`, { headers });
    await request.delete(`/api/config/connectors/${connector.id}`, { headers });
  }
});
