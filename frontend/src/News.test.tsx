import { afterEach, expect, test, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import News from "./News";

afterEach(cleanup);
test("enables a news subscription and filters a source-attributed story", async () => {
  const data = {
    settings: {
      enabled: false,
      sources: ["cisa"],
      notifications: false,
      destinations: [],
      categories: ["security", "vulnerability"],
    },
    sources: [{ id: "cisa", name: "CISA Advisories" }],
    items: [
      {
        id: "a",
        source: "cisa",
        title: "A zero-day vulnerability",
        url: "https://example.org/story",
        category: "vulnerability",
        published: null,
        discovered: 1,
        highlight: "Headline mentions a zero-day",
      },
    ],
  };
  const api = vi.fn(async () => data);
  render(
    <News
      api={api}
      connectors={[{ id: "telegram", name: "Telegram", enabled: true }]}
      onConnectors={() => {}}
    />,
  );
  expect(await screen.findByText("A zero-day vulnerability ↗")).toHaveAttribute(
    "href",
    "https://example.org/story",
  );
  fireEvent.change(screen.getByLabelText("Filter news"), {
    target: { value: "highlight" },
  });
  expect(screen.getByText("A zero-day vulnerability ↗")).toBeInTheDocument();
  fireEvent.click(screen.getByLabelText("Enable news collection"));
  fireEvent.click(screen.getByLabelText("Send new articles to connectors"));
  fireEvent.click(screen.getByLabelText("Telegram"));
  fireEvent.click(screen.getByRole("button", { name: "Save news settings" }));
  await waitFor(() =>
    expect(api).toHaveBeenCalledWith(
      "/news/settings",
      "PUT",
      expect.objectContaining({
        enabled: true,
        notifications: true,
        destinations: ["telegram"],
      }),
    ),
  );
});
