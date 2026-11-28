import { afterEach, expect, test, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import TelegramSetup from "./TelegramSetup";

afterEach(cleanup);
const bot = { id: "123456", username: "relay_test_bot", name: "News" };
const chat = { id: "42", name: "Operator", type: "private" };
const success = { ok: true, bot, webhook_active: false, chats: [chat] };

async function chooseChat() {
  fireEvent.click(screen.getByRole("button", { name: "Check bot" }));
  await screen.findByText("@relay_test_bot");
  fireEvent.click(screen.getByRole("button", { name: "Find chats" }));
  fireEvent.change(
    await screen.findByRole("combobox", { name: "Recent chats" }),
    { target: { value: "42" } },
  );
  fireEvent.click(screen.getByRole("button", { name: "Continue" }));
}

test("guides bot and chat selection and waits for confirmed test delivery", async () => {
  let checks = 0;
  const saved = vi.fn();
  const api = vi.fn(async (path: string, method?: string) => {
    if (path === "/telegram/setup/probe") return success;
    if (path === "/config/connectors" && method === "POST")
      return { id: "connector" };
    if (path === "/connectors/connector/test")
      return { queued: "test-message" };
    if (path === "/deliveries/test-message")
      return { state: ++checks > 1 ? "sent" : "pending" };
    throw new Error("Unexpected request");
  });
  render(<TelegramSetup api={api} onSaved={saved} onClose={() => {}} />);
  fireEvent.change(screen.getByLabelText("Token environment variable"), {
    target: { value: "TELEGRAM_NEWS_BOT_TOKEN" },
  });
  await chooseChat();
  fireEvent.click(
    screen.getByRole("button", { name: "Save connector and send test" }),
  );
  await screen.findByText("Test status: pending");
  expect(
    screen.queryByText("Telegram accepted the test message."),
  ).not.toBeInTheDocument();
  expect(api).toHaveBeenCalledWith(
    "/config/connectors",
    "POST",
    expect.objectContaining({
      chat_id: "42",
      token_env: "TELEGRAM_NEWS_BOT_TOKEN",
      kind: "telegram",
    }),
  );
  expect(saved).toHaveBeenCalledOnce();
  fireEvent.click(screen.getByRole("button", { name: "Refresh test status" }));
  await screen.findByText("Telegram accepted the test message.");
  expect(
    screen.getByRole("button", { name: "Finish setup" }),
  ).toBeInTheDocument();
});

test("shows token rejection without pretending that the bot is connected", async () => {
  const api = vi.fn(async () => ({
    ok: false,
    message: "Telegram rejected this token.",
  }));
  render(<TelegramSetup api={api} onSaved={() => {}} onClose={() => {}} />);
  fireEvent.click(screen.getByRole("button", { name: "Check bot" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Telegram rejected this token.",
  );
  expect(
    screen.queryByRole("button", { name: "Find chats" }),
  ).not.toBeInTheDocument();
});

test("allows manual destination entry when a webhook prevents discovery", async () => {
  const api = vi.fn(async () => ({
    ...success,
    webhook_active: true,
    chats: [],
  }));
  render(<TelegramSetup api={api} onSaved={() => {}} onClose={() => {}} />);
  fireEvent.click(screen.getByRole("button", { name: "Check bot" }));
  await screen.findByText(/This bot has an active webhook/);
  expect(
    screen.queryByRole("button", { name: "Find chats" }),
  ).not.toBeInTheDocument();
  fireEvent.change(
    screen.getByLabelText("Chat ID or public channel username"),
    { target: { value: "@news_channel" } },
  );
  fireEvent.click(screen.getByRole("button", { name: "Continue" }));
  expect(
    screen.getByRole("button", { name: "Save connector and send test" }),
  ).toBeInTheDocument();
});

test("explains an empty chat list and permits a manual ID", async () => {
  const api = vi.fn(async () => ({ ...success, chats: [] }));
  render(<TelegramSetup api={api} onSaved={() => {}} onClose={() => {}} />);
  fireEvent.click(screen.getByRole("button", { name: "Check bot" }));
  await screen.findByText("@relay_test_bot");
  fireEvent.click(screen.getByRole("button", { name: "Find chats" }));
  await screen.findByText(/No recent chats found/);
  fireEvent.change(
    screen.getByLabelText("Chat ID or public channel username"),
    { target: { value: "-1001234567890" } },
  );
  fireEvent.click(screen.getByRole("button", { name: "Continue" }));
  expect(
    screen.getByRole("button", { name: "Save connector and send test" }),
  ).toBeInTheDocument();
});

test("does not duplicate the saved connector when test enqueue needs a retry", async () => {
  let tests = 0;
  const api = vi.fn(async (path: string, method?: string) => {
    if (path === "/telegram/setup/probe") return success;
    if (path === "/config/connectors" && method === "POST")
      return { id: "connector" };
    if (path === "/connectors/connector/test") {
      if (++tests === 1) throw new Error("Connection lost");
      return { queued: "test-message" };
    }
    return { state: "sent" };
  });
  render(<TelegramSetup api={api} onSaved={() => {}} onClose={() => {}} />);
  await chooseChat();
  fireEvent.click(
    screen.getByRole("button", { name: "Save connector and send test" }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent("Connection lost");
  fireEvent.click(screen.getByRole("button", { name: "Send another test" }));
  await waitFor(() =>
    expect(
      screen.getByText("Telegram accepted the test message."),
    ).toBeInTheDocument(),
  );
  expect(
    api.mock.calls.filter(
      ([path, method]) => path === "/config/connectors" && method === "POST",
    ),
  ).toHaveLength(1);
});
