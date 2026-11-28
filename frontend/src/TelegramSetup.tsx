import { useEffect, useRef, useState, type FormEvent } from "react";
import ConnectorSchedule, {
  scheduleDescription,
  type DeliverySchedule,
} from "./ConnectorSchedule";
import "./telegram-setup.css";

type Api = (path: string, method?: string, body?: unknown) => Promise<any>;
type Bot = { id: string; username: string; name: string };
type Chat = { id: string; name: string; type: string };
type Delivery = {
  state: string;
  last_error?: string | null;
  available_at?: number;
};
const terminal = new Set(["sent", "failed", "cancelled", "dismissed"]);
const validVariable = (value: string) => /^[A-Z][A-Z0-9_]{0,99}$/.test(value);
const validChat = (value: string) =>
  /^(?:-?\d{1,30}|@[A-Za-z0-9_]{5,32})$/.test(value.trim());

export default function TelegramSetup({
  api,
  onSaved,
  onClose,
}: {
  api: Api;
  onSaved: () => void | Promise<void>;
  onClose: () => void;
}) {
  const [step, setStep] = useState(0);
  const [tokenEnv, setTokenEnv] = useState("TELEGRAM_BOT_TOKEN");
  const [bot, setBot] = useState<Bot | null>(null);
  const [chats, setChats] = useState<Chat[]>([]);
  const [discovered, setDiscovered] = useState(false);
  const [webhook, setWebhook] = useState(false);
  const [chatId, setChatId] = useState("");
  const [name, setName] = useState("");
  const [schedule, setSchedule] = useState<DeliverySchedule | null>(null);
  const [connectorId, setConnectorId] = useState<string | null>(null);
  const [testId, setTestId] = useState<string | null>(null);
  const [delivery, setDelivery] = useState<Delivery | null>(null);
  const [refresh, setRefresh] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [probeNotice, setProbeNotice] = useState("");
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    heading.current?.focus();
  }, [step]);
  useEffect(() => {
    if (!testId) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const result: Delivery = await api(`/deliveries/${testId}`);
        if (!active) return;
        setDelivery(result);
        setError("");
        if (!terminal.has(result.state))
          timer = setTimeout(() => void poll(), 2500);
      } catch (reason) {
        if (active) setError((reason as Error).message);
      }
    };
    void poll();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [api, testId, refresh]);

  async function inspect(mode: "bot" | "chats") {
    if (!validVariable(tokenEnv)) {
      setError("Enter the environment variable name, not the bot token.");
      return;
    }
    setBusy(true);
    setError("");
    setProbeNotice("");
    try {
      const result = await api("/telegram/setup/probe", "POST", {
        token_env: tokenEnv,
        mode,
      });
      if (!result.ok) {
        setError(
          result.message +
            (result.retry_after
              ? ` Try again in ${result.retry_after} seconds.`
              : ""),
        );
        return;
      }
      setBot(result.bot);
      setWebhook(result.webhook_active);
      if (mode === "bot") {
        if (!name)
          setName(
            `Telegram · ${result.bot.name || result.bot.username}`.slice(
              0,
              120,
            ),
          );
        setStep(1);
      } else {
        setChats(result.chats);
        setDiscovered(true);
        setProbeNotice(
          result.chats.length
            ? "Recent chats found. Select your destination below."
            : "No recent chats found. Send a new /start message to the bot shown above, then check again. A reply is not required.",
        );
      }
    } catch (reason) {
      setError((reason as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function saveAndTest(event: FormEvent) {
    event.preventDefault();
    if (!bot || !validChat(chatId) || !name.trim()) return;
    setBusy(true);
    setError("");
    try {
      let id = connectorId;
      if (!id) {
        const saved = await api("/config/connectors", "POST", {
          name: name.trim(),
          kind: "telegram",
          enabled: true,
          token_env: tokenEnv,
          chat_id: chatId.trim(),
          min_interval_seconds: 3.1,
          delivery_schedule: schedule,
        });
        id = saved.id;
        setConnectorId(id);
        void onSaved();
      }
      const queued = await api(`/connectors/${id}/test`, "POST");
      setDelivery({ state: "pending" });
      setTestId(queued.queued);
    } catch (reason) {
      setError((reason as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section
      className="panel telegram-setup"
      aria-label="Telegram setup assistant"
    >
      <div className="section-heading">
        <h2>Set up Telegram</h2>
        <button className="secondary" type="button" onClick={onClose}>
          Close setup
        </button>
      </div>
      <div className="telegram-setup-body">
        <ol className="telegram-setup-progress" aria-label="Setup progress">
          {["Check bot", "Choose chat", "Send test"].map((label, index) => (
            <li key={label} aria-current={step === index ? "step" : undefined}>
              <span>{String(index + 1).padStart(2, "0")}</span> {label}
            </li>
          ))}
        </ol>
        {error && (
          <div className="alert error" role="alert">
            {error}
          </div>
        )}
        <h3 ref={heading} tabIndex={-1}>
          {
            [
              "Connect your bot",
              "Where should messages go?",
              "Save and test your destination",
            ][step]
          }
        </h3>
        {step === 0 && (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void inspect("bot");
            }}
          >
            <p className="help">
              Use an existing bot or create one with{" "}
              <a
                href="https://t.me/BotFather"
                target="_blank"
                rel="noopener noreferrer"
              >
                @BotFather
              </a>
              . This check confirms which bot the server token belongs to.
            </p>
            <label>
              Token environment variable
              <input
                required
                maxLength={100}
                value={tokenEnv}
                list="telegram-token-variables"
                autoComplete="off"
                spellCheck={false}
                disabled={busy}
                onChange={(event) => {
                  setTokenEnv(event.target.value);
                  setBot(null);
                  setChats([]);
                  setDiscovered(false);
                  setChatId("");
                  setError("");
                }}
              />
            </label>
            <datalist id="telegram-token-variables">
              <option value="TELEGRAM_BOT_TOKEN" />
              <option value="TELEGRAM_NEWS_BOT_TOKEN" />
            </datalist>
            <details className="telegram-setup-help">
              <summary>Where do I put the token?</summary>
              <p>
                In BotFather, use /mybots, choose your bot and open API Token.
                Add the complete token to the server's existing .env file using
                the variable name above. For a second bot, choose a separate
                variable such as TELEGRAM_NEWS_BOT_TOKEN.
              </p>
              {validVariable(tokenEnv) && (
                <pre>{`${tokenEnv}=YOUR_BOT_TOKEN`}</pre>
              )}
              <p>
                Then recreate both containers from your installation folder:
              </p>
              <pre>docker compose up -d --force-recreate --wait</pre>
              <p>
                Keep the actual token on the server. This form accepts its
                variable name only.
              </p>
            </details>
            <div className="form-actions">
              <button
                className="primary"
                disabled={busy || !validVariable(tokenEnv)}
              >
                Check bot
              </button>
            </div>
          </form>
        )}
        {step === 1 && bot && (
          <>
            <p className="telegram-bot-identity" role="status">
              Connected bot: <strong>@{bot.username}</strong>
              {bot.name && ` · ${bot.name}`}
            </p>
            <p className="help">
              For a private chat,{" "}
              <a
                href={`https://t.me/${bot.username}?start=vulnrelay_setup`}
                target="_blank"
                rel="noopener noreferrer"
              >
                open this bot in Telegram
              </a>
              , press Start or send /start, then choose Find chats. The bot does
              not need to reply.
            </p>
            <details className="telegram-setup-help">
              <summary>Using a group or channel?</summary>
              <p>
                Add the bot to the group, then send /start@{bot.username}. For a
                channel, add the bot as an administrator with permission to
                post, and publish a new channel message. You can also enter a
                known chat ID or a public channel username below.
              </p>
            </details>
            {webhook ? (
              <p className="alert" role="status">
                This bot has an active webhook. Automatic discovery is
                unavailable; enter the chat ID manually. Your existing
                integration stays connected.
              </p>
            ) : (
              <button
                type="button"
                className="secondary"
                disabled={busy}
                onClick={() => void inspect("chats")}
              >
                {busy ? "Finding chats…" : "Find chats"}
              </button>
            )}
            {probeNotice && (
              <p className="help" role="status">
                {probeNotice}
              </p>
            )}
            {discovered && chats.length > 0 && (
              <label>
                Recent chats
                <select
                  aria-label="Recent chats"
                  value={chats.some((chat) => chat.id === chatId) ? chatId : ""}
                  onChange={(event) => setChatId(event.target.value)}
                >
                  <option value="">Choose a chat</option>
                  {chats.map((chat) => (
                    <option key={chat.id} value={chat.id}>
                      {chat.name} · {chat.type} · {chat.id}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <label>
              Chat ID or public channel username
              <input
                value={chatId}
                onChange={(event) => setChatId(event.target.value)}
                placeholder="123456789, -1001234567890 or @channel_name"
                maxLength={33}
                spellCheck={false}
              />
            </label>
            <p className="help">
              Discovery reads only recent updates without acknowledging them.
              Another bot integration or an older message can leave this list
              empty. For the same personal Telegram account, an existing
              private-chat ID can be reused after starting this bot.
            </p>
            <div className="form-actions">
              <button
                type="button"
                className="secondary"
                disabled={busy}
                onClick={() => {
                  setStep(0);
                  setError("");
                }}
              >
                Back
              </button>
              <button
                type="button"
                className="primary"
                disabled={busy || !validChat(chatId)}
                onClick={() => {
                  setStep(2);
                  setError("");
                }}
              >
                Continue
              </button>
            </div>
          </>
        )}
        {step === 2 && bot && (
          <form onSubmit={(event) => void saveAndTest(event)}>
            <p className="help">
              Bot @{bot.username} → {chatId}
            </p>
            <label>
              Connector name
              <input
                required
                maxLength={120}
                value={name}
                disabled={Boolean(connectorId) || busy}
                onChange={(event) => setName(event.target.value)}
              />
            </label>
            {!connectorId && (
              <ConnectorSchedule value={schedule} onChange={setSchedule} />
            )}
            <p className="help">
              Delivery hours: {scheduleDescription(schedule)}. The test uses the
              normal queue, delivery hours and rate limits. Keep the monitor
              running.
            </p>
            {connectorId && (
              <p className="help">
                Connector saved. Select it in News or your notification rules to
                receive alerts.
              </p>
            )}
            {delivery && (
              <div className="telegram-test-status" role="status">
                {delivery.state === "sent" ? (
                  <>
                    <strong>Telegram accepted the test message.</strong>
                    <p>
                      Check the selected chat to confirm that you received it.
                    </p>
                  </>
                ) : (
                  <>
                    <strong>Test status: {delivery.state}</strong>
                    <p>
                      {delivery.last_error ||
                        "Waiting for the monitor. Delivery hours and provider limits may delay the test."}
                    </p>
                    {delivery.last_error?.includes("403") && (
                      <p>
                        Start this bot in the selected private chat, or check
                        its membership and posting permissions in your group or
                        channel.
                      </p>
                    )}
                  </>
                )}
              </div>
            )}
            <div className="form-actions">
              {!connectorId && (
                <button
                  type="button"
                  className="secondary"
                  disabled={busy}
                  onClick={() => setStep(1)}
                >
                  Back
                </button>
              )}
              {testId && (
                <button
                  type="button"
                  className="secondary"
                  disabled={busy}
                  onClick={() => setRefresh((value) => value + 1)}
                >
                  Refresh test status
                </button>
              )}
              {(!testId ||
                (delivery &&
                  terminal.has(delivery.state) &&
                  delivery.state !== "sent")) && (
                <button className="primary" disabled={busy || !name.trim()}>
                  {connectorId
                    ? "Send another test"
                    : "Save connector and send test"}
                </button>
              )}
              {connectorId && (
                <button type="button" className="secondary" onClick={onClose}>
                  {delivery?.state === "sent" ? "Finish setup" : "Finish later"}
                </button>
              )}
            </div>
          </form>
        )}
      </div>
    </section>
  );
}
