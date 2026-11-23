import { useEffect, useState, type FormEvent } from "react";

type Configuration = {
  enabled: boolean;
  provider: "openai" | "anthropic" | "openai_compatible";
  model: string;
  api_key_env: string;
  language: string;
  daily_request_limit: number;
  max_output_tokens: number;
};
type Usage = { day_utc: string; requests: number };
type Api = (path: string, method?: string, body?: unknown) => Promise<any>;

export default function AISettings({ api }: { api: Api }) {
  const [config, setConfig] = useState<Configuration | null>(null);
  const [saved, setSaved] = useState("");
  const [usage, setUsage] = useState<Usage | null>(null);
  const [endpointConfigured, setEndpointConfigured] = useState(false);
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [sample, setSample] = useState("");

  useEffect(() => {
    let current = true;
    api("/ai/settings")
      .then((data) => {
        if (!current) return;
        setConfig(data.settings);
        setSaved(JSON.stringify(data.settings));
        setUsage(data.usage);
        setEndpointConfigured(data.custom_endpoint_configured);
        setAllowPrivate(data.private_hosts_allowed);
      })
      .catch((reason) => {
        if (current) setError((reason as Error).message);
      });
    return () => {
      current = false;
    };
  }, [api]);

  async function save(event: FormEvent) {
    event.preventDefault();
    if (!config) return;
    setBusy(true);
    setMessage("");
    setError("");
    setSample("");
    try {
      const result = await api("/ai/settings", "PUT", config);
      setConfig(result.settings);
      setSaved(JSON.stringify(result.settings));
      setUsage(result.usage);
      setMessage("AI settings saved.");
    } catch (reason) {
      setError((reason as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function testConnection() {
    setBusy(true);
    setMessage("");
    setError("");
    setSample("");
    try {
      const result = await api("/ai/test", "POST");
      setUsage(result.usage);
      if (!result.ok) throw new Error(result.message);
      setMessage("Connection succeeded using a fictional test description.");
      setSample(result.summary);
    } catch (reason) {
      setError((reason as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!config)
    return (
      <div className="panel inline-empty" role="status">
        {error || "Loading AI settings…"}
      </div>
    );
  const dirty = JSON.stringify(config) !== saved;
  return (
    <section className="panel editor" aria-label="AI configuration">
      <div className="section-heading">
        <h2>Optional AI summaries</h2>
        <span className="badge">{config.enabled ? "Enabled" : "Off"}</span>
      </div>
      <form onSubmit={save}>
        <p className="editor-intro">
          Add a clearly labeled summary to relevant alerts. AI never decides
          whether a vulnerability matches your assets. If it is unavailable, the
          source-based alert still goes out.
        </p>
        <label className="check-label">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) =>
              setConfig({ ...config, enabled: e.target.checked })
            }
          />{" "}
          Include AI summaries in alerts
        </label>
        <p className="help">
          Only the CVE ID and public source description are sent to the selected
          provider after matching. Asset names, rules and destinations stay
          local. AI output can be wrong; verify the original sources.
        </p>
        <div className="form-grid">
          <label>
            API protocol
            <select
              aria-label="AI API protocol"
              value={config.provider}
              onChange={(e) =>
                setConfig({
                  ...config,
                  provider: e.target.value as Configuration["provider"],
                })
              }
            >
              <option value="openai">OpenAI Responses API</option>
              <option value="anthropic">Anthropic Messages API</option>
              <option value="openai_compatible">
                OpenAI-compatible Chat Completions
              </option>
            </select>
          </label>
          <label>
            Model name
            <input
              required={config.enabled}
              maxLength={128}
              placeholder="Enter your provider's model ID"
              value={config.model}
              onChange={(e) => setConfig({ ...config, model: e.target.value })}
            />
          </label>
        </div>
        <label>
          API key environment variable
          <input
            required
            pattern="VULNRELAY_AI_KEY[A-Z0-9_]*"
            value={config.api_key_env}
            onChange={(e) =>
              setConfig({ ...config, api_key_env: e.target.value })
            }
          />
        </label>
        <p className="help">
          Put the key in this server environment variable, not in the interface.
          Recreate both containers after editing .env. OpenAI-compatible local
          servers may work without a key.
        </p>
        {config.provider === "openai_compatible" && (
          <p className="help">
            Set the provider's base URL in VULNRELAY_AI_BASE_URL on the server,
            for example an endpoint ending in /v1. Status:{" "}
            {endpointConfigured ? "configured" : "not configured"}. Private
            server access is {allowPrivate ? "explicitly enabled" : "disabled"}.
            Providers must support Chat Completions.
          </p>
        )}
        <div className="form-grid">
          <label>
            Summary language
            <input
              required
              maxLength={30}
              value={config.language}
              onChange={(e) =>
                setConfig({ ...config, language: e.target.value })
              }
            />
          </label>
          <label>
            Maximum output tokens
            <input
              type="number"
              min={64}
              max={1024}
              required
              value={config.max_output_tokens}
              onChange={(e) =>
                setConfig({
                  ...config,
                  max_output_tokens: Number(e.target.value),
                })
              }
            />
          </label>
          <label>
            Maximum requests per UTC day
            <input
              type="number"
              min={0}
              max={500}
              required
              value={config.daily_request_limit}
              onChange={(e) =>
                setConfig({
                  ...config,
                  daily_request_limit: Number(e.target.value),
                })
              }
            />
          </label>
        </div>
        <p className="help">
          Used today ({usage?.day_utc || "UTC"}): {usage?.requests ?? 0}{" "}
          requests. Connection tests and failed requests count; cached summaries
          do not. This is a request cap, not a currency limit. Your provider may
          charge for input and output; set a spending limit there too.
        </p>
        {error && (
          <div className="alert error" role="alert">
            {error}
          </div>
        )}
        {message && (
          <div className="alert success" role="status">
            {message}
          </div>
        )}
        {sample && (
          <p className="help">AI test output (unverified): {sample}</p>
        )}
        <div className="form-actions">
          <button
            type="button"
            className="secondary"
            disabled={busy || dirty || !config.model}
            onClick={() => void testConnection()}
          >
            Test connection
          </button>
          <button className="primary" disabled={busy || !dirty}>
            Save AI settings
          </button>
        </div>
        {dirty && (
          <p className="help">
            Save your changes before testing. The test sends a fictional
            description and may incur provider charges.
          </p>
        )}
      </form>
    </section>
  );
}
