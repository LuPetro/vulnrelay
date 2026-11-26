import { useEffect, useState, type FormEvent } from "react";

type Api = (path: string, method?: string, body?: unknown) => Promise<any>;
type Connector = { id: string; name: string; enabled: boolean };
type Config = {
  enabled: boolean;
  sources: string[];
  notifications: boolean;
  destinations: string[];
  categories: string[];
};
type Source = {
  id: string;
  name: string;
  last_success?: number | null;
  last_error?: string | null;
};
type Item = {
  id: string;
  source: string;
  title: string;
  url: string;
  category: string;
  published: string | null;
  discovered: number;
  highlight: string | null;
};
type Data = { settings: Config; sources: Source[]; items: Item[] };

export default function News({
  api,
  connectors,
  onConnectors,
}: {
  api: Api;
  connectors: Connector[];
  onConnectors: () => void;
}) {
  const [data, setData] = useState<Data | null>(null);
  const [draft, setDraft] = useState<Config | null>(null);
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    const load = () =>
      api("/news")
        .then((response: Data) => {
          if (active) {
            setData(response);
            setDraft((current) => current ?? response.settings);
          }
        })
        .catch((reason) => {
          if (active) setError((reason as Error).message);
        });
    void load();
    const timer = window.setInterval(() => void load(), 15000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [api]);
  const toggle = (
    key: "sources" | "destinations" | "categories",
    value: string,
  ) => {
    if (draft)
      setDraft({
        ...draft,
        [key]: draft[key].includes(value)
          ? draft[key].filter((item) => item !== value)
          : [...draft[key], value],
      });
  };
  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (!draft) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await api("/news/settings", "PUT", draft);
      setData(await api("/news"));
      setNotice(
        draft.enabled
          ? "News settings saved. The monitor will refresh enabled feeds shortly."
          : "News settings saved. News collection is paused.",
      );
    } catch (reason) {
      setError((reason as Error).message);
    } finally {
      setBusy(false);
    }
  };
  if (!data || !draft)
    return error ? (
      <div className="alert error" role="alert">
        {error}
      </div>
    ) : (
      <p>Loading news…</p>
    );
  const items = data.items.filter(
    (item) =>
      (filter === "all" ||
        (filter === "highlight" ? item.highlight : item.category === filter)) &&
      item.title.toLowerCase().includes(search.toLowerCase().trim()),
  );
  return (
    <>
      <p className="editor-intro">
        Follow reporting and advisories from selected sources. Headlines are
        grouped by simple keywords, not independently ranked or verified. News
        does not indicate that your assets are affected.
      </p>
      {error && (
        <div className="alert error" role="alert">
          {error}
        </div>
      )}
      {notice && (
        <div className="alert success" role="status">
          {notice}
        </div>
      )}
      <form
        className="panel editor news-settings"
        onSubmit={(event) => void save(event)}
      >
        <div className="section-heading">
          <h2>News subscriptions</h2>
        </div>
        <label className="news-check">
          <input
            type="checkbox"
            checked={draft.enabled}
            onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
          />{" "}
          Enable news collection
        </label>
        <p>
          Feeds are checked alongside the monitor. The first successful check
          establishes a baseline and does not send old articles.
        </p>
        <fieldset>
          <legend>Sources</legend>
          {data.sources.map((source) => (
            <label className="news-check" key={source.id}>
              <input
                type="checkbox"
                checked={draft.sources.includes(source.id)}
                onChange={() => toggle("sources", source.id)}
              />{" "}
              {source.name}{" "}
              <span className="news-source-status">
                {source.last_error
                  ? "· Last check failed"
                  : source.last_success
                    ? `· Updated ${new Date(source.last_success * 1000).toLocaleString()}`
                    : "· Not checked yet"}
              </span>
            </label>
          ))}
        </fieldset>
        <label className="news-check">
          <input
            type="checkbox"
            checked={draft.notifications}
            onChange={(e) =>
              setDraft({ ...draft, notifications: e.target.checked })
            }
          />{" "}
          Send new articles to connectors
        </label>
        {draft.notifications && (
          <>
            <fieldset>
              <legend>Topics</legend>
              <label className="news-check">
                <input
                  type="checkbox"
                  checked={draft.categories.includes("security")}
                  onChange={() => toggle("categories", "security")}
                />{" "}
                Security and threat news
              </label>
              <label className="news-check">
                <input
                  type="checkbox"
                  checked={draft.categories.includes("vulnerability")}
                  onChange={() => toggle("categories", "vulnerability")}
                />{" "}
                Vulnerability news
              </label>
            </fieldset>
            <fieldset>
              <legend>Destinations</legend>
              {connectors.length ? (
                connectors.map((connector) => (
                  <label className="news-check" key={connector.id}>
                    <input
                      type="checkbox"
                      checked={draft.destinations.includes(connector.id)}
                      onChange={() => toggle("destinations", connector.id)}
                    />{" "}
                    {connector.name}
                    {!connector.enabled && " (disabled)"}
                  </label>
                ))
              ) : (
                <button
                  type="button"
                  className="secondary"
                  onClick={onConnectors}
                >
                  Add a connector
                </button>
              )}
            </fieldset>
          </>
        )}
        <button className="primary" type="submit" disabled={busy}>
          Save news settings
        </button>
      </form>
      <section className="panel" aria-label="Latest security news">
        <div className="section-heading">
          <h2>Latest stories</h2>
          <select
            aria-label="Filter news"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          >
            <option value="all">All topics</option>
            <option value="highlight">Exploitation and zero-days</option>
            <option value="security">Security news</option>
            <option value="vulnerability">Vulnerability news</option>
          </select>
        </div>
        <div className="news-search">
          <input
            type="search"
            aria-label="Search headlines"
            placeholder="Search headlines or CVE IDs"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </div>
        {items.length === 0 ? (
          <div className="empty">
            <p>
              {data.items.length > 0
                ? "No stories match the current search or topic."
                : draft.enabled
                  ? "No stories yet. The monitor will check your selected feeds."
                  : "Enable news collection to follow the latest stories."}
            </p>
          </div>
        ) : (
          items.map((item) => (
            <article className="news-item" key={item.id}>
              <div className="news-meta">
                {data.sources.find((source) => source.id === item.source)
                  ?.name || item.source}{" "}
                ·{" "}
                {item.category === "vulnerability"
                  ? "Vulnerability news"
                  : "Security news"}{" "}
                ·{" "}
                {item.published
                  ? new Date(item.published).toLocaleString()
                  : "Publication date unknown"}
                {item.highlight && <> · {item.highlight}</>}
              </div>
              <h3>
                <a href={item.url} target="_blank" rel="noopener noreferrer">
                  {item.title} ↗
                </a>
              </h3>
            </article>
          ))
        )}
      </section>
    </>
  );
}
