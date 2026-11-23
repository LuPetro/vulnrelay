import { useEffect, useState, type FormEvent } from "react";

type Api = (path: string, method?: string, body?: unknown) => Promise<any>;
type Connector = { id: string; name: string; enabled: boolean };
type Config = {
  name: string;
  enabled: boolean;
  scope: "global" | "relevant";
  frequency: "daily" | "weekly";
  timezone: string;
  time: string;
  weekday: number;
  destinations: string[];
  min_cvss: number;
  item_limit: number;
};
type Report = Config & { id: string; next_run: number };
const initial = (): Config => ({
  name: "",
  enabled: true,
  scope: "global",
  frequency: "weekly",
  timezone: "UTC",
  time: "08:00",
  weekday: 0,
  destinations: [],
  min_cvss: 0,
  item_limit: 10,
});
const weekdays = [
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
  "Sunday",
];
function nextLabel(timestamp: number, timezone: string) {
  try {
    return new Date(timestamp * 1000).toLocaleString(undefined, {
      timeZone: timezone,
      timeZoneName: "short",
    });
  } catch {
    return new Date(timestamp * 1000)
      .toISOString()
      .replace("T", " ")
      .replace(".000Z", " UTC");
  }
}

export default function Reports({
  api,
  connectors,
  onConnectors,
}: {
  api: Api;
  connectors: Connector[];
  onConnectors: () => void;
}) {
  const [reports, setReports] = useState<Report[]>([]);
  const [draft, setDraft] = useState<Config | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [preview, setPreview] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const refresh = async () => setReports(await api("/digests"));
  useEffect(() => {
    let current = true;
    api("/digests")
      .then((data) => {
        if (current) setReports(data);
      })
      .catch((reason) => {
        if (current) setError((reason as Error).message);
      });
    return () => {
      current = false;
    };
  }, [api]);
  function edit(report?: Report) {
    setEditing(report?.id || null);
    if (report) {
      const { id: _id, next_run: _next, ...settings } = report;
      setDraft(settings);
    } else setDraft(initial());
    setPreview(null);
    setError("");
    setNotice("");
  }
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!draft) return;
    if (!draft.destinations.length) {
      setError("Choose at least one destination.");
      return;
    }
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await api(
        editing ? `/digests/${editing}` : "/digests",
        editing ? "PUT" : "POST",
        draft,
      );
      await refresh();
      setDraft(null);
      setNotice("Report schedule saved.");
    } catch (reason) {
      setError((reason as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function remove(report: Report) {
    if (
      !window.confirm(
        `Delete “${report.name}”? Queued reports will be cancelled.`,
      )
    )
      return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await api(`/digests/${report.id}`, "DELETE");
      await refresh();
      setPreview(null);
      setNotice("Report removed.");
    } catch (reason) {
      setError((reason as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function showPreview(report: Report) {
    setBusy(true);
    setError("");
    setNotice("");
    setPreview(null);
    try {
      setPreview(await api(`/digests/${report.id}/preview`, "POST"));
    } catch (reason) {
      setError((reason as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <p className="editor-intro">
        Choose a worldwide report or one based on your enabled asset rules.
        Reports use locally synchronized NVD records; source outages and
        incomplete history can leave gaps. They are sent through the normal
        queue and respect connector delivery hours.
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
      <div className="collection-toolbar">
        <span>{reports.length} configured</span>
        <button className="primary" onClick={() => edit()}>
          Add report
        </button>
      </div>
      {draft && (
        <section className="panel editor">
          <div className="section-heading">
            <h2>{editing ? "Edit report" : "Add report"}</h2>
          </div>
          <form onSubmit={save}>
            <label>
              Report name
              <input
                required
                maxLength={120}
                value={draft.name}
                onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              />
            </label>
            <div className="form-grid">
              <label>
                Coverage
                <select
                  aria-label="Coverage"
                  value={draft.scope}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      scope: e.target.value as Config["scope"],
                    })
                  }
                >
                  <option value="global">
                    Worldwide: latest local NVD records
                  </option>
                  <option value="relevant">
                    My assets: match enabled rules
                  </option>
                </select>
              </label>
              <label>
                Frequency
                <select
                  aria-label="Frequency"
                  value={draft.frequency}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      frequency: e.target.value as Config["frequency"],
                    })
                  }
                >
                  <option value="weekly">Weekly</option>
                  <option value="daily">Daily</option>
                </select>
              </label>
              {draft.frequency === "weekly" && (
                <label>
                  Weekday
                  <select
                    aria-label="Weekday"
                    value={draft.weekday}
                    onChange={(e) =>
                      setDraft({ ...draft, weekday: Number(e.target.value) })
                    }
                  >
                    {weekdays.map((day, index) => (
                      <option key={day} value={index}>
                        {day}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              <label>
                Local time
                <input
                  required
                  type="time"
                  value={draft.time}
                  onChange={(e) => setDraft({ ...draft, time: e.target.value })}
                />
              </label>
              <label>
                IANA timezone
                <input
                  required
                  placeholder="Europe/Vienna"
                  value={draft.timezone}
                  onChange={(e) =>
                    setDraft({ ...draft, timezone: e.target.value })
                  }
                />
              </label>
              <label>
                Minimum CVSS
                <input
                  required
                  type="number"
                  min={0}
                  max={10}
                  step={0.1}
                  value={draft.min_cvss}
                  onChange={(e) =>
                    setDraft({ ...draft, min_cvss: Number(e.target.value) })
                  }
                />
              </label>
              <label>
                Maximum entries
                <input
                  required
                  type="number"
                  min={1}
                  max={20}
                  value={draft.item_limit}
                  onChange={(e) =>
                    setDraft({ ...draft, item_limit: Number(e.target.value) })
                  }
                />
              </label>
            </div>
            <p className="help">
              A minimum of 0 includes records with no CVSS score. Higher
              minimums exclude unknown scores. Up to 1,000 recent candidates are
              examined; the report states how much it covered.
            </p>
            <fieldset>
              <legend>Destinations</legend>
              {connectors.length ? (
                connectors.map((item) => (
                  <label className="check-label" key={item.id}>
                    <input
                      type="checkbox"
                      checked={draft.destinations.includes(item.id)}
                      onChange={(e) =>
                        setDraft({
                          ...draft,
                          destinations: e.target.checked
                            ? [...draft.destinations, item.id]
                            : draft.destinations.filter((id) => id !== item.id),
                        })
                      }
                    />
                    {item.name}
                    {!item.enabled ? " (disabled)" : ""}
                  </label>
                ))
              ) : (
                <button
                  className="secondary"
                  type="button"
                  onClick={onConnectors}
                >
                  Add a connector first
                </button>
              )}
            </fieldset>
            <label className="check-label">
              <input
                type="checkbox"
                checked={draft.enabled}
                onChange={(e) =>
                  setDraft({ ...draft, enabled: e.target.checked })
                }
              />{" "}
              Enable this report
            </label>
            <p className="help">
              The first report is scheduled for the next chosen time. Editing
              resets the next occurrence. After a long outage, only the latest
              completed period is queued.
            </p>
            <div className="form-actions">
              <button
                type="button"
                className="secondary"
                onClick={() => setDraft(null)}
              >
                Cancel
              </button>
              <button className="primary" disabled={busy}>
                Save report
              </button>
            </div>
          </form>
        </section>
      )}
      <section className="panel" aria-label="Scheduled reports">
        {reports.length === 0 ? (
          <div className="inline-empty">No reports configured yet.</div>
        ) : (
          reports.map((report) => (
            <div className="entry-row" key={report.id}>
              <div className="entry-main">
                <strong>{report.name}</strong>
                <small>
                  {report.scope === "global"
                    ? "Worldwide CVEs"
                    : "My matching assets"}{" "}
                  · {report.frequency}
                  {report.frequency === "weekly"
                    ? ` · ${weekdays[report.weekday]}`
                    : ""}{" "}
                  · {report.time} {report.timezone} ·{" "}
                  {report.enabled
                    ? `next ${nextLabel(report.next_run, report.timezone)}`
                    : "disabled"}
                </small>
              </div>
              <div className="row-actions">
                <button
                  className="secondary small"
                  disabled={busy || !report.enabled}
                  onClick={() => void showPreview(report)}
                >
                  Preview
                </button>
                <button
                  className="secondary small"
                  onClick={() => edit(report)}
                >
                  Edit
                </button>
                <button
                  className="secondary small"
                  disabled={busy}
                  onClick={() => void remove(report)}
                >
                  Delete
                </button>
              </div>
            </div>
          ))
        )}
      </section>
      {preview && (
        <section className="panel">
          <div className="section-heading">
            <h2>Report preview · {preview.name}</h2>
            <button
              className="secondary small"
              onClick={() => setPreview(null)}
            >
              Close preview
            </button>
          </div>
          <div className="inline-empty">
            <p>
              Screened {preview.scanned} of {preview.candidates} locally stored
              candidates. NVD last successful sync:{" "}
              {preview.nvd_synced || "unknown"}. Coverage can be incomplete.
            </p>
            {preview.entries.length ? (
              <ul>
                {preview.entries.map((entry: any) => (
                  <li key={entry.id}>
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${entry.id}`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {entry.id}
                    </a>{" "}
                    · {entry.severity || "unknown"} · CVSS{" "}
                    {entry.cvss ?? "unknown"}
                    {entry.match && (
                      <div>
                        Why: {entry.match.asset} · {entry.match.rule} ·{" "}
                        {entry.match.confidence} match.{" "}
                        {entry.match.explanation}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p>No matching records in this period.</p>
            )}
          </div>
        </section>
      )}
    </>
  );
}
