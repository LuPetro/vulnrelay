import { useState } from "react";

type Item = {
  id: string;
  name: string;
  ecosystem: string;
  package: string;
  version: string;
  enabled: boolean;
};
type Result = { created: Item[]; existing: Item[]; preview: boolean };
type Props = {
  api: (path: string, method?: string, body?: unknown) => Promise<any>;
  onImported: () => Promise<void>;
  onClose: () => void;
};

export default function PackageImport({ api, onImported, onClose }: Props) {
  const [text, setText] = useState("");
  const [group, setGroup] = useState("application");
  const [environment, setEnvironment] = useState("");
  const [team, setTeam] = useState("");
  const [importance, setImportance] = useState("normal");
  const [exposed, setExposed] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [review, setReview] = useState<{ key: string; result: Result } | null>(
    null,
  );
  const [complete, setComplete] = useState<{
    key: string;
    result: Result;
  } | null>(null);
  const purls = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const selection = { purls, group, environment, team, importance, exposed };
  const key = JSON.stringify(selection);
  const preview = review?.key === key ? review.result : null;
  const result = complete?.key === key ? complete.result : null;

  async function submit(importNow: boolean) {
    setBusy(true);
    setError("");
    try {
      const response: Result = await api(
        importNow ? "/packages/import" : "/packages/preview",
        "POST",
        selection,
      );
      if (importNow) {
        setComplete({ key, result: response });
        setReview(null);
        await onImported();
      } else {
        setComplete(null);
        setReview({ key, result: response });
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel editor" aria-label="Import package list">
      <div className="section-heading">
        <h2>Import package list</h2>
        <button className="secondary" type="button" onClick={onClose}>
          Close
        </button>
      </div>
      <p className="help">
        Paste up to 100 supported package URLs, one per line. Every URL needs an
        exact version and must have no qualifiers or subpath. Review before
        importing; existing rules may match new assets immediately.
      </p>
      <p className="help">
        Preview is local. When OSV monitoring is enabled, package names and
        versions are sent to OSV.dev for checks.
      </p>
      {error && (
        <div className="alert error" role="alert">
          {error}
        </div>
      )}
      <label>
        Package URLs
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={5}
          maxLength={100000}
          placeholder={"pkg:npm/next@15.1.0\npkg:pypi/django@5.1.0"}
        />
      </label>
      <div className="form-grid">
        <label>
          Asset group
          <input
            value={group}
            maxLength={100}
            onChange={(e) => setGroup(e.target.value)}
          />
        </label>
        <label>
          Environment (optional)
          <input
            value={environment}
            maxLength={100}
            onChange={(e) => setEnvironment(e.target.value)}
          />
        </label>
        <label>
          Team (optional)
          <input
            value={team}
            maxLength={100}
            onChange={(e) => setTeam(e.target.value)}
          />
        </label>
        <label>
          Importance
          <select
            value={importance}
            onChange={(e) => setImportance(e.target.value)}
          >
            <option value="low">Low</option>
            <option value="normal">Normal</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </label>
      </div>
      <label className="check-label">
        <input
          type="checkbox"
          checked={exposed}
          onChange={(e) => setExposed(e.target.checked)}
        />
        Internet exposed
      </label>
      {preview && (
        <div role="status">
          <strong>
            {preview.created.length} new · {preview.existing.length} already
            present or repeated
          </strong>
          <p className="help">
            Existing assets keep their settings. Different groups, environments,
            teams or version strings remain separate.
          </p>
          <ul>
            {preview.created.map((item) => (
              <li key={item.id}>
                {item.ecosystem} {item.package} {item.version}
              </li>
            ))}
          </ul>
          {preview.existing.length > 0 && (
            <details>
              <summary>Review existing or repeated entries</summary>
              <ul>
                {preview.existing.map((item, index) => (
                  <li key={`${item.id}-${index}`}>
                    {item.ecosystem} {item.package} {item.version}
                    {!item.enabled && " · disabled; not re-enabled"}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}
      {result && (
        <p role="status">
          Imported {result.created.length} assets; {result.existing.length} were
          already present or repeated. Existing settings were preserved.
        </p>
      )}
      <div className="form-actions">
        <button
          className="secondary"
          type="button"
          disabled={
            busy || purls.length === 0 || purls.length > 100 || !group.trim()
          }
          onClick={() => void submit(false)}
        >
          Review package list
        </button>
        <button
          className="primary"
          type="button"
          disabled={busy || !preview || preview.created.length === 0}
          onClick={() => void submit(true)}
        >
          Import packages
        </button>
      </div>
      {purls.length > 100 && (
        <p className="help">A selection can contain at most 100 URLs.</p>
      )}
    </section>
  );
}
