import { useEffect, useMemo, useState } from "react";
import {
  ArrowRight,
  Box,
  Check,
  CheckCheck,
  ExternalLink,
  Layers3,
  Plus,
  Search,
  X,
} from "lucide-react";

type Product = {
  id: string;
  name: string;
  category: string;
  description: string;
  kind: string;
  vendor: string;
  product: string;
  source_url: string;
};
type Pack = {
  id: string;
  name: string;
  description: string;
  category: string;
  products: string[];
};
type CatalogData = { products: Product[]; packs: Pack[] };
type Preview = {
  created: { name: string }[];
  existing: { name: string; enabled: boolean }[];
};
type Props = {
  api: (path: string, method?: string, body?: unknown) => Promise<any>;
  onImported: () => Promise<void>;
  onManual: () => void;
  onInventory: () => void;
};

export default function Catalog({
  api,
  onImported,
  onManual,
  onInventory,
}: Props) {
  const [data, setData] = useState<CatalogData | null>(null);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("All technologies");
  const [mode, setMode] = useState("products");
  const [selected, setSelected] = useState<string[]>([]);
  const [group, setGroup] = useState("production");
  const [environment, setEnvironment] = useState("production");
  const [team, setTeam] = useState("");
  const [importance, setImportance] = useState("normal");
  const [exposed, setExposed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<{
    key: string;
    result: Preview;
  } | null>(null);
  const [result, setResult] = useState<Preview | null>(null);
  useEffect(() => {
    let active = true;
    api("/catalog")
      .then((value) => {
        if (active) setData(value);
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [api]);
  const selection = {
    products: selected,
    group,
    environment,
    team,
    importance,
    exposed,
  };
  const key = JSON.stringify(selection);
  const currentPreview = preview?.key === key ? preview.result : null;
  const byId = useMemo(
    () => Object.fromEntries((data?.products || []).map((p) => [p.id, p])),
    [data],
  );
  const categories = [...new Set(data?.products.map((p) => p.category) || [])];
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  const products =
    data?.products.filter(
      (p) =>
        (category === "All technologies" || p.category === category) &&
        words.every((word) =>
          `${p.name} ${p.id} ${p.description} ${p.vendor} ${p.product}`
            .toLowerCase()
            .includes(word),
        ),
    ) || [];
  const packs =
    data?.packs.filter((p) =>
      words.every((word) =>
        `${p.name} ${p.description} ${p.products.map((id) => byId[id]?.name).join(" ")}`
          .toLowerCase()
          .includes(word),
      ),
    ) || [];
  function toggle(id: string) {
    setSelected((old) =>
      old.includes(id) ? old.filter((value) => value !== id) : [...old, id],
    );
    setResult(null);
  }
  async function submit(importNow: boolean) {
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const response = await api(
        importNow ? "/catalog/import" : "/catalog/preview",
        "POST",
        selection,
      );
      if (importNow) {
        setResult(response);
        setSelected([]);
        setPreview(null);
        await onImported();
      } else setPreview({ key, result: response });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  if (!data)
    return (
      <div className="panel inline-empty" role={error ? "alert" : "status"}>
        {error || "Loading technology catalog…"}
      </div>
    );
  return (
    <>
      <section className="catalog-intro">
        <div>
          <span className="eyebrow">BUILD YOUR WATCHLIST</span>
          <h2>Your stack. A few clicks away.</h2>
          <p>
            Pick familiar technologies or start with an environment pack. You
            choose what belongs.
          </p>
        </div>
        <div className="catalog-total">
          <strong>{data.products.length}</strong>
          <span>
            technologies
            <br />
            {data.packs.length} starter packs
          </span>
        </div>
      </section>
      {error && (
        <div className="alert error" role="alert">
          {error}
        </div>
      )}
      {result && (
        <div className="import-success" role="status">
          <CheckCheck size={24} />
          <div>
            <strong>
              {result.created.length} assets added · {result.existing.length}{" "}
              already present
            </strong>
            <p>
              Your selection is saved. Existing asset settings were preserved.
            </p>
          </div>
          <button className="secondary" onClick={onInventory}>
            View assets <ArrowRight size={16} />
          </button>
        </div>
      )}
      <div className="catalog-layout">
        <section className="catalog-browser" aria-label="Technology catalog">
          <div className="catalog-controls">
            <div className="segmented" aria-label="Catalog view">
              <button
                aria-pressed={mode === "products"}
                onClick={() => {
                  setMode("products");
                  setQuery("");
                }}
              >
                <Box size={16} />
                Technologies
              </button>
              <button
                aria-pressed={mode === "packs"}
                onClick={() => {
                  setMode("packs");
                  setQuery("");
                }}
              >
                <Layers3 size={16} />
                Environment packs
              </button>
            </div>
            <label className="search-box">
              <Search size={18} />
              <input
                aria-label="Search catalog"
                placeholder={
                  mode === "products"
                    ? "Search NGINX, PostgreSQL, Kubernetes…"
                    : "Search a stack or technology…"
                }
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </label>
          </div>
          {mode === "products" && (
            <div
              className="category-filters"
              aria-label="Technology categories"
            >
              {["All technologies", ...categories].map((value) => (
                <button
                  key={value}
                  aria-pressed={value === category}
                  onClick={() => setCategory(value)}
                >
                  {value}
                </button>
              ))}
            </div>
          )}
          <div className="catalog-results-label">
            {mode === "products"
              ? `${products.length} technologies`
              : `${packs.length} starter packs`}
            <span>Bundled catalog · works offline</span>
          </div>
          <div className={mode === "products" ? "product-grid" : "pack-grid"}>
            {mode === "products"
              ? products.map((p) => {
                  const chosen = selected.includes(p.id);
                  return (
                    <article
                      className={`product-card ${chosen ? "chosen" : ""}`}
                      key={p.id}
                    >
                      <button
                        disabled={busy}
                        className="product-pick"
                        aria-pressed={chosen}
                        aria-label={`Select ${p.name}`}
                        onClick={() => toggle(p.id)}
                      >
                        <span
                          className={`technology-mark hue-${categories.indexOf(p.category) % 5}`}
                          aria-hidden="true"
                        >
                          {p.name.replace(/[^a-z0-9]/gi, "").slice(0, 2)}
                        </span>
                        <span className="pick-check" aria-hidden="true">
                          {chosen ? <Check size={15} /> : <Plus size={15} />}
                        </span>
                        <strong>{p.name}</strong>
                        <span className="product-category">{p.category}</span>
                        <span className="product-description">
                          {p.description}
                        </span>
                      </button>
                      <details className="catalog-evidence">
                        <summary>Matching identity</summary>
                        <p>
                          {p.vendor || "Any vendor"} / {p.product}
                        </p>
                        <p>
                          Potential product match. Versions need verification.
                        </p>
                        <a href={p.source_url} target="_blank" rel="noreferrer">
                          Search NVD dictionary <ExternalLink size={12} />
                        </a>
                      </details>
                    </article>
                  );
                })
              : packs.map((pack, i) => (
                  <article className={`pack-card pack-${i % 4}`} key={pack.id}>
                    <div className="pack-top">
                      <span className="pack-symbol">
                        <Layers3 size={25} />
                      </span>
                      <span className="badge">
                        {pack.products.length} technologies
                      </span>
                    </div>
                    <h3>{pack.name}</h3>
                    <p>{pack.description}</p>
                    <div className="pack-products">
                      {pack.products.map((id) => (
                        <span key={id}>{byId[id].name}</span>
                      ))}
                    </div>
                    <button
                      className="secondary"
                      disabled={
                        busy ||
                        pack.products.every((id) => selected.includes(id))
                      }
                      onClick={() => {
                        setSelected((old) => [
                          ...new Set([...old, ...pack.products]),
                        ]);
                        setResult(null);
                      }}
                    >
                      {pack.products.every((id) => selected.includes(id)) ? (
                        <>
                          <Check size={16} />
                          Selected
                        </>
                      ) : (
                        <>
                          Select {pack.name}
                          <Plus size={16} />
                        </>
                      )}
                    </button>
                  </article>
                ))}
          </div>
          {(mode === "products" ? products : packs).length === 0 && (
            <div className="empty">
              <Search size={28} />
              <h3>No matching entries</h3>
              <p>
                Try another name or category. You can always add a custom asset.
              </p>
            </div>
          )}
          <div className="catalog-footnote">
            <span>
              A starter catalog, not a full software inventory. Packs do not
              detect your installed software.
            </span>
            <button className="text-button" onClick={onManual}>
              Add a custom asset <ArrowRight size={15} />
            </button>
          </div>
        </section>
        <aside className="selection-panel" aria-label="Selected technologies">
          <div className="selection-heading">
            <div>
              <span className="eyebrow">YOUR SELECTION</span>
              <h2>Make it your environment</h2>
            </div>
            <span className="selection-count">{selected.length}</span>
          </div>
          <fieldset disabled={busy} className="selection-fields">
            {selected.length ? (
              <div className="selected-products">
                {selected.map((id) => (
                  <span key={id}>
                    {byId[id].name}
                    <button
                      className="icon-button"
                      aria-label={`Remove ${byId[id].name}`}
                      onClick={() => toggle(id)}
                    >
                      <X size={13} />
                    </button>
                  </span>
                ))}
              </div>
            ) : (
              <div className="selection-empty">
                <Box size={30} />
                <p>
                  Select technologies on the left.
                  <br />
                  Review everything before adding.
                </p>
              </div>
            )}
            <label>
              Asset group
              <input
                value={group}
                maxLength={100}
                onChange={(e) => setGroup(e.target.value)}
                required
              />
            </label>
            <label>
              Environment
              <select
                value={environment}
                onChange={(e) => setEnvironment(e.target.value)}
              >
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
                <option value="homelab">Homelab</option>
                <option value="">Unspecified</option>
              </select>
            </label>
            <details className="context-details">
              <summary>Team & importance</summary>
              <label>
                Team
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
                  {["low", "normal", "high", "critical"].map((v) => (
                    <option key={v}>{v}</option>
                  ))}
                </select>
              </label>
              <label className="check-label">
                <input
                  type="checkbox"
                  checked={exposed}
                  onChange={(e) => setExposed(e.target.checked)}
                />
                Internet exposed
              </label>
            </details>
          </fieldset>
          {currentPreview && (
            <div className="import-preview" role="status">
              <strong>
                {currentPreview.created.length} new ·{" "}
                {currentPreview.existing.length} already present
              </strong>
              <p>
                Existing entries keep their settings, including disabled state.
                Same identity, version, group, environment and team are reused.
              </p>
            </div>
          )}
          <p className="help">
            Product matching does not confirm a vulnerable version. Existing
            notification rules may apply to newly added assets.
          </p>
          <button
            className="primary selection-submit"
            disabled={busy || !selected.length || !group.trim()}
            onClick={() => void submit(!!currentPreview)}
          >
            {busy
              ? "Working…"
              : currentPreview
                ? `Add ${currentPreview.created.length} assets`
                : "Review selection"}
            <ArrowRight size={16} />
          </button>
        </aside>
      </div>
    </>
  );
}
