import { version as appVersion } from "../package.json";
import React, { useCallback, useEffect, useState } from "react";
import {
  Activity,
  ArrowRight,
  Bell,
  Check,
  ChevronRight,
  CircleHelp,
  Layers3,
  ListFilter,
  Moon,
  Plus,
  Radio,
  RefreshCw,
  Search,
  Send,
  Settings,
  ShieldCheck,
  Sun,
  Trash2,
  X,
} from "lucide-react";

type Entry = Record<string, any> & {
  id: string;
  name: string;
  enabled: boolean;
};
type Overview = {
  counts: Record<string, number>;
  sources: any[];
  deliveries: Record<string, number>;
  engine: Record<string, number>;
  setup_required: boolean;
};
type Expression = {
  kind: string;
  field?: string;
  op?: string;
  value?: any;
  children?: Expression[];
};
const pages = [
  "Overview",
  "Assets",
  "Notification rules",
  "Connectors",
  "Vulnerabilities",
  "Settings",
];
const icons = [Activity, Layers3, ListFilter, Radio, ShieldCheck, Settings];
const initialAsset = {
  name: "",
  kind: "vendor_product",
  vendor: "",
  product: "",
  version: "",
  cpe: "",
  keyword: "",
  group: "production",
  environment: "",
  team: "",
  importance: "normal",
  exposed: false,
  tags: [] as string[],
};
const initialCondition: Expression = {
  kind: "any",
  children: [
    { kind: "condition", field: "cvss", op: "gte", value: 9 },
    { kind: "condition", field: "kev", op: "eq", value: true },
  ],
};
const initialRule = {
  name: "",
  enabled: true,
  assets: [] as string[],
  groups: [] as string[],
  destinations: [] as string[],
  condition: initialCondition,
  format: "compact",
  renotify_changes: true,
};
const emptyOverview: Overview = {
  counts: {},
  sources: [],
  deliveries: {},
  engine: {},
  setup_required: true,
};
const date = (value: any) =>
  value
    ? new Date(
        typeof value === "number" ? value * 1000 : value,
      ).toLocaleString()
    : "Never";
function Badge({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode;
  tone?: string;
}) {
  return <span className={`badge ${tone}`}>{children}</span>;
}
function Empty({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="empty">
      <Layers3 size={28} />
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}

function ConditionEditor({
  node,
  onChange,
  depth = 0,
}: {
  node: Expression;
  onChange: (node: Expression) => void;
  depth?: number;
}) {
  const fields = [
    "cvss",
    "severity",
    "epss",
    "percentile",
    "kev",
    "group",
    "exposed",
    "importance",
    "confidence",
    "vendor",
    "product",
    "keyword",
    "tags",
  ];
  const numeric = ["cvss", "epss", "percentile"].includes(node.field || "");
  const boolean = ["kev", "exposed"].includes(node.field || "");
  const changeField = (field: string) =>
    onChange({
      kind: "condition",
      field,
      op: ["cvss", "epss", "percentile"].includes(field) ? "gte" : "eq",
      value: ["kev", "exposed"].includes(field)
        ? true
        : ["cvss", "epss", "percentile"].includes(field)
          ? field === "cvss"
            ? 9
            : 0.7
          : "",
    });
  return (
    <div className="condition">
      <div className="condition-top">
        <select
          aria-label="Condition group"
          value={node.kind}
          onChange={(e) =>
            onChange(
              e.target.value === "condition"
                ? { kind: "condition", field: "cvss", op: "gte", value: 9 }
                : {
                    kind: e.target.value,
                    children: node.children?.slice(
                      0,
                      e.target.value === "not" ? 1 : 30,
                    ) || [
                      { kind: "condition", field: "cvss", op: "gte", value: 9 },
                    ],
                  },
            )
          }
        >
          <option value="condition">Condition</option>
          <option value="all">All of these · AND</option>
          <option value="any">Any of these · OR</option>
          <option value="not">None of this · NOT</option>
        </select>
      </div>
      {node.kind === "condition" ? (
        <div className="condition-fields">
          <select
            aria-label="Condition field"
            value={node.field}
            onChange={(e) => changeField(e.target.value)}
          >
            {fields.map((field) => (
              <option key={field}>{field}</option>
            ))}
          </select>
          <select
            aria-label="Condition operator"
            value={node.op}
            onChange={(e) => onChange({ ...node, op: e.target.value })}
          >
            {(numeric
              ? ["gte", "lte", "eq"]
              : boolean
                ? ["eq"]
                : ["eq", "contains", "in"]
            ).map((op) => (
              <option key={op}>{op}</option>
            ))}
          </select>
          {boolean ? (
            <select
              aria-label="Condition value"
              value={String(node.value)}
              onChange={(e) =>
                onChange({ ...node, value: e.target.value === "true" })
              }
            >
              <option value="true">Yes</option>
              <option value="false">No</option>
            </select>
          ) : (
            <input
              aria-label="Condition value"
              type={numeric ? "number" : "text"}
              min={numeric ? 0 : undefined}
              max={numeric ? (node.field === "cvss" ? 10 : 1) : undefined}
              step={numeric ? "0.01" : undefined}
              value={
                Array.isArray(node.value)
                  ? node.value.join(",")
                  : (node.value ?? "")
              }
              onChange={(e) =>
                onChange({
                  ...node,
                  value: numeric
                    ? Number(e.target.value)
                    : node.op === "in"
                      ? e.target.value.split(",").map((v) => v.trim())
                      : e.target.value,
                })
              }
            />
          )}
        </div>
      ) : (
        <div className="condition-children">
          {node.children?.map((child, index) => (
            <div key={index} className="child">
              <ConditionEditor
                depth={depth + 1}
                node={child}
                onChange={(value) =>
                  onChange({
                    ...node,
                    children: node.children!.map((old, i) =>
                      i === index ? value : old,
                    ),
                  })
                }
              />
              {node.children!.length > 1 && (
                <button
                  type="button"
                  className="icon-button"
                  aria-label="Remove condition"
                  onClick={() =>
                    onChange({
                      ...node,
                      children: node.children!.filter((_, i) => i !== index),
                    })
                  }
                >
                  <X size={15} />
                </button>
              )}
            </div>
          ))}
          {node.kind !== "not" && depth < 6 && (
            <button
              type="button"
              className="text-button"
              onClick={() =>
                onChange({
                  ...node,
                  children: [
                    ...node.children!,
                    { kind: "condition", field: "cvss", op: "gte", value: 9 },
                  ],
                })
              }
            >
              <Plus size={14} /> Add condition
            </button>
          )}
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [page, setPage] = useState("Overview");
  const [overview, setOverview] = useState<Overview>(emptyOverview);
  const [assets, setAssets] = useState<Entry[]>([]),
    [rules, setRules] = useState<Entry[]>([]),
    [connectors, setConnectors] = useState<Entry[]>([]);
  const [deliveries, setDeliveries] = useState<any[]>([]),
    [cves, setCves] = useState<any[]>([]);
  const [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [busy, setBusy] = useState(false),
    [loading, setLoading] = useState(true);
  const [token, setToken] = useState(""),
    [tokenDraft, setTokenDraft] = useState("");
  const [query, setQuery] = useState(""),
    [detail, setDetail] = useState<any>(null),
    [report, setReport] = useState<any>(null);
  const [editor, setEditor] = useState<string | null>(null),
    [editId, setEditId] = useState<string | null>(null);
  const [asset, setAsset] = useState<any>(initialAsset),
    [rule, setRule] = useState<any>(initialRule),
    [connector, setConnector] = useState<any>({
      name: "",
      chat_id: "",
      token_env: "TELEGRAM_BOT_TOKEN",
      enabled: true,
      kind: "telegram",
    });
  const [theme, setTheme] = useState(
    () => localStorage.getItem("vulnrelay-theme") || "light",
  );
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("vulnrelay-theme", theme);
  }, [theme]);
  const api = useCallback(
    async (path: string, method = "GET", body?: any) => {
      const response = await fetch("/api" + path, {
        method,
        headers: {
          ...(method === "GET"
            ? {}
            : {
                "Content-Type": "application/json",
                "X-VulnRelay-Request": "1",
              }),
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(
          response.status === 401
            ? "API token required. Enter it in Settings."
            : typeof data.detail === "string"
              ? data.detail
              : `Request failed (${response.status})`,
        );
      }
      return response.json();
    },
    [token],
  );
  const load = useCallback(async () => {
    try {
      const [status, a, r, c, d] = await Promise.all([
        api("/overview"),
        api("/config/assets"),
        api("/config/rules"),
        api("/config/connectors"),
        api("/deliveries"),
      ]);
      setOverview(status);
      setAssets(a);
      setRules(r);
      setConnectors(c);
      setDeliveries(d);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [api]);
  useEffect(() => {
    void load();
    const interval = setInterval(() => void load(), 15000);
    return () => clearInterval(interval);
  }, [load]);
  useEffect(() => {
    if (page === "Vulnerabilities") {
      const timer = setTimeout(
        () =>
          api("/vulnerabilities?q=" + encodeURIComponent(query))
            .then(setCves)
            .catch((e) => setError(e.message)),
        250,
      );
      return () => clearTimeout(timer);
    }
  }, [api, page, query]);
  async function action(fn: () => Promise<any>, success = "Saved.") {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const result = await fn();
      setNotice(success);
      await load();
      return result;
    } catch (e) {
      setError((e as Error).message);
      return null;
    } finally {
      setBusy(false);
    }
  }
  function navigate(value: string) {
    setPage(value);
    setEditor(null);
    setDetail(null);
    setReport(null);
    setNotice("");
  }
  function openEditor(kind: string, entry?: Entry) {
    setEditId(entry?.id || null);
    setEditor(kind);
    if (kind === "assets")
      setAsset(entry ? { ...entry } : structuredClone(initialAsset));
    if (kind === "rules")
      setRule(entry ? { ...entry } : structuredClone(initialRule));
    if (kind === "connectors")
      setConnector(
        entry
          ? { ...entry }
          : {
              name: "",
              chat_id: "",
              token_env: "TELEGRAM_BOT_TOKEN",
              enabled: true,
              kind: "telegram",
            },
      );
  }
  async function save(event: React.FormEvent) {
    event.preventDefault();
    const document = {
      ...(editor === "assets" ? asset : editor === "rules" ? rule : connector),
    };
    delete document.id;
    const result = await action(() =>
      api(
        `/config/${editor}${editId ? "/" + editId : ""}`,
        editId ? "PUT" : "POST",
        document,
      ),
    );
    if (result) setEditor(null);
  }
  async function remove(collection: string, entry: Entry) {
    if (
      !window.confirm(
        `Delete “${entry.name}”? Existing delivery history is retained.`,
      )
    )
      return;
    await action(
      () => api(`/config/${collection}/${entry.id}`, "DELETE"),
      "Deleted.",
    );
  }
  async function toggle(entry: Entry) {
    const document = { ...entry, enabled: !entry.enabled };
    delete (document as any).id;
    await action(() => api(`/config/rules/${entry.id}`, "PUT", document));
  }
  const activeRules = rules.filter((row) => row.enabled).length;
  const monitorSeen =
    overview.engine.delivery_heartbeat || overview.engine.last_cycle;
  const monitorRecent = monitorSeen && Date.now() / 1000 - monitorSeen < 120;
  return (
    <div className="app">
      <aside className="sidebar">
        <a
          className="brand"
          href="#"
          onClick={(e) => {
            e.preventDefault();
            navigate("Overview");
          }}
        >
          <span className="brand-mark">
            <Radio size={25} />
          </span>
          <span>
            VulnRelay<small>VULNERABILITY NOTIFICATIONS</small>
          </span>
        </a>
        <div className="workspace">
          <span className="workspace-dot" />
          <div>
            Local workspace<small>Self-hosted · private by default</small>
          </div>
          <ChevronRight size={15} />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav aria-label="Main navigation">
          {pages.map((item, index) => {
            const Icon = icons[index];
            return (
              <button
                key={item}
                className={page === item ? "selected" : ""}
                onClick={() => navigate(item)}
              >
                <Icon size={19} />
                {item}
                {item === "Assets" && <span>{assets.length}</span>}
              </button>
            );
          })}
        </nav>
        <div className="sidebar-bottom">
          <div className="local-note">
            <ShieldCheck size={17} />
            <div>
              Your infrastructure.
              <br />
              Your intelligence.
            </div>
          </div>
          <div className="version">
            VulnRelay <span>{appVersion}</span>
            <button
              className="icon-button"
              aria-label="Toggle color theme"
              onClick={() => setTheme(theme === "light" ? "dark" : "light")}
            >
              {theme === "light" ? <Moon size={17} /> : <Sun size={17} />}
            </button>
          </div>
        </div>
      </aside>
      <div className="content">
        <header className="topbar">
          <div>
            <span className="breadcrumb">Workspace</span>
            <ChevronRight size={13} />
            <span>{page}</span>
          </div>
          <div className="local-pill">
            <span className="dot" /> localhost{" "}
            <span className="separator">/</span> local instance
          </div>
        </header>
        <main>
          <div className="page-heading">
            <div>
              <div className="eyebrow">KNOW WHAT MATTERS. GET NOTIFIED.</div>
              <h1>{page === "Overview" ? "Your security, on watch." : page}</h1>
              <p>
                {page === "Overview"
                  ? "Connect your assets to the intelligence that matters."
                  : page === "Assets"
                    ? "Tell VulnRelay which technologies belong to your environment."
                    : page === "Notification rules"
                      ? "Decide what matters, and where it should go."
                      : page === "Connectors"
                        ? "Bring relevant vulnerability alerts to your team."
                        : page === "Vulnerabilities"
                          ? "Inspect locally synchronized intelligence and matching evidence."
                          : "Configure access and understand your local instance."}
              </p>
            </div>
            <button
              className="secondary"
              disabled={busy}
              onClick={() => void action(load, "Status refreshed.")}
            >
              <RefreshCw size={15} /> Refresh
            </button>
          </div>
          {error && (
            <div className="alert error" role="alert">
              {error}
              <button
                className="icon-button"
                aria-label="Dismiss error"
                onClick={() => setError("")}
              >
                <X size={15} />
              </button>
            </div>
          )}
          {notice && (
            <div className="alert success" role="status">
              <Check size={16} />
              {notice}
            </div>
          )}
          {loading ? (
            <div className="empty" role="status">
              Connecting to your instance…
            </div>
          ) : (
            <>
              {page === "Overview" && (
                <>
                  <section className="engine-banner">
                    <div className="engine-icon">
                      <Activity size={24} />
                    </div>
                    <div>
                      <h2>
                        {monitorRecent
                          ? "Monitoring heartbeat received"
                          : monitorSeen
                            ? "Monitoring heartbeat is stale"
                            : "Ready when you are"}
                      </h2>
                      <p>
                        {monitorSeen
                          ? `Last worker heartbeat: ${date(monitorSeen)}`
                          : "Configure an asset, connect Telegram, then start the monitor."}
                      </p>
                    </div>
                    <Badge tone={monitorRecent ? "green" : "amber"}>
                      {monitorRecent
                        ? "Recent heartbeat"
                        : "Waiting for monitor"}
                    </Badge>
                  </section>
                  <div className="metrics">
                    {[
                      [
                        Layers3,
                        assets.length,
                        "Monitored assets",
                        `${new Set(assets.map((a) => a.group)).size} asset groups`,
                      ],
                      [
                        Radio,
                        connectors.filter((c) => c.enabled).length,
                        "Enabled connectors",
                        "Telegram destinations",
                      ],
                      [
                        ListFilter,
                        activeRules,
                        "Active rules",
                        "Deterministic & explainable",
                      ],
                      [
                        Bell,
                        overview.deliveries.sent || 0,
                        "Delivered alerts",
                        `${(overview.deliveries.pending || 0) + (overview.deliveries.retry || 0)} waiting in queue`,
                      ],
                    ].map(([Icon, count, label, sub]: any) => (
                      <div className="metric" key={label}>
                        <div>
                          <span>{label}</span>
                          <Icon size={18} />
                        </div>
                        <strong>{count}</strong>
                        <small>{sub}</small>
                      </div>
                    ))}
                  </div>
                  {overview.setup_required && (
                    <section className="panel setup">
                      <div className="section-heading">
                        <div>
                          <span className="eyebrow">GET CONNECTED</span>
                          <h2>A few steps to your first alert</h2>
                        </div>
                        <Badge>First-run setup</Badge>
                      </div>
                      <div className="setup-steps">
                        {[
                          {
                            label: "Add your assets",
                            done: assets.length > 0,
                            target: "Assets",
                            text: "Products, vendors, CPEs or keywords.",
                          },
                          {
                            label: "Connect Telegram",
                            done: connectors.length > 0,
                            target: "Connectors",
                            text: "Reference a bot token from your environment.",
                          },
                          {
                            label: "Create a rule",
                            done: rules.length > 0,
                            target: "Notification rules",
                            text: "Choose metrics and destinations.",
                          },
                        ].map((step, i) => (
                          <button
                            key={step.label}
                            onClick={() => navigate(step.target)}
                          >
                            <span
                              className={
                                step.done
                                  ? "step-number complete"
                                  : "step-number"
                              }
                            >
                              {step.done ? <Check size={16} /> : i + 1}
                            </span>
                            <strong>{step.label}</strong>
                            <p>{step.text}</p>
                            <ArrowRight size={17} />
                          </button>
                        ))}
                      </div>
                    </section>
                  )}
                  <div className="two-columns">
                    <section className="panel">
                      <div className="section-heading">
                        <h2>Intelligence sources</h2>
                        <span className="muted">Saved checkpoints</span>
                      </div>
                      {["nvd", "cisa_kev", "epss"].map((name) => {
                        const source = overview.sources.find(
                          (row) => row.source === name,
                        );
                        return (
                          <div className="source-row" key={name}>
                            <div className="source-monogram">
                              {name === "nvd"
                                ? "N"
                                : name === "epss"
                                  ? "E"
                                  : "C"}
                            </div>
                            <div>
                              <strong>
                                {name === "nvd"
                                  ? "National Vulnerability Database"
                                  : name === "epss"
                                    ? "FIRST EPSS · daily scores"
                                    : "CISA Known Exploited Vulnerabilities"}
                              </strong>
                              <small>
                                {source?.last_error ||
                                  `Last success: ${date(source?.last_success_at)}`}
                              </small>
                            </div>
                            <Badge
                              tone={
                                source?.last_error
                                  ? "amber"
                                  : source?.last_success_at
                                    ? "green"
                                    : "neutral"
                              }
                            >
                              {source?.last_error
                                ? "Error"
                                : source?.last_success_at
                                  ? "Synced"
                                  : "Not synced"}
                            </Badge>
                          </div>
                        );
                      })}
                      <div className="panel-footer">
                        CVSS measures severity. EPSS estimates exploitation
                        probability. KEV records known exploitation.
                      </div>
                    </section>
                    <section className="panel">
                      <div className="section-heading">
                        <h2>Recent deliveries</h2>
                        <button
                          className="text-button"
                          onClick={() => navigate("Connectors")}
                        >
                          View history <ArrowRight size={14} />
                        </button>
                      </div>
                      {deliveries.length === 0 ? (
                        <Empty title="Your channel is quiet">
                          Relevant alerts appear here after a matching CVE is
                          queued and delivered.
                        </Empty>
                      ) : (
                        deliveries.slice(0, 5).map((row) => (
                          <div className="delivery-row" key={row.id}>
                            <Send size={16} />
                            <div>
                              <strong>{row.id.slice(0, 8)}</strong>
                              <small>{date(row.created_at)}</small>
                            </div>
                            <Badge
                              tone={
                                row.state === "sent"
                                  ? "green"
                                  : row.state === "failed"
                                    ? "red"
                                    : row.state === "cancelled"
                                      ? "neutral"
                                      : "amber"
                              }
                            >
                              {row.state}
                            </Badge>
                          </div>
                        ))
                      )}
                    </section>
                  </div>
                  <section className="panel groups">
                    <div className="section-heading">
                      <h2>Asset groups</h2>
                      <button
                        className="text-button"
                        onClick={() => navigate("Assets")}
                      >
                        Manage assets <ArrowRight size={14} />
                      </button>
                    </div>
                    {assets.length === 0 ? (
                      <div className="inline-empty">
                        Your first asset group will appear here when you add an
                        asset.
                      </div>
                    ) : (
                      Array.from(new Set(assets.map((a) => a.group))).map(
                        (group) => (
                          <div className="group-row" key={group}>
                            <div className="group-icon">
                              <Layers3 size={20} />
                            </div>
                            <div>
                              <strong>{group}</strong>
                              <small>
                                {assets
                                  .filter((a) => a.group === group)
                                  .map((a) => a.name)
                                  .join(" · ")}
                              </small>
                            </div>
                            <Badge>
                              {assets.filter((a) => a.group === group).length}{" "}
                              assets
                            </Badge>
                          </div>
                        ),
                      )
                    )}
                  </section>
                </>
              )}
              {(page === "Assets" ||
                page === "Notification rules" ||
                page === "Connectors") && (
                <>
                  <div className="collection-toolbar">
                    <div>
                      {page === "Assets"
                        ? assets.length
                        : page === "Connectors"
                          ? connectors.length
                          : rules.length}{" "}
                      configured
                    </div>
                    <button
                      className="primary transition-colors duration-150"
                      onClick={() =>
                        openEditor(
                          page === "Assets"
                            ? "assets"
                            : page === "Connectors"
                              ? "connectors"
                              : "rules",
                        )
                      }
                    >
                      <Plus size={16} /> Add{" "}
                      {page === "Assets"
                        ? "asset"
                        : page === "Connectors"
                          ? "connector"
                          : "rule"}
                    </button>
                  </div>
                  {editor && (
                    <section className="panel editor">
                      <div className="section-heading">
                        <h2>
                          {editId ? "Edit" : "Add"}{" "}
                          {editor === "assets"
                            ? "asset"
                            : editor === "rules"
                              ? "notification rule"
                              : "Telegram connector"}
                        </h2>
                        <button
                          className="icon-button"
                          aria-label="Close editor"
                          onClick={() => setEditor(null)}
                        >
                          <X size={19} />
                        </button>
                      </div>
                      <form onSubmit={save}>
                        <label>
                          Name
                          <input
                            required
                            maxLength={120}
                            value={
                              editor === "assets"
                                ? asset.name
                                : editor === "rules"
                                  ? rule.name
                                  : connector.name
                            }
                            onChange={(e) =>
                              editor === "assets"
                                ? setAsset({ ...asset, name: e.target.value })
                                : editor === "rules"
                                  ? setRule({ ...rule, name: e.target.value })
                                  : setConnector({
                                      ...connector,
                                      name: e.target.value,
                                    })
                            }
                          />
                        </label>
                        {editor === "assets" && (
                          <>
                            <div className="form-grid">
                              <label>
                                Match by
                                <select
                                  value={asset.kind}
                                  onChange={(e) =>
                                    setAsset({ ...asset, kind: e.target.value })
                                  }
                                >
                                  {[
                                    "vendor_product",
                                    "product",
                                    "vendor",
                                    "cpe",
                                    "keyword",
                                  ].map((kind) => (
                                    <option key={kind} value={kind}>
                                      {kind.replace("_", " + ")}
                                    </option>
                                  ))}
                                </select>
                              </label>
                              <label>
                                Asset group
                                <input
                                  required
                                  value={asset.group}
                                  onChange={(e) =>
                                    setAsset({
                                      ...asset,
                                      group: e.target.value,
                                    })
                                  }
                                />
                              </label>
                            </div>
                            <div className="form-grid">
                              {["vendor", "vendor_product"].includes(
                                asset.kind,
                              ) && (
                                <label>
                                  Vendor
                                  <input
                                    required
                                    value={asset.vendor}
                                    onChange={(e) =>
                                      setAsset({
                                        ...asset,
                                        vendor: e.target.value,
                                      })
                                    }
                                  />
                                </label>
                              )}
                              {["product", "vendor_product"].includes(
                                asset.kind,
                              ) && (
                                <label>
                                  Product
                                  <input
                                    required
                                    value={asset.product}
                                    onChange={(e) =>
                                      setAsset({
                                        ...asset,
                                        product: e.target.value,
                                      })
                                    }
                                  />
                                </label>
                              )}
                              {asset.kind === "cpe" && (
                                <label>
                                  CPE 2.3
                                  <input
                                    required
                                    placeholder="cpe:2.3:a:vendor:product:…"
                                    value={asset.cpe}
                                    onChange={(e) =>
                                      setAsset({
                                        ...asset,
                                        cpe: e.target.value,
                                      })
                                    }
                                  />
                                </label>
                              )}
                              {asset.kind === "keyword" && (
                                <label>
                                  Explicit keyword
                                  <input
                                    required
                                    value={asset.keyword}
                                    onChange={(e) =>
                                      setAsset({
                                        ...asset,
                                        keyword: e.target.value,
                                      })
                                    }
                                  />
                                </label>
                              )}
                              <label>
                                Installed version (optional)
                                <input
                                  value={asset.version}
                                  onChange={(e) =>
                                    setAsset({
                                      ...asset,
                                      version: e.target.value,
                                    })
                                  }
                                />
                              </label>
                            </div>
                            <div className="form-grid">
                              <label>
                                Importance
                                <select
                                  value={asset.importance}
                                  onChange={(e) =>
                                    setAsset({
                                      ...asset,
                                      importance: e.target.value,
                                    })
                                  }
                                >
                                  {["low", "normal", "high", "critical"].map(
                                    (v) => (
                                      <option key={v}>{v}</option>
                                    ),
                                  )}
                                </select>
                              </label>
                              <label>
                                Tags, comma separated
                                <input
                                  value={asset.tags.join(",")}
                                  onChange={(e) =>
                                    setAsset({
                                      ...asset,
                                      tags: e.target.value
                                        .split(",")
                                        .map((v) => v.trim())
                                        .filter(Boolean),
                                    })
                                  }
                                />
                              </label>
                            </div>
                            <label className="check-label">
                              <input
                                type="checkbox"
                                checked={asset.exposed}
                                onChange={(e) =>
                                  setAsset({
                                    ...asset,
                                    exposed: e.target.checked,
                                  })
                                }
                              />{" "}
                              Internet exposed
                            </label>
                            <p className="help">
                              Product and keyword matches are potential matches.
                              Version applicability is shown explicitly in the
                              matching evidence.
                            </p>
                          </>
                        )}
                        {editor === "connectors" && (
                          <>
                            <label>
                              Telegram chat ID or channel username
                              <input
                                required
                                placeholder="-1001234567890 or @security_channel"
                                value={connector.chat_id}
                                onChange={(e) =>
                                  setConnector({
                                    ...connector,
                                    chat_id: e.target.value,
                                  })
                                }
                              />
                            </label>
                            <label>
                              Token environment variable
                              <input
                                required
                                value={connector.token_env}
                                onChange={(e) =>
                                  setConnector({
                                    ...connector,
                                    token_env: e.target.value,
                                  })
                                }
                              />
                            </label>
                            <p className="help">
                              Put your bot token in this environment variable on
                              the server. Add the bot to your Telegram group or
                              channel and grant permission to send messages. The
                              actual token is never stored in this form.
                            </p>
                          </>
                        )}
                        {editor === "rules" && (
                          <>
                            <fieldset>
                              <legend>Destinations</legend>
                              {connectors.length === 0 ? (
                                <p className="help">Add a connector first.</p>
                              ) : (
                                connectors.map((c) => (
                                  <label className="check-label" key={c.id}>
                                    <input
                                      type="checkbox"
                                      checked={rule.destinations.includes(c.id)}
                                      onChange={(e) =>
                                        setRule({
                                          ...rule,
                                          destinations: e.target.checked
                                            ? [...rule.destinations, c.id]
                                            : rule.destinations.filter(
                                                (v: string) => v !== c.id,
                                              ),
                                        })
                                      }
                                    />
                                    {c.name}
                                  </label>
                                ))
                              )}
                            </fieldset>
                            <label>
                              Asset group (empty means all)
                              <input
                                value={rule.groups.join(",")}
                                onChange={(e) =>
                                  setRule({
                                    ...rule,
                                    groups: e.target.value
                                      .split(",")
                                      .map((v) => v.trim())
                                      .filter(Boolean),
                                  })
                                }
                              />
                            </label>
                            <fieldset>
                              <legend>Conditions</legend>
                              <ConditionEditor
                                node={rule.condition}
                                onChange={(condition) =>
                                  setRule({ ...rule, condition })
                                }
                              />
                            </fieldset>
                            <label>
                              Message format
                              <select
                                value={rule.format}
                                onChange={(e) =>
                                  setRule({ ...rule, format: e.target.value })
                                }
                              >
                                <option value="compact">Compact</option>
                                <option value="detailed">Detailed</option>
                              </select>
                            </label>
                            <label className="check-label">
                              <input
                                type="checkbox"
                                checked={rule.enabled}
                                onChange={(e) =>
                                  setRule({
                                    ...rule,
                                    enabled: e.target.checked,
                                  })
                                }
                              />{" "}
                              Rule enabled
                            </label>
                            <label className="check-label">
                              <input
                                type="checkbox"
                                checked={rule.renotify_changes}
                                onChange={(e) =>
                                  setRule({
                                    ...rule,
                                    renotify_changes: e.target.checked,
                                  })
                                }
                              />{" "}
                              Re-notify when material metrics or patch
                              references change
                            </label>
                            <p className="help">
                              A missing metric evaluates to unknown, including
                              inside a NOT group. Unknown results do not trigger
                              alerts.
                            </p>
                          </>
                        )}
                        <div className="form-actions">
                          <button
                            className="secondary"
                            type="button"
                            onClick={() => setEditor(null)}
                          >
                            Cancel
                          </button>
                          <button
                            className="primary transition-colors duration-150"
                            disabled={busy}
                          >
                            Save{" "}
                            {editor === "assets"
                              ? "asset"
                              : editor === "rules"
                                ? "rule"
                                : "connector"}
                          </button>
                        </div>
                      </form>
                    </section>
                  )}
                  <section className="panel">
                    {(page === "Assets"
                      ? assets
                      : page === "Connectors"
                        ? connectors
                        : rules
                    ).length === 0 ? (
                      <Empty
                        title={
                          page === "Assets"
                            ? "What do you want to watch?"
                            : page === "Connectors"
                              ? "Give your alerts a destination"
                              : "Define your first notification rule"
                        }
                      >
                        {page === "Assets"
                          ? "Add technologies you run, with optional groups, versions and exposure."
                          : page === "Connectors"
                            ? "Connect a Telegram bot to your group, channel or direct chat."
                            : "Start with CVSS ≥ 9 or known exploitation, then refine your filters."}
                      </Empty>
                    ) : (
                      (page === "Assets"
                        ? assets
                        : page === "Connectors"
                          ? connectors
                          : rules
                      ).map((entry) => (
                        <div className="entry-row" key={entry.id}>
                          <div className="entry-icon">
                            {page === "Assets" ? (
                              <Layers3 size={21} />
                            ) : page === "Connectors" ? (
                              <Radio size={21} />
                            ) : (
                              <ListFilter size={21} />
                            )}
                          </div>
                          <div className="entry-main">
                            <strong>{entry.name}</strong>
                            <small>
                              {page === "Assets"
                                ? `${entry.group} · ${entry.kind.replace("_", " + ")} · ${entry.product || entry.vendor || entry.keyword || entry.cpe}`
                                : page === "Connectors"
                                  ? `${entry.chat_id} · token: $${entry.token_env}`
                                  : `${entry.groups.join(", ") || "All groups"} · ${entry.destinations.length} destination(s) · ${entry.format}`}
                            </small>
                          </div>
                          <Badge tone={entry.enabled ? "green" : "neutral"}>
                            {entry.enabled ? "Enabled" : "Disabled"}
                          </Badge>
                          <div className="row-actions">
                            {page === "Notification rules" && (
                              <>
                                <button
                                  className="secondary small"
                                  onClick={() =>
                                    void action(async () => {
                                      const result = await api(
                                        "/evaluate?rule_id=" + entry.id,
                                      );
                                      setReport(result);
                                      return result;
                                    }, "Rule evaluated against stored intelligence.")
                                  }
                                >
                                  Test rule
                                </button>
                                <button
                                  className="text-button"
                                  onClick={() => void toggle(entry)}
                                >
                                  {entry.enabled ? "Disable" : "Enable"}
                                </button>
                              </>
                            )}
                            {page === "Connectors" && (
                              <button
                                className="secondary small"
                                disabled={busy}
                                onClick={() =>
                                  void action(
                                    () =>
                                      api(
                                        `/connectors/${entry.id}/test`,
                                        "POST",
                                      ),
                                    "Test queued. The monitoring worker sends queued messages.",
                                  )
                                }
                              >
                                <Send size={14} /> Test
                              </button>
                            )}
                            <button
                              className="text-button"
                              onClick={() =>
                                openEditor(
                                  page === "Assets"
                                    ? "assets"
                                    : page === "Connectors"
                                      ? "connectors"
                                      : "rules",
                                  entry,
                                )
                              }
                            >
                              Edit
                            </button>
                            <button
                              className="icon-button danger"
                              aria-label={`Delete ${entry.name}`}
                              onClick={() =>
                                void remove(
                                  page === "Assets"
                                    ? "assets"
                                    : page === "Connectors"
                                      ? "connectors"
                                      : "rules",
                                  entry,
                                )
                              }
                            >
                              <Trash2 size={16} />
                            </button>
                          </div>
                        </div>
                      ))
                    )}
                  </section>
                  {report && (
                    <section className="panel report">
                      <div className="section-heading">
                        <h2>Rule test results</h2>
                        <Badge>{report.evaluations} evaluations</Badge>
                      </div>
                      {report.reports.length === 0 ? (
                        <div className="inline-empty">
                          No asset identities matched the stored CVEs.
                          Synchronize sources or refine your assets.
                        </div>
                      ) : (
                        report.reports.map((row: any, index: number) => (
                          <div className="report-row" key={index}>
                            <div>
                              <strong>{row.cve_id}</strong>
                              <small>
                                {row.asset} · {row.match.confidence} ·{" "}
                                {row.match.explanation}
                              </small>
                            </div>
                            <Badge tone={row.matched ? "green" : "neutral"}>
                              {row.matched
                                ? "Matched"
                                : "Not matched / unknown"}
                            </Badge>
                            <details>
                              <summary>Condition evidence</summary>
                              <pre>
                                {JSON.stringify(row.evaluation, null, 2)}
                              </pre>
                            </details>
                          </div>
                        ))
                      )}
                    </section>
                  )}
                  {page === "Connectors" && (
                    <section className="panel">
                      <div className="section-heading">
                        <h2>Delivery history</h2>
                        <button
                          className="secondary small"
                          disabled={busy}
                          onClick={() =>
                            void action(
                              () => api("/deliveries/next", "POST"),
                              "Delivery attempt completed.",
                            )
                          }
                        >
                          <Send size={14} /> Process next message
                        </button>
                      </div>
                      {deliveries.length === 0 ? (
                        <div className="inline-empty">
                          No delivery attempts yet.
                        </div>
                      ) : (
                        deliveries.map((row) => (
                          <div className="delivery-row" key={row.id}>
                            <div>
                              <strong>{row.id.slice(0, 8)}</strong>
                              <small>
                                {date(row.created_at)} · {row.attempts}{" "}
                                attempt(s)
                                {row.last_error ? ` · ${row.last_error}` : ""}
                              </small>
                            </div>
                            <Badge
                              tone={
                                row.state === "sent"
                                  ? "green"
                                  : row.state === "failed"
                                    ? "red"
                                    : row.state === "cancelled"
                                      ? "neutral"
                                      : "amber"
                              }
                            >
                              {row.state}
                            </Badge>
                            {row.state === "failed" && (
                              <button
                                className="secondary small"
                                disabled={busy}
                                onClick={() =>
                                  void action(
                                    () =>
                                      api(
                                        `/deliveries/${row.id}/retry`,
                                        "POST",
                                      ),
                                    "Delivery queued for retry.",
                                  )
                                }
                              >
                                Retry
                              </button>
                            )}
                          </div>
                        ))
                      )}
                    </section>
                  )}
                </>
              )}
              {page === "Vulnerabilities" && (
                <>
                  <div className="search-box">
                    <Search size={18} />
                    <input
                      aria-label="Search vulnerabilities"
                      placeholder="Search CVE ID or description…"
                      value={query}
                      onChange={(e) => setQuery(e.target.value)}
                    />
                    <Badge>Local history</Badge>
                  </div>
                  <section className="panel">
                    {cves.length === 0 ? (
                      <Empty title="No intelligence to show yet">
                        The monitoring worker synchronizes NVD and CISA. You can
                        also run vulnrelay sync and vulnrelay sync-kev.
                      </Empty>
                    ) : (
                      cves.map((row) => (
                        <button
                          className="cve-row"
                          key={row.id}
                          onClick={() =>
                            void action(async () => {
                              const data = await api(
                                "/vulnerabilities/" + row.id,
                              );
                              setDetail(data);
                              return data;
                            }, "Details loaded.")
                          }
                        >
                          <div>
                            <strong>{row.id}</strong>
                            <p>{row.description?.slice(0, 170)}</p>
                          </div>
                          <Badge
                            tone={
                              row.severity === "CRITICAL" ? "red" : "neutral"
                            }
                          >
                            {row.severity || "Unscored"}
                          </Badge>
                          <span className="mono">{row.cvss ?? "—"}</span>
                          {row.kev && <Badge tone="amber">KEV</Badge>}
                          <ChevronRight size={18} />
                        </button>
                      ))
                    )}
                  </section>
                  {detail && (
                    <section className="panel detail">
                      <div className="section-heading">
                        <h2>{detail.vulnerability.id}</h2>
                        <button
                          className="icon-button"
                          aria-label="Close details"
                          onClick={() => setDetail(null)}
                        >
                          <X size={18} />
                        </button>
                      </div>
                      <p>{detail.vulnerability.description}</p>
                      <div className="detail-metrics">
                        <Badge>
                          CVSS {detail.vulnerability.cvss ?? "unknown"}
                        </Badge>
                        <Badge>
                          EPSS{" "}
                          {detail.vulnerability.epss == null
                            ? "unknown"
                            : `${(detail.vulnerability.epss * 100).toFixed(1)}%`}
                        </Badge>
                        <Badge>
                          KEV{" "}
                          {detail.vulnerability.kev == null
                            ? "unknown"
                            : detail.vulnerability.kev
                              ? "listed"
                              : "not listed"}
                        </Badge>
                      </div>
                      <p className="help">
                        EPSS measurement:{" "}
                        {detail.vulnerability.epss_date || "unknown"} · KEV
                        catalog:{" "}
                        {detail.vulnerability.kev_catalog || "not synchronized"}
                      </p>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${detail.vulnerability.id}`}
                        target="_blank"
                        rel="noreferrer"
                      >
                        View NVD record ↗
                      </a>
                      <details>
                        <summary>Matching evidence</summary>
                        <pre>{JSON.stringify(detail.matches, null, 2)}</pre>
                      </details>
                    </section>
                  )}
                </>
              )}
              {page === "Settings" && (
                <div className="two-columns">
                  <section className="panel settings-panel">
                    <div className="section-heading">
                      <h2>Application access</h2>
                      <ShieldCheck size={18} />
                    </div>
                    <p>
                      This instance is intended for localhost. An optional API
                      token protects configuration endpoints.
                    </p>
                    <form
                      onSubmit={(e) => {
                        e.preventDefault();
                        setError("");
                        setToken(tokenDraft);
                        setNotice(
                          "API token applied for this browser session.",
                        );
                      }}
                    >
                      <label>
                        API token
                        <input
                          type="password"
                          autoComplete="off"
                          value={tokenDraft}
                          onChange={(e) => setTokenDraft(e.target.value)}
                        />
                      </label>
                      <p className="help">
                        Must match VULNRELAY_API_TOKEN on your server. Kept only
                        in memory.
                      </p>
                      <button className="primary transition-colors duration-150">
                        Use token
                      </button>
                    </form>
                  </section>
                  <section className="panel settings-panel">
                    <div className="section-heading">
                      <h2>Monitoring & configuration</h2>
                      <CircleHelp size={18} />
                    </div>
                    <p>
                      Docker Compose starts the monitoring worker automatically.
                      For native installs, run these commands from your
                      environment:
                    </p>
                    <pre>vulnrelay init{"\n"}vulnrelay monitor</pre>
                    <p className="help">
                      The worker stores source schedules and delivery state in
                      the database. Sync intervals and connector tokens are
                      configured through environment variables. AI is optional
                      and is not used by this version.
                    </p>
                    <button
                      className="secondary"
                      disabled={busy}
                      onClick={() =>
                        void action(
                          () => api("/queue/evaluate", "POST"),
                          "Matching alerts added to the queue.",
                        )
                      }
                    >
                      <ListFilter size={15} /> Evaluate saved intelligence
                    </button>
                  </section>
                </div>
              )}
            </>
          )}
          <footer>
            <span>
              <ShieldCheck size={13} /> Open source · Self-hosted · Notification
              first
            </span>
            <span>VulnRelay — Know what matters.</span>
          </footer>
        </main>
      </div>
    </div>
  );
}
