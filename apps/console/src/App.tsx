import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import type { User } from "oidc-client-ts";
import {
  api,
  configureApi,
  type BackupBatch,
  type MeResponse,
  type ReplicationContract,
  type ReplicationSource,
  type WorkspaceAccess,
} from "./api";
import { initializeAuth, login, logout, oidcConfigured } from "./auth";

type Language = "zh" | "en";
const copy = {
  zh: {
    section: "备份与企业镜像",
    title: "Backup & Twin",
    subtitle: "验证企业事实如何被封存、投影，并与 AI 影子记录保持边界。",
    mode: "Demo · 合成资料",
    seed: "载入合成工单",
    refresh: "刷新",
    sources: "复制来源",
    healthy: "运行中",
    paused: "已暂停",
    contracts: "合同版本",
    batches: "封存批次",
    records: "记录",
    detail: "批次详情",
    empty: "尚无备份批次。先载入合成工单建立首个可验证快照。",
    vault: "加密来源库",
    restore: "恢复校验",
    projection: "生成 AI 投影",
    pause: "暂停",
    resume: "恢复",
    latest: "最新合同",
    trace: "Trace",
    ready: "已封存",
    newContract: "新建合同版本",
    saveContract: "封存合同版本",
    cancel: "取消",
    contractTitle: "复制合同新版本",
  },
  en: {
    section: "Backup & Enterprise Twin",
    title: "Backup & Twin",
    subtitle: "Verify how enterprise facts are sealed and projected without mixing them with AI shadow records.",
    mode: "Demo · Synthetic data",
    seed: "Load synthetic tickets",
    refresh: "Refresh",
    sources: "Replication sources",
    healthy: "Active",
    paused: "Paused",
    contracts: "Contract versions",
    batches: "Sealed batches",
    records: "records",
    detail: "Batch detail",
    empty: "No backup batches yet. Load synthetic tickets to create a verifiable snapshot.",
    vault: "Encrypted source vault",
    restore: "Restore verification",
    projection: "Create AI projection",
    pause: "Pause",
    resume: "Resume",
    latest: "Latest contract",
    trace: "Trace",
    ready: "Sealed",
    newContract: "New contract version",
    saveContract: "Seal contract version",
    cancel: "Cancel",
    contractTitle: "New replication contract version",
  },
};

export function App() {
  const [initialized, setInitialized] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const [me, setMe] = useState<MeResponse>();
  const [selected, setSelected] = useState<WorkspaceAccess>();
  const [authError, setAuthError] = useState<string>();

  useEffect(() => {
    void (async () => {
      try {
        const current = await initializeAuth();
        setUser(current);
        if (current) {
          configureApi(current.access_token);
          const profile = await api.me();
          const initial = profile.workspaces[0];
          if (!initial) throw new Error("No authorized Agentobe workspace was returned.");
          configureApi(current.access_token, initial.workspaceId);
          setMe(profile);
          setSelected(initial);
        }
      } catch (cause) {
        setAuthError(cause instanceof Error ? cause.message : "OIDC authentication failed.");
      } finally {
        setInitialized(true);
      }
    })();
  }, []);

  if (!oidcConfigured) return <AuthScreen title="OIDC configuration required" detail="Set VITE_OIDC_AUTHORITY and VITE_OIDC_CLIENT_ID before building the Console." />;
  if (!initialized) return <AuthScreen title="Signing in" detail="Validating the OIDC session and tenant membership…" />;
  if (authError) return <AuthScreen title="Access denied" detail={authError} action="Try sign in" onAction={() => void login()} />;
  if (!user || !me || !selected) return <AuthScreen title="Partner access" detail="Sign in with an approved organization identity." action="Sign in with OIDC" onAction={() => void login()} />;

  return <BackupTwin
    key={selected.workspaceId}
    access={selected}
    accesses={me.workspaces}
    identityName={me.identity.displayName ?? me.identity.email ?? me.identity.subject}
    onWorkspaceChange={(workspaceId) => {
      const next = me.workspaces.find((entry) => entry.workspaceId === workspaceId);
      if (!next) return;
      configureApi(user.access_token, next.workspaceId);
      setSelected(next);
    }}
    onLogout={() => void logout()}
  />;
}

function AuthScreen(props: {
  title: string;
  detail: string;
  action?: string;
  onAction?: () => void;
}) {
  return <div className="auth-shell"><div className="auth-card">
    <span className="brand-mark">A</span><small>AGENTOBE SECURE CONSOLE</small>
    <h1>{props.title}</h1><p>{props.detail}</p>
    {props.action && <button onClick={props.onAction}>{props.action}</button>}
  </div></div>;
}

function BackupTwin(props: {
  access: WorkspaceAccess;
  accesses: WorkspaceAccess[];
  identityName: string;
  onWorkspaceChange: (workspaceId: string) => void;
  onLogout: () => void;
}) {
  const [language, setLanguage] = useState<Language>("zh");
  const [sources, setSources] = useState<ReplicationSource[]>([]);
  const [contracts, setContracts] = useState<ReplicationContract[]>([]);
  const [batches, setBatches] = useState<BackupBatch[]>([]);
  const [selectedId, setSelectedId] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [verification, setVerification] = useState<string>();
  const [showContractForm, setShowContractForm] = useState(false);
  const t = copy[language];
  const can = (permission: string) => props.access.permissions.includes(permission);

  const load = useCallback(async () => {
    setError(undefined);
    try {
      const [sourceData, contractData, batchData] = await Promise.all([
        api.sources(), api.contracts(), api.batches(),
      ]);
      setSources(sourceData.items);
      setContracts(contractData.items);
      setBatches(batchData.items);
      setSelectedId((current) => current ?? batchData.items[0]?.id);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load workspace");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);
  const selected = useMemo(
    () => batches.find((batch) => batch.id === selectedId),
    [batches, selectedId],
  );

  async function run(action: () => Promise<unknown>) {
    setBusy(true);
    setError(undefined);
    try { await action(); await load(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Operation failed"); }
    finally { setBusy(false); }
  }

  async function verify(kind: "vault" | "restore") {
    if (!selected) return;
    setBusy(true);
    try {
      const result = kind === "vault"
        ? await api.verifyVault(selected.id)
        : await api.verifyRestore(selected.id);
      setVerification(JSON.stringify(result, null, 2));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Verification failed");
    } finally { setBusy(false); }
  }

  async function submitContract(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const values = (name: string) => String(data.get(name) ?? "")
      .split(",").map((value) => value.trim()).filter(Boolean);
    setBusy(true);
    setError(undefined);
    try {
      await api.createContract({
        source: String(data.get("source")),
        version: String(data.get("version")),
        rules: {
          entity: "ticket",
          mode: "snapshot_plus_events",
          allow: values("allow"),
          tokenize: values("tokenize"),
          deny: values("deny"),
          simulation_use: values("simulationUse"),
        },
        freshnessSloSeconds: Number(data.get("freshness")),
        retentionDays: Number(data.get("retention")),
      });
      setShowContractForm(false);
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Contract creation failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">A</span><b>Agentobe</b></div>
        <nav>
          <a>Overview</a>
          <a className="active">Backup & Twin</a>
          <a>Missions</a><a>Decisions</a><a>Execution</a><a>Audit</a>
        </nav>
        <div className="boundary"><span></span><div><b>Shadow boundary</b><small>No production credentials</small></div></div>
      </aside>

      <main>
        <header className="topbar">
          <div><span className="crumb">Agentobe Console / {t.section}</span><h1>{t.title}</h1></div>
          <div className="top-actions">
            <select
              className="workspace-select"
              aria-label="Workspace"
              value={props.access.workspaceId}
              onChange={(event) => props.onWorkspaceChange(event.target.value)}
            >
              {props.accesses.map((entry) => <option key={entry.workspaceId} value={entry.workspaceId}>
                {entry.organizationName} / {entry.workspaceName}
              </option>)}
            </select>
            <span className="identity"><b>{props.identityName}</b><small>{props.access.roles.join(" · ")}</small></span>
            <span className="mode"><i></i>OIDC · {t.mode}</span>
            <button className="language" onClick={() => setLanguage(language === "zh" ? "en" : "zh")}>{language === "zh" ? "EN" : "中文"}</button>
            <button className="language" onClick={props.onLogout}>Sign out</button>
          </div>
        </header>

        <div className="content">
          <section className="intro">
            <p>{t.subtitle}</p>
            <div><button className="ghost" disabled={busy} onClick={() => void load()}>{t.refresh}</button><button disabled={busy || !can("backup:write")} onClick={() => void run(api.seed)}>{t.seed}</button></div>
          </section>
          {error && <div className="error-banner">{error}</div>}

          <section className="metrics">
            <article><span>{t.sources}</span><strong>{sources.length}</strong><small>{sources.filter((s) => s.status === "active").length} {t.healthy}</small></article>
            <article><span>{t.contracts}</span><strong>{contracts.length}</strong><small>{contracts[0]?.version ? `${t.latest} ${contracts[0].version}` : "—"}</small></article>
            <article><span>{t.batches}</span><strong>{batches.length}</strong><small>{batches.reduce((sum, item) => sum + item.recordCount, 0)} {t.records}</small></article>
            <article className="integrity"><span>Integrity</span><strong>{batches.length > 0 && batches.every((b) => b.status === "sealed") ? "100%" : "—"}</strong><small>Manifest + checksum</small></article>
          </section>

          <section className="panel sources-panel">
            <div className="panel-title"><div><span>01</span><h2>{t.sources}</h2></div><button disabled={!can("contract:write")} className="small ghost" onClick={() => setShowContractForm(true)}>{t.newContract}</button></div>
            {sources.map((source) => (
              <div className="source-row" key={source.source}>
                <div className="source-icon">↕</div>
                <div className="source-name"><b>{source.source}</b><small>{source.contract_count} {t.contracts.toLowerCase()} · v{source.version}</small></div>
                <span className={`status ${source.status}`}><i></i>{source.status === "active" ? t.healthy : t.paused}</span>
                <button className="small ghost" disabled={busy || !can("source:control")} onClick={() => void run(() => api.changeSourceState(
                  source.source,
                  source.status === "active" ? "paused" : "active",
                  source.status === "active" ? "Paused from Backup & Twin console" : "Resumed from Backup & Twin console",
                ))}>{source.status === "active" ? t.pause : t.resume}</button>
              </div>
            ))}
          </section>

          <div className="workspace-grid">
            <section className="panel batches-panel">
              <div className="panel-title"><div><span>02</span><h2>{t.batches}</h2></div></div>
              {batches.length === 0 && <div className="empty">{t.empty}</div>}
              {batches.map((batch) => (
                <button className={`batch-row ${selectedId === batch.id ? "selected" : ""}`} key={batch.id} onClick={() => { setSelectedId(batch.id); setVerification(undefined); }}>
                  <span className="batch-dot"></span><div><b>{batch.source}</b><small>{new Date(batch.sealedAt).toLocaleString(language === "zh" ? "zh-TW" : "en-US")}</small></div><em>{batch.recordCount}</em>
                </button>
              ))}
            </section>

            <section className="panel detail-panel">
              <div className="panel-title"><div><span>03</span><h2>{t.detail}</h2></div>{selected && <span className="status active"><i></i>{t.ready}</span>}</div>
              {!selected ? <div className="empty">{t.empty}</div> : <>
                <div className="detail-head"><div><small>Batch ID</small><code>{selected.id}</code></div><div><small>{t.trace}</small><code>{selected.traceId}</code></div></div>
                <dl>
                  <div><dt>Manifest hash</dt><dd>{selected.manifestHash}</dd></div>
                  <div><dt>Cursor</dt><dd>{selected.cursor.start} → {selected.cursor.end}</dd></div>
                  <div><dt>Classification</dt><dd>{selected.classifications.join(" · ")}</dd></div>
                  <div><dt>Schema / Contract</dt><dd>{selected.schemaVersion} / {selected.contractVersion}</dd></div>
                </dl>
                <div className="detail-actions">
                  <button className="ghost" disabled={busy || !can("backup:verify")} onClick={() => void verify("vault")}>{t.vault}</button>
                  <button className="ghost" disabled={busy || !can("backup:verify")} onClick={() => void verify("restore")}>{t.restore}</button>
                  <button disabled={busy || !can("projection:write")} onClick={() => void run(() => api.createProjection(selected.id))}>{t.projection}</button>
                </div>
                {verification && <pre>{verification}</pre>}
              </>}
            </section>
          </div>
        </div>
        {showContractForm && <div className="modal-backdrop" role="presentation">
          <form className="contract-form" onSubmit={(event) => void submitContract(event)}>
            <div className="form-head"><div><small>Append-only</small><h2>{t.contractTitle}</h2></div><button type="button" className="ghost" onClick={() => setShowContractForm(false)}>×</button></div>
            <div className="form-grid">
              <label>Source<input name="source" required defaultValue={sources[0]?.source ?? "ticketing-sandbox"} /></label>
              <label>Version<input name="version" required placeholder="v2" /></label>
              <label className="wide">Allow fields<input name="allow" required defaultValue="ticket_id,state,priority,customer_tier,sla_due_at,tags,queue,requester_id,created_at,updated_at" /></label>
              <label>Tokenize<input name="tokenize" defaultValue="requester_id" /></label>
              <label>Deny<input name="deny" required defaultValue="email_body,attachments,access_token,api_key,password,private_key" /></label>
              <label className="wide">Simulation use<input name="simulationUse" required defaultValue="triage,prioritization,capacity_planning" /></label>
              <label>Freshness SLO (seconds)<input name="freshness" type="number" min="30" defaultValue="300" /></label>
              <label>Retention (days)<input name="retention" type="number" min="1" defaultValue="30" /></label>
            </div>
            <p>New versions are immutable. D4 secret fields are rejected even when listed in Allow.</p>
            <div className="form-actions"><button type="button" className="ghost" onClick={() => setShowContractForm(false)}>{t.cancel}</button><button disabled={busy}>{t.saveContract}</button></div>
          </form>
        </div>}
      </main>
    </div>
  );
}
