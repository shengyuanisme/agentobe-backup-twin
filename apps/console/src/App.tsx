import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import type { User } from "oidc-client-ts";
import {
  api,
  configureApi,
  type BackupBatch,
  type MeResponse,
  type ReplicationContract,
  type ReplicationSource,
  type Projection,
  type SimulationBranch,
  type SimulationMission,
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
  const [surface, setSurface] = useState<"backup" | "simulation">("backup");

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

  const common = {
    access: selected,
    accesses: me.workspaces,
    identityName: me.identity.displayName ?? me.identity.email ?? me.identity.subject,
    onWorkspaceChange: (workspaceId: string) => {
      const next = me.workspaces.find((entry) => entry.workspaceId === workspaceId);
      if (!next) return;
      configureApi(user.access_token, next.workspaceId);
      setSelected(next);
    },
    onLogout: () => void logout(),
  };
  return surface === "backup"
    ? <BackupTwin key={`backup-${selected.workspaceId}`} {...common} onNavigate={() => setSurface("simulation")} />
    : <SimulationSpace key={`simulation-${selected.workspaceId}`} {...common} onNavigate={() => setSurface("backup")} />;
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
  onNavigate: () => void;
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
          <button type="button">Overview</button>
          <button type="button" className="active">Backup & Twin</button>
          <button type="button" onClick={props.onNavigate}>Simulation Space</button>
          <button type="button">Decisions</button><button type="button">Execution</button><button type="button">Audit</button>
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

function SimulationSpace(props: {
  access: WorkspaceAccess;
  accesses: WorkspaceAccess[];
  identityName: string;
  onWorkspaceChange: (workspaceId: string) => void;
  onLogout: () => void;
  onNavigate: () => void;
}) {
  const [language, setLanguage] = useState<Language>("zh");
  const [projections, setProjections] = useState<Projection[]>([]);
  const [missions, setMissions] = useState<SimulationMission[]>([]);
  const [selectedId, setSelectedId] = useState<string>();
  const [detail, setDetail] = useState<SimulationMission>();
  const [selectedBranchId, setSelectedBranchId] = useState<string>();
  const [showMissionForm, setShowMissionForm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const can = (permission: string) => props.access.permissions.includes(permission);
  const zh = language === "zh";

  const load = useCallback(async () => {
    setError(undefined);
    try {
      const [projectionData, missionData] = await Promise.all([api.projections(), api.missions()]);
      setProjections(projectionData.items);
      setMissions(missionData.items);
      setSelectedId((current) => current ?? missionData.items[0]?.id);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load simulation space");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    if (!selectedId) { setDetail(undefined); return; }
    void api.mission(selectedId).then((mission) => {
      setDetail(mission);
      setSelectedBranchId((current) => current ?? mission.experiments?.[0]?.branches[0]?.id);
    }).catch((cause) => setError(cause instanceof Error ? cause.message : "Unable to load mission"));
  }, [selectedId]);

  async function createAndRun(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const projection = projections.find((entry) => entry.id === String(data.get("projectionId")));
    if (!projection) return;
    setBusy(true);
    setError(undefined);
    try {
      const maxBranches = Number(data.get("maxBranches"));
      const mission = await api.createMission({
        name: String(data.get("name")),
        objective: String(data.get("objective")),
        projectionId: projection.id,
        successMetric: "sla_breach_rate",
        guardMetric: "escalation_rate",
        constraints: {
          prohibitTicketClosure: true,
          prohibitExternalMessages: true,
          maxP1AgeHours: Number(data.get("maxP1AgeHours")),
          queueCapacity: {
            "apac-general": Number(data.get("generalCapacity")),
            integrations: Number(data.get("integrationsCapacity")),
            overflow: Number(data.get("overflowCapacity")),
          },
        },
        budget: {
          maxBranches,
          maxStepsPerBranch: Number(data.get("maxSteps")),
          maxRuntimeSeconds: Number(data.get("maxRuntime")),
        },
        toolScope: ["ticket.priority", "ticket.queue", "ticket.capacity"],
      });
      const completed = await api.runMission(mission.id, maxBranches);
      setShowMissionForm(false);
      await load();
      setSelectedId(completed.id);
      setDetail(completed);
      setSelectedBranchId(completed.experiments?.[0]?.branches[0]?.id);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Simulation failed");
    } finally {
      setBusy(false);
    }
  }

  const experiment = detail?.experiments?.[0];
  const branch = experiment?.branches.find((entry) => entry.id === selectedBranchId)
    ?? experiment?.branches[0];

  return <div className="app-shell simulation-shell">
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark">A</span><b>Agentobe</b></div>
      <nav>
        <button type="button">Overview</button>
        <button type="button" onClick={props.onNavigate}>Backup & Twin</button>
        <button type="button" className="active">Simulation Space</button>
        <button type="button">Decisions</button><button type="button">Execution</button><button type="button">Audit</button>
      </nav>
      <div className="boundary"><span></span><div><b>Shadow boundary</b><small>0 production credentials · 0 side effects</small></div></div>
    </aside>
    <main>
      <header className="topbar">
        <div><span className="crumb">Agentobe Console / AI Simulation Space</span><h1>{zh ? "AI Simulation Space / AI 仿真空间" : "AI Simulation Space"}</h1></div>
        <div className="top-actions">
          <select className="workspace-select" aria-label="Workspace" value={props.access.workspaceId} onChange={(event) => props.onWorkspaceChange(event.target.value)}>
            {props.accesses.map((entry) => <option key={entry.workspaceId} value={entry.workspaceId}>{entry.organizationName} / {entry.workspaceName}</option>)}
          </select>
          <span className="identity"><b>{props.identityName}</b><small>{props.access.roles.join(" · ")}</small></span>
          <span className="mode"><i></i>{zh ? "隔离影子运行时" : "Isolated shadow runtime"}</span>
          <button className="language" onClick={() => setLanguage(zh ? "en" : "zh")}>{zh ? "EN" : "中文"}</button>
          <button className="language" onClick={props.onLogout}>Sign out</button>
        </div>
      </header>
      <div className="content simulation-content">
        <section className="intro simulation-intro">
          <div><span className="eyebrow">SLICE 2 · SHADOW INTELLIGENCE</span><p>{zh ? "固定企业投影，自主建立隔离分支，并以统一指标比较可重放结果。" : "Pin an enterprise projection, explore isolated branches autonomously, and compare replayable outcomes."}</p></div>
          <div><button className="ghost" disabled={busy} onClick={() => void load()}>{zh ? "刷新" : "Refresh"}</button><button disabled={busy || !can("mission:write") || !can("simulation:run") || projections.length === 0} onClick={() => setShowMissionForm(true)}>{zh ? "创建仿真任务" : "Create mission"}</button></div>
        </section>
        {error && <div className="error-banner">{error}</div>}
        {projections.length === 0 && <div className="simulation-notice"><b>{zh ? "需要固定投影" : "A fixed projection is required"}</b><span>{zh ? "请先回到 Backup & Twin，从健康封存批次生成 AI 投影。" : "Return to Backup & Twin and create an AI projection from a healthy sealed batch."}</span><button className="ghost" onClick={props.onNavigate}>{zh ? "前往备份与镜像" : "Go to Backup & Twin"}</button></div>}

        <section className="metrics simulation-metrics">
          <article><span>{zh ? "固定投影" : "Pinned projections"}</span><strong>{projections.length}</strong><small>{projections[0]?.projectionHash.slice(0, 12) ?? "—"}</small></article>
          <article><span>{zh ? "任务" : "Missions"}</span><strong>{missions.length}</strong><small>{missions.filter((item) => item.status === "completed").length} {zh ? "已完成" : "completed"}</small></article>
          <article><span>{zh ? "隔离分支" : "Isolated branches"}</span><strong>{experiment?.summary.branchCount ?? 0}</strong><small>{experiment?.summary.reproducibleBranches ?? 0} {zh ? "可重放" : "replayable"}</small></article>
          <article className="integrity"><span>{zh ? "生产副作用" : "Production side effects"}</span><strong>{experiment?.summary.productionSideEffects ?? 0}</strong><small>{zh ? "无生产凭据" : "No production credentials"}</small></article>
        </section>

        <div className="simulation-grid">
          <section className="panel mission-list">
            <div className="panel-title"><div><span>01</span><h2>{zh ? "Missions / 任务" : "Missions"}</h2></div></div>
            {missions.length === 0 && <div className="empty">{zh ? "尚无任务。创建后运行器会在固定投影上自主完成至少三个分支。" : "No missions yet. The runner will autonomously explore at least three branches on a fixed projection."}</div>}
            {missions.map((mission) => <button key={mission.id} className={`mission-row ${selectedId === mission.id ? "selected" : ""}`} onClick={() => { setSelectedId(mission.id); setSelectedBranchId(undefined); }}>
              <span className={`mission-state ${mission.status}`}></span><div><b>{mission.name}</b><small>{mission.status} · {new Date(mission.createdAt).toLocaleString(zh ? "zh-TW" : "en-US")}</small></div><em>{mission.budget.maxBranches}</em>
            </button>)}
          </section>

          <section className="panel branch-panel">
            <div className="panel-title"><div><span>02</span><h2>{zh ? "Branch Comparison / 分支比较" : "Branch Comparison"}</h2></div>{experiment && <span className="status active"><i></i>{experiment.status}</span>}</div>
            {!experiment ? <div className="empty">{zh ? "选择或运行任务后显示分支指标。" : "Select or run a mission to compare branch metrics."}</div> : <>
              <div className="mission-summary"><div><small>{zh ? "目标" : "Objective"}</small><p>{detail?.objective}</p></div><div><small>Input hash</small><code>{experiment.inputHash}</code></div></div>
              <div className="branch-table" role="table">
                <div className="branch-head" role="row"><span>{zh ? "策略" : "Strategy"}</span><span>SLA %</span><span>{zh ? "队列年龄" : "Age h"}</span><span>{zh ? "升级率" : "Escalation"}</span><span>{zh ? "置信度" : "Confidence"}</span></div>
                {experiment.branches.map((item) => <button role="row" key={item.id} className={branch?.id === item.id ? "selected" : ""} onClick={() => setSelectedBranchId(item.id)}>
                  <span><b>{item.name}</b><small>{item.reproducible ? (zh ? "可重放" : "Replayable") : item.status}</small></span><span>{item.metrics.slaBreachRate}<em>{signed(item.delta.slaBreachRate)}</em></span><span>{item.metrics.averageQueueAgeHours}<em>{signed(item.delta.averageQueueAgeHours)}</em></span><span>{item.metrics.escalationRate}<em>{signed(item.delta.escalationRate)}</em></span><span>{Math.round(item.confidence * 100)}%</span>
                </button>)}
              </div>
            </>}
          </section>
        </div>

        {branch && <section className="panel replay-panel">
          <div className="panel-title"><div><span>03</span><h2>{zh ? "Replay & Evidence / 回放与证据" : "Replay & Evidence"}</h2></div><code>{branch.stateHash.slice(0, 16)}</code></div>
          <div className="replay-grid">
            <div className="replay-steps">{branch.steps.map((step) => <article key={step.sequence}><span>{String(step.sequence).padStart(2, "0")}</span><div><b>{step.tool}</b><p>{step.summary}</p><code>{step.stateHash.slice(0, 20)}</code></div></article>)}</div>
            <div className="evidence-notes"><h3>{zh ? "明确假设" : "Explicit assumptions"}</h3>{branch.assumptions.map((item) => <p key={item}>✓ {item}</p>)}<h3>{zh ? "已知盲点" : "Known blind spots"}</h3>{branch.blindSpots.map((item) => <p key={item}>! {item}</p>)}</div>
          </div>
        </section>}
        {showMissionForm && <div className="modal-backdrop" role="presentation">
          <form className="contract-form mission-form" onSubmit={(event) => void createAndRun(event)}>
            <div className="form-head"><div><small>FIXED INPUT · ISOLATED TOOLS</small><h2>{zh ? "Create Mission / 创建任务" : "Create Mission"}</h2></div><button type="button" className="ghost" onClick={() => setShowMissionForm(false)}>×</button></div>
            <div className="form-grid">
              <label>{zh ? "任务名称" : "Mission name"}<input name="name" required minLength={3} defaultValue={zh ? "SLA 风险自主探索" : "Autonomous SLA Risk Exploration"} /></label>
              <label>{zh ? "固定投影" : "Pinned projection"}<select name="projectionId" required>{projections.map((projection) => <option key={projection.id} value={projection.id}>{projection.projectionHash.slice(0, 16)} · {projection.payload.tickets.length} tickets</option>)}</select></label>
              <label className="wide">{zh ? "业务目标" : "Objective"}<textarea name="objective" required minLength={10} defaultValue={zh ? "在不关闭工单或对外发送消息的前提下，降低预测的 SLA 违约率。" : "Reduce projected SLA breach rate without closing tickets or sending external messages."} /></label>
              <label>{zh ? "最大分支" : "Max branches"}<input name="maxBranches" type="number" min="3" max="4" defaultValue="4" /></label>
              <label>{zh ? "每分支最大步骤" : "Max steps / branch"}<input name="maxSteps" type="number" min="1" max="100" defaultValue="20" /></label>
              <label>{zh ? "最长运行秒数" : "Runtime seconds"}<input name="maxRuntime" type="number" min="1" max="3600" defaultValue="60" /></label>
              <label>{zh ? "P1 最大年龄（小时）" : "Max P1 age (hours)"}<input name="maxP1AgeHours" type="number" min="1" max="720" defaultValue="24" /></label>
              <label>apac-general capacity<input name="generalCapacity" type="number" min="1" defaultValue="1" /></label>
              <label>integrations capacity<input name="integrationsCapacity" type="number" min="1" defaultValue="1" /></label>
              <label>overflow capacity<input name="overflowCapacity" type="number" min="1" defaultValue="2" /></label>
            </div>
            <p>{zh ? "运行器只能使用工单优先级、影子队列和模拟容量工具；禁止关闭工单、外发消息和任何生产副作用。" : "The runner is limited to ticket priority, shadow queue, and simulated capacity tools. Ticket closure, external messaging, and production side effects are prohibited."}</p>
            <div className="form-actions"><button type="button" className="ghost" onClick={() => setShowMissionForm(false)}>{zh ? "取消" : "Cancel"}</button><button disabled={busy}>{busy ? (zh ? "运行中…" : "Running…") : (zh ? "创建并运行" : "Create & run")}</button></div>
          </form>
        </div>}
      </div>
    </main>
  </div>;
}

function signed(value: number): string {
  if (value === 0) return "—";
  return value > 0 ? `+${value}` : String(value);
}
