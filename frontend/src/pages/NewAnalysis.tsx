import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { AnalysisType, Health, Sample } from "../types";
import { Badge, Icon, type IconName } from "../ui";

const TYPES: { id: AnalysisType; title: string; desc: string; icon: IconName; featured?: boolean }[] = [
  {
    id: "full_analysis", title: "Initiate full analysis", icon: "sparkle", featured: true,
    desc: "Just add a repository. PatchPilot understands it, audits the code to find bugs on its own, proves the top bug with a failing test, repairs and verifies it, and runs the full security scan.",
  },
  { id: "full_repair", title: "Find & fix a bug", desc: "Investigate → reproduce with a real failing test → patch a copy → verify → security scan.", icon: "wrench" },
  { id: "investigate_only", title: "Investigate only", desc: "Root-cause analysis and reproduction without generating a patch.", icon: "search" },
  { id: "security_scan", title: "Security scan", desc: "Static analysis, secrets, vulnerable dependencies and suspicious-code detection.", icon: "shield" },
  { id: "patch_review", title: "Review an AI patch", desc: "Original + modified versions → detect unnecessary or risky changes.", icon: "git" },
];

const GH_RE = /^(?:https?:\/\/)?(?:www\.)?github\.com\/[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}?(?:\.git)?(?:\/tree\/[A-Za-z0-9._/-]{1,200})?\/?$/;

type Mode = "zip" | "url";

interface Source { mode: Mode; file: File | null; url: string }

function DropZone({ file, onFile, label }: { file: File | null; onFile: (f: File | null) => void; label: string }) {
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  return (
    <div
      className={`dropzone ${over ? "over" : ""}`}
      onClick={() => input.current?.click()}
      onDragOver={(e) => { e.preventDefault(); setOver(true); }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => { e.preventDefault(); setOver(false); onFile(e.dataTransfer.files[0] ?? null); }}
    >
      <input ref={input} type="file" accept=".zip,application/zip" hidden onChange={(e) => onFile(e.target.files?.[0] ?? null)} />
      {file ? (
        <><div className="dz-icon"><Icon name="file" size={20} /></div><div className="file">{file.name}</div><div className="small">{(file.size / 1024).toFixed(1)} KB · click to replace</div></>
      ) : (
        <><div className="dz-icon"><Icon name="upload" size={20} /></div><div style={{ color: "var(--text)", fontWeight: 600 }}>{label}</div><div className="small">Drop a .zip here or click to choose. Nothing in it is executed on upload.</div></>
      )}
    </div>
  );
}

function SourcePicker({ value, onChange, label, optional }: { value: Source; onChange: (s: Source) => void; label: string; optional?: boolean }) {
  const urlBad = value.mode === "url" && value.url.trim() !== "" && !GH_RE.test(value.url.trim());
  return (
    <div className="stack" style={{ gap: 10 }}>
      <div className="row">
        <strong style={{ fontSize: 13.5 }}>{label}</strong>
        {optional && <Badge tone="neutral">optional</Badge>}
        <span className="spacer" />
        <div className="segmented" role="tablist" aria-label={`${label} source`}>
          <button role="tab" aria-selected={value.mode === "url"} className={value.mode === "url" ? "on" : ""} onClick={() => onChange({ ...value, mode: "url" })}><Icon name="git" size={14} /> GitHub URL</button>
          <button role="tab" aria-selected={value.mode === "zip"} className={value.mode === "zip" ? "on" : ""} onClick={() => onChange({ ...value, mode: "zip" })}><Icon name="upload" size={14} /> Upload ZIP</button>
        </div>
      </div>
      {value.mode === "zip" ? (
        <DropZone file={value.file} onFile={(f) => onChange({ ...value, file: f })} label={`${label} (.zip)`} />
      ) : (
        <div className="url-box">
          <div className="url-input">
            <span className="url-icon"><Icon name="git" size={18} /></span>
            <input type="text" value={value.url} onChange={(e) => onChange({ ...value, url: e.target.value })} placeholder="https://github.com/owner/repository" spellCheck={false} autoComplete="off" />
          </div>
          <div className={`small ${urlBad ? "url-err" : "muted"}`}>
            {urlBad ? "That doesn't look like a GitHub repository URL. Use https://github.com/owner/repo (optionally …/tree/branch)." :
              "Public repositories only. Add /tree/<branch> for a specific branch. PatchPilot downloads the archive from GitHub — it never runs git or executes the code on download."}
          </div>
        </div>
      )}
    </div>
  );
}

const ready = (s: Source) => (s.mode === "zip" ? !!s.file : GH_RE.test(s.url.trim()));

export function NewAnalysis({ health }: { health: Health | null }) {
  const [type, setType] = useState<AnalysisType>("full_analysis");
  const [repo, setRepo] = useState<Source>({ mode: "url", file: null, url: "" });
  const [modified, setModified] = useState<Source>({ mode: "url", file: null, url: "" });
  const [name, setName] = useState("");
  const [bug, setBug] = useState("");
  const [allowLocal, setAllowLocal] = useState(false);
  const [security, setSecurity] = useState(true);
  const [samples, setSamples] = useState<Sample[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [sampleNote, setSampleNote] = useState("");

  useEffect(() => { api.samples().then(setSamples).catch(() => setSamples([])); }, []);

  const isFull = type === "full_analysis";
  const needsBug = type === "full_repair" || type === "investigate_only";
  const executes = needsBug || isFull;
  const showModified = type === "patch_review";
  const docker = health?.execution.docker.available;

  async function useSample(s: Sample) {
    setErr("");
    setBusy(true);
    try {
      setType(s.analysis_type);
      setName(s.name);
      setBug(s.analysis_type === "full_analysis" ? "" : s.bug_description || "");
      setRepo({ mode: "zip", file: await api.sampleZip(s.name, "repo"), url: "" });
      setModified({ mode: "zip", file: s.analysis_type === "patch_review" ? await api.sampleZip(s.name, "modified") : null, url: "" });
      setSampleNote(`Loaded bundled sample “${s.title}”. It will be uploaded and analysed exactly like any other repository.`);
    } catch (e) {
      setErr(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  }

  async function submit() {
    setErr("");
    if (!ready(repo)) return setErr(repo.mode === "zip" ? "Choose a repository ZIP first." : "Enter a valid GitHub repository URL.");
    if (type === "patch_review" && !ready(modified)) return setErr("Patch review needs the modified version too (ZIP or GitHub URL).");
    if (needsBug && bug.trim().length < 10) return setErr("Describe the bug in at least a sentence.");
    const form = new FormData();
    if (repo.mode === "zip" && repo.file) form.append("file", repo.file);
    else form.append("repo_url", repo.url.trim());
    if (showModified && ready(modified)) {
      if (modified.mode === "zip" && modified.file) form.append("modified_file", modified.file);
      else form.append("modified_repo_url", modified.url.trim());
    }
    form.append("analysis_type", type);
    form.append("project_name", name);
    form.append("bug_description", needsBug || type === "patch_review" ? bug : "");
    form.append("allow_local_execution", String(allowLocal));
    form.append("run_security_scan", String(isFull ? true : security));
    setBusy(true);
    try {
      const job = await api.createJob(form);
      window.location.hash = `#/jobs/${job.id}`;
    } catch (e) {
      setErr(String((e as Error).message));
      setBusy(false);
    }
  }

  const full = TYPES[0];
  const busyText = repo.mode === "url" ? "Downloading from GitHub…" : "Uploading…";

  return (
    <>
      <div className="page-head">
        <div>
          <h1>New analysis</h1>
          <p>Paste a GitHub URL or upload a ZIP. The repository is extracted into an isolated workspace; the original is never modified — patches go to disposable copies only.</p>
        </div>
      </div>

      {health && !health.api_key_configured && health.llm_mode !== "replay" && (
        <div className="alert warn" style={{ marginBottom: 16 }}>
          ANTHROPIC_API_KEY is not configured on the server. Deterministic tools (indexing, scanners, test runs) will still work, but AI stages will be reported as blocked.
        </div>
      )}

      <div className="grid new-layout" style={{ gridTemplateColumns: "minmax(0, 2fr) minmax(0, 1fr)", alignItems: "start" }}>
        <div className="stack">
          <div className="card stack">
            <div className="card-head" style={{ marginBottom: 0 }}><span className="step-num">1</span><h2>Add repository</h2></div>
            {sampleNote && <div className="alert info">{sampleNote}</div>}
            <SourcePicker value={repo} onChange={(v) => { setRepo(v); setSampleNote(""); setName(""); }} label={type === "patch_review" ? "Original version" : "Repository"} />
          </div>

          <div className="card stack">
            <div className="card-head" style={{ marginBottom: 0 }}><span className="step-num">2</span><h2>Choose analysis type</h2></div>
            <button className={`type-card featured ${type === full.id ? "selected" : ""}`} onClick={() => setType(full.id)}>
              <span className="tc-icon"><Icon name={full.icon} size={21} /></span>
              <span style={{ flex: 1 }}>
                <span className="row" style={{ gap: 8 }}><span className="t">{full.title}</span><Badge tone="accent">Recommended</Badge></span>
                <span className="d">{full.desc}</span>
                <span className="chips" style={{ marginTop: 8 }}>
                  {["Understanding", "Bug discovery", "Reproduction", "Repair", "Verification", "Security scan", "Patch review", "Report"].map((c) => <span key={c} className="mini-chip">{c}</span>)}
                </span>
              </span>
            </button>
            <div className="grid grid-2">
              {TYPES.slice(1).map((t) => (
                <button key={t.id} className={`type-card ${type === t.id ? "selected" : ""}`} onClick={() => setType(t.id)}>
                  <span className="tc-icon"><Icon name={t.icon} size={19} /></span><span><span className="t">{t.title}</span><span className="d">{t.desc}</span></span>
                </button>
              ))}
            </div>
            {showModified && (
              <>
                <div className="divider" style={{ margin: "4px 0" }} />
                <SourcePicker value={modified} onChange={setModified} label="Modified version (with an AI patch)" />
              </>
            )}
            {isFull && (
              <div className="subtle small" style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                <span style={{ color: "var(--accent)", marginTop: 1 }}><Icon name="sparkle" size={16} /></span>
                <span>No bug description needed — PatchPilot audits the code to <strong>find bugs on its own</strong>, proves the most important one with a failing test, then fixes and verifies it. The project name is taken from the repository.</span>
              </div>
            )}
            {(needsBug || type === "patch_review") && (
              <label className="field">
                {type === "patch_review" ? "What was the patch supposed to fix?" : "Bug description"}
                <span className="hint">
                  {needsBug ? "Symptoms, expected vs actual behaviour, stack traces. Treated as untrusted text."
                    : "Optional — improves relatedness judgements for patch review."}
                </span>
                <textarea value={bug} onChange={(e) => setBug(e.target.value)} placeholder="e.g. Orders of exactly $50 are charged shipping, but $50+ should ship free…" />
              </label>
            )}
          </div>

          <div className="card stack">
            <div className="card-head" style={{ marginBottom: 0 }}><span className="step-num">3</span><h2>Safety & execution</h2><Icon name="lock" size={17} /></div>
            <div className="subtle small">
              {docker ? (
                <>Docker sandbox available: tests run in a container with <strong>no network</strong>, dropped capabilities, and memory/CPU/process limits.</>
              ) : (
                <>No Docker sandbox on this server. Untrusted code is <strong>not executed</strong> unless you explicitly trust this repository below; static analysis always runs.</>
              )}
            </div>
            {!docker && (executes || needsBug || isFull) && (
              <label className="check warn">
                <input type="checkbox" checked={allowLocal} onChange={(e) => setAllowLocal(e.target.checked)} />
                <div>
                  <strong>I trust this repository — allow restricted local execution</strong>
                  <div className="small muted">Needed to run tests for bug reproduction and verification. Runs in a Windows Job Object / rlimit-restricted process with a scrubbed environment (no API keys or credentials), process and memory caps, a {health?.limits.sandbox_timeout_seconds ?? 120}s timeout and in-process network blocking. Weaker than a container and <em>not</em> a security boundary. Dependencies are never installed.</div>
                </div>
              </label>
            )}
            <label className={`check ${isFull ? "locked" : ""}`}>
              <input type="checkbox" checked={isFull ? true : security} disabled={isFull} onChange={(e) => setSecurity(e.target.checked)} />
              <div><strong>Run security scanners</strong>{isFull && <Badge tone="accent">always on in full analysis</Badge>}<div className="small muted">Bandit, Semgrep, secret detection, suspicious-code rules and OSV dependency lookups (package names/versions only are sent to osv.dev).</div></div>
            </label>
          </div>

          {err && <div className="alert bad">{err}</div>}
          {isFull && !docker && !allowLocal && (
            <div className="alert warn">Tick “I trust this repository” above so agents 3–5 can run tests. Without it, bugs can still be found but not proven, fixed and verified.</div>
          )}
          <div className="row">
            <button className="btn primary lg" onClick={submit} disabled={busy}><Icon name="sparkle" /> {busy ? busyText : isFull ? "Initiate full analysis" : "Start analysis"}</button>
            <span className="muted small">Max archive {health?.limits.max_upload_mb ?? 25} MB · repair retries capped at {health?.limits.max_repair_attempts ?? 2}</span>
          </div>
        </div>

        <div className="stack">
          <div className="card">
            <div className="card-head"><h3>Bundled demo repositories</h3><span className="head-icon"><Icon name="folder" size={17} /></span></div>
            <div className="stack">
              {samples.map((s) => (
                <div key={s.name} className="subtle stack" style={{ gap: 6 }}>
                  <div className="row"><strong>{s.title}</strong></div>
                  <div className="small muted">{s.description}</div>
                  <div className="row">
                    <Badge tone="accent">{s.analysis_type.replace(/_/g, " ")}</Badge>
                    <span className="spacer" />
                    <a className="btn small" href={`/api/samples/${s.name}/download`}><Icon name="download" size={14} /> ZIP</a>
                    <button className="btn small primary" onClick={() => useSample(s)} disabled={busy}>Use sample</button>
                  </div>
                </div>
              ))}
              {samples.length === 0 && <div className="muted small">No samples found.</div>}
            </div>
          </div>
          <div className="card small muted stack" style={{ gap: 8 }}>
            <strong style={{ color: "var(--text)", display: "flex", gap: 8, alignItems: "center" }}><Icon name="lock" size={15} /> What PatchPilot will never do</strong>
            <div>· Modify your uploaded repository</div>
            <div>· Report a test as passed without running it</div>
            <div>· Send secrets to the AI (values are redacted first)</div>
            <div>· Execute code without a sandbox or your consent</div>
            <div>· Call a repository “secure” or “bug-free”</div>
          </div>
        </div>
      </div>
    </>
  );
}
