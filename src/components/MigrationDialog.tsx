import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AlertTriangle, CheckCircle2, Database, File, FolderOpen, LockKeyhole, RefreshCw, ShieldCheck } from "lucide-react";
import type { HostProfile } from "../types";
import { Dialog } from "./Dialog";

type MigrationSource = "finalshell" | "open-ssh" | "putty" | "xshell" | "secure-crt" | "moba-xterm" | "tabby" | "termius";

interface MigrationFieldReport {
  field: string;
  status: "imported" | "skipped" | "failed";
  message: string;
}

interface MigrationItemReport {
  item: string;
  status: "ready" | "skipped" | "failed";
  message: string;
  fields: MigrationFieldReport[];
}

interface MigrationPreview {
  token: string;
  source: Exclude<MigrationSource, "finalshell">;
  expiresAtEpochMs: number;
  filesFound: number;
  profilesReady: number;
  importedFields: number;
  skippedFields: number;
  failedItems: number;
  reports: MigrationItemReport[];
}

interface AuditedMigrationResult {
  profiles: HostProfile[];
  source: Exclude<MigrationSource, "finalshell">;
  importedFields: number;
  skippedFields: number;
  failedItems: number;
  reports: MigrationItemReport[];
}

export interface FinalShellImportResult {
  profiles: HostProfile[];
  filesFound: number;
  credentialsImported: number;
  credentialsFailed: number;
  filesSkipped: number;
}

export interface MigrationImportResult extends FinalShellImportResult {
  sourceLabel: string;
}

interface MigrationDialogProps {
  onClose: () => void;
  onImported: (result: MigrationImportResult) => void;
  showToast: (message: string) => void;
}

const SOURCES: Array<{ value: MigrationSource; label: string; hint: string }> = [
  { value: "finalshell", label: "FinalShell", hint: "*_connect_config.json 目录；可选迁移密码到系统凭据库" },
  { value: "open-ssh", label: "OpenSSH", hint: "config / known_hosts；只迁移可静态映射的 Host 资料" },
  { value: "putty", label: "PuTTY", hint: "用户主动导出的 Sessions .reg 文件" },
  { value: "xshell", label: "Xshell", hint: "用户导出的 .xsh 会话文件或目录" },
  { value: "secure-crt", label: "SecureCRT", hint: "Config/Sessions 下的会话 .ini 文件或目录" },
  { value: "moba-xterm", label: "MobaXterm", hint: "用户导出的 .ini / .mobaconf bookmark 文件" },
  { value: "tabby", label: "Tabby", hint: "用户导出的 YAML/JSON 配置；不读取 vault" },
  { value: "termius", label: "Termius", hint: "用户主动导出的 JSON；不访问账户或加密云仓库" },
];

function isDesktopRuntime() {
  return "__TAURI_INTERNALS__" in window;
}

export function MigrationDialog({ onClose, onImported, showToast }: MigrationDialogProps) {
  const [source, setSource] = useState<MigrationSource>("finalshell");
  const [path, setPath] = useState("");
  const [includePasswords, setIncludePasswords] = useState(false);
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<MigrationPreview | null>(null);
  const [lastResult, setLastResult] = useState<MigrationImportResult | null>(null);

  const selectedSource = SOURCES.find((item) => item.value === source) ?? SOURCES[0];

  function invalidatePreview(nextPath = path) {
    setPath(nextPath);
    setPreview(null);
    setLastResult(null);
  }

  async function choosePath(directory: boolean) {
    if (!isDesktopRuntime()) {
      showToast("路径选择只在桌面应用中可用");
      return;
    }
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({
      directory,
      multiple: false,
      title: directory ? `选择 ${selectedSource.label} 配置目录` : `选择 ${selectedSource.label} 导出文件`,
    });
    if (typeof selected === "string") invalidatePreview(selected);
  }

  async function runMigration() {
    if (!path.trim()) {
      showToast("请先选择配置文件或目录");
      return;
    }
    if (!isDesktopRuntime()) {
      showToast("迁移只在桌面应用中可用");
      return;
    }

    setBusy(true);
    try {
      if (source === "finalshell") {
        const result = await invoke<FinalShellImportResult>("import_finalshell", {
          path: path.trim(),
          includePasswords,
        });
        const normalized = { ...result, sourceLabel: "FinalShell" };
        setLastResult(normalized);
        onImported(normalized);
        return;
      }

      if (!preview) {
        const nextPreview = await invoke<MigrationPreview>("preview_migration", {
          request: { source, path: path.trim() },
        });
        setPreview(nextPreview);
        showToast(`预览完成：${nextPreview.profilesReady} 项可导入，请核对后确认`);
        return;
      }

      const result = await invoke<AuditedMigrationResult>("apply_migration", {
        request: { token: preview.token },
      });
      const normalized: MigrationImportResult = {
        profiles: result.profiles,
        sourceLabel: selectedSource.label,
        filesFound: preview.filesFound,
        credentialsImported: 0,
        credentialsFailed: 0,
        filesSkipped: result.failedItems + result.reports.filter((report) => report.status === "skipped").length,
      };
      setLastResult(normalized);
      setPreview(null);
      onImported(normalized);
    } catch (error) {
      showToast(String(error));
      if (preview) setPreview(null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      title="迁移连接资料"
      wide
      onClose={onClose}
      footer={(
        <>
          <button className="secondary-button" type="button" onClick={onClose}>关闭</button>
          <button className="primary-button" type="button" disabled={busy || !path.trim() || (preview?.profilesReady === 0)} onClick={() => void runMigration()}>
            {busy ? <RefreshCw className="spin" size={14} /> : preview ? <CheckCircle2 size={14} /> : <Database size={14} />}
            {busy ? "正在处理" : preview ? `确认导入 ${preview.profilesReady} 项` : source === "finalshell" ? "开始导入" : "生成预览"}
          </button>
        </>
      )}
    >
      <div className="migration-callout">
        <ShieldCheck size={19} />
        <div>
          <strong>本机、只读、可审计</strong>
          <span>{source === "finalshell" ? "密码仅在 Rust 中解码并直接写入系统凭据管理器。" : "只迁移主机、端口、用户名等非敏感字段；密码、Token、私钥内容和其他应用 vault 一律跳过。"}</span>
        </div>
      </div>

      <label className="field full">
        <span>来源</span>
        <select
          value={source}
          onChange={(event) => {
            setSource(event.target.value as MigrationSource);
            invalidatePreview("");
            setIncludePasswords(false);
          }}
        >
          {SOURCES.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
        </select>
        <small>{selectedSource.hint}</small>
      </label>

      <label className="field full migration-path">
        <span>配置路径</span>
        <div className="path-picker migration-path-actions">
          <input value={path} onChange={(event) => invalidatePreview(event.target.value)} placeholder="选择明确的导出文件或配置目录" spellCheck={false} />
          <button className="secondary-button" type="button" title="选择文件" onClick={() => void choosePath(false)}><File size={14} /> 文件</button>
          <button className="secondary-button" type="button" title="选择目录" onClick={() => void choosePath(true)}><FolderOpen size={14} /> 目录</button>
        </div>
      </label>

      {source === "finalshell" ? (
        <label className="credential-option">
          <input type="checkbox" checked={includePasswords} onChange={(event) => setIncludePasswords(event.target.checked)} />
          <LockKeyhole size={16} />
          <span><strong>同时迁移已保存密码</strong><small>默认关闭；明文不返回 WebView，只写入系统凭据管理器。</small></span>
        </label>
      ) : null}

      {preview ? (
        <section className="migration-preview" aria-label="迁移预览">
          <header>
            <div><strong>待确认预览</strong><small>路径或来源改变会立即作废；预览令牌五分钟、单次有效。</small></div>
            {preview.failedItems > 0 ? <AlertTriangle size={18} /> : <CheckCircle2 size={18} />}
          </header>
          <div className="result-metrics">
            <span><b>{preview.profilesReady}</b> 个资料</span>
            <span><b>{preview.importedFields}</b> 个字段映射</span>
            <span><b>{preview.skippedFields}</b> 个字段跳过</span>
            <span><b>{preview.failedItems}</b> 个失败项</span>
          </div>
          <div className="migration-report-list">
            {preview.reports.slice(0, 100).map((report, index) => (
              <article key={`${report.item}-${index}`} className={`migration-report ${report.status}`}>
                <div><strong>{report.item}</strong><span>{report.message}</span></div>
                {report.fields.length ? (
                  <ul>{report.fields.map((field, fieldIndex) => <li key={`${field.field}-${fieldIndex}`}><b>{field.field}</b><span className={field.status}>{field.status}</span><small>{field.message}</small></li>)}</ul>
                ) : null}
              </article>
            ))}
          </div>
          {preview.reports.length > 100 ? <small>界面仅显示前 100 条；计数包含全部 {preview.reports.length} 条有界报告。</small> : null}
        </section>
      ) : null}

      {lastResult ? (
        <div className="migration-result" role="status">
          <strong>{lastResult.sourceLabel} 导入完成</strong>
          <div className="result-metrics">
            <span><b>{lastResult.profiles.length}</b> 个主机</span>
            <span><b>{lastResult.credentialsImported}</b> 个密码</span>
            <span><b>{lastResult.filesSkipped}</b> 个跳过/失败</span>
            <span><b>{lastResult.credentialsFailed}</b> 个密码未迁移</span>
          </div>
          <small>共扫描 {lastResult.filesFound} 个配置文件。资料合并不会连接远端、接受主机密钥或证明凭据有效。</small>
        </div>
      ) : null}
    </Dialog>
  );
}
