import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Database, FolderOpen, LockKeyhole, RefreshCw, ShieldCheck } from "lucide-react";
import type { HostProfile } from "../types";
import { Dialog } from "./Dialog";

export interface FinalShellImportResult {
  profiles: HostProfile[];
  filesFound: number;
  credentialsImported: number;
  credentialsFailed: number;
  filesSkipped: number;
}

interface MigrationDialogProps {
  onClose: () => void;
  onImported: (result: FinalShellImportResult) => void;
  showToast: (message: string) => void;
}

function isDesktopRuntime() {
  return "__TAURI_INTERNALS__" in window;
}

export function MigrationDialog({ onClose, onImported, showToast }: MigrationDialogProps) {
  const [path, setPath] = useState("");
  const [includePasswords, setIncludePasswords] = useState(true);
  const [busy, setBusy] = useState(false);
  const [lastResult, setLastResult] = useState<FinalShellImportResult | null>(null);

  async function chooseDirectory() {
    if (!isDesktopRuntime()) {
      showToast("目录选择只在桌面应用中可用");
      return;
    }
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({ directory: true, multiple: false, title: "选择 FinalShell 配置目录" });
    if (typeof selected === "string") setPath(selected);
  }

  async function runImport() {
    if (!path.trim()) {
      showToast("请先选择 FinalShell 配置目录");
      return;
    }
    if (!isDesktopRuntime()) {
      showToast("FinalShell 导入只在桌面应用中可用");
      return;
    }

    setBusy(true);
    try {
      const result = await invoke<FinalShellImportResult>("import_finalshell", {
        path: path.trim(),
        includePasswords,
      });
      setLastResult(result);
      onImported(result);
    } catch (error) {
      showToast(String(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      title="从 FinalShell 迁移"
      wide
      onClose={onClose}
      footer={(
        <>
          <button className="secondary-button" type="button" onClick={onClose}>关闭</button>
          <button className="primary-button" type="button" disabled={busy || !path.trim()} onClick={() => void runImport()}>
            {busy ? <RefreshCw className="spin" size={14} /> : <Database size={14} />}
            {busy ? "正在导入" : "开始导入"}
          </button>
        </>
      )}
    >
      <div className="migration-callout">
        <ShieldCheck size={19} />
        <div><strong>本机迁移</strong><span>密码解密后直接写入系统凭据管理器，不会返回到 WebView 或写入资料库 JSON。</span></div>
      </div>

      <div className="migration-source-row">
        <span className="source-logo"><Database size={20} /></span>
        <div><strong>FinalShell</strong><small>连接配置目录中的 *_connect_config.json</small></div>
        <span className="available-badge">当前可用</span>
      </div>

      <label className="field full migration-path">
        <span>配置目录</span>
        <div className="path-picker">
          <input value={path} onChange={(event) => setPath(event.target.value)} placeholder="选择包含 FinalShell 配置的文件夹" spellCheck={false} />
          <button className="secondary-button" type="button" onClick={() => void chooseDirectory()}><FolderOpen size={14} /> 选择</button>
        </div>
      </label>

      <label className="credential-option">
        <input type="checkbox" checked={includePasswords} onChange={(event) => setIncludePasswords(event.target.checked)} />
        <LockKeyhole size={16} />
        <span><strong>同时迁移已保存密码</strong><small>导入系统凭据管理器；直连终端、负载采样和 SFTP 会自动复用。</small></span>
      </label>

      {lastResult ? (
        <div className="migration-result" role="status">
          <strong>本次扫描完成</strong>
          <div className="result-metrics">
            <span><b>{lastResult.profiles.length}</b> 个主机</span>
            <span><b>{lastResult.credentialsImported}</b> 个密码</span>
            <span><b>{lastResult.filesSkipped}</b> 个跳过</span>
            <span><b>{lastResult.credentialsFailed}</b> 个密码未迁移</span>
          </div>
          <small>共发现 {lastResult.filesFound} 个配置文件；“未迁移”只表示无法解密或写入系统凭据库，不是远端密码校验结果。重复主机在加入资料库时会再次合并。</small>
        </div>
      ) : null}
    </Dialog>
  );
}
