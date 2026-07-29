import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Check, FileKey2, FolderOpen, KeyRound, Plus, RefreshCw, Server } from "lucide-react";
import type { SshKeyProfile } from "../types";
import { Dialog } from "./Dialog";

interface KeyManagerDialogProps {
  keys: SshKeyProfile[];
  activeHostLabel: string;
  activeSessionId: string;
  connected: boolean;
  onGenerated: (key: SshKeyProfile) => void;
  onClose: () => void;
  showToast: (message: string) => void;
}

function isDesktopRuntime() {
  return "__TAURI_INTERNALS__" in window;
}

export function KeyManagerDialog({ keys, activeHostLabel, activeSessionId, connected, onGenerated, onClose, showToast }: KeyManagerDialogProps) {
  const [creating, setCreating] = useState(keys.length === 0);
  const [algorithm, setAlgorithm] = useState<"ed25519" | "rsa4096">("ed25519");
  const [path, setPath] = useState("");
  const [comment, setComment] = useState("VPShell");
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [savePassphrase, setSavePassphrase] = useState(false);
  const [busy, setBusy] = useState(false);

  async function choosePath() {
    if (!isDesktopRuntime()) {
      showToast("文件选择只在桌面应用中可用");
      return;
    }
    const { save } = await import("@tauri-apps/plugin-dialog");
    const selected = await save({ title: "保存 SSH 私钥", defaultPath: algorithm === "ed25519" ? "id_ed25519" : "id_rsa" });
    if (selected) setPath(selected);
  }

  async function generateKey() {
    if (!path.trim()) {
      showToast("请先选择私钥保存路径");
      return;
    }
    if (passphrase !== confirmPassphrase) {
      showToast("两次输入的私钥口令不一致");
      return;
    }
    if (!isDesktopRuntime()) {
      showToast("SSH 密钥生成只在桌面应用中可用");
      return;
    }

    setBusy(true);
    try {
      const key = await invoke<SshKeyProfile>("generate_ssh_key", {
        request: { algorithm, path: path.trim(), comment, passphrase, savePassphrase },
      });
      onGenerated(key);
      setPassphrase("");
      setConfirmPassphrase("");
      setCreating(false);
      showToast(`已生成 ${key.name}`);
    } catch (error) {
      showToast(String(error));
    } finally {
      setBusy(false);
    }
  }

  async function installKey(key: SshKeyProfile) {
    if (!connected || !isDesktopRuntime()) {
      showToast("请先连接目标主机");
      return;
    }
    const { confirm } = await import("@tauri-apps/plugin-dialog");
    const approved = await confirm(`把 ${key.name} 的公钥安装到 ${activeHostLabel}？`, {
      title: "确认安装 SSH 公钥",
      kind: "warning",
    });
    if (!approved) return;
    try {
      await invoke("install_public_key", { sessionId: activeSessionId, publicKeyPath: key.publicKeyPath });
      showToast("公钥安装命令已发送到当前终端");
    } catch (error) {
      showToast(String(error));
    }
  }

  return (
    <Dialog
      title="SSH 密钥管理器"
      wide
      onClose={onClose}
      footer={(
        <>
          <button className="secondary-button" type="button" onClick={onClose}>关闭</button>
          {!creating ? <button className="primary-button" type="button" onClick={() => setCreating(true)}><Plus size={14} /> 生成密钥</button> : null}
          {creating ? <button className="primary-button" type="button" disabled={busy} onClick={() => void generateKey()}>{busy ? <RefreshCw className="spin" size={14} /> : <KeyRound size={14} />} 生成</button> : null}
        </>
      )}
    >
      {creating ? (
        <div className="key-create-form">
          <div className="algorithm-picker" role="radiogroup" aria-label="密钥算法">
            <button className={algorithm === "ed25519" ? "active" : ""} type="button" onClick={() => setAlgorithm("ed25519")}><strong>Ed25519</strong><span>推荐</span></button>
            <button className={algorithm === "rsa4096" ? "active" : ""} type="button" onClick={() => setAlgorithm("rsa4096")}><strong>RSA 4096</strong><span>兼容旧系统</span></button>
          </div>
          <div className="form-grid">
            <label className="field full"><span>私钥保存路径</span><div className="path-picker"><input value={path} onChange={(event) => setPath(event.target.value)} spellCheck={false} /><button className="secondary-button" type="button" onClick={() => void choosePath()}><FolderOpen size={14} /> 选择</button></div></label>
            <label className="field full"><span>注释</span><input value={comment} maxLength={160} onChange={(event) => setComment(event.target.value)} /></label>
            <label className="field span-2"><span>私钥口令（可选，至少 10 位）</span><input type="password" value={passphrase} autoComplete="new-password" onChange={(event) => setPassphrase(event.target.value)} /></label>
            <label className="field span-2"><span>确认口令</span><input type="password" value={confirmPassphrase} autoComplete="new-password" onChange={(event) => setConfirmPassphrase(event.target.value)} /></label>
          </div>
          <label className="credential-option"><input type="checkbox" checked={savePassphrase} disabled={!passphrase} onChange={(event) => setSavePassphrase(event.target.checked)} /><FileKey2 size={16} /><span><strong>保存口令到系统凭据管理器</strong><small>私钥文件使用 OpenSSH AES-256 加密。</small></span></label>
        </div>
      ) : (
        <div className="key-list">
          {keys.map((key) => (
            <article className="key-row" key={key.id}>
              <span className="key-icon"><KeyRound size={18} /></span>
              <div><strong>{key.name}</strong><code>{key.fingerprint}</code><small>{key.algorithm.toUpperCase()} · {key.privateKeyPath}</small></div>
              <button className="secondary-button" type="button" disabled={!connected} onClick={() => void installKey(key)}><Server size={14} /> 安装到当前主机</button>
            </article>
          ))}
          {keys.length === 0 ? <div className="empty-state"><KeyRound size={24} /><span>还没有本机 SSH 密钥</span></div> : null}
          {connected ? <div className="connected-target"><Check size={14} /> 当前目标：{activeHostLabel}</div> : null}
        </div>
      )}
    </Dialog>
  );
}
