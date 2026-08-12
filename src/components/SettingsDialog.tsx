import { useEffect, useRef, useState } from "react";
import type { Update } from "@tauri-apps/plugin-updater";
import {
  CheckCircle2,
  Download,
  FileCode2,
  FolderOpen,
  Info,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import { Dialog } from "./Dialog";

export interface SettingsValues {
  externalEditorPath: string;
  autoUploadEditedFiles: boolean;
}

interface SettingsDialogProps {
  externalEditorPath: string;
  autoUploadEditedFiles: boolean;
  onSave: (settings: SettingsValues) => void | Promise<void>;
  onClose: () => void;
  showToast: (message: string) => void;
}

type UpdateStatus = "idle" | "checking" | "current" | "available" | "downloading" | "installing" | "error";

function isDesktopRuntime() {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function formatBytes(bytes: number) {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

export function SettingsDialog({
  externalEditorPath,
  autoUploadEditedFiles,
  onSave,
  onClose,
  showToast,
}: SettingsDialogProps) {
  const desktopRuntime = isDesktopRuntime();
  const [editorPath, setEditorPath] = useState(externalEditorPath);
  const [autoUpload, setAutoUpload] = useState(autoUploadEditedFiles);
  const [saving, setSaving] = useState(false);
  const [appVersion, setAppVersion] = useState(desktopRuntime ? "读取中..." : "浏览器预览");
  const [updateStatus, setUpdateStatus] = useState<UpdateStatus>("idle");
  const [availableUpdate, setAvailableUpdate] = useState<Update | null>(null);
  const updateRef = useRef<Update | null>(null);
  const [downloadedBytes, setDownloadedBytes] = useState(0);
  const [downloadTotal, setDownloadTotal] = useState<number | undefined>();

  useEffect(() => {
    if (!desktopRuntime) return;
    let active = true;
    void import("@tauri-apps/api/app")
      .then(({ getVersion }) => getVersion())
      .then((version) => {
        if (active) setAppVersion(version);
      })
      .catch(() => {
        if (active) setAppVersion("未知");
      });
    return () => {
      active = false;
    };
  }, [desktopRuntime]);

  useEffect(() => () => {
    void updateRef.current?.close().catch(() => undefined);
  }, []);

  async function chooseEditor() {
    if (!desktopRuntime) {
      showToast("编辑器选择只在桌面应用中可用");
      return;
    }
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const selected = await open({
        title: "选择外部编辑器",
        multiple: false,
        directory: false,
        filters: [{ name: "应用程序", extensions: ["exe", "app", "AppImage"] }],
      });
      if (typeof selected === "string") setEditorPath(selected);
    } catch (error) {
      showToast(`无法选择编辑器：${String(error)}`);
    }
  }

  async function saveSettings() {
    setSaving(true);
    try {
      await onSave({
        externalEditorPath: editorPath.trim(),
        autoUploadEditedFiles: autoUpload,
      });
      showToast("设置已保存");
      onClose();
    } catch (error) {
      showToast(`保存设置失败：${String(error)}`);
    } finally {
      setSaving(false);
    }
  }

  async function checkForUpdates() {
    if (!desktopRuntime) {
      showToast("浏览器预览不能检查桌面更新");
      return;
    }
    setUpdateStatus("checking");
    setDownloadedBytes(0);
    setDownloadTotal(undefined);
    try {
      const { check } = await import("@tauri-apps/plugin-updater");
      const update = await check();
      if (updateRef.current) await updateRef.current.close().catch(() => undefined);
      updateRef.current = update;
      setAvailableUpdate(update);
      if (update) {
        setUpdateStatus("available");
        showToast(`发现新版本 ${update.version}`);
      } else {
        setUpdateStatus("current");
        showToast("当前已经是最新版本");
      }
    } catch (error) {
      setUpdateStatus("error");
      showToast(`检查更新失败：${String(error)}`);
    }
  }

  async function installUpdate() {
    if (!availableUpdate || !desktopRuntime) return;
    setUpdateStatus("downloading");
    setDownloadedBytes(0);
    setDownloadTotal(undefined);
    try {
      await availableUpdate.downloadAndInstall((event) => {
        if (event.event === "Started") {
          setDownloadTotal(event.data.contentLength);
          return;
        }
        if (event.event === "Progress") {
          setDownloadedBytes((current) => current + event.data.chunkLength);
          return;
        }
        setUpdateStatus("installing");
      });
      showToast("更新已安装，正在重启 VPShell");
      const { relaunch } = await import("@tauri-apps/plugin-process");
      await relaunch();
    } catch (error) {
      setUpdateStatus("error");
      showToast(`安装更新失败：${String(error)}`);
    }
  }

  const updateBusy = updateStatus === "checking" || updateStatus === "downloading" || updateStatus === "installing";

  function requestClose() {
    if (updateStatus === "downloading" || updateStatus === "installing") {
      showToast("更新正在进行，请等待安装完成");
      return;
    }
    onClose();
  }

  return (
    <Dialog
      title="设置"
      wide
      onClose={requestClose}
      footer={(
        <>
          <button className="secondary-button" type="button" disabled={updateBusy} onClick={requestClose}>取消</button>
          <button className="primary-button" type="button" disabled={saving} onClick={() => void saveSettings()}>
            {saving ? <RefreshCw className="spin" size={14} /> : <CheckCircle2 size={14} />} 保存设置
          </button>
        </>
      )}
    >
      <div className="settings-dialog-content">
        <section className="settings-section" aria-labelledby="settings-editor-title">
          <div className="settings-section-heading">
            <FileCode2 size={17} />
            <div><h3 id="settings-editor-title">远程文件编辑器</h3><p>支持 Notepad++、VS Code/VSCodium、自定义程序和系统默认编辑器。</p></div>
          </div>
          <div className="form-grid">
            <label className="field full">
              <span>编辑器可执行文件</span>
              <div className="path-picker">
                <input
                  value={editorPath}
                  onChange={(event) => setEditorPath(event.target.value)}
                  placeholder="Notepad++ 或 VS Code 的绝对可执行文件路径"
                  spellCheck={false}
                />
                <button className="secondary-button" type="button" disabled={!desktopRuntime} onClick={() => void chooseEditor()}>
                  <FolderOpen size={14} /> 选择
                </button>
              </div>
            </label>
          </div>
          <label className="credential-option settings-auto-upload">
            <input type="checkbox" checked={autoUpload} onChange={(event) => setAutoUpload(event.target.checked)} />
            <ShieldCheck size={16} />
            <span><strong>保存后自动上传</strong><small>上传前校验远端版本；远端内容已变化时阻止覆盖，并要求你确认。</small></span>
          </label>
        </section>

        <section className="settings-section settings-about" aria-labelledby="settings-about-title">
          <div className="settings-section-heading">
            <Info size={17} />
            <div><h3 id="settings-about-title">关于与升级</h3><p>VPShell {appVersion}</p></div>
          </div>

          {!desktopRuntime ? (
            <p className="settings-update-disabled" role="status">
              浏览器预览中：检查、下载和安装更新仅在桌面应用内可用。
            </p>
          ) : null}

          {availableUpdate ? (
            <div className="settings-update-details" role="status">
              <strong>可升级到 {availableUpdate.version}</strong>
              {availableUpdate.date ? <small>发布于 {availableUpdate.date}</small> : null}
              {availableUpdate.body ? <p className="settings-update-notes">{availableUpdate.body}</p> : null}
            </div>
          ) : null}

          {updateStatus === "current" ? <p className="settings-update-current"><CheckCircle2 size={14} /> 当前已经是最新版本。</p> : null}
          {updateStatus === "error" ? <p className="settings-update-error">更新操作失败，请检查网络或稍后重试。</p> : null}

          {updateStatus === "downloading" || updateStatus === "installing" ? (
            <div className="settings-update-progress" role="status" aria-live="polite">
              <progress
                max={downloadTotal ?? 1}
                value={downloadTotal ? Math.min(downloadedBytes, downloadTotal) : undefined}
              />
              <span>
                {updateStatus === "installing"
                  ? "正在安装签名更新..."
                  : `正在下载 ${formatBytes(downloadedBytes)}${downloadTotal ? ` / ${formatBytes(downloadTotal)}` : ""}`}
              </span>
            </div>
          ) : null}

          <div className="settings-update-actions">
            <button className="secondary-button" type="button" disabled={!desktopRuntime || updateBusy} onClick={() => void checkForUpdates()}>
              {updateStatus === "checking" ? <RefreshCw className="spin" size={14} /> : <RefreshCw size={14} />} 检查更新
            </button>
            {availableUpdate ? (
              <button className="primary-button" type="button" disabled={updateBusy} onClick={() => void installUpdate()}>
                {updateStatus === "downloading" || updateStatus === "installing"
                  ? <RefreshCw className="spin" size={14} />
                  : <Download size={14} />}
                下载并安装
              </button>
            ) : null}
          </div>
        </section>
      </div>
    </Dialog>
  );
}
