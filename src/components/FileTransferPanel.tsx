import { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  ArrowUp,
  CheckCircle2,
  Download,
  File,
  FilePenLine,
  FileSymlink,
  Folder,
  FolderOpen,
  LoaderCircle,
  Package,
  RefreshCw,
  RotateCcw,
  Save,
  ShieldAlert,
  TriangleAlert,
  Upload,
  X,
} from "lucide-react";

export interface SshConnectionSpec {
  host: string;
  port: number;
  username: string;
  credentialRef?: string;
  identityFile?: string;
  identityPassphraseRef?: string;
  proxyJump?: string;
}

type RemoteEntryKind = "file" | "directory" | "symlink";

interface RemoteFileEntry {
  name: string;
  path: string;
  kind: RemoteEntryKind;
  size: number;
  modified: string | number | null;
  permissions: string;
  owner: string;
}

interface RemoteDirectoryResult {
  path: string;
  entries: RemoteFileEntry[];
}

type TransferStatus = "preparing" | "packaging" | "transferring" | "extracting" | "completed" | "failed" | "cancelled";

interface TransferProgressEvent {
  transferId: string;
  status?: string;
  phase?: string;
  transferredBytes?: number;
  bytesTransferred?: number;
  totalBytes?: number;
  currentPath?: string;
  path?: string;
  message?: string;
}

interface ActiveTransfer {
  id: string;
  direction: "upload" | "download";
  status: TransferStatus;
  transferredBytes: number;
  totalBytes: number;
  currentPath?: string;
  message?: string;
}

interface BeginExternalEditResult {
  sessionId: string;
  remotePath: string;
  localPath: string;
  editorLabel: string;
}

interface ExternalEditStatus {
  sessionId: string;
  remotePath: string;
  localPath: string;
  dirty: boolean;
  busy: boolean;
  localMissing: boolean;
  localSize: number;
  localModifiedMillis: number | null;
  localRevision: string;
}

interface SaveExternalEditResult {
  outcome: "saved" | "unchanged" | "conflict";
  remoteVersion: {
    size: number;
    modified: number | null;
    permissions: number | null;
  } | null;
}

interface ExternalEditSession extends BeginExternalEditResult {
  dirty: boolean;
  busy: boolean;
  localMissing: boolean;
  localRevision: string;
  conflict: boolean;
  error?: string;
}

interface FileTransferPanelProps {
  connection: SshConnectionSpec;
  connected: boolean;
  initialPath: string;
  externalEditorPath: string;
  autoUploadEditedFiles: boolean;
  onPathChanged: (path: string) => void;
  showToast: (message: string) => void;
  onClose: () => void;
}

const PACKAGE_TRANSFER_STORAGE_KEY = "vpshell.package-transfer.enabled";
const LEGACY_PACKAGE_TRANSFER_STORAGE_KEY = "opsshell.package-transfer.enabled";

function isDesktopRuntime() {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function initialPackageTransferSetting() {
  try {
    const current = localStorage.getItem(PACKAGE_TRANSFER_STORAGE_KEY);
    const saved = current ?? localStorage.getItem(LEGACY_PACKAGE_TRANSFER_STORAGE_KEY);
    return saved !== "false";
  } catch {
    return true;
  }
}

function makeTransferId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `transfer-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function normalizePickedPaths(value: string | string[] | null) {
  if (value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function parentRemotePath(value: string) {
  const path = value.trim().replace(/\/+$/, "") || "/";
  if (path === "/" || path === "~") return path;
  const slash = path.lastIndexOf("/");
  if (slash < 0) return "/";
  if (slash === 0) return "/";
  return path.slice(0, slash);
}

function formatSize(bytes: number, kind: RemoteEntryKind) {
  if (kind === "directory") return "-";
  if (!Number.isFinite(bytes) || bytes < 0) return "-";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)} ${units[unitIndex]}`;
}

function formatModified(value: RemoteFileEntry["modified"]) {
  if (value === null || value === "") return "-";
  const raw = typeof value === "number" && value < 1_000_000_000_000 ? value * 1000 : value;
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function normalizedTransferStatus(value: string | undefined): TransferStatus {
  if (value === "completed" || value === "done") return "completed";
  if (value === "failed" || value === "error") return "failed";
  if (value === "cancelled") return "cancelled";
  if (value === "packaging") return "packaging";
  if (value === "extracting") return "extracting";
  if (value === "connecting" || value === "checking") return "preparing";
  return "transferring";
}

function transferStatusText(transfer: ActiveTransfer) {
  const action = transfer.direction === "upload" ? "上传" : "下载";
  const labels: Record<TransferStatus, string> = {
    preparing: `正在准备${action}`,
    packaging: "正在打包",
    transferring: `正在${action}`,
    extracting: "正在远端解包",
    completed: `${action}完成`,
    failed: `${action}失败`,
    cancelled: `${action}已取消`,
  };
  return labels[transfer.status];
}

function entryIcon(kind: RemoteEntryKind) {
  if (kind === "directory") return <Folder size={15} aria-hidden="true" />;
  if (kind === "symlink") return <FileSymlink size={15} aria-hidden="true" />;
  return <File size={15} aria-hidden="true" />;
}

export function FileTransferPanel({
  connection,
  connected,
  initialPath,
  externalEditorPath,
  autoUploadEditedFiles,
  onPathChanged,
  showToast,
  onClose,
}: FileTransferPanelProps) {
  const panelRef = useRef<HTMLElement>(null);
  const selectAllRef = useRef<HTMLInputElement>(null);
  const connectionRef = useRef(connection);
  const connectedRef = useRef(connected);
  const pathRef = useRef(initialPath.trim() || "/");
  const lastReportedPathRef = useRef("");
  const loadGenerationRef = useRef(0);
  const uploadPathsRef = useRef<(paths: string[]) => void>(() => undefined);
  const editSessionsRef = useRef<ExternalEditSession[]>([]);
  const editSaveInFlightRef = useRef<Set<string>>(new Set());
  const autoSaveRevisionRef = useRef<Set<string>>(new Set());
  const autoUploadEditedFilesRef = useRef(autoUploadEditedFiles);
  const [path, setPath] = useState(initialPath.trim() || "/");
  const [pathInput, setPathInput] = useState(initialPath.trim() || "/");
  const [entries, setEntries] = useState<RemoteFileEntry[]>([]);
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(() => new Set());
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [packageTransfer, setPackageTransfer] = useState(initialPackageTransferSetting);
  const [activeTransfer, setActiveTransfer] = useState<ActiveTransfer | null>(null);
  const [dragInside, setDragInside] = useState(false);
  const [dragItemCount, setDragItemCount] = useState(0);
  const [editOpeningPath, setEditOpeningPath] = useState<string | null>(null);
  const [editSessions, setEditSessions] = useState<ExternalEditSession[]>([]);

  connectionRef.current = connection;
  connectedRef.current = connected;
  pathRef.current = path;
  editSessionsRef.current = editSessions;
  autoUploadEditedFilesRef.current = autoUploadEditedFiles;

  const connectionKey = [
    connection.host,
    connection.port,
    connection.username,
    connection.credentialRef ?? "",
    connection.identityFile ?? "",
    connection.identityPassphraseRef ?? "",
    connection.proxyJump ?? "",
  ].join("\u0000");

  const sortedEntries = useMemo(() => [...entries].sort((left, right) => {
    if (left.kind === "directory" && right.kind !== "directory") return -1;
    if (left.kind !== "directory" && right.kind === "directory") return 1;
    return left.name.localeCompare(right.name, "zh-CN", { numeric: true, sensitivity: "base" });
  }), [entries]);

  const selectedEntries = useMemo(
    () => entries.filter((entry) => selectedPaths.has(entry.path)),
    [entries, selectedPaths],
  );
  const editableSelection = selectedEntries.length === 1 && selectedEntries[0].kind === "file"
    ? selectedEntries[0]
    : null;

  const transferBusy = activeTransfer !== null
    && !["completed", "failed", "cancelled"].includes(activeTransfer.status);

  async function loadDirectory(targetPath: string) {
    const requestedPath = targetPath.trim() || "/";
    if (!connectedRef.current || !isDesktopRuntime()) {
      setEntries([]);
      setSelectedPaths(new Set());
      setLoading(false);
      setLoadError(null);
      return;
    }

    const generation = loadGenerationRef.current + 1;
    loadGenerationRef.current = generation;
    setLoading(true);
    setLoadError(null);
    try {
      const result = await invoke<RemoteDirectoryResult>("list_remote_files", {
        connection: connectionRef.current,
        path: requestedPath,
      });
      if (generation !== loadGenerationRef.current) return;
      const resolvedPath = result.path.trim() || requestedPath;
      setEntries(result.entries);
      setSelectedPaths(new Set());
      setPath(resolvedPath);
      setPathInput(resolvedPath);
      lastReportedPathRef.current = resolvedPath;
      onPathChanged(resolvedPath);
    } catch (error) {
      if (generation !== loadGenerationRef.current) return;
      setEntries([]);
      setSelectedPaths(new Set());
      setLoadError(String(error));
    } finally {
      if (generation === loadGenerationRef.current) setLoading(false);
    }
  }

  async function uploadPaths(localPaths: string[]) {
    if (localPaths.length === 0) return;
    if (!connectedRef.current || !isDesktopRuntime()) {
      showToast("连接主机后才能上传文件");
      return;
    }
    if (transferBusy) {
      showToast("当前传输完成后再开始新任务");
      return;
    }

    const transferId = makeTransferId();
    setActiveTransfer({
      id: transferId,
      direction: "upload",
      status: "preparing",
      transferredBytes: 0,
      totalBytes: 0,
    });
    try {
      await invoke("upload_remote", {
        connection: connectionRef.current,
        localPaths,
        remoteDirectory: pathRef.current,
        packageTransfer,
        transferId,
      });
      setActiveTransfer((current) => current?.id === transferId
        ? { ...current, status: "completed" }
        : current);
      showToast(`已上传 ${localPaths.length} 项`);
      await loadDirectory(pathRef.current);
    } catch (error) {
      setActiveTransfer((current) => current?.id === transferId
        ? { ...current, status: "failed", message: String(error) }
        : current);
      showToast("上传失败，请查看传输状态");
    }
  }

  uploadPathsRef.current = (localPaths) => {
    void uploadPaths(localPaths);
  };

  function updateEditSession(sessionId: string, patch: Partial<ExternalEditSession>) {
    setEditSessions((current) => current.map((session) => (
      session.sessionId === sessionId ? { ...session, ...patch } : session
    )));
  }

  async function openExternalEditor(entry: RemoteFileEntry) {
    if (entry.kind !== "file") {
      showToast(entry.kind === "symlink" ? "安全模式不通过符号链接启动编辑器" : "请选择普通文件");
      return;
    }
    if (!connectedRef.current || !isDesktopRuntime()) {
      showToast("连接主机后才能编辑远端文件");
      return;
    }
    if (editSessionsRef.current.some((session) => session.remotePath === entry.path)) {
      showToast("该文件已经在外部编辑器中打开");
      return;
    }

    setEditOpeningPath(entry.path);
    try {
      const result = await invoke<BeginExternalEditResult>("begin_external_edit", {
        connection: connectionRef.current,
        remotePath: entry.path,
        editorPath: externalEditorPath.trim(),
      });
      const next: ExternalEditSession = {
        ...result,
        dirty: false,
        busy: false,
        localMissing: false,
        localRevision: "",
        conflict: false,
      };
      setEditSessions((current) => [...current, next]);
      showToast("已用 " + result.editorLabel + " 打开 " + entry.name);
    } catch (error) {
      showToast("无法打开外部编辑器：" + String(error));
    } finally {
      setEditOpeningPath(null);
    }
  }

  async function saveExternalEdit(sessionId: string, force = false, automatic = false) {
    if (editSaveInFlightRef.current.has(sessionId)) return;
    editSaveInFlightRef.current.add(sessionId);
    updateEditSession(sessionId, { busy: true, error: undefined });
    try {
      const result = await invoke<SaveExternalEditResult>("save_external_edit", { sessionId, force });
      if (result.outcome === "conflict") {
        updateEditSession(sessionId, { busy: false, conflict: true });
        showToast("远端文件已变化，已阻止静默覆盖");
      } else {
        updateEditSession(sessionId, { busy: false, dirty: false, conflict: false });
        if (result.outcome === "saved") {
          showToast(automatic ? "本地保存已安全回传" : "编辑结果已安全回传");
          await loadDirectory(pathRef.current);
        } else if (!automatic) {
          showToast("文件内容没有变化");
        }
      }
    } catch (error) {
      updateEditSession(sessionId, { busy: false, error: String(error) });
      if (!automatic) showToast("回传失败：" + String(error));
    } finally {
      editSaveInFlightRef.current.delete(sessionId);
    }
  }

  async function reloadExternalEdit(sessionId: string) {
    if (!window.confirm("重新下载会丢弃当前本地修改，确定继续吗？")) return;
    updateEditSession(sessionId, { busy: true, error: undefined });
    try {
      await invoke("reload_external_edit", { sessionId });
      autoSaveRevisionRef.current.forEach((key) => {
        if (key.startsWith(sessionId + ":")) autoSaveRevisionRef.current.delete(key);
      });
      updateEditSession(sessionId, {
        busy: false,
        dirty: false,
        conflict: false,
        localMissing: false,
        localRevision: "",
      });
      showToast("已重新下载远端版本");
    } catch (error) {
      updateEditSession(sessionId, { busy: false, error: String(error) });
      showToast("重新下载失败：" + String(error));
    }
  }

  async function forceSaveExternalEdit(sessionId: string) {
    if (!window.confirm("远端版本已变化。强制覆盖会替换其他人或进程的修改，确定继续吗？")) return;
    await saveExternalEdit(sessionId, true);
  }

  async function endExternalEdit(session: ExternalEditSession) {
    if ((session.dirty || session.conflict)
      && !window.confirm("本地仍有未回传修改，结束后临时副本会被清理。确定结束吗？")) return;
    updateEditSession(session.sessionId, { busy: true, error: undefined });
    try {
      await invoke("end_external_edit", { sessionId: session.sessionId });
      setEditSessions((current) => current.filter((item) => item.sessionId !== session.sessionId));
      showToast("外部编辑会话已结束");
    } catch (error) {
      updateEditSession(session.sessionId, { busy: false, error: String(error) });
      showToast("无法结束编辑会话：" + String(error));
    }
  }

  function requestClosePanel() {
    if (editSessionsRef.current.length > 0) {
      showToast("请先结束外部编辑会话，再关闭文件面板");
      return;
    }
    onClose();
  }

  useEffect(() => {
    try {
      localStorage.setItem(PACKAGE_TRANSFER_STORAGE_KEY, String(packageTransfer));
    } catch {
      // A blocked localStorage should not prevent file transfer.
    }
  }, [packageTransfer]);

  useEffect(() => {
    if (!isDesktopRuntime()) return undefined;
    let disposed = false;

    async function pollExternalEdits() {
      const sessions = editSessionsRef.current.filter((session) => !session.busy);
      await Promise.all(sessions.map(async (session) => {
        try {
          const status = await invoke<ExternalEditStatus>("get_external_edit_status", {
            sessionId: session.sessionId,
          });
          if (disposed) return;
          updateEditSession(session.sessionId, {
            dirty: status.dirty,
            busy: status.busy,
            localMissing: status.localMissing,
            localRevision: status.localRevision,
            error: status.localMissing ? "本地临时副本已丢失" : undefined,
          });

          const revisionKey = session.sessionId + ":" + status.localRevision;
          if (autoUploadEditedFilesRef.current
            && status.dirty
            && !status.busy
            && !status.localMissing
            && !session.conflict
            && status.localRevision
            && !autoSaveRevisionRef.current.has(revisionKey)) {
            autoSaveRevisionRef.current.add(revisionKey);
            void saveExternalEdit(session.sessionId, false, true);
          }
        } catch (error) {
          if (!disposed) updateEditSession(session.sessionId, { error: String(error) });
        }
      }));
    }

    void pollExternalEdits();
    const timer = window.setInterval(() => void pollExternalEdits(), 1500);
    return () => {
      disposed = true;
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    const targetPath = initialPath.trim() || "/";
    lastReportedPathRef.current = "";
    setPath(targetPath);
    setPathInput(targetPath);
    setEntries([]);
    setSelectedPaths(new Set());
    setLoadError(null);
    if (connected && isDesktopRuntime()) void loadDirectory(targetPath);
    return () => {
      loadGenerationRef.current += 1;
    };
    // Reload only when the remote connection identity changes.
  }, [connectionKey, connected]);

  useEffect(() => {
    const externalPath = initialPath.trim() || "/";
    if (externalPath === lastReportedPathRef.current || externalPath === pathRef.current) return;
    setPath(externalPath);
    setPathInput(externalPath);
    if (connected && isDesktopRuntime()) void loadDirectory(externalPath);
  }, [initialPath]);

  useEffect(() => {
    if (!selectAllRef.current) return;
    selectAllRef.current.indeterminate = selectedPaths.size > 0 && selectedPaths.size < entries.length;
  }, [entries.length, selectedPaths]);

  useEffect(() => {
    if (!isDesktopRuntime()) return undefined;
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void listen<TransferProgressEvent>("transfer-progress", (event) => {
      const progress = event.payload;
      setActiveTransfer((current) => {
        if (!current || current.id !== progress.transferId) return current;
        return {
          ...current,
          status: normalizedTransferStatus(progress.status ?? progress.phase),
          transferredBytes: progress.transferredBytes ?? progress.bytesTransferred ?? current.transferredBytes,
          totalBytes: progress.totalBytes ?? current.totalBytes,
          currentPath: progress.currentPath ?? progress.path ?? current.currentPath,
          message: progress.message ?? current.message,
        };
      });
    }).then((stop) => {
      if (disposed) stop();
      else unlisten = stop;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  useEffect(() => {
    if (!isDesktopRuntime()) return undefined;
    let disposed = false;
    let unlisten: (() => void) | undefined;
    let scaleFactor = window.devicePixelRatio || 1;

    void getCurrentWindow().scaleFactor().then((value) => {
      if (!disposed && Number.isFinite(value) && value > 0) scaleFactor = value;
    });

    function isInsidePanel(physicalX: number, physicalY: number) {
      const bounds = panelRef.current?.getBoundingClientRect();
      if (!bounds) return false;
      const logicalX = physicalX / scaleFactor;
      const logicalY = physicalY / scaleFactor;
      return logicalX >= bounds.left && logicalX <= bounds.right
        && logicalY >= bounds.top && logicalY <= bounds.bottom;
    }

    void getCurrentWebview().onDragDropEvent((event) => {
      const payload = event.payload;
      if (payload.type === "leave") {
        setDragInside(false);
        setDragItemCount(0);
        return;
      }
      const inside = isInsidePanel(payload.position.x, payload.position.y);
      setDragInside(inside);
      if (payload.type === "enter") setDragItemCount(payload.paths.length);
      if (payload.type === "drop") {
        setDragInside(false);
        setDragItemCount(0);
        if (inside
          && payload.paths.length > 0
          && window.confirm("上传 " + payload.paths.length + " 项到 " + pathRef.current + "？")) {
          uploadPathsRef.current(payload.paths);
        }
      }
    }).then((stop) => {
      if (disposed) stop();
      else unlisten = stop;
    });

    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  function toggleSelection(remotePath: string) {
    setSelectedPaths((current) => {
      const next = new Set(current);
      if (next.has(remotePath)) next.delete(remotePath);
      else next.add(remotePath);
      return next;
    });
  }

  function toggleAllEntries() {
    setSelectedPaths((current) => current.size === entries.length
      ? new Set()
      : new Set(entries.map((entry) => entry.path)));
  }

  async function chooseFilesToUpload() {
    if (!connected || !isDesktopRuntime()) {
      showToast("连接主机后才能上传文件");
      return;
    }
    const { open } = await import("@tauri-apps/plugin-dialog");
    const picked = await open({ multiple: true, directory: false, title: "选择要上传的文件" });
    await uploadPaths(normalizePickedPaths(picked));
  }

  async function chooseFolderToUpload() {
    if (!connected || !isDesktopRuntime()) {
      showToast("连接主机后才能上传文件夹");
      return;
    }
    const { open } = await import("@tauri-apps/plugin-dialog");
    const picked = await open({ multiple: true, directory: true, title: "选择要上传的文件夹" });
    await uploadPaths(normalizePickedPaths(picked));
  }

  async function downloadSelection() {
    if (selectedEntries.length === 0) {
      showToast("请先选择要下载的文件或文件夹");
      return;
    }
    if (!connected || !isDesktopRuntime()) {
      showToast("连接主机后才能下载文件");
      return;
    }
    if (transferBusy) {
      showToast("当前传输完成后再开始新任务");
      return;
    }

    const { open } = await import("@tauri-apps/plugin-dialog");
    const localDirectory = await open({ multiple: false, directory: true, title: "选择下载保存目录" });
    if (typeof localDirectory !== "string") return;

    const transferId = makeTransferId();
    setActiveTransfer({
      id: transferId,
      direction: "download",
      status: "preparing",
      transferredBytes: 0,
      totalBytes: 0,
    });
    try {
      await invoke("download_remote", {
        connection: connectionRef.current,
        remotePaths: selectedEntries.map((entry) => entry.path),
        localDirectory,
        packageTransfer,
        transferId,
      });
      setActiveTransfer((current) => current?.id === transferId
        ? { ...current, status: "completed" }
        : current);
      showToast(`已下载 ${selectedEntries.length} 项`);
    } catch (error) {
      setActiveTransfer((current) => current?.id === transferId
        ? { ...current, status: "failed", message: String(error) }
        : current);
      showToast("下载失败，请查看传输状态");
    }
  }

  const transferPercent = activeTransfer && activeTransfer.totalBytes > 0
    ? Math.min(100, Math.max(0, activeTransfer.transferredBytes / activeTransfer.totalBytes * 100))
    : 0;
  const previewOnly = !connected || !isDesktopRuntime();

  return (
    <section
      ref={panelRef}
      className="file-panel file-transfer-panel"
      aria-label="SFTP 文件传输"
      style={{ position: "relative" }}
    >
      <header className="file-panel-header">
        <div>
          <FolderOpen size={16} aria-hidden="true" />
          <strong>SFTP 文件</strong>
          <span className={`preview-badge ${connected ? "connected" : ""}`}>{connected ? "已连接" : "未连接"}</span>
        </div>
        <div>
          <button
            className="icon-button compact"
            type="button"
            title="刷新目录"
            aria-label="刷新目录"
            disabled={previewOnly || loading}
            onClick={() => void loadDirectory(path)}
          >
            <RefreshCw className={loading ? "spin" : ""} size={15} />
          </button>
          <button className="icon-button compact" type="button" title="关闭文件面板" aria-label="关闭文件面板" onClick={requestClosePanel}>
            <X size={15} />
          </button>
        </div>
      </header>

      <form
        className="remote-path"
        aria-label="远程路径"
        onSubmit={(event) => {
          event.preventDefault();
          void loadDirectory(pathInput);
        }}
      >
        <button
          className="icon-button compact"
          type="button"
          title="上一级目录"
          aria-label="上一级目录"
          disabled={previewOnly || loading || path === "/" || path === "~"}
          onClick={() => void loadDirectory(parentRemotePath(path))}
        >
          <ArrowUp size={14} />
        </button>
        <input
          aria-label="远程目录路径"
          value={pathInput}
          spellCheck={false}
          disabled={previewOnly}
          onChange={(event) => setPathInput(event.target.value)}
          style={{
            minWidth: 0,
            height: 25,
            flex: 1,
            padding: "0 7px",
            color: "var(--text)",
            background: "var(--surface, #fff)",
            border: "1px solid var(--border)",
            borderRadius: 3,
            font: "inherit",
          }}
        />
      </form>

      <div className="file-toolbar" role="toolbar" aria-label="文件传输操作">
        <button type="button" disabled={previewOnly || transferBusy} onClick={() => void chooseFilesToUpload()}>
          <Upload size={15} /><span>上传文件</span>
        </button>
        <button type="button" disabled={previewOnly || transferBusy} onClick={() => void chooseFolderToUpload()}>
          <FolderOpen size={15} /><span>上传文件夹</span>
        </button>
        <button type="button" disabled={previewOnly || selectedEntries.length === 0 || transferBusy} onClick={() => void downloadSelection()}>
          <Download size={15} /><span>下载所选</span>
        </button>
        <button
          type="button"
          disabled={previewOnly || editableSelection === null || editOpeningPath !== null}
          onClick={() => editableSelection && void openExternalEditor(editableSelection)}
        >
          {editOpeningPath ? <LoaderCircle className="spin" size={15} /> : <FilePenLine size={15} />}
          <span>外部编辑</span>
        </button>
        <label className="package-toggle" title="多个文件或文件夹打包后传输">
          <input
            type="checkbox"
            checked={packageTransfer}
            disabled={transferBusy}
            onChange={(event) => setPackageTransfer(event.target.checked)}
          />
          <Package size={15} /><span>打包传输</span>
        </label>
      </div>

      {editSessions.length > 0 ? (
        <div className="external-edit-list" aria-label="外部编辑会话">
          {editSessions.map((session) => {
            const fileName = session.remotePath.split("/").filter(Boolean).pop() || session.remotePath;
            const stateLabel = session.conflict
              ? "远端冲突"
              : session.localMissing
                ? "本地副本丢失"
                : session.busy
                  ? "处理中"
                  : session.dirty
                    ? autoUploadEditedFiles ? "等待自动回传" : "有未回传修改"
                    : "已同步";
            return (
              <div
                className={"external-edit-row" + (session.conflict ? " conflict" : "")}
                key={session.sessionId}
                title={session.error || session.localPath}
              >
                <FilePenLine size={14} aria-hidden="true" />
                <span className="external-edit-file">
                  <strong>{fileName}</strong>
                  <small>{stateLabel}</small>
                </span>
                {session.busy ? <LoaderCircle className="spin" size={14} aria-label="处理中" /> : null}
                {session.conflict ? (
                  <>
                    <button
                      className="icon-button compact"
                      type="button"
                      title="丢弃本地修改并重新下载"
                      aria-label={"重新下载 " + fileName}
                      disabled={session.busy}
                      onClick={() => void reloadExternalEdit(session.sessionId)}
                    >
                      <RotateCcw size={14} />
                    </button>
                    <button
                      className="icon-button compact danger"
                      type="button"
                      title="确认后强制覆盖远端版本"
                      aria-label={"强制覆盖 " + fileName}
                      disabled={session.busy || session.localMissing}
                      onClick={() => void forceSaveExternalEdit(session.sessionId)}
                    >
                      <ShieldAlert size={14} />
                    </button>
                  </>
                ) : (
                  <button
                    className="icon-button compact"
                    type="button"
                    title="安全回传到远端"
                    aria-label={"保存 " + fileName}
                    disabled={session.busy || session.localMissing || !session.dirty}
                    onClick={() => void saveExternalEdit(session.sessionId)}
                  >
                    <Save size={14} />
                  </button>
                )}
                <button
                  className="icon-button compact"
                  type="button"
                  title="结束外部编辑"
                  aria-label={"结束编辑 " + fileName}
                  disabled={session.busy}
                  onClick={() => void endExternalEdit(session)}
                >
                  <X size={14} />
                </button>
              </div>
            );
          })}
        </div>
      ) : null}

      <div className="file-list" role="table" aria-label={`远程目录 ${path}`} aria-busy={loading}>
        <div
          className="file-list-head"
          role="row"
          style={{ gridTemplateColumns: "26px minmax(180px, 1fr) 78px 132px 90px 104px", minWidth: 700 }}
        >
          <span role="columnheader">
            <input
              ref={selectAllRef}
              type="checkbox"
              aria-label="全选远程文件"
              checked={entries.length > 0 && selectedPaths.size === entries.length}
              disabled={entries.length === 0}
              onChange={toggleAllEntries}
            />
          </span>
          <span role="columnheader">名称</span>
          <span role="columnheader">大小</span>
          <span role="columnheader">修改时间</span>
          <span role="columnheader">权限</span>
          <span role="columnheader">所有者</span>
        </div>

        {previewOnly ? (
          <div className="file-list-state" role="status" style={{ display: "grid", minHeight: 120, placeItems: "center", color: "var(--text-muted)", fontSize: 11 }}>
            <span>连接主机后加载远程目录</span>
          </div>
        ) : loading ? (
          <div className="file-list-state" role="status" style={{ display: "grid", minHeight: 120, placeItems: "center", color: "var(--text-muted)", fontSize: 11 }}>
            <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}><LoaderCircle className="spin" size={15} />正在读取目录</span>
          </div>
        ) : loadError ? (
          <div className="file-list-state error" role="alert" style={{ display: "grid", minHeight: 120, placeItems: "center", padding: 16, color: "var(--red, #c94f49)", fontSize: 11, textAlign: "center" }}>
            <span style={{ display: "grid", justifyItems: "center", gap: 8 }}>
              <TriangleAlert size={17} />
              <span>{loadError}</span>
              <button className="secondary-button" type="button" onClick={() => void loadDirectory(path)}>重试</button>
            </span>
          </div>
        ) : sortedEntries.length === 0 ? (
          <div className="file-list-state" role="status" style={{ display: "grid", minHeight: 120, placeItems: "center", color: "var(--text-muted)", fontSize: 11 }}>
            <span>此目录为空</span>
          </div>
        ) : sortedEntries.map((entry) => {
          const selected = selectedPaths.has(entry.path);
          return (
            <div
              className={`file-row ${selected ? "selected" : ""}`}
              role="row"
              aria-selected={selected}
              tabIndex={0}
              key={entry.path}
              title={`${entry.name}\n${entry.permissions}  ${entry.owner}`}
              style={{
                gridTemplateColumns: "26px minmax(180px, 1fr) 78px 132px 90px 104px",
                minWidth: 700,
                background: selected ? "var(--green-soft, #e8f4eb)" : undefined,
              }}
              onClick={() => toggleSelection(entry.path)}
              onDoubleClick={() => {
                if (entry.kind === "directory") void loadDirectory(entry.path);
                else if (entry.kind === "file") void openExternalEditor(entry);
              }}
              onKeyDown={(event) => {
                if (event.key === "Enter" && entry.kind === "directory") {
                  event.preventDefault();
                  void loadDirectory(entry.path);
                } else if (event.key === "Enter" && entry.kind === "file") {
                  event.preventDefault();
                  void openExternalEditor(entry);
                } else if (event.key === " ") {
                  event.preventDefault();
                  toggleSelection(entry.path);
                }
              }}
            >
              <span role="cell">
                <input
                  type="checkbox"
                  aria-label={`选择 ${entry.name}`}
                  checked={selected}
                  onClick={(event) => event.stopPropagation()}
                  onChange={() => toggleSelection(entry.path)}
                />
              </span>
              <span role="cell" style={{ display: "flex", minWidth: 0, alignItems: "center", gap: 6 }}>
                {entryIcon(entry.kind)}<span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{entry.name}</span>
              </span>
              <span role="cell">{formatSize(entry.size, entry.kind)}</span>
              <span role="cell">{formatModified(entry.modified)}</span>
              <span role="cell">{entry.permissions || "-"}</span>
              <span role="cell">{entry.owner || "-"}</span>
            </div>
          );
        })}
      </div>

      <div
        className={`transfer-summary ${activeTransfer?.status ?? "idle"}`}
        role="status"
        aria-live="polite"
        style={activeTransfer ? { minHeight: 42, height: "auto", flexBasis: 42, position: "relative", paddingBottom: 5 } : undefined}
      >
        {activeTransfer ? (
          <>
            {transferBusy ? <LoaderCircle className="spin" size={14} />
              : activeTransfer.status === "completed" ? <CheckCircle2 size={14} />
                : <TriangleAlert size={14} />}
            <span style={{ minWidth: 0, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {transferStatusText(activeTransfer)}
              {activeTransfer.currentPath ? ` · ${activeTransfer.currentPath}` : ""}
              {activeTransfer.message ? ` · ${activeTransfer.message}` : ""}
            </span>
            {activeTransfer.totalBytes > 0 ? <span>{transferPercent.toFixed(0)}%</span> : null}
            {transferBusy ? (
              <span
                aria-hidden="true"
                style={{ position: "absolute", right: 0, bottom: 0, left: 0, height: 2, overflow: "hidden", background: "var(--border)" }}
              >
                <span
                  style={{ display: "block", width: activeTransfer.totalBytes > 0 ? `${transferPercent}%` : "35%", height: "100%", background: "var(--green)" }}
                />
              </span>
            ) : null}
          </>
        ) : (
          <><CheckCircle2 size={14} /><span>传输队列为空</span></>
        )}
      </div>

      {dragInside ? (
        <div
          className="file-drop-overlay"
          role="status"
          style={{
            position: "absolute",
            zIndex: 5,
            inset: 5,
            display: "grid",
            placeItems: "center",
            color: "var(--green)",
            background: "rgba(239, 248, 241, 0.96)",
            border: "2px dashed var(--green)",
            borderRadius: 4,
            pointerEvents: "none",
          }}
        >
          <span style={{ display: "grid", justifyItems: "center", gap: 8, fontSize: 12, fontWeight: 600 }}>
            <Upload size={24} />拖放上传{dragItemCount > 0 ? ` ${dragItemCount} 项` : ""}
          </span>
        </div>
      ) : null}
    </section>
  );
}
