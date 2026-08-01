import { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  ArrowUp,
  CircleStop,
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

type TransferTaskStatus = "queued" | "running" | "cancelling" | "completed" | "failed" | "cancelled";
type TransferDisplayStatus = TransferTaskStatus | "finalizing";
type TransferCleanupStatus = "notRequired" | "pending" | "completed" | "warning";

interface TransferResult {
  transferId: string;
  mode: string;
  filesTransferred: number;
  bytesTransferred: number;
  skippedSymlinks: number;
  fallbackUsed: boolean;
  resumable: boolean;
  verification: string;
  limitations: string[];
}

interface TransferSnapshot {
  transferId: string;
  kind: "upload" | "download";
  host: string;
  port: number;
  username: string;
  status: TransferTaskStatus;
  seq: number;
  phase: string;
  currentPath: string;
  transferredBytes: number;
  totalBytes: number | null;
  result: TransferResult | null;
  error: string | null;
  partialCommit: boolean;
  cleanupStatus: TransferCleanupStatus;
  cleanupWarnings: string[];
  finalizing: boolean;
  canCancel: boolean;
  canDismiss: boolean;
  createdAt: number;
  updatedAt: number;
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

function isActiveTransfer(snapshot: TransferSnapshot | null) {
  return snapshot !== null && ["queued", "running", "cancelling"].includes(snapshot.status);
}

function displayTransferStatus(snapshot: TransferSnapshot): TransferDisplayStatus {
  return snapshot.finalizing || snapshot.phase === "finalizing" ? "finalizing" : snapshot.status;
}

function transferStatusText(snapshot: TransferSnapshot) {
  const action = snapshot.kind === "upload" ? "上传" : "下载";
  const status = displayTransferStatus(snapshot);
  if (status === "queued") return `${action}任务已排队`;
  if (status === "cancelling") return `正在取消${action}`;
  if (status === "finalizing") return `正在提交${action}结果`;
  if (status === "completed") return `${action}完成`;
  if (status === "failed") return `${action}失败`;
  if (status === "cancelled") return `${action}已取消`;

  const phaseLabels: Record<string, string> = {
    starting: `正在准备${action}`,
    connecting: "正在建立 SFTP 连接",
    checking: "正在检查打包传输能力",
    fallback: "正在切换到逐文件传输",
    packaging: "正在打包",
    extracting: "正在解包",
    uploading: "正在上传",
    downloading: "正在下载",
  };
  return phaseLabels[snapshot.phase] ?? `正在${action}`;
}

function normalizeHost(host: string) {
  return host.trim().replace(/^\[|\]$/g, "").toLocaleLowerCase("en-US");
}

function snapshotMatchesConnection(snapshot: TransferSnapshot, connection: SshConnectionSpec) {
  return normalizeHost(snapshot.host) === normalizeHost(connection.host)
    && snapshot.port === connection.port
    && snapshot.username === connection.username;
}

function makePendingSnapshot(
  transferId: string,
  kind: TransferSnapshot["kind"],
  connection: SshConnectionSpec,
): TransferSnapshot {
  const now = Date.now();
  return {
    transferId,
    kind,
    host: connection.host,
    port: connection.port,
    username: connection.username,
    status: "queued",
    seq: 0,
    phase: "queued",
    currentPath: "",
    transferredBytes: 0,
    totalBytes: null,
    result: null,
    error: null,
    partialCommit: false,
    cleanupStatus: "notRequired",
    cleanupWarnings: [],
    finalizing: false,
    canCancel: false,
    canDismiss: false,
    createdAt: now,
    updatedAt: now,
  };
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
  const transferSequenceRef = useRef<Map<string, number>>(new Map());
  const handledTerminalTransfersRef = useRef<Set<string>>(new Set());
  const transferRecoveryGenerationRef = useRef(0);
  const [path, setPath] = useState(initialPath.trim() || "/");
  const [pathInput, setPathInput] = useState(initialPath.trim() || "/");
  const [entries, setEntries] = useState<RemoteFileEntry[]>([]);
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(() => new Set());
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [packageTransfer, setPackageTransfer] = useState(initialPackageTransferSetting);
  const [activeTransfer, setActiveTransfer] = useState<TransferSnapshot | null>(null);
  const [transferActionError, setTransferActionError] = useState<string | null>(null);
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

  const transferBusy = isActiveTransfer(activeTransfer);

  function applyTransferSnapshot(snapshot: TransferSnapshot) {
    if (!snapshotMatchesConnection(snapshot, connectionRef.current)) return false;
    const previousSequence = transferSequenceRef.current.get(snapshot.transferId) ?? -1;
    if (snapshot.seq <= previousSequence) return false;
    transferSequenceRef.current.set(snapshot.transferId, snapshot.seq);

    setActiveTransfer((current) => {
      if (current?.transferId === snapshot.transferId) return snapshot;
      if (isActiveTransfer(current)) return current;
      if (isActiveTransfer(snapshot)) return snapshot;
      if (current === null || snapshot.updatedAt >= current.updatedAt) return snapshot;
      return current;
    });
    return true;
  }

  async function recoverTransfer(transferId: string) {
    try {
      const snapshot = await invoke<TransferSnapshot | null>("get_transfer_task", { transferId });
      if (snapshot) applyTransferSnapshot(snapshot);
      return snapshot;
    } catch {
      return null;
    }
  }

  function failPendingTransfer(transferId: string, error: unknown) {
    setActiveTransfer((current) => current?.transferId === transferId
      ? {
          ...current,
          status: "failed",
          phase: "failed",
          error: String(error),
          canCancel: false,
          canDismiss: true,
          updatedAt: Date.now(),
        }
      : current);
  }

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
    transferSequenceRef.current.delete(transferId);
    handledTerminalTransfersRef.current.delete(transferId);
    setTransferActionError(null);
    setActiveTransfer(makePendingSnapshot(transferId, "upload", connectionRef.current));
    try {
      const snapshot = await invoke<TransferSnapshot>("upload_remote", {
        connection: connectionRef.current,
        localPaths,
        remoteDirectory: pathRef.current,
        packageTransfer,
        transferId,
      });
      applyTransferSnapshot(snapshot);
    } catch (error) {
      const recovered = await recoverTransfer(transferId);
      if (!recovered) {
        failPendingTransfer(transferId, error);
        showToast("上传任务未能启动，请查看传输状态");
      }
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
    // Let the interactive OpenSSH login finish before opening the independent SFTP connection.
    // Several small VPS providers throttle simultaneous pre-auth handshakes.
    const timer = connected && isDesktopRuntime()
      ? window.setTimeout(() => void loadDirectory(targetPath), 2_000)
      : undefined;
    return () => {
      if (timer !== undefined) window.clearTimeout(timer);
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
    const generation = transferRecoveryGenerationRef.current + 1;
    transferRecoveryGenerationRef.current = generation;
    transferSequenceRef.current.clear();
    setActiveTransfer(null);
    setTransferActionError(null);

    void invoke<TransferSnapshot[]>("list_transfer_tasks")
      .then((tasks) => {
        if (generation !== transferRecoveryGenerationRef.current) return;
        const matching = tasks
          .filter((task) => snapshotMatchesConnection(task, connectionRef.current))
          .sort((left, right) => {
            const activeDifference = Number(isActiveTransfer(right)) - Number(isActiveTransfer(left));
            return activeDifference || right.updatedAt - left.updatedAt || right.seq - left.seq;
          });
        matching.forEach((task) => {
          transferSequenceRef.current.set(task.transferId, task.seq);
          if (!isActiveTransfer(task)) handledTerminalTransfersRef.current.add(task.transferId);
        });
        setActiveTransfer(matching[0] ?? null);
      })
      .catch((error) => {
        if (generation === transferRecoveryGenerationRef.current) {
          setTransferActionError(`无法恢复传输任务：${String(error)}`);
        }
      });

    return () => {
      if (transferRecoveryGenerationRef.current === generation) {
        transferRecoveryGenerationRef.current += 1;
      }
    };
  }, [connectionKey]);

  useEffect(() => {
    if (!isDesktopRuntime()) return undefined;
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void listen<TransferSnapshot>("transfer-task-updated", (event) => {
      applyTransferSnapshot(event.payload);
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
    const transferId = activeTransfer?.transferId;
    if (!transferId || !transferBusy || !isDesktopRuntime()) return undefined;
    let disposed = false;

    async function pollTransfer() {
      try {
        const snapshot = await invoke<TransferSnapshot | null>("get_transfer_task", { transferId });
        if (disposed) return;
        if (snapshot) applyTransferSnapshot(snapshot);
        else setActiveTransfer((current) => current?.transferId === transferId ? null : current);
      } catch {
        // Events are primary; polling only closes gaps caused by a suspended or hidden webview.
      }
    }

    const timer = window.setInterval(() => void pollTransfer(), 1_250);
    return () => {
      disposed = true;
      window.clearInterval(timer);
    };
  }, [activeTransfer?.transferId, transferBusy]);

  useEffect(() => {
    if (!activeTransfer || isActiveTransfer(activeTransfer)) return;
    if (handledTerminalTransfersRef.current.has(activeTransfer.transferId)) return;
    handledTerminalTransfersRef.current.add(activeTransfer.transferId);

    const action = activeTransfer.kind === "upload" ? "上传" : "下载";
    if (activeTransfer.status === "completed") {
      const count = activeTransfer.result?.filesTransferred;
      showToast(count ? `${action}完成，共 ${count} 项` : `${action}完成`);
      if (activeTransfer.kind === "upload"
        && connectedRef.current
        && snapshotMatchesConnection(activeTransfer, connectionRef.current)) {
        void loadDirectory(pathRef.current);
      }
    } else if (activeTransfer.status === "failed") {
      showToast(`${action}失败，请查看传输状态`);
    } else if (activeTransfer.partialCommit || activeTransfer.cleanupStatus === "warning") {
      showToast(`${action}已取消，但有部分结果或临时文件需要核对`);
    } else {
      showToast(`${action}已取消`);
    }
  }, [activeTransfer?.transferId, activeTransfer?.status, activeTransfer?.seq]);

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
    transferSequenceRef.current.delete(transferId);
    handledTerminalTransfersRef.current.delete(transferId);
    setTransferActionError(null);
    setActiveTransfer(makePendingSnapshot(transferId, "download", connectionRef.current));
    try {
      const snapshot = await invoke<TransferSnapshot>("download_remote", {
        connection: connectionRef.current,
        remotePaths: selectedEntries.map((entry) => entry.path),
        localDirectory,
        packageTransfer,
        transferId,
      });
      applyTransferSnapshot(snapshot);
    } catch (error) {
      const recovered = await recoverTransfer(transferId);
      if (!recovered) {
        failPendingTransfer(transferId, error);
        showToast("下载任务未能启动，请查看传输状态");
      }
    }
  }

  async function cancelActiveTransfer() {
    if (!activeTransfer?.canCancel || !isDesktopRuntime()) return;
    const transferId = activeTransfer.transferId;
    setTransferActionError(null);
    try {
      const snapshot = await invoke<TransferSnapshot>("cancel_transfer_task", { transferId });
      applyTransferSnapshot(snapshot);
    } catch (error) {
      const message = `取消请求失败：${String(error)}`;
      setTransferActionError(message);
      showToast(message);
      await recoverTransfer(transferId);
    }
  }

  async function dismissActiveTransfer() {
    if (!activeTransfer?.canDismiss || !isDesktopRuntime()) return;
    const transferId = activeTransfer.transferId;
    if (activeTransfer.seq === 0) {
      setActiveTransfer(null);
      setTransferActionError(null);
      return;
    }
    try {
      await invoke("dismiss_transfer_task", { transferId });
      setActiveTransfer((current) => current?.transferId === transferId ? null : current);
      setTransferActionError(null);
      transferSequenceRef.current.delete(transferId);
      handledTerminalTransfersRef.current.delete(transferId);
    } catch (error) {
      const message = `无法清除传输记录：${String(error)}`;
      setTransferActionError(message);
      showToast(message);
    }
  }

  const transferPercent = activeTransfer && activeTransfer.totalBytes !== null && activeTransfer.totalBytes > 0
    ? Math.min(100, Math.max(0, activeTransfer.transferredBytes / activeTransfer.totalBytes * 100))
    : 0;
  const transferNotices = activeTransfer ? [
    transferActionError,
    activeTransfer.error,
    activeTransfer.partialCommit ? "已有部分文件提交，请核对目标目录" : null,
    activeTransfer.cleanupStatus === "pending" ? "正在清理未完成传输的临时文件" : null,
    activeTransfer.cleanupStatus === "warning"
      ? `临时文件清理不完整${activeTransfer.cleanupWarnings.length > 0 ? `：${activeTransfer.cleanupWarnings.join("；")}` : ""}`
      : null,
  ].filter((message): message is string => Boolean(message)) : [];
  const transferDetail = transferNotices.join(" · ") || activeTransfer?.currentPath || "";
  const transferHasWarning = transferNotices.length > 0;
  const activeTransferDisplayStatus = activeTransfer ? displayTransferStatus(activeTransfer) : "idle";
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
        className={`transfer-summary ${activeTransferDisplayStatus}`}
        role="status"
        aria-live="polite"
        style={activeTransfer ? { minHeight: 42, height: "auto", flexBasis: 42, position: "relative", paddingBottom: 5 } : undefined}
      >
        {activeTransfer ? (
          <>
            {transferBusy ? <LoaderCircle className="spin" size={14} />
              : activeTransfer.status === "completed" ? <CheckCircle2 size={14} />
                : <TriangleAlert size={14} />}
            <span
              title={transferDetail || undefined}
              style={{ minWidth: 0, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
            >
              {transferStatusText(activeTransfer)}
              {transferDetail ? ` · ${transferDetail}` : ""}
            </span>
            {activeTransfer.totalBytes !== null && activeTransfer.totalBytes > 0
              ? <span>{transferPercent.toFixed(0)}%</span>
              : null}
            {activeTransfer.canCancel ? (
              <button
                className="icon-button compact danger"
                type="button"
                title="取消传输"
                aria-label="取消当前传输"
                onClick={() => void cancelActiveTransfer()}
              >
                <CircleStop size={14} />
              </button>
            ) : null}
            {activeTransfer.canDismiss ? (
              <button
                className="icon-button compact"
                type="button"
                title="清除传输记录"
                aria-label="清除当前传输记录"
                onClick={() => void dismissActiveTransfer()}
              >
                <X size={14} />
              </button>
            ) : null}
            {transferBusy ? (
              <span
                aria-hidden="true"
                style={{ position: "absolute", right: 0, bottom: 0, left: 0, height: 2, overflow: "hidden", background: "var(--border)" }}
              >
                <span
                  style={{
                    display: "block",
                    width: activeTransfer.totalBytes !== null && activeTransfer.totalBytes > 0 ? `${transferPercent}%` : "35%",
                    height: "100%",
                    background: transferHasWarning ? "var(--red, #c94f49)" : "var(--green)",
                  }}
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
