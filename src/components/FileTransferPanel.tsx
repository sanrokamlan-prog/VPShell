import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent as ReactMouseEvent,
} from "react";
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
  FolderPlus,
  KeyRound,
  LoaderCircle,
  MoveRight,
  Package,
  Pencil,
  Play,
  RefreshCw,
  RotateCcw,
  Save,
  ShieldAlert,
  TriangleAlert,
  Trash2,
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

type RemoteEntryKind = "file" | "directory" | "symlink" | "other";

interface RemoteFileEntry {
  name: string;
  path: string;
  kind: RemoteEntryKind;
  size: number;
  modified: string | number | null;
  permissions: string;
  ownerGroup: string | null;
}

interface RemoteDirectoryResult {
  path: string;
  entries: RemoteFileEntry[];
}

type TransferTaskStatus = "queued" | "running" | "cancelling" | "interrupted" | "completed" | "failed" | "cancelled";
type TransferDisplayStatus = TransferTaskStatus | "finalizing";
type TransferCleanupStatus = "notRequired" | "pending" | "completed" | "warning";
type TransferRecoveryState = "none" | "retryAvailable" | "retryExhausted" | "unsafeToRetry";

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
  operationResult: RemoteOperationResult | null;
}

interface TransferSnapshot {
  transferId: string;
  kind: "upload" | "download" | "fileOperation";
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
  recoveryState: TransferRecoveryState;
  recoveryReason: string | null;
  retryAttempts: number;
  maxRetryAttempts: number;
  canRetry: boolean;
  createdAt: number;
  updatedAt: number;
}

interface RecoveryStoreStatus {
  warning: string | null;
  loadedRecords: number;
  discardedRecords: number;
  retentionDays: number;
  maximumRecords: number;
  maximumRetryAttempts: number;
}

type RemoteFileOperationRequest =
  | { operation: "createDirectory"; parentPath: string; name: string }
  | { operation: "rename"; sourcePath: string; newName: string }
  | { operation: "move"; sourcePaths: string[]; destinationDirectory: string; conflictPolicy: "fail" | "rename" | "overwrite" }
  | { operation: "setPermissions"; paths: string[]; mode: number; recursive: boolean }
  | { operation: "delete"; paths: string[]; recursive: boolean };

interface RemoteOperationPreviewItem {
  path: string;
  targetPath: string | null;
  kind: RemoteEntryKind;
  currentPermissions: string | null;
  requestedPermissions: string | null;
  action: "apply" | "skip";
  warning: string | null;
}

interface RemoteOperationPreview {
  confirmationToken: string;
  operation: RemoteFileOperationRequest["operation"];
  summary: string;
  destructive: boolean;
  requiresSecondConfirmation: boolean;
  expiresAt: number;
  items: RemoteOperationPreviewItem[];
}

interface RemoteOperationResultItem {
  path: string;
  targetPath: string | null;
  outcome: "succeeded" | "failed" | "skipped";
  message: string;
  partial: boolean;
}

interface RemoteOperationResult {
  operation: RemoteFileOperationRequest["operation"];
  outcome: "completed" | "partial" | "failed" | "cancelled";
  succeeded: number;
  failed: number;
  skipped: number;
  partial: boolean;
  cancelled: boolean;
  items: RemoteOperationResultItem[];
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

interface ExternalEditRecovery {
  sessionId: string;
  host: string;
  port: number;
  username: string;
  remotePath: string;
  localFileName: string;
  createdAt: number;
  updatedAt: number;
  conflict: boolean;
  state: "active" | "recovery";
}

interface ExternalEditRecoveryList {
  sessions: ExternalEditRecovery[];
  warning: string | null;
  retentionDays: number;
  maximumSessions: number;
}

interface FileTransferPanelProps {
  connection: SshConnectionSpec;
  connected: boolean;
  androidSessionId?: string;
  initialPath: string;
  externalEditorPath: string;
  autoUploadEditedFiles: boolean;
  packageTransfer: boolean;
  onPackageTransferChanged: (enabled: boolean) => void;
  onPathChanged: (path: string) => void;
  showToast: (message: string) => void;
  onClose: () => void;
}

function isDesktopRuntime() {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window && !isAndroidRuntime();
}

function isAndroidRuntime() {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window && /Android/i.test(navigator.userAgent);
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
  const action = snapshot.kind === "upload" ? "上传"
    : snapshot.kind === "download" ? "下载"
      : "文件操作";
  const status = displayTransferStatus(snapshot);
  if (status === "queued") return `${action}任务已排队`;
  if (status === "cancelling") return `正在取消${action}`;
  if (status === "finalizing") return `正在提交${action}结果`;
  if (status === "interrupted") return `${action}需要恢复决定`;
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
    fileOperation: "正在执行远端文件操作",
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
    recoveryState: "none",
    recoveryReason: null,
    retryAttempts: 0,
    maxRetryAttempts: 3,
    canRetry: false,
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
  androidSessionId,
  initialPath,
  externalEditorPath,
  autoUploadEditedFiles,
  packageTransfer,
  onPackageTransferChanged,
  onPathChanged,
  showToast,
  onClose,
}: FileTransferPanelProps) {
  const panelRef = useRef<HTMLElement>(null);
  const pathInputRef = useRef<HTMLInputElement>(null);
  const rowRefs = useRef<Map<string, HTMLDivElement>>(new Map());
  const selectionAnchorRef = useRef<string | null>(null);
  const selectedPathsRef = useRef<Set<string>>(new Set());
  const operationBusyRef = useRef(false);
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
  const [activeTransfer, setActiveTransfer] = useState<TransferSnapshot | null>(null);
  const [transferActionError, setTransferActionError] = useState<string | null>(null);
  const [recoveryStoreWarning, setRecoveryStoreWarning] = useState<string | null>(null);
  const [matchingTransferCount, setMatchingTransferCount] = useState(0);
  const [dragInside, setDragInside] = useState(false);
  const [dragItemCount, setDragItemCount] = useState(0);
  const [editOpeningPath, setEditOpeningPath] = useState<string | null>(null);
  const [editSessions, setEditSessions] = useState<ExternalEditSession[]>([]);
  const [editRecoveries, setEditRecoveries] = useState<ExternalEditRecovery[]>([]);
  const [editRecoveryWarning, setEditRecoveryWarning] = useState<string | null>(null);
  const [editRecoveryBusy, setEditRecoveryBusy] = useState<string | null>(null);
  const [operationBusy, setOperationBusy] = useState(false);
  const [operationResult, setOperationResult] = useState<RemoteOperationResult | null>(null);

  connectionRef.current = connection;
  connectedRef.current = connected;
  pathRef.current = path;
  selectedPathsRef.current = selectedPaths;
  editSessionsRef.current = editSessions;
  autoUploadEditedFilesRef.current = autoUploadEditedFiles;

  const connectionKey = [
    connection.host,
    connection.port,
    connection.username,
    connection.credentialRef ?? "",
    connection.identityFile ?? "",
    connection.identityPassphraseRef ?? "",
    androidSessionId ?? "",
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
  const fileTaskBusy = transferBusy || operationBusy;

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
    if (!connectedRef.current || (!isDesktopRuntime() && !androidSessionId)) {
      setEntries([]);
      setSelectedPaths(new Set());
      selectionAnchorRef.current = null;
      setLoading(false);
      setLoadError(null);
      return;
    }

    const generation = loadGenerationRef.current + 1;
    loadGenerationRef.current = generation;
    setLoading(true);
    setLoadError(null);
    try {
      const result = androidSessionId
        ? await invoke<Array<{ name: string; kind: RemoteEntryKind | "special"; size: number; mode: number | null }>>("android_list_remote_files", {
          sessionId: androidSessionId,
          path: requestedPath,
        }).then((mobileEntries): RemoteDirectoryResult => ({
          path: requestedPath,
          entries: mobileEntries.map((entry) => ({
            name: entry.name,
            path: `${requestedPath.replace(/\/$/, "")}/${entry.name}` || "/",
            kind: entry.kind === "special" ? "other" : entry.kind,
            size: entry.size,
            modified: null,
            permissions: entry.mode === null ? "-" : (entry.mode & 0o7777).toString(8).padStart(4, "0"),
            ownerGroup: null,
          })),
        }))
        : await invoke<RemoteDirectoryResult>("list_remote_files", {
          connection: connectionRef.current,
          path: requestedPath,
        });
      if (generation !== loadGenerationRef.current) return;
      const resolvedPath = result.path.trim() || requestedPath;
      setEntries(result.entries);
      setSelectedPaths(new Set());
      selectionAnchorRef.current = null;
      setPath(resolvedPath);
      setPathInput(resolvedPath);
      lastReportedPathRef.current = resolvedPath;
      onPathChanged(resolvedPath);
    } catch (error) {
      if (generation !== loadGenerationRef.current) return;
      setEntries([]);
      setSelectedPaths(new Set());
      selectionAnchorRef.current = null;
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
    if (fileTaskBusy) {
      showToast("当前文件任务完成后再开始新任务");
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

  async function refreshEditRecoveries() {
    if (!isDesktopRuntime()) return;
    try {
      const result = await invoke<ExternalEditRecoveryList>("list_external_edit_recovery");
      setEditRecoveries(result.sessions.filter((session) => session.state === "recovery"));
      setEditRecoveryWarning(result.warning);
    } catch (error) {
      setEditRecoveryWarning(String(error));
    }
  }

  async function resumeExternalEdit(recovery: ExternalEditRecovery) {
    const matchesCurrentConnection = recovery.host === connectionRef.current.host
      && recovery.port === connectionRef.current.port
      && recovery.username === connectionRef.current.username;
    if (!connectedRef.current || !matchesCurrentConnection) {
      showToast("请先连接恢复记录对应的主机和用户");
      return;
    }
    setEditRecoveryBusy(recovery.sessionId);
    try {
      const result = await invoke<BeginExternalEditResult>("resume_external_edit", {
        connection: connectionRef.current,
        sessionId: recovery.sessionId,
        editorPath: externalEditorPath.trim(),
      });
      setEditSessions((current) => [...current, {
        ...result,
        dirty: true,
        busy: false,
        localMissing: false,
        localRevision: "",
        conflict: recovery.conflict,
      }]);
      await refreshEditRecoveries();
      showToast(`已恢复 ${result.remotePath} 的编辑会话`);
    } catch (error) {
      showToast(`无法恢复编辑会话：${String(error)}`);
    } finally {
      setEditRecoveryBusy(null);
    }
  }

  async function discardExternalEditRecovery(recovery: ExternalEditRecovery) {
    const label = recovery.remotePath.split("/").filter(Boolean).pop() || recovery.remotePath;
    if (!window.confirm(`丢弃 ${label} 的恢复记录会永久删除受管本地副本，确定继续吗？`)) return;
    setEditRecoveryBusy(recovery.sessionId);
    try {
      await invoke("discard_external_edit_recovery", { sessionId: recovery.sessionId });
      await refreshEditRecoveries();
      showToast("已丢弃外部编辑恢复记录");
    } catch (error) {
      showToast(`无法丢弃编辑恢复记录：${String(error)}`);
    } finally {
      setEditRecoveryBusy(null);
    }
  }

  async function exportExternalEditCopy(sessionId: string, fileName: string) {
    try {
      const { save } = await import("@tauri-apps/plugin-dialog");
      const destination = await save({
        title: "另存本地编辑副本",
        defaultPath: fileName,
      });
      if (!destination) return;
      const savedPath = await invoke<string>("export_external_edit_copy", {
        sessionId,
        destination,
      });
      showToast(`本地编辑副本已另存到 ${savedPath}`);
    } catch (error) {
      showToast(`无法另存编辑副本：${String(error)}`);
    }
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
      await refreshEditRecoveries();
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
        await refreshEditRecoveries();
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
      await refreshEditRecoveries();
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
      await refreshEditRecoveries();
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
    void refreshEditRecoveries();
  }, []);

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
    selectionAnchorRef.current = null;
    setOperationResult(null);
    setLoadError(null);
    // Let the interactive OpenSSH login finish before opening the independent SFTP connection.
    // Several small VPS providers throttle simultaneous pre-auth handshakes.
    const timer = connected && (isDesktopRuntime() || Boolean(androidSessionId))
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
    if (connected && (isDesktopRuntime() || Boolean(androidSessionId))) void loadDirectory(externalPath);
  }, [androidSessionId, initialPath]);

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

    void Promise.all([
      invoke<TransferSnapshot[]>("list_transfer_tasks"),
      invoke<RecoveryStoreStatus>("get_transfer_recovery_status"),
    ])
      .then(([tasks, storeStatus]) => {
        if (generation !== transferRecoveryGenerationRef.current) return;
        setRecoveryStoreWarning(storeStatus.warning);
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
        setMatchingTransferCount(matching.length);
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

    const action = activeTransfer.kind === "upload" ? "上传"
      : activeTransfer.kind === "download" ? "下载"
        : "远端文件操作";
    const remoteResult = activeTransfer.result?.operationResult ?? null;
    if (remoteResult) {
      setOperationResult(remoteResult);
      if (remoteResult.outcome === "completed") {
        showToast(`远端文件操作完成，共 ${remoteResult.succeeded} 项`);
      } else if (remoteResult.outcome === "cancelled") {
        showToast(`远端文件操作已取消：成功 ${remoteResult.succeeded}，跳过 ${remoteResult.skipped}`);
      } else {
        showToast(`远端文件操作部分完成：成功 ${remoteResult.succeeded}，失败 ${remoteResult.failed}，跳过 ${remoteResult.skipped}`);
      }
      if (connectedRef.current && snapshotMatchesConnection(activeTransfer, connectionRef.current)) {
        void loadDirectory(pathRef.current);
      }
      return;
    }
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
    selectionAnchorRef.current = remotePath;
  }

  function toggleAllEntries() {
    setSelectedPaths((current) => current.size === entries.length
      ? new Set()
      : new Set(entries.map((entry) => entry.path)));
    selectionAnchorRef.current = null;
  }

  function selectEntry(entry: RemoteFileEntry, event: ReactMouseEvent<HTMLDivElement>) {
    if (event.shiftKey && selectionAnchorRef.current) {
      const anchorIndex = sortedEntries.findIndex((item) => item.path === selectionAnchorRef.current);
      const targetIndex = sortedEntries.findIndex((item) => item.path === entry.path);
      if (anchorIndex >= 0 && targetIndex >= 0) {
        const start = Math.min(anchorIndex, targetIndex);
        const end = Math.max(anchorIndex, targetIndex);
        setSelectedPaths(new Set(sortedEntries.slice(start, end + 1).map((item) => item.path)));
        return;
      }
    }
    if (event.ctrlKey || event.metaKey) {
      toggleSelection(entry.path);
      return;
    }
    setSelectedPaths(new Set([entry.path]));
    selectionAnchorRef.current = entry.path;
  }

  function moveRowFocus(
    entry: RemoteFileEntry,
    offset: number,
    event: ReactKeyboardEvent<HTMLDivElement>,
  ) {
    const index = sortedEntries.findIndex((item) => item.path === entry.path);
    const target = sortedEntries[Math.min(sortedEntries.length - 1, Math.max(0, index + offset))];
    if (!target || target.path === entry.path) return;
    rowRefs.current.get(target.path)?.focus();
    if (event.ctrlKey || event.metaKey) return;
    if (event.shiftKey && selectionAnchorRef.current) {
      const anchorIndex = sortedEntries.findIndex((item) => item.path === selectionAnchorRef.current);
      const targetIndex = sortedEntries.findIndex((item) => item.path === target.path);
      const start = Math.min(anchorIndex, targetIndex);
      const end = Math.max(anchorIndex, targetIndex);
      setSelectedPaths(new Set(sortedEntries.slice(start, end + 1).map((item) => item.path)));
    } else {
      setSelectedPaths(new Set([target.path]));
      selectionAnchorRef.current = target.path;
    }
  }

  function operationContextFingerprint() {
    return JSON.stringify({
      path: pathRef.current,
      selected: [...selectedPathsRef.current].sort(),
    });
  }

  function formatOperationPreview(preview: RemoteOperationPreview) {
    const shown = preview.items.slice(0, 12).map((item) => {
      const target = item.targetPath ? ` -> ${item.targetPath}` : "";
      const permissions = item.requestedPermissions
        ? ` (${item.currentPermissions ?? "---"} -> ${item.requestedPermissions})`
        : "";
      const warning = item.warning ? ` [${item.warning}]` : "";
      return `${item.action === "skip" ? "跳过" : "执行"}: ${item.path}${target}${permissions}${warning}`;
    });
    if (preview.items.length > shown.length) {
      shown.push(`另有 ${preview.items.length - shown.length} 项未在此处展开`);
    }
    return `${preview.summary}\n\n${shown.join("\n")}`;
  }

  async function runRemoteOperation(request: RemoteFileOperationRequest) {
    if (!connectedRef.current || !isDesktopRuntime()) {
      showToast("连接主机后才能执行远端文件操作");
      return;
    }
    if (transferBusy || operationBusyRef.current) {
      showToast("当前文件任务完成后再执行新操作");
      return;
    }
    const context = operationContextFingerprint();
    operationBusyRef.current = true;
    setOperationBusy(true);
    setOperationResult(null);
    try {
      const preview = await invoke<RemoteOperationPreview>("preview_remote_file_operation", {
        connection: connectionRef.current,
        request,
      });
      if (context !== operationContextFingerprint()) {
        showToast("目录或选择已变化，旧操作预览已作废");
        return;
      }
      if (!window.confirm(`${formatOperationPreview(preview)}\n\n核对以上远端路径后继续？`)) return;
      if (context !== operationContextFingerprint()) {
        showToast("目录或选择已变化，旧确认不能继续使用");
        return;
      }
      const secondMessage = preview.destructive
        ? "这是不可撤销或可能影响访问权限的操作。再次确认执行？"
        : "再次确认按预览内容执行？";
      if (preview.requiresSecondConfirmation && !window.confirm(secondMessage)) return;
      if (context !== operationContextFingerprint() || preview.expiresAt <= Date.now()) {
        showToast("操作预览已失效，请重新发起");
        return;
      }
      const transferId = makeTransferId();
      transferSequenceRef.current.delete(transferId);
      handledTerminalTransfersRef.current.delete(transferId);
      setActiveTransfer(makePendingSnapshot(transferId, "fileOperation", connectionRef.current));
      const snapshot = await invoke<TransferSnapshot>("execute_remote_file_operation", {
        connection: connectionRef.current,
        confirmationToken: preview.confirmationToken,
        transferId,
      });
      applyTransferSnapshot(snapshot);
    } catch (error) {
      showToast(`远端文件操作失败：${String(error)}`);
    } finally {
      operationBusyRef.current = false;
      setOperationBusy(false);
    }
  }

  function canPromptRemoteOperation() {
    if (!connectedRef.current || !isDesktopRuntime()) {
      showToast("连接主机后才能执行远端文件操作");
      return false;
    }
    if (loading || transferBusy || operationBusyRef.current) {
      showToast("当前文件任务或目录加载完成后再执行操作");
      return false;
    }
    return true;
  }

  function createDirectory() {
    if (!canPromptRemoteOperation()) return;
    const name = window.prompt("新目录名称");
    if (name === null) return;
    void runRemoteOperation({ operation: "createDirectory", parentPath: pathRef.current, name });
  }

  function renameSelection() {
    if (!canPromptRemoteOperation()) return;
    if (selectedEntries.length !== 1) {
      showToast("重命名需要且只能选择一个普通文件或目录");
      return;
    }
    const entry = selectedEntries[0];
    if (entry.kind === "symlink" || entry.kind === "other") {
      showToast("安全模式只重命名普通文件或目录");
      return;
    }
    if (editSessionsRef.current.some((session) => session.remotePath === entry.path)) {
      showToast("请先结束该文件的外部编辑会话");
      return;
    }
    const newName = window.prompt("新的文件或目录名称", entry.name);
    if (newName === null) return;
    void runRemoteOperation({ operation: "rename", sourcePath: entry.path, newName });
  }

  function moveSelection() {
    if (!canPromptRemoteOperation()) return;
    if (selectedEntries.length === 0) {
      showToast("请先选择要移动的文件或目录");
      return;
    }
    if (selectedEntries.some((entry) => entry.kind === "symlink" || entry.kind === "other")) {
      showToast("跨目录移动不会复制符号链接或特殊条目");
      return;
    }
    const destinationDirectory = window.prompt("移动到远端目录", pathRef.current);
    if (destinationDirectory === null) return;
    const policy = window.prompt("目标冲突策略：fail、rename 或 overwrite", "fail")?.trim().toLowerCase();
    if (policy === undefined) return;
    if (policy !== "fail" && policy !== "rename" && policy !== "overwrite") {
      showToast("冲突策略必须是 fail、rename 或 overwrite");
      return;
    }
    void runRemoteOperation({
      operation: "move",
      sourcePaths: selectedEntries.map((entry) => entry.path),
      destinationDirectory,
      conflictPolicy: policy,
    });
  }

  function editSelectionPermissions() {
    if (!canPromptRemoteOperation()) return;
    if (selectedEntries.length === 0) {
      showToast("请先选择要修改权限的文件或目录");
      return;
    }
    const currentModes = new Set(selectedEntries.map((entry) => entry.permissions.slice(-3)));
    const initial = currentModes.size === 1 ? [...currentModes][0] : "755";
    const value = window.prompt("输入三位八进制权限（000 到 777）", initial);
    if (value === null) return;
    if (!/^[0-7]{3}$/.test(value)) {
      showToast("权限必须是 000 到 777 的三位八进制数");
      return;
    }
    const recursive = selectedEntries.some((entry) => entry.kind === "directory")
      && window.confirm("是否递归修改所选目录内容？符号链接始终隔离且保持不变。\n\n确定：递归；取消：仅修改所选目录本身。\n后续仍会显示完整预览和二次确认。");
    void runRemoteOperation({
      operation: "setPermissions",
      paths: selectedEntries.map((entry) => entry.path),
      mode: Number.parseInt(value, 8),
      recursive,
    });
  }

  function deleteSelection() {
    if (!canPromptRemoteOperation()) return;
    if (selectedEntries.length === 0) {
      showToast("请先选择要删除的文件或目录");
      return;
    }
    const editing = new Set(editSessionsRef.current.map((session) => session.remotePath));
    if (selectedEntries.some((entry) => editing.has(entry.path))) {
      showToast("请先结束所选文件的外部编辑会话");
      return;
    }
    void runRemoteOperation({
      operation: "delete",
      paths: selectedEntries.map((entry) => entry.path),
      recursive: selectedEntries.some((entry) => entry.kind === "directory"),
    });
  }

  function handlePanelKeyDown(event: ReactKeyboardEvent<HTMLElement>) {
    const target = event.target as HTMLElement;
    const editingText = target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement;
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "l") {
      event.preventDefault();
      pathInputRef.current?.focus();
      pathInputRef.current?.select();
    } else if ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key.toLowerCase() === "n") {
      event.preventDefault();
      if (!editingText) createDirectory();
    } else if ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key.toLowerCase() === "m") {
      event.preventDefault();
      if (!editingText) moveSelection();
    } else if (event.altKey && event.key === "ArrowUp" && !editingText) {
      event.preventDefault();
      void loadDirectory(parentRemotePath(pathRef.current));
    }
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
    if (fileTaskBusy) {
      showToast("当前文件任务完成后再开始新任务");
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

  async function retryActiveTransfer() {
    if (!activeTransfer?.canRetry || !connected || !isDesktopRuntime()) return;
    const transferId = activeTransfer.transferId;
    setTransferActionError(null);
    handledTerminalTransfersRef.current.delete(transferId);
    try {
      if (activeTransfer.kind === "fileOperation") {
        const preview = await invoke<RemoteOperationPreview>("preview_remote_file_operation_recovery", {
          connection: connectionRef.current,
          transferId,
        });
        if (!window.confirm(`${formatOperationPreview(preview)}\n\n这是恢复任务生成的新预览。核对当前远端状态后继续？`)) return;
        if (!window.confirm("恢复文件任务仍可能产生不可撤销更改。再次确认执行当前新预览？")) return;
        if (preview.expiresAt <= Date.now()) {
          showToast("恢复预览已过期，请重新重试");
          return;
        }
        const snapshot = await invoke<TransferSnapshot>("execute_remote_file_operation", {
          connection: connectionRef.current,
          confirmationToken: preview.confirmationToken,
          transferId,
        });
        applyTransferSnapshot(snapshot);
        return;
      }
      const snapshot = await invoke<TransferSnapshot>("retry_transfer_task", {
        connection: connectionRef.current,
        transferId,
      });
      applyTransferSnapshot(snapshot);
    } catch (error) {
      const message = `无法重试传输：${String(error)}`;
      setTransferActionError(message);
      showToast(message);
      await recoverTransfer(transferId);
    }
  }

  async function dismissActiveTransfer() {
    if (!activeTransfer?.canDismiss || !isDesktopRuntime()) return;
    const transferId = activeTransfer.transferId;
    if (activeTransfer.recoveryState !== "none"
      && !window.confirm("丢弃恢复记录不会删除、覆盖或回滚任何已写入的文件。请先核对目标，确定继续吗？")) return;
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
      const tasks = await invoke<TransferSnapshot[]>("list_transfer_tasks");
      const matching = tasks
        .filter((task) => snapshotMatchesConnection(task, connectionRef.current))
        .sort((left, right) => right.updatedAt - left.updatedAt || right.seq - left.seq);
      setMatchingTransferCount(matching.length);
      if (matching[0]) {
        transferSequenceRef.current.set(matching[0].transferId, matching[0].seq);
        if (!isActiveTransfer(matching[0])) {
          handledTerminalTransfersRef.current.add(matching[0].transferId);
        }
        setActiveTransfer(matching[0]);
      }
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
    activeTransfer.recoveryReason,
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
      onKeyDown={handlePanelKeyDown}
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
          ref={pathInputRef}
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
        <button type="button" disabled={previewOnly || fileTaskBusy} onClick={() => void chooseFilesToUpload()}>
          <Upload size={15} /><span>上传文件</span>
        </button>
        <button type="button" disabled={previewOnly || fileTaskBusy} onClick={() => void chooseFolderToUpload()}>
          <FolderOpen size={15} /><span>上传文件夹</span>
        </button>
        <button type="button" disabled={previewOnly || selectedEntries.length === 0 || fileTaskBusy} onClick={() => void downloadSelection()}>
          <Download size={15} /><span>下载所选</span>
        </button>
        <button
          type="button"
          disabled={previewOnly || editableSelection === null || editOpeningPath !== null || operationBusy}
          onClick={() => editableSelection && void openExternalEditor(editableSelection)}
        >
          {editOpeningPath ? <LoaderCircle className="spin" size={15} /> : <FilePenLine size={15} />}
          <span>外部编辑</span>
        </button>
        <span className="file-toolbar-separator" aria-hidden="true" />
        <button
          className="icon-button compact"
          type="button"
          title="新建目录"
          aria-label="新建远程目录"
          disabled={previewOnly || fileTaskBusy || loading}
          onClick={createDirectory}
        >
          <FolderPlus size={15} />
        </button>
        <button
          className="icon-button compact"
          type="button"
          title="重命名"
          aria-label="重命名所选远程条目"
          disabled={previewOnly || fileTaskBusy || loading || selectedEntries.length !== 1}
          onClick={renameSelection}
        >
          <Pencil size={14} />
        </button>
        <button
          className="icon-button compact"
          type="button"
          title="移动到目录"
          aria-label="移动所选远程条目到其他目录"
          disabled={previewOnly || fileTaskBusy || loading || selectedEntries.length === 0}
          onClick={moveSelection}
        >
          <MoveRight size={14} />
        </button>
        <button
          className="icon-button compact"
          type="button"
          title="编辑权限"
          aria-label="编辑所选远程条目权限"
          disabled={previewOnly || fileTaskBusy || loading || selectedEntries.length === 0}
          onClick={editSelectionPermissions}
        >
          <KeyRound size={14} />
        </button>
        <button
          className="icon-button compact danger"
          type="button"
          title="删除所选"
          aria-label="删除所选远程条目"
          disabled={previewOnly || fileTaskBusy || loading || selectedEntries.length === 0}
          onClick={deleteSelection}
        >
          <Trash2 size={14} />
        </button>
        <label className="package-toggle" title="多个文件或文件夹打包后传输">
          <input
            type="checkbox"
            checked={packageTransfer}
            disabled={fileTaskBusy}
            onChange={(event) => onPackageTransferChanged(event.target.checked)}
          />
          <Package size={15} /><span>打包传输</span>
        </label>
      </div>

      {operationResult ? (
        <div
          className={`file-operation-result ${operationResult.outcome}`}
          aria-label="远端文件操作结果"
          aria-live="polite"
          role="region"
        >
          <div className="file-operation-result-summary">
            {operationResult.outcome === "completed"
              ? <CheckCircle2 size={14} aria-hidden="true" />
              : <TriangleAlert size={14} aria-hidden="true" />}
            <strong>
              成功 {operationResult.succeeded} · 失败 {operationResult.failed} · 跳过 {operationResult.skipped}
            </strong>
            <button
              className="icon-button compact"
              type="button"
              title="关闭操作结果"
              aria-label="关闭远端文件操作结果"
              onClick={() => setOperationResult(null)}
            >
              <X size={13} />
            </button>
          </div>
          <div className="file-operation-result-items">
            {operationResult.items.map((item, index) => (
              <div className={item.outcome} key={`${item.path}-${index}`}>
                <span>{item.outcome === "succeeded" ? "成功" : item.outcome === "failed" ? "失败" : "跳过"}</span>
                <code title={item.targetPath ? `${item.path} -> ${item.targetPath}` : item.path}>
                  {item.path}{item.targetPath ? ` -> ${item.targetPath}` : ""}
                </code>
                <small>{item.message}{item.partial ? "（已部分执行）" : ""}</small>
              </div>
            ))}
          </div>
        </div>
      ) : operationBusy ? (
        <div className="file-operation-running" role="status">
          <LoaderCircle className="spin" size={14} />正在核对并执行远端文件操作
        </div>
      ) : null}

      {editRecoveries.length > 0 || editRecoveryWarning ? (
        <div className="external-edit-list recovery-center" aria-label="外部编辑恢复与冲突中心">
          <div className="external-edit-recovery-heading">
            <strong>编辑恢复与冲突</strong>
            <small>{editRecoveries.length} 项待处理</small>
          </div>
          {editRecoveryWarning ? (
            <div className="external-edit-recovery-warning" role="status">
              <TriangleAlert size={13} aria-hidden="true" />{editRecoveryWarning}
            </div>
          ) : null}
          {editRecoveries.map((recovery) => {
            const fileName = recovery.remotePath.split("/").filter(Boolean).pop() || recovery.remotePath;
            const matchesCurrentConnection = recovery.host === connection.host
              && recovery.port === connection.port
              && recovery.username === connection.username;
            const busy = editRecoveryBusy === recovery.sessionId;
            return (
              <div className={`external-edit-row recovery ${recovery.conflict ? "conflict" : ""}`} key={recovery.sessionId}>
                <FilePenLine size={14} aria-hidden="true" />
                <span className="external-edit-file">
                  <strong>{fileName}</strong>
                  <small>{recovery.username}@{recovery.host}:{recovery.port} · {recovery.conflict ? "远端冲突待决策" : "应用重启后待恢复"}</small>
                </span>
                {busy ? <LoaderCircle className="spin" size={14} aria-label="处理中" /> : (
                  <button
                    className="icon-button compact"
                    type="button"
                    title={matchesCurrentConnection ? "恢复编辑会话" : "连接对应主机后恢复"}
                    aria-label={`恢复 ${fileName}`}
                    disabled={!connected || !matchesCurrentConnection}
                    onClick={() => void resumeExternalEdit(recovery)}
                  >
                    <Play size={14} />
                  </button>
                )}
                <button
                  className="icon-button compact"
                  type="button"
                  title="另存本地编辑副本"
                  aria-label={`另存 ${fileName} 的本地编辑副本`}
                  disabled={busy}
                  onClick={() => void exportExternalEditCopy(recovery.sessionId, fileName)}
                >
                  <Download size={14} />
                </button>
                <button
                  className="icon-button compact danger"
                  type="button"
                  title="丢弃恢复记录和受管本地副本"
                  aria-label={`丢弃 ${fileName} 的编辑恢复记录`}
                  disabled={busy}
                  onClick={() => void discardExternalEditRecovery(recovery)}
                >
                  <Trash2 size={14} />
                </button>
              </div>
            );
          })}
        </div>
      ) : null}

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
                      title="另存本地编辑副本"
                      aria-label={"另存 " + fileName + " 的本地编辑副本"}
                      disabled={session.busy || session.localMissing}
                      onClick={() => void exportExternalEditCopy(session.sessionId, fileName)}
                    >
                      <Download size={14} />
                    </button>
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

      <div
        className="file-list"
        role="table"
        aria-label={`远程目录 ${path}`}
        aria-busy={loading}
        tabIndex={sortedEntries.length === 0 ? 0 : -1}
        onKeyDown={(event) => {
          if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "a") {
            event.preventDefault();
            setSelectedPaths(new Set(entries.map((entry) => entry.path)));
            selectionAnchorRef.current = null;
          } else if (event.key === "F5") {
            event.preventDefault();
            void loadDirectory(pathRef.current);
          } else if (event.key === "Delete") {
            event.preventDefault();
            deleteSelection();
          } else if (event.key === "F2") {
            event.preventDefault();
            renameSelection();
          } else if (event.key === "Escape") {
            event.preventDefault();
            setSelectedPaths(new Set());
            selectionAnchorRef.current = null;
          }
        }}
      >
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
              ref={(node) => {
                if (node) rowRefs.current.set(entry.path, node);
                else rowRefs.current.delete(entry.path);
              }}
              key={entry.path}
              title={`${entry.name}\n${entry.permissions}  ${entry.ownerGroup ?? "-"}`}
              style={{
                gridTemplateColumns: "26px minmax(180px, 1fr) 78px 132px 90px 104px",
                minWidth: 700,
                background: selected ? "var(--green-soft, #e8f4eb)" : undefined,
              }}
              onClick={(event) => selectEntry(entry, event)}
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
                } else if (event.key === "ArrowDown") {
                  event.preventDefault();
                  moveRowFocus(entry, 1, event);
                } else if (event.key === "ArrowUp") {
                  event.preventDefault();
                  moveRowFocus(entry, -1, event);
                } else if (event.key === "Home") {
                  event.preventDefault();
                  moveRowFocus(entry, -sortedEntries.length, event);
                } else if (event.key === "End") {
                  event.preventDefault();
                  moveRowFocus(entry, sortedEntries.length, event);
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
              <span role="cell">{entry.ownerGroup || "-"}</span>
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
            {activeTransfer.canRetry ? (
              <button
                className="icon-button compact"
                type="button"
                title={connected ? `明确重试（${activeTransfer.retryAttempts}/${activeTransfer.maxRetryAttempts}）` : "连接当前主机后才能重试"}
                aria-label="重试恢复任务"
                disabled={!connected}
                onClick={() => void retryActiveTransfer()}
              >
                <RotateCcw size={14} />
              </button>
            ) : null}
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
                title={activeTransfer.recoveryState === "none" ? "清除传输记录" : "丢弃恢复记录"}
                aria-label={activeTransfer.recoveryState === "none" ? "清除当前传输记录" : "丢弃当前恢复记录"}
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
        ) : recoveryStoreWarning || transferActionError ? (
          <><TriangleAlert size={14} /><span>{recoveryStoreWarning ?? transferActionError}</span></>
        ) : (
          <><CheckCircle2 size={14} /><span>传输队列为空{matchingTransferCount > 1 ? `（另有 ${matchingTransferCount - 1} 条记录）` : ""}</span></>
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
