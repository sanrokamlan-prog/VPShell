import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  AlertTriangle,
  BookOpenText,
  Braces,
  Cable,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Clock3,
  CircleHelp,
  Cloud,
  CloudOff,
  Columns2,
  Command,
  Copy,
  Database,
  Download,
  ExternalLink,
  Globe2,
  HardDrive,
  History,
  Image,
  KeyRound,
  Library,
  MoreHorizontal,
  Minus,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  PanelRightClose,
  PanelRightOpen,
  Play,
  Plus,
  RadioTower,
  RefreshCw,
  RotateCcw,
  Route,
  Search,
  Server,
  Settings2,
  ShieldCheck,
  Square,
  SquareTerminal,
  Trash2,
  Type,
  Upload,
  Wifi,
  WifiOff,
  X,
} from "lucide-react";
import { initialState, migratePersistedAppState } from "./data";
import { Dialog } from "./components/Dialog";
import { FileTransferPanel } from "./components/FileTransferPanel";
import { HostOverview } from "./components/HostOverview";
import { KeyManagerDialog } from "./components/KeyManagerDialog";
import { MigrationDialog, type MigrationImportResult } from "./components/MigrationDialog";
import { NetworkToolsDialog, type NetworkToolMode, type RouteMeasurementOption } from "./components/NetworkToolsDialog";
import { OnboardingDialog } from "./components/OnboardingDialog";
import { SettingsDialog } from "./components/SettingsDialog";
import { TerminalView } from "./components/TerminalView";
import { type AppStoreSnapshot, usePersistedState } from "./hooks/usePersistedState";
import brandMark from "./assets/vpshell.svg";
import {
  postAndroidVisibility,
  requestAndroidSecurity,
  type AndroidSecurityStatus,
} from "./androidSecurity";
import type {
  AppState,
  CommandParameter,
  CommandRecipe,
  ConnectionHistoryItem,
  EnvironmentKind,
  HostProfile,
  ScriptRecipe,
  SshKeyProfile,
  SyncProviderKind,
  TerminalSession,
} from "./types";
import "./App.css";

type SidebarView = "hosts" | "commands" | "scripts" | "history";
type DialogKind = "host" | "host-key" | "sync" | "wallpaper" | "settings" | "guide" | "script" | "command" | "custom-script" | "migration" | "key-manager" | "network" | "local-forward" | null;

const RECYCLE_BIN_DAYS = 30;
const MAX_PARAMETER_HISTORY = 10_000;

function isSensitiveParameterName(value: string) {
  const compact = value.toLowerCase().replace(/[-_ ]/g, "");
  return ["password", "passphrase", "token", "secret", "privatekey", "credential", "authorization", "apikey"]
    .some((needle) => compact.includes(needle));
}

function isSensitiveCommandParameter(parameter: CommandParameter) {
  return parameter.sensitive === true || isSensitiveParameterName(parameter.name);
}

interface IntentSuggestion {
  kind: "command" | "script";
  score: number;
  item: CommandRecipe | ScriptRecipe;
}

interface RemoteMetricsResponse {
  connectionHost: string;
  hostname: string;
  primaryIp?: string;
  cpuPercent: number;
  memoryPercent: number;
  diskPercent: number;
  loadOne: number;
  loadFive: number;
  loadFifteen: number;
  uptimeSeconds: number;
  rxBytesPerSecond: number;
  txBytesPerSecond: number;
  topProcesses: Array<{ pid: number; name: string; cpuPercent: number; memoryPercent: number }>;
}

interface HostMetricsState {
  metrics?: RemoteMetricsResponse;
  history: MonitorTrendPoint[];
  loading: boolean;
  paused: boolean;
  intervalSeconds: number;
  totalSamples: number;
  droppedSamples: number;
  error?: string;
  sampledAt?: string;
}

interface MonitorTrendPoint {
  sampledAtMs: number;
  cpuPercent: number;
  memoryPercent: number;
  diskPercent: number;
  loadOne: number;
  rxBytesPerSecond: number;
  txBytesPerSecond: number;
}

interface MonitorSnapshotResponse {
  sessionId: string;
  intervalSeconds: number;
  paused: boolean;
  sampling: boolean;
  latest?: RemoteMetricsResponse;
  history: MonitorTrendPoint[];
  lastError?: string;
  totalSamples: number;
  droppedSamples: number;
}

interface BroadcastPreviewResponse {
  confirmationToken: string;
  command: string;
  targets: Array<{
    sessionId: string;
    label: string;
    environment: EnvironmentKind;
  }>;
  risk: "normal" | "high";
  warning: string;
  productionTargets: number;
  expiresAt: number;
}

interface BroadcastResultResponse {
  outcome: "completed" | "partial" | "failed" | "skipped";
  succeeded: number;
  failed: number;
  skipped: number;
  items: Array<{
    sessionId: string;
    label: string;
    outcome: "succeeded" | "failed" | "skipped";
    message: string;
  }>;
}

interface HostKeyInspection {
  host: string;
  port: number;
  status: "verified" | "unknown" | "changed" | "failure";
  algorithm: string;
  fingerprint: string;
}

interface NativeEngineProbeResult {
  schemaVersion: number;
  engine: "russh";
  sshReady: boolean;
  sftpReady: boolean;
}

interface NativeTerminalStartResult {
  schemaVersion: number;
  engine: "russh";
  sessionId: string;
  connection: ConnectionHistoryItem;
}

interface OpenSshTerminalStartResult {
  schemaVersion: number;
  engine: "openssh";
  sessionId: string;
  connection: ConnectionHistoryItem;
}

interface MoshTerminalStartResult {
  schemaVersion: number;
  engine: "mosh";
  sessionId: string;
  connection: ConnectionHistoryItem;
}

interface AndroidConnectionResult {
  sessionId: string;
  connection: ConnectionHistoryItem;
}

interface NativeLocalForwardSnapshot {
  schemaVersion: number;
  forwardId: string;
  state: "starting" | "active";
  bindHost: "127.0.0.1";
  bindPort: number;
  routeHost: string;
  routeHops: number;
  targetHost: string;
  targetPort: number;
  activeConnections: number;
  acceptedConnections: number;
  rejectedConnections: number;
}

interface NativeRemoteForwardSnapshot {
  schemaVersion: number;
  forwardId: string;
  state: "starting" | "active";
  bindHost: "127.0.0.1";
  bindPort: number;
  routeHost: string;
  routeHops: number;
  targetHost: "127.0.0.1";
  targetPort: number;
  activeConnections: number;
  acceptedConnections: number;
  rejectedConnections: number;
  failedConnections: number;
}

interface NativeDynamicForwardSnapshot {
  schemaVersion: number;
  forwardId: string;
  state: "starting" | "active";
  bindHost: "127.0.0.1";
  bindPort: number;
  routeHost: string;
  routeHops: number;
  activeConnections: number;
  acceptedConnections: number;
  rejectedConnections: number;
}

interface NativeEngineErrorPayload {
  code?: string;
  message?: string;
  retryable?: boolean;
  hopIndex?: number;
  fallbackEngine?: "openssh";
}

const nativeOpenSshFallbackCodes = new Set([
  "native-engine-key-invalid",
  "native-engine-auth-negotiation-failed",
  "native-engine-rsa-sha2-unavailable",
]);

function canFallbackNativeTerminalToOpenSsh(error: unknown) {
  if (!error || typeof error !== "object") return false;
  const payload = error as NativeEngineErrorPayload;
  return payload.fallbackEngine === "openssh"
    && typeof payload.code === "string"
    && nativeOpenSshFallbackCodes.has(payload.code);
}

function invokeErrorMessage(error: unknown) {
  if (error && typeof error === "object") {
    const payload = error as NativeEngineErrorPayload;
    if (typeof payload.message === "string") {
      const hop = typeof payload.hopIndex === "number" ? `第 ${payload.hopIndex} 跳：` : "";
      return payload.code ? `${hop}${payload.message}（${payload.code}）` : `${hop}${payload.message}`;
    }
  }
  return String(error);
}

type SyncCoordinatorPhase = "notConfigured" | "idle" | "uploading" | "downloading" | "merging" | "waitingRetry" | "conflicts" | "reconcileRequired" | "suspended" | "cancelled";

interface SyncCoordinatorStatus {
  schemaVersion: number;
  phase: SyncCoordinatorPhase;
  configured: boolean;
  running: boolean;
  generation: number;
  pendingObjects: number;
  pendingBytes: number;
  mergeRevision: number;
  openConflicts: number;
  recoveryRequired: boolean;
  recoveryNote?: string;
  lastErrorCode?: string;
  lastCompletedAtMs?: number;
  lastUploadedObjects: number;
  lastDownloadedObjects: number;
}

interface SyncCycleResult {
  status: SyncCoordinatorStatus;
  appStore: AppStoreSnapshot;
}

type SyncConflictEntityKind = "host" | "script" | "setting" | "background";
type SyncConflictReason = "concurrent-edit" | "connection-identity" | "script-content" | "risk-lowered" | "deleted-entity-edited" | "concurrent-delete";

interface SyncConflictAlternative {
  index: number;
  valueType: "text" | "integer" | "flag" | "text-list" | "blob-ref" | "clear" | "deleted";
  preview?: string;
  byteLength: number;
  contentHash?: string;
  truncated: boolean;
}

interface SyncConflictItem {
  conflictId: string;
  entityKind: SyncConflictEntityKind;
  entityId: string;
  field: string;
  reason: SyncConflictReason;
  alternatives: [SyncConflictAlternative, SyncConflictAlternative];
}

interface SyncConflictCenterSnapshot {
  schemaVersion: number;
  mergeRevision: number;
  total: number;
  offset: number;
  conflicts: SyncConflictItem[];
}

const SYNC_CONFLICT_PAGE_SIZE = 10;

interface RenderAsset {
  dataUrl: string;
  label: string;
  mediaType: string;
  size: number;
}

const CUSTOM_FONT_FAMILY = "VPShell Custom Font";

interface PendingHostKey extends HostKeyInspection {
  hostId: string;
  sessionId: string;
}

const providerLabels: Record<SyncProviderKind, string> = {
  local: "本地同步目录",
  webdav: "WebDAV",
  sftp: "SFTP",
  s3: "S3 兼容存储",
  gateway: "自建同步网关",
};

const environmentLabels: Record<EnvironmentKind, string> = {
  production: "生产",
  staging: "基础设施",
  development: "测试",
};

const syncPhaseLabels: Record<SyncCoordinatorPhase, string> = {
  notConfigured: "未配置",
  idle: "空闲",
  uploading: "正在上传",
  downloading: "正在下载",
  merging: "正在合并",
  waitingRetry: "等待重试",
  conflicts: "存在冲突",
  reconcileRequired: "需要恢复核对",
  suspended: "已暂停",
  cancelled: "已取消",
};

const syncConflictKindLabels: Record<SyncConflictEntityKind, string> = {
  host: "主机",
  script: "脚本",
  setting: "设置",
  background: "背景",
};

const syncConflictReasonLabels: Record<SyncConflictReason, string> = {
  "concurrent-edit": "并发编辑",
  "connection-identity": "连接身份不一致",
  "script-content": "脚本内容不一致",
  "risk-lowered": "风险等级降低",
  "deleted-entity-edited": "删除后又被编辑",
  "concurrent-delete": "并发删除",
};

function syncConflictAlternativeLabel(alternative: SyncConflictAlternative) {
  if (alternative.valueType === "deleted") return "保持删除";
  if (alternative.valueType === "clear") return "清空该值";
  if (alternative.valueType === "flag") return alternative.preview === "true" ? "启用" : "关闭";
  return alternative.preview || "空值";
}

const sidebarLabels: Record<SidebarView, { eyebrow: string; title: string; placeholder: string }> = {
  hosts: { eyebrow: "CONNECTIONS", title: "主机", placeholder: "搜索名称、IP、标签" },
  commands: { eyebrow: "COMMAND LIBRARY", title: "命令库", placeholder: "搜索想完成的操作" },
  scripts: { eyebrow: "SCRIPT LIBRARY", title: "脚本中心", placeholder: "搜索脚本、分组" },
  history: { eyebrow: "COMMAND HISTORY", title: "历史记录", placeholder: "搜索已执行命令" },
};

function makeSession(host: HostProfile): TerminalSession {
  return {
    id: crypto.randomUUID(),
    hostId: host.id,
    title: host.name,
    state: "idle",
    engine: host.jumpRoute?.length ? "russh" : "openssh",
    currentPath: host.lastPath ?? "~",
    contextSource: "profile",
    contextStack: [],
  };
}

const emptyHost: HostProfile = {
  id: "__vpshell-empty-host__",
  name: "新标签",
  group: "",
  host: "",
  port: 22,
  username: "root",
  environment: "development",
  tags: [],
  lastPath: "~",
};

function isDesktopRuntime() {
  return "__TAURI_INTERNALS__" in window && !isAndroidRuntime();
}

function isAndroidRuntime() {
  return "__TAURI_INTERNALS__" in window && /Android/i.test(navigator.userAgent);
}

function relativeTime(value?: string) {
  if (!value) return "尚未同步";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return "刚刚同步";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}

function shellQuote(value: string) {
  return `'${value.split("'").join(`'"'"'`)}'`;
}

function encodeUtf8Base64(value: string) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function hostCredentialReferences(host: HostProfile) {
  return [host.credentialRef, host.androidKeyRef, host.androidKeyPassphraseRef]
    .filter((reference): reference is string => Boolean(reference));
}

function nativeRouteHosts(host: HostProfile, hosts: HostProfile[]) {
  const jumpRoute = host.jumpRoute ?? [];
  if (jumpRoute.length > 3) throw new Error("原生 SSH 路线最多允许三台跳板机");
  const routeIds = [...jumpRoute, host.id];
  if (new Set(routeIds).size !== routeIds.length) {
    throw new Error("原生 SSH 路线不能重复或形成循环");
  }
  return routeIds.map((hostId) => {
    const routeHost = hosts.find((candidate) => candidate.id === hostId);
    if (!routeHost) throw new Error("原生 SSH 路线引用了不存在的主机资料");
    return routeHost;
  });
}

function nativeRoute(
  host: HostProfile,
  hosts: HostProfile[],
  sshKeys: SshKeyProfile[],
  targetHostKeySha256?: string,
) {
  return {
    hops: nativeRouteHosts(host, hosts).map((routeHost) => {
      const hostKeySha256 = routeHost.id === host.id
        ? targetHostKeySha256 ?? routeHost.hostKeySha256
        : routeHost.hostKeySha256;
      if (!hostKeySha256) throw new Error(`请先为“${routeHost.name}”保存 SHA256 主机指纹`);
      if (!routeHost.identityFile && !routeHost.credentialRef) {
        throw new Error(`“${routeHost.name}”缺少原生引擎可用的认证来源`);
      }
      const identityPassphraseRef = sshKeys.find(
        (key) => key.privateKeyPath === routeHost.identityFile,
      )?.passphraseRef;
      return {
        hopId: crypto.randomUUID(),
        host: routeHost.host,
        port: routeHost.port,
        username: routeHost.username,
        hostKeySha256,
        timeoutSeconds: 15,
        credentialRef: routeHost.identityFile ? undefined : routeHost.credentialRef,
        identityFile: routeHost.identityFile,
        identityPassphraseRef,
      };
    }),
  };
}

function buildRouteMeasurementOptions(
  host: HostProfile,
  hosts: HostProfile[],
  sshKeys: SshKeyProfile[],
): RouteMeasurementOption[] {
  const directHost = { ...host, jumpRoute: [] };
  const options: RouteMeasurementOption[] = [{
    candidateId: "direct",
    label: "直连",
    route: nativeRoute(directHost, hosts, sshKeys),
  }];
  if (host.jumpRoute?.length) {
    const jumpLabels = nativeRouteHosts(host, hosts)
      .slice(0, -1)
      .map((routeHost) => routeHost.name)
      .join(" > ");
    options.push({
      candidateId: "configured-jump",
      label: `跳板 · ${jumpLabels}`,
      route: nativeRoute(host, hosts, sshKeys),
    });
  }
  return options;
}

function scoreIntent(query: string, fields: string[]) {
  const normalized = query.trim().toLocaleLowerCase();
  if (!normalized) return 0;
  const terms = normalized.split(/\s+/).filter(Boolean);
  const haystack = fields.join(" ").toLocaleLowerCase();
  const compact = normalized.replace(/\s+/g, "");
  const characters = Array.from(compact);
  const bigrams = characters.slice(0, -1).map((character, index) => `${character}${characters[index + 1]}`);
  const termHits = terms.filter((term) => haystack.includes(term)).length;
  const bigramHits = bigrams.filter((term) => haystack.includes(term)).length;
  if (termHits === 0 && bigramHits === 0) return 0;
  let score = termHits * 3 + bigramHits * 2;
  if (fields[0]?.toLocaleLowerCase().includes(normalized)) score += 12;
  if (fields.slice(1).some((field) => field.toLocaleLowerCase().includes(normalized))) score += 5;
  return score;
}

function explicitlyRequestsDestructiveAction(query: string) {
  const normalized = query.toLocaleLowerCase();
  return ["重装", "dd", "擦除", "格式化", "重新安装系统"].some((term) => normalized.includes(term));
}

function migrateAppStateIntoSqlite(value: AppState) {
  const migrated = migratePersistedAppState(value);
  try {
    const saved = localStorage.getItem("vpshell.package-transfer.enabled")
      ?? localStorage.getItem("opsshell.package-transfer.enabled");
    if (saved !== null) {
      return {
        ...migrated,
        settings: { ...migrated.settings, packageTransfersEnabled: saved !== "false" },
      };
    }
  } catch {
    // The default remains enabled when legacy WebView storage is unavailable.
  }
  return migrated;
}

function App() {
  const [appState, setAppState, appStoreStatus, applyAppStoreSnapshot] = usePersistedState<AppState>(
    "vpshell-state-v1",
    initialState,
    ["opsshell-state-v6"],
    migrateAppStateIntoSqlite,
    ["vpshell.package-transfer.enabled", "opsshell.package-transfer.enabled"],
  );
  const [sessions, setSessions] = useState<TerminalSession[]>([makeSession(appState.hosts[0] ?? emptyHost)]);
  const [activeSessionId, setActiveSessionId] = useState(sessions[0].id);
  const [sidebarView, setSidebarView] = useState<SidebarView>("hosts");
  const [searchText, setSearchText] = useState("");
  const [dialog, setDialog] = useState<DialogKind>(appState.onboardingCompleted ? null : "guide");
  const [selectedScript, setSelectedScript] = useState<ScriptRecipe | null>(null);
  const [selectedCommand, setSelectedCommand] = useState<CommandRecipe | null>(null);
  const [commandParameters, setCommandParameters] = useState<Record<string, string>>({});
  const [networkMode, setNetworkMode] = useState<NetworkToolMode>("trace");
  const [commandInput, setCommandInput] = useState("");
  const [filePanelOpen, setFilePanelOpen] = useState(true);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [broadcastOpen, setBroadcastOpen] = useState(false);
  const [broadcastTargets, setBroadcastTargets] = useState<string[]>([]);
  const [broadcastPreview, setBroadcastPreview] = useState<BroadcastPreviewResponse | null>(null);
  const [broadcastResult, setBroadcastResult] = useState<BroadcastResultResponse | null>(null);
  const [broadcastExecuting, setBroadcastExecuting] = useState(false);
  const [syncPassword, setSyncPassword] = useState("");
  const [webDavPassword, setWebDavPassword] = useState("");
  const [webDavCaPath, setWebDavCaPath] = useState("");
  const [webDavCaLabel, setWebDavCaLabel] = useState("");
  const [webDavUseSystemCa, setWebDavUseSystemCa] = useState(false);
  const [syncSetupMode, setSyncSetupMode] = useState<"unlock" | "initialize">("unlock");
  const [desktopSyncStatus, setDesktopSyncStatus] = useState<SyncCoordinatorStatus | null>(null);
  const [desktopSyncError, setDesktopSyncError] = useState<string | null>(null);
  const [desktopSyncBusy, setDesktopSyncBusy] = useState(false);
  const [syncConflictCenter, setSyncConflictCenter] = useState<SyncConflictCenterSnapshot | null>(null);
  const [syncConflictOffset, setSyncConflictOffset] = useState(0);
  const [syncConflictError, setSyncConflictError] = useState<string | null>(null);
  const [resolvingConflictId, setResolvingConflictId] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [installedFonts, setInstalledFonts] = useState<string[]>([]);
  const [fontRevision, setFontRevision] = useState(0);
  const [renderedWallpaper, setRenderedWallpaper] = useState("");
  const [hostMetrics, setHostMetrics] = useState<Record<string, HostMetricsState>>({});
  const [pendingHostKey, setPendingHostKey] = useState<PendingHostKey | null>(null);
  const [trustingHostKey, setTrustingHostKey] = useState(false);
  const [androidTerminalIds, setAndroidTerminalIds] = useState<Record<string, string>>({});
  const [androidCredentialKind, setAndroidCredentialKind] = useState<"password" | "privateKey">("password");
  const [androidSyncStatus, setAndroidSyncStatus] = useState<SyncCoordinatorStatus | null>(null);
  const [androidSyncError, setAndroidSyncError] = useState<string | null>(null);
  const [androidSecurityStatus, setAndroidSecurityStatus] = useState<AndroidSecurityStatus | null>(null);
  const [nativeProbeInspecting, setNativeProbeInspecting] = useState(false);
  const [nativeProbeOperationId, setNativeProbeOperationId] = useState<string | null>(null);
  const [nativeTerminalStartingIds, setNativeTerminalStartingIds] = useState<string[]>([]);
  const [nativeLocalForwards, setNativeLocalForwards] = useState<NativeLocalForwardSnapshot[]>([]);
  const [nativeRemoteForwards, setNativeRemoteForwards] = useState<NativeRemoteForwardSnapshot[]>([]);
  const [nativeDynamicForwards, setNativeDynamicForwards] = useState<NativeDynamicForwardSnapshot[]>([]);
  const [nativeForwardMode, setNativeForwardMode] = useState<"local" | "remote" | "dynamic">("local");
  const [nativeLocalForwardBusy, setNativeLocalForwardBusy] = useState(false);
  const [nativeLocalForwardError, setNativeLocalForwardError] = useState<string | null>(null);

  const activeSession = sessions.find((session) => session.id === activeSessionId) ?? sessions[0];
  const activeHost = appState.hosts.find((host) => host.id === activeSession.hostId) ?? appState.hosts[0] ?? emptyHost;
  const hasActiveHost = appState.hosts.some((host) => host.id === activeHost.id);
  const activeIdentityPassphraseRef = appState.sshKeys.find(
    (key) => key.privateKeyPath === activeHost.identityFile,
  )?.passphraseRef;
  const activeShellContext = activeSession.contextStack?.[activeSession.contextStack.length - 1];
  const deletedHosts = appState.deletedHosts ?? [];

  const refreshAndroidSyncStatus = useCallback(async () => {
    if (!isAndroidRuntime()) return;
    try {
      const status = await invoke<SyncCoordinatorStatus>("android_sync_status");
      setAndroidSyncStatus(status);
      setAndroidSyncError(null);
    } catch (error) {
      setAndroidSyncError(String(error));
    }
  }, []);

  const refreshDesktopSyncStatus = useCallback(async () => {
    if (!isDesktopRuntime()) return;
    try {
      const status = await invoke<SyncCoordinatorStatus>("desktop_sync_status");
      setDesktopSyncStatus(status);
      setDesktopSyncError(null);
    } catch (error) {
      setDesktopSyncError(invokeErrorMessage(error));
    }
  }, []);

  const refreshSyncConflicts = useCallback(async (offset: number) => {
    if (!isDesktopRuntime()) return;
    try {
      const snapshot = await invoke<SyncConflictCenterSnapshot>("list_sync_conflicts", {
        request: { offset, limit: SYNC_CONFLICT_PAGE_SIZE },
      });
      setSyncConflictCenter(snapshot);
      setSyncConflictError(null);
      if (snapshot.total > 0 && snapshot.conflicts.length === 0 && offset > 0) {
        setSyncConflictOffset(Math.max(0, offset - SYNC_CONFLICT_PAGE_SIZE));
      }
    } catch (error) {
      setSyncConflictError(invokeErrorMessage(error));
    }
  }, []);

  useEffect(() => {
    if (!isAndroidRuntime()) return undefined;
    let active = true;
    let unlocking = false;
    const enterBackground = () => {
      postAndroidVisibility("hide");
      setAndroidSecurityStatus((current) => current ? { ...current, locked: true } : current);
      void invoke("android_enter_background").catch(() => undefined);
    };
    const unlock = async () => {
      if (unlocking) return;
      unlocking = true;
      try {
        const status = await requestAndroidSecurity("unlock");
        if (!active) return;
        setAndroidSecurityStatus(status);
        postAndroidVisibility(status.locked ? "failed" : "show");
      } catch (error) {
        if (!active || String(error).includes("authentication-in-progress")) return;
        postAndroidVisibility("failed");
        void requestAndroidSecurity("status")
          .then((status) => active && setAndroidSecurityStatus(status))
          .catch(() => undefined);
      } finally {
        unlocking = false;
      }
    };
    const updateLifecycle = () => {
      if (document.hidden) enterBackground();
      else void unlock();
    };
    postAndroidVisibility("hide");
    void unlock();
    document.addEventListener("visibilitychange", updateLifecycle);
    window.addEventListener("vpshell-native-background", enterBackground);
    window.addEventListener("vpshell-native-resume", unlock);
    return () => {
      active = false;
      document.removeEventListener("visibilitychange", updateLifecycle);
      window.removeEventListener("vpshell-native-background", enterBackground);
      window.removeEventListener("vpshell-native-resume", unlock);
    };
  }, []);

  useEffect(() => {
    if (!isAndroidRuntime()) return undefined;
    void refreshAndroidSyncStatus();
    const timer = window.setInterval(() => void refreshAndroidSyncStatus(), 15_000);
    return () => window.clearInterval(timer);
  }, [refreshAndroidSyncStatus]);

  useEffect(() => {
    if (!isDesktopRuntime()) return undefined;
    void refreshDesktopSyncStatus();
    const timer = window.setInterval(
      () => void refreshDesktopSyncStatus(),
      dialog === "sync" ? 1_000 : 15_000,
    );
    return () => window.clearInterval(timer);
  }, [dialog, refreshDesktopSyncStatus]);

  useEffect(() => {
    if (
      !isDesktopRuntime()
      || dialog !== "sync"
      || !desktopSyncStatus?.configured
      || desktopSyncStatus.openConflicts === 0
    ) {
      if (desktopSyncStatus?.openConflicts === 0) {
        setSyncConflictCenter(null);
        setSyncConflictError(null);
        setSyncConflictOffset(0);
      }
      return;
    }
    void refreshSyncConflicts(syncConflictOffset);
  }, [desktopSyncStatus?.configured, desktopSyncStatus?.mergeRevision, desktopSyncStatus?.openConflicts, dialog, refreshSyncConflicts, syncConflictOffset]);

  useEffect(() => {
    if (!isDesktopRuntime()) return undefined;
    let active = true;
    let stopListening: (() => void) | undefined;
    void listen<SyncCycleResult>("desktop-sync-cycle", (event) => {
      if (!active) return;
      setDesktopSyncStatus(event.payload.status);
      setDesktopSyncError(event.payload.status.lastErrorCode ?? null);
      try {
        if (!applyAppStoreSnapshot(event.payload.appStore)) {
          setDesktopSyncError(event.payload.status.lastErrorCode ?? "local-state-busy");
        }
      } catch (error) {
        setDesktopSyncError(invokeErrorMessage(error));
      }
    }).then((unlisten) => {
      if (!active) unlisten();
      else stopListening = unlisten;
    }).catch((error) => {
      if (active) setDesktopSyncError(invokeErrorMessage(error));
    });
    return () => {
      active = false;
      stopListening?.();
    };
  }, [applyAppStoreSnapshot]);

  useEffect(() => {
    if (!isDesktopRuntime()) return undefined;
    let active = true;
    const refresh = () => {
      void Promise.all([
        invoke<NativeLocalForwardSnapshot[]>("list_native_local_forwards"),
        invoke<NativeRemoteForwardSnapshot[]>("list_native_remote_forwards"),
        invoke<NativeDynamicForwardSnapshot[]>("list_native_dynamic_forwards"),
      ])
        .then(([localForwards, remoteForwards, dynamicForwards]) => {
          if (!active) return;
          setNativeLocalForwards(localForwards);
          setNativeRemoteForwards(remoteForwards);
          setNativeDynamicForwards(dynamicForwards);
          setNativeLocalForwardError(null);
        })
        .catch((error) => {
          if (active) setNativeLocalForwardError(invokeErrorMessage(error));
        });
    };
    refresh();
    const timer = window.setInterval(refresh, dialog === "local-forward" ? 1_000 : 5_000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [dialog]);

  useEffect(() => {
    if (!appStoreStatus.ready || appState.hosts.length === 0) return;
    if (sessions.length === 1 && sessions[0].hostId === emptyHost.id) {
      const restored = makeSession(appState.hosts[0]);
      setSessions([restored]);
      setActiveSessionId(restored.id);
    }
  }, [appState.hosts, appStoreStatus.ready, sessions]);

  useEffect(() => {
    if (appStoreStatus.error) setToast(`本地事件库：${appStoreStatus.error}`);
    else if (appStoreStatus.recoveryNote) setToast(appStoreStatus.recoveryNote);
  }, [appStoreStatus.error, appStoreStatus.recoveryNote]);

  useEffect(() => {
    const now = Date.now();
    const expired = deletedHosts.filter((item) => Date.parse(item.expiresAt) <= now);
    if (expired.length === 0) return;

    void (async () => {
      if (isDesktopRuntime() || isAndroidRuntime()) {
        const retainedReferences = new Set([
          ...appState.hosts.flatMap(hostCredentialReferences),
          ...deletedHosts
            .filter((item) => Date.parse(item.expiresAt) > now)
            .flatMap((item) => hostCredentialReferences(item.host)),
        ]);
        await Promise.all(expired.map(async (item) => {
          await Promise.all(hostCredentialReferences(item.host).map((reference) => (
            retainedReferences.has(reference)
              ? Promise.resolve()
              : invoke(isAndroidRuntime() ? "android_delete_credential" : "delete_credential", { reference }).catch(() => undefined)
          )));
        }));
      }
      setAppState((current) => ({
        ...current,
        deletedHosts: (current.deletedHosts ?? []).filter((item) => Date.parse(item.expiresAt) > Date.now()),
      }));
    })();
  // Expiry is evaluated once for the persisted snapshot loaded at startup.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const visibleHosts = useMemo(() => {
    const query = searchText.trim().toLocaleLowerCase();
    return appState.hosts.filter((host) =>
      !query || [host.name, host.host, host.username, host.group, ...host.tags].join(" ").toLocaleLowerCase().includes(query),
    );
  }, [appState.hosts, searchText]);

  const recentConnections = useMemo(() => {
    const seen = new Set<string>();
    return (appState.connectionHistory ?? []).flatMap((item) => {
      if (seen.has(item.hostId)) return [];
      const host = appState.hosts.find((candidate) => candidate.id === item.hostId);
      if (!host) return [];
      seen.add(item.hostId);
      return [{ item, host }];
    }).slice(0, 8);
  }, [appState.connectionHistory, appState.hosts]);

  const visibleScripts = useMemo(() => {
    const query = searchText.trim().toLocaleLowerCase();
    return appState.scripts.filter((script) =>
      !query || [script.title, script.description, script.category].join(" ").toLocaleLowerCase().includes(query),
    );
  }, [appState.scripts, searchText]);

  const visibleCommands = useMemo(() => {
    const query = searchText.trim().toLocaleLowerCase();
    return appState.commands.filter((command) =>
      !query || [command.title, command.description, command.category, command.usage, ...command.keywords].join(" ").toLocaleLowerCase().includes(query),
    );
  }, [appState.commands, searchText]);

  const intentSuggestions = useMemo<IntentSuggestion[]>(() => {
    const query = commandInput.trim();
    if (!query || query.length > 120 || query.includes("\n")) return [];
    const commands = appState.commands.map((item) => ({
      kind: "command" as const,
      item,
      score: scoreIntent(query, [item.title, item.description, item.category, item.usage, ...item.keywords, item.command ?? ""]),
    }));
    const scripts = appState.scripts.map((item) => ({
      kind: "script" as const,
      item,
      score: item.risk === "destructive" && !explicitlyRequestsDestructiveAction(query)
        ? 0
        : scoreIntent(query, [item.title, item.description, item.category, item.command ?? ""]),
    }));
    return [...commands, ...scripts].filter((item) => item.score > 0).sort((a, b) => b.score - a.score).slice(0, 6);
  }, [appState.commands, appState.scripts, commandInput]);

  const hostGroups = useMemo(() => {
    const groups = new Map<string, HostProfile[]>();
    visibleHosts.forEach((host) => groups.set(host.group, [...(groups.get(host.group) ?? []), host]));
    return [...groups.entries()];
  }, [visibleHosts]);

  const showToast = useCallback((message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(null), 3200);
  }, []);

  const applyMonitorSnapshot = useCallback((snapshot: MonitorSnapshotResponse) => {
    const latestPoint = snapshot.history[snapshot.history.length - 1];
    setHostMetrics((current) => ({
      ...current,
      [snapshot.sessionId]: {
        metrics: snapshot.latest,
        history: snapshot.history,
        loading: snapshot.sampling,
        paused: snapshot.paused,
        intervalSeconds: snapshot.intervalSeconds,
        totalSamples: snapshot.totalSamples,
        droppedSamples: snapshot.droppedSamples,
        error: snapshot.lastError,
        sampledAt: latestPoint
          ? new Date(latestPoint.sampledAtMs).toLocaleTimeString("zh-CN", { hour12: false })
          : undefined,
      },
    }));
  }, []);

  useEffect(() => {
    if (!isDesktopRuntime() || activeSession.state !== "connected") return;
    let disposed = false;
    let stopListening: (() => void) | undefined;

    async function startMonitor() {
      try {
        const unlisten = await listen<MonitorSnapshotResponse>("remote-monitor-update", (event) => {
          if (!disposed && event.payload.sessionId === activeSession.id) {
            applyMonitorSnapshot(event.payload);
          }
        });
        if (disposed) {
          unlisten();
          return;
        }
        stopListening = unlisten;
        const snapshot = await invoke<MonitorSnapshotResponse>("start_remote_monitor", {
          request: {
            sessionId: activeSession.id,
            intervalSeconds: appState.settings.monitorIntervalSeconds,
            connection: {
              host: activeHost.host,
              port: activeHost.port,
              username: activeHost.username,
              identityFile: activeHost.identityFile,
              credentialRef: activeHost.credentialRef,
              identityPassphraseRef: activeIdentityPassphraseRef,
            },
          },
        });
        if (disposed) {
          await invoke("stop_remote_monitor", { sessionId: activeSession.id }).catch(() => undefined);
          return;
        }
        applyMonitorSnapshot(snapshot);
      } catch (error) {
        if (!disposed) {
          setHostMetrics((current) => ({
            ...current,
            [activeSession.id]: {
              history: current[activeSession.id]?.history ?? [],
              loading: false,
              paused: false,
              intervalSeconds: current[activeSession.id]?.intervalSeconds ?? appState.settings.monitorIntervalSeconds,
              totalSamples: current[activeSession.id]?.totalSamples ?? 0,
              droppedSamples: current[activeSession.id]?.droppedSamples ?? 0,
              metrics: current[activeSession.id]?.metrics,
              sampledAt: current[activeSession.id]?.sampledAt,
              error: String(error),
            },
          }));
        }
      }
    }

    void startMonitor();
    return () => {
      disposed = true;
      stopListening?.();
      void invoke("stop_remote_monitor", { sessionId: activeSession.id }).catch(() => undefined);
    };
  }, [activeHost.credentialRef, activeHost.host, activeHost.identityFile, activeHost.port, activeHost.username, activeIdentityPassphraseRef, activeSession.id, activeSession.state, appState.settings.monitorIntervalSeconds, applyMonitorSnapshot]);

  const setMonitorPaused = useCallback(async (sessionId: string, paused: boolean) => {
    try {
      const snapshot = await invoke<MonitorSnapshotResponse>("set_remote_monitor_paused", { sessionId, paused });
      applyMonitorSnapshot(snapshot);
    } catch (error) {
      showToast(`无法${paused ? "暂停" : "恢复"}监控：${String(error)}`);
    }
  }, [applyMonitorSnapshot, showToast]);

  const setMonitorInterval = useCallback(async (sessionId: string, intervalSeconds: number) => {
    try {
      const snapshot = await invoke<MonitorSnapshotResponse>("set_remote_monitor_interval", { sessionId, intervalSeconds });
      applyMonitorSnapshot(snapshot);
      setAppState((current) => ({
        ...current,
        settings: { ...current.settings, monitorIntervalSeconds: snapshot.intervalSeconds },
      }));
    } catch (error) {
      showToast(`无法调整监控频率：${String(error)}`);
    }
  }, [applyMonitorSnapshot, showToast]);

  useEffect(() => {
    if (!appStoreStatus.ready || !isDesktopRuntime()) return;
    void invoke<RenderAsset | null>("load_font_asset").then((asset) => {
      if (asset) void registerFontAsset(asset);
    }).catch(() => undefined);
    if (appState.wallpaper.source === "none") {
      setRenderedWallpaper("");
      return;
    }
    if (appState.wallpaper.source === "local" && appState.wallpaper.value.startsWith("data:image/")) {
      void invoke<RenderAsset>("install_wallpaper_asset", {
        request: { source: "legacy-data", value: appState.wallpaper.value },
      }).then((asset) => {
        setRenderedWallpaper(asset.dataUrl);
        setAppState((current) => ({ ...current, wallpaper: { ...current.wallpaper, value: asset.label } }));
      }).catch((error) => showToast(`旧壁纸迁移失败：${String(error)}`));
      return;
    }
    void invoke<RenderAsset | null>("load_wallpaper_asset")
      .then((asset) => setRenderedWallpaper(asset?.dataUrl ?? ""))
      .catch(() => setRenderedWallpaper(""));
  // Managed assets are restored once after the SQLite snapshot is ready.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appStoreStatus.ready]);

  const updateSession = useCallback((sessionId: string, patch: Partial<TerminalSession>) => {
    setSessions((current) => current.map((session) => session.id === sessionId ? { ...session, ...patch } : session));
  }, []);

  const handleDisconnected = useCallback((sessionId: string, message?: string) => {
    updateSession(sessionId, { state: message ? "error" : "closed" });
    if (message) showToast(message);
  }, [showToast, updateSession]);

  const handleContextChanged = useCallback((
    sessionId: string,
    stack: Array<{ hostname: string; username: string; cwd: string }>,
    warning?: string,
  ) => {
    const current = stack[stack.length - 1];
    updateSession(sessionId, {
      contextStack: stack,
      contextSource: current ? "shell-integration" : "profile",
      reportedHostname: current?.hostname,
      currentPath: current?.cwd ?? "~",
    });
    if (warning) showToast(warning);
  }, [showToast, updateSession]);

  async function enableShellIntegration() {
    if (activeSession.state !== "connected" || !isDesktopRuntime()) return;
    try {
      await invoke("enable_shell_integration", { sessionId: activeSession.id });
      showToast("已向当前 Shell 注入一次有界上下文探针；嵌套 SSH 后可再次点击识别");
    } catch (error) {
      showToast(`无法启用 Shell Integration：${String(error)}`);
    }
  }

  function openHost(host: HostProfile) {
    const existing = sessions.find((session) => session.hostId === host.id && session.state !== "closed");
    if (existing) {
      setActiveSessionId(existing.id);
      return;
    }
    const session = makeSession(host);
    setSessions((current) => (
      current.length === 1 && current[0].hostId === emptyHost.id
        ? [session]
        : [...current, session]
    ));
    setActiveSessionId(session.id);
  }

  function closeSession(sessionId: string) {
    const closing = sessions.find((session) => session.id === sessionId);
    if (closing?.state === "connecting") {
      if (closing.engine === "russh" && nativeTerminalStartingIds.includes(sessionId)) {
        void invoke("cancel_native_engine_operation", { operationId: sessionId })
          .then(() => showToast("正在取消原生终端连接"))
          .catch((error) => showToast(invokeErrorMessage(error)));
      } else {
        showToast("连接准备完成前不能关闭标签");
      }
      return;
    }
    if (closing?.state === "connected" && isAndroidRuntime()) {
      void invoke("android_disconnect_host", { sessionId }).catch(() => undefined);
      setAndroidTerminalIds((current) => {
        const next = { ...current };
        delete next[sessionId];
        return next;
      });
    } else if (closing?.state === "connected" && isDesktopRuntime()) {
      void invoke("stop_terminal", { sessionId }).catch(() => undefined);
    }
    setSessions((current) => {
      if (current.length === 1) return current;
      const next = current.filter((session) => session.id !== sessionId);
      if (sessionId === activeSessionId) setActiveSessionId(next[next.length - 1]?.id ?? next[0].id);
      return next;
    });
    setBroadcastTargets((current) => current.filter((id) => id !== sessionId));
  }

  async function startSshSession(session: TerminalSession, host: HostProfile, hostKeySha256?: string) {
    if (isAndroidRuntime()) {
      const credentialRef = host.androidKeyRef ?? host.credentialRef;
      if (!credentialRef || !host.hostKeySha256) {
        throw new Error("Android 连接需要已保存凭据和已确认的 SHA256 主机指纹");
      }
      const connected = await invoke<AndroidConnectionResult>("android_connect_host", {
        hostId: host.id,
        initialPath: session.currentPath,
        request: {
          sessionId: session.id,
          host: host.host,
          port: host.port,
          username: host.username,
          hostKeySha256: host.hostKeySha256,
          timeoutSeconds: 15,
          authKind: host.androidKeyRef ? "privateKeyReference" : "passwordReference",
          credentialRef,
          passphraseRef: host.androidKeyPassphraseRef,
        },
      });
      const sessionId = connected.sessionId;
      let terminalId: string;
      try {
        terminalId = await invoke<string>("android_open_terminal", {
          sessionId,
          cols: 120,
          rows: 32,
        });
      } catch (error) {
        await invoke("android_disconnect_host", { sessionId }).catch(() => undefined);
        throw error;
      }
      setAndroidTerminalIds((current) => ({ ...current, [sessionId]: terminalId }));
      updateSession(session.id, { state: "connected" });
      setAppState((current) => ({
        ...current,
        connectionHistory: [connected.connection, ...(current.connectionHistory ?? [])].slice(0, 10_000),
      }));
      showToast(`已连接 ${host.name}`);
      return;
    }
    const identityPassphraseRef = appState.sshKeys.find(
      (key) => key.privateKeyPath === host.identityFile,
    )?.passphraseRef;
    const startOpenSshTerminal = async () => {
      const result = await invoke<OpenSshTerminalStartResult>("start_ssh_session", {
        hostId: host.id,
        initialPath: session.currentPath,
        request: {
          sessionId: session.id,
          host: host.host,
          port: host.port,
          username: host.username,
          identityFile: host.identityFile,
          credentialRef: host.credentialRef,
          identityPassphraseRef,
          cols: 120,
          rows: 32,
        },
      });
      if (result.schemaVersion !== 1 || result.engine !== "openssh" || result.sessionId !== session.id) {
        await invoke("stop_terminal", { sessionId: session.id }).catch(() => undefined);
        throw new Error("OpenSSH 返回了不受支持的会话结果");
      }
      return result.connection;
    };
    updateSession(session.id, { state: "connecting" });
    let effectiveEngine = session.engine;
    let usedCompatibilityFallback = false;
    let authenticatedConnection: ConnectionHistoryItem | undefined;
    if (session.engine === "russh") {
      if (!hostKeySha256) throw new Error("原生终端需要已验证的 SHA256 主机指纹");
      if (!host.identityFile && !host.credentialRef) {
        throw new Error("原生终端目前需要已保存的密码或显式私钥；可切回 OpenSSH 使用 agent 等兼容认证");
      }
      setNativeTerminalStartingIds((current) => current.includes(session.id) ? current : [...current, session.id]);
      let result: NativeTerminalStartResult | undefined;
      try {
        result = await invoke<NativeTerminalStartResult>("start_native_terminal", {
          hostId: host.id,
          initialPath: session.currentPath,
          request: {
            sessionId: session.id,
            route: nativeRoute(host, appState.hosts, appState.sshKeys, hostKeySha256),
            cols: 120,
            rows: 32,
          },
        });
      } catch (error) {
        if (host.jumpRoute?.length || !canFallbackNativeTerminalToOpenSsh(error)) throw error;
        authenticatedConnection = await startOpenSshTerminal();
        effectiveEngine = "openssh";
        usedCompatibilityFallback = true;
        updateSession(session.id, { engine: "openssh" });
      } finally {
        setNativeTerminalStartingIds((current) => current.filter((sessionId) => sessionId !== session.id));
      }
      if (effectiveEngine === "russh"
        && (!result || result.schemaVersion !== 1 || result.engine !== "russh" || result.sessionId !== session.id)) {
        await invoke("stop_terminal", { sessionId: session.id }).catch(() => undefined);
        throw new Error("原生终端返回了不受支持的会话结果");
      }
      if (effectiveEngine === "russh") authenticatedConnection = result?.connection;
    } else if (session.engine === "mosh") {
      if (host.jumpRoute?.length) {
        throw new Error("Mosh 是直连 UDP 交互模式，不支持跳板路线");
      }
      const result = await invoke<MoshTerminalStartResult>("start_mosh_session", {
        hostId: host.id,
        initialPath: session.currentPath,
        request: {
          sessionId: session.id,
          host: host.host,
          port: host.port,
          username: host.username,
          identityFile: host.identityFile,
          credentialRef: host.credentialRef,
          identityPassphraseRef,
          cols: 120,
          rows: 32,
          udpPortStart: 60000,
          udpPortEnd: 61000,
        },
      });
      if (result.schemaVersion !== 1 || result.engine !== "mosh" || result.sessionId !== session.id) {
        await invoke("stop_terminal", { sessionId: session.id }).catch(() => undefined);
        throw new Error("Mosh 返回了不受支持的会话结果");
      }
      authenticatedConnection = result.connection;
    } else {
      authenticatedConnection = await startOpenSshTerminal();
    }
    if (!authenticatedConnection) {
      await invoke("stop_terminal", { sessionId: session.id }).catch(() => undefined);
      throw new Error("连接成功但未返回 Rust 认证记录");
    }
    updateSession(session.id, { state: "connected" });
    setAppState((current) => ({
      ...current,
      connectionHistory: [authenticatedConnection, ...(current.connectionHistory ?? [])].slice(0, 10_000),
    }));
    const engineLabel = effectiveEngine === "russh"
      ? "原生 russh"
      : effectiveEngine === "mosh"
        ? "Mosh"
        : usedCompatibilityFallback ? "OpenSSH 兼容回退" : "OpenSSH";
    showToast(`已通过 ${engineLabel} 连接 ${host.name}`);
  }

  async function connectActiveSession() {
    if (!hasActiveHost) {
      setDialog("host");
      showToast("请先添加或导入主机配置");
      return;
    }
    if (!isDesktopRuntime() && !isAndroidRuntime()) {
      showToast("浏览器预览不启动 SSH；桌面应用中可直接连接");
      return;
    }
    updateSession(activeSession.id, { state: "connecting" });
    try {
      if (!isAndroidRuntime() && activeHost.jumpRoute?.length) {
        if (activeSession.engine !== "russh") {
          throw new Error("已配置的跳板路线只能通过原生 russh 引擎连接");
        }
        if (!activeHost.hostKeySha256) {
          throw new Error("跳板路线的目标主机需要预先保存 SHA256 主机指纹");
        }
        await startSshSession(activeSession, activeHost, activeHost.hostKeySha256);
        return;
      }
      const inspection: HostKeyInspection = isAndroidRuntime()
        ? await invoke<HostKeyInspection>("android_inspect_host_key", {
          host: activeHost.host,
          port: activeHost.port,
          timeoutSeconds: 15,
        }).then((value): HostKeyInspection => ({
          ...value,
          status: activeHost.hostKeySha256
            ? (value.fingerprint === activeHost.hostKeySha256 ? "verified" : "changed")
            : "unknown",
        }))
        : await invoke<HostKeyInspection>("inspect_host_key", {
          request: { host: activeHost.host, port: activeHost.port },
        });
      if (inspection.status === "unknown") {
        setPendingHostKey({ ...inspection, hostId: activeHost.id, sessionId: activeSession.id });
        setDialog("host-key");
        updateSession(activeSession.id, { state: "idle" });
        return;
      }
      if (inspection.status === "changed") {
        throw new Error(`主机指纹与本机记录不一致，已拒绝连接：${inspection.fingerprint}`);
      }
      if (inspection.status !== "verified") {
        throw new Error("无法验证 SSH 主机指纹，已拒绝连接");
      }
      if (!isAndroidRuntime() && activeHost.hostKeySha256 !== inspection.fingerprint) {
        setAppState((current) => ({
          ...current,
          hosts: current.hosts.map((host) => host.id === activeHost.id
            ? { ...host, hostKeySha256: inspection.fingerprint }
            : host),
        }));
      }
      await startSshSession(activeSession, activeHost, inspection.fingerprint);
    } catch (error) {
      updateSession(activeSession.id, { state: "error" });
      showToast(invokeErrorMessage(error));
    }
  }

  async function disconnectActiveSession() {
    if (isAndroidRuntime()) {
      await invoke("android_disconnect_host", { sessionId: activeSession.id }).catch((error) => showToast(String(error)));
      setAndroidTerminalIds((current) => {
        const next = { ...current };
        delete next[activeSession.id];
        return next;
      });
    } else if (isDesktopRuntime()) {
      await invoke("stop_terminal", { sessionId: activeSession.id }).catch((error) => showToast(String(error)));
    }
    updateSession(activeSession.id, { state: "closed" });
  }

  async function cancelNativeTerminalStart() {
    if (!nativeTerminalStartingIds.includes(activeSession.id)) return;
    try {
      await invoke("cancel_native_engine_operation", { operationId: activeSession.id });
      showToast("正在取消原生终端连接");
    } catch (error) {
      showToast(invokeErrorMessage(error));
    }
  }

  async function probeNativeEngine() {
    if (nativeProbeOperationId) {
      const operationId = nativeProbeOperationId;
      try {
        await invoke("cancel_native_engine_operation", { operationId });
        showToast("正在取消原生引擎检查");
      } catch (error) {
        showToast(invokeErrorMessage(error));
      }
      return;
    }
    if (nativeProbeInspecting || !hasActiveHost || !isDesktopRuntime()) return;
    if (!activeHost.identityFile && !activeHost.credentialRef) {
      showToast("原生引擎检查目前需要已保存的密码或显式私钥；该主机继续使用系统 OpenSSH");
      return;
    }
    const operationId = crypto.randomUUID();
    setNativeProbeInspecting(true);
    try {
      let targetHostKeySha256 = activeHost.hostKeySha256;
      if (!activeHost.jumpRoute?.length) {
        const inspection = await invoke<HostKeyInspection>("inspect_host_key", {
          request: { host: activeHost.host, port: activeHost.port },
        });
        if (inspection.status === "unknown") {
          throw new Error("请先通过正常连接流程核验并保存主机指纹");
        }
        if (inspection.status === "changed") {
          throw new Error(`主机指纹与本机记录不一致，原生检查已拒绝：${inspection.fingerprint}`);
        }
        if (inspection.status !== "verified") {
          throw new Error("无法验证 SSH 主机指纹，原生检查已拒绝");
        }
        targetHostKeySha256 = inspection.fingerprint;
      }
      if (!targetHostKeySha256) {
        throw new Error("跳板路线的目标主机需要预先保存 SHA256 主机指纹");
      }
      setNativeProbeInspecting(false);
      setNativeProbeOperationId(operationId);
      const result = await invoke<NativeEngineProbeResult>("native_engine_probe", {
        request: {
          operationId,
          route: nativeRoute(activeHost, appState.hosts, appState.sshKeys, targetHostKeySha256),
        },
      });
      if (result.schemaVersion !== 1 || result.engine !== "russh" || !result.sshReady || !result.sftpReady) {
        throw new Error("原生引擎返回了不受支持的检查结果");
      }
      showToast(`${activeHost.name} 的原生 SSH/SFTP 检查通过`);
    } catch (error) {
      showToast(invokeErrorMessage(error));
    } finally {
      setNativeProbeInspecting(false);
      setNativeProbeOperationId((current) => current === operationId ? null : current);
    }
  }

  async function refreshNativeForwards() {
    if (!isDesktopRuntime()) return;
    try {
      const [localForwards, remoteForwards, dynamicForwards] = await Promise.all([
        invoke<NativeLocalForwardSnapshot[]>("list_native_local_forwards"),
        invoke<NativeRemoteForwardSnapshot[]>("list_native_remote_forwards"),
        invoke<NativeDynamicForwardSnapshot[]>("list_native_dynamic_forwards"),
      ]);
      setNativeLocalForwards(localForwards);
      setNativeRemoteForwards(remoteForwards);
      setNativeDynamicForwards(dynamicForwards);
      setNativeLocalForwardError(null);
    } catch (error) {
      setNativeLocalForwardError(invokeErrorMessage(error));
    }
  }

  async function startNativeLocalForward(form: HTMLFormElement) {
    if (!hasActiveHost || nativeLocalForwardBusy || !isDesktopRuntime()) return;
    const data = new FormData(form);
    const bindPort = Number(data.get("bindPort"));
    const targetHost = String(data.get("targetHost") ?? "").trim();
    const targetPort = Number(data.get("targetPort"));
    if (!Number.isInteger(bindPort) || bindPort < 0 || bindPort > 65_535) {
      setNativeLocalForwardError("本地端口必须在 0 到 65535 之间");
      return;
    }
    if (!targetHost || !Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65_535) {
      setNativeLocalForwardError("请填写有效的目标地址和端口");
      return;
    }
    setNativeLocalForwardBusy(true);
    setNativeLocalForwardError(null);
    try {
      const forward = await invoke<NativeLocalForwardSnapshot>("start_native_local_forward", {
        request: {
          forwardId: crypto.randomUUID(),
          route: nativeRoute(activeHost, appState.hosts, appState.sshKeys),
          bindPort,
          targetHost,
          targetPort,
        },
      });
      setNativeLocalForwards((current) => [
        forward,
        ...current.filter((item) => item.forwardId !== forward.forwardId),
      ]);
      form.reset();
      showToast(`本地转发已监听 ${forward.bindHost}:${forward.bindPort}`);
    } catch (error) {
      setNativeLocalForwardError(invokeErrorMessage(error));
    } finally {
      setNativeLocalForwardBusy(false);
    }
  }

  async function stopNativeLocalForward(forwardId: string) {
    if (nativeLocalForwardBusy || !isDesktopRuntime()) return;
    setNativeLocalForwardBusy(true);
    setNativeLocalForwardError(null);
    try {
      await invoke("stop_native_local_forward", { forwardId });
      showToast("正在停止本地转发");
      await refreshNativeForwards();
    } catch (error) {
      setNativeLocalForwardError(invokeErrorMessage(error));
    } finally {
      setNativeLocalForwardBusy(false);
    }
  }

  async function startNativeRemoteForward(form: HTMLFormElement) {
    if (!hasActiveHost || nativeLocalForwardBusy || !isDesktopRuntime()) return;
    const data = new FormData(form);
    const bindPort = Number(data.get("bindPort"));
    const targetPort = Number(data.get("targetPort"));
    if (!Number.isInteger(bindPort) || bindPort < 0 || bindPort > 65_535) {
      setNativeLocalForwardError("远端端口必须在 0 到 65535 之间");
      return;
    }
    if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65_535) {
      setNativeLocalForwardError("本机目标端口必须在 1 到 65535 之间");
      return;
    }
    setNativeLocalForwardBusy(true);
    setNativeLocalForwardError(null);
    try {
      const forward = await invoke<NativeRemoteForwardSnapshot>("start_native_remote_forward", {
        request: {
          forwardId: crypto.randomUUID(),
          route: nativeRoute(activeHost, appState.hosts, appState.sshKeys),
          bindPort,
          targetPort,
        },
      });
      setNativeRemoteForwards((current) => [
        forward,
        ...current.filter((item) => item.forwardId !== forward.forwardId),
      ]);
      form.reset();
      showToast(`远端转发已监听 ${forward.bindHost}:${forward.bindPort}`);
    } catch (error) {
      setNativeLocalForwardError(invokeErrorMessage(error));
    } finally {
      setNativeLocalForwardBusy(false);
    }
  }

  async function stopNativeRemoteForward(forwardId: string) {
    if (nativeLocalForwardBusy || !isDesktopRuntime()) return;
    setNativeLocalForwardBusy(true);
    setNativeLocalForwardError(null);
    try {
      await invoke("stop_native_remote_forward", { forwardId });
      showToast("正在停止远端转发");
      await refreshNativeForwards();
    } catch (error) {
      setNativeLocalForwardError(invokeErrorMessage(error));
    } finally {
      setNativeLocalForwardBusy(false);
    }
  }

  async function startNativeDynamicForward(form: HTMLFormElement) {
    if (!hasActiveHost || nativeLocalForwardBusy || !isDesktopRuntime()) return;
    const data = new FormData(form);
    const bindPort = Number(data.get("bindPort"));
    if (!Number.isInteger(bindPort) || bindPort < 0 || bindPort > 65_535) {
      setNativeLocalForwardError("SOCKS 端口必须在 0 到 65535 之间");
      return;
    }
    setNativeLocalForwardBusy(true);
    setNativeLocalForwardError(null);
    try {
      const forward = await invoke<NativeDynamicForwardSnapshot>("start_native_dynamic_forward", {
        request: {
          forwardId: crypto.randomUUID(),
          route: nativeRoute(activeHost, appState.hosts, appState.sshKeys),
          bindPort,
        },
      });
      setNativeDynamicForwards((current) => [
        forward,
        ...current.filter((item) => item.forwardId !== forward.forwardId),
      ]);
      form.reset();
      showToast(`SOCKS5 已监听 ${forward.bindHost}:${forward.bindPort}`);
    } catch (error) {
      setNativeLocalForwardError(invokeErrorMessage(error));
    } finally {
      setNativeLocalForwardBusy(false);
    }
  }

  async function stopNativeDynamicForward(forwardId: string) {
    if (nativeLocalForwardBusy || !isDesktopRuntime()) return;
    setNativeLocalForwardBusy(true);
    setNativeLocalForwardError(null);
    try {
      await invoke("stop_native_dynamic_forward", { forwardId });
      showToast("正在停止 SOCKS5 转发");
      await refreshNativeForwards();
    } catch (error) {
      setNativeLocalForwardError(invokeErrorMessage(error));
    } finally {
      setNativeLocalForwardBusy(false);
    }
  }

  async function trustPendingHostKey() {
    if (!pendingHostKey || trustingHostKey) return;
    const pending = pendingHostKey;
    setTrustingHostKey(true);
    try {
      if (isAndroidRuntime()) {
        const currentHost = appState.hosts.find((host) => host.id === pending.hostId);
        if (!currentHost || currentHost.host !== pending.host || currentHost.port !== pending.port) {
          throw new Error("主机资料已变化，请重新检查指纹");
        }
        setAppState((current) => ({
          ...current,
          hosts: current.hosts.map((host) => host.id === pending.hostId ? { ...host, hostKeySha256: pending.fingerprint } : host),
        }));
      } else {
        await invoke<HostKeyInspection>("trust_host_key", {
          request: { host: pending.host, port: pending.port },
          expectedFingerprint: pending.fingerprint,
        });
        setAppState((current) => ({
          ...current,
          hosts: current.hosts.map((host) => host.id === pending.hostId
            ? { ...host, hostKeySha256: pending.fingerprint }
            : host),
        }));
      }
      setPendingHostKey(null);
      setDialog(null);
      const session = sessions.find((candidate) => candidate.id === pending.sessionId);
      const host = appState.hosts.find((candidate) => candidate.id === pending.hostId);
      if (!session || !host || host.host !== pending.host || host.port !== pending.port) {
        showToast("主机指纹已保存；原会话已变化，请重新点击连接");
        return;
      }
      showToast("主机指纹已保存，正在连接");
      await startSshSession(
        session,
        { ...host, hostKeySha256: pending.fingerprint },
        pending.fingerprint,
      );
    } catch (error) {
      updateSession(pending.sessionId, { state: "error" });
      showToast(invokeErrorMessage(error));
    } finally {
      setTrustingHostKey(false);
    }
  }

  async function writeToSessions(command: string, targetIds: string[]) {
    const targetSessions = sessions.filter((session) => targetIds.includes(session.id));
    if (isAndroidRuntime()) {
      await Promise.all(targetSessions.filter((session) => session.state === "connected").map((session) => {
        const terminalId = androidTerminalIds[session.id];
        if (!terminalId) return Promise.reject(new Error("Android 终端尚未就绪"));
        return invoke("android_write_terminal", {
          request: {
            sessionId: session.id,
            terminalId,
            dataBase64: encodeUtf8Base64(`${command}\r`),
          },
        });
      }));
    } else if (isDesktopRuntime()) {
      await Promise.all(targetSessions.filter((session) => session.state === "connected").map((session) =>
        invoke("write_terminal", { sessionId: session.id, data: `${command}\r` }),
      ));
    }

    const now = new Date().toISOString();
    setAppState((current) => ({
      ...current,
      commandHistory: [
        ...targetSessions.map((session) => ({
          id: crypto.randomUUID(),
          command,
          hostId: session.hostId,
          path: session.currentPath,
          createdAt: now,
        })),
        ...current.commandHistory,
      ],
    }));

    if (!targetSessions.some((session) => session.state === "connected")) {
      showToast("命令已加入历史；连接主机后才会执行");
    }
  }

  async function submitCommand() {
    const command = commandInput.trim();
    if (!command) return;
    if (broadcastOpen) {
      if (broadcastTargets.length === 0) {
        showToast("广播模式必须先明确选择至少一个已连接目标");
        return;
      }
      const targets = sessions
        .filter((session) => broadcastTargets.includes(session.id) && session.state === "connected")
        .map((session) => {
          const host = appState.hosts.find((candidate) => candidate.id === session.hostId);
          return {
            sessionId: session.id,
            label: session.title,
            environment: host?.environment ?? "development",
          };
        });
      try {
        const preview = await invoke<BroadcastPreviewResponse>("preview_broadcast", { command, targets });
        setBroadcastPreview(preview);
        setBroadcastResult(null);
      } catch (error) {
        showToast(`广播已阻止：${String(error)}`);
      }
      return;
    }
    await writeToSessions(command, [activeSession.id]);
    setCommandInput("");
  }

  async function confirmBroadcast() {
    if (!broadcastPreview || broadcastExecuting) return;
    setBroadcastExecuting(true);
    try {
      const result = await invoke<BroadcastResultResponse>("execute_broadcast", {
        confirmationToken: broadcastPreview.confirmationToken,
      });
      const successfulIds = result.items
        .filter((item) => item.outcome === "succeeded")
        .map((item) => item.sessionId);
      if (successfulIds.length > 0) {
        const now = new Date().toISOString();
        setAppState((current) => ({
          ...current,
          commandHistory: [
            ...sessions.filter((session) => successfulIds.includes(session.id)).map((session) => ({
              id: crypto.randomUUID(),
              command: broadcastPreview.command,
              hostId: session.hostId,
              path: session.currentPath,
              createdAt: now,
            })),
            ...current.commandHistory,
          ],
        }));
      }
      setBroadcastResult(result);
      setBroadcastPreview(null);
      setBroadcastTargets([]);
      setCommandInput("");
      showToast(`广播结果：成功 ${result.succeeded}，失败 ${result.failed}，跳过 ${result.skipped}`);
    } catch (error) {
      setBroadcastPreview(null);
      showToast(`广播确认失败：${String(error)}`);
    } finally {
      setBroadcastExecuting(false);
    }
  }

  function closeBroadcast() {
    setBroadcastOpen(false);
    setBroadcastTargets([]);
    setBroadcastPreview(null);
    setBroadcastResult(null);
  }

  function chooseScript(script: ScriptRecipe) {
    setSelectedScript(script);
    setDialog("script");
  }

  function chooseCommand(command: CommandRecipe) {
    if (command.action === "install-public-key") {
      setDialog("key-manager");
      return;
    }
    if (command.action) {
      setNetworkMode(command.action === "trace-route" ? "trace" : command.action === "udp-speed-test" ? "udp" : "download");
      setDialog("network");
      return;
    }
    setSelectedCommand(command);
    setCommandParameters(Object.fromEntries((command.parameters ?? []).map((parameter) => {
      const recent = isSensitiveCommandParameter(parameter)
        ? undefined
        : appState.parameterHistory.find((item) =>
            item.commandId === command.id && item.parameterName === parameter.name
          );
      return [parameter.name, recent?.value ?? parameter.defaultValue ?? ""];
    })));
    setDialog("command");
  }

  function materializeCommand(command: CommandRecipe) {
    let value = command.command ?? "";
    for (const parameter of command.parameters ?? []) {
      value = value.split(`{{${parameter.name}}}`).join(shellQuote(commandParameters[parameter.name]?.trim() ?? ""));
    }
    return value;
  }

  function rememberCommandParameters(command: CommandRecipe) {
    const createdAt = new Date().toISOString();
    const additions = (command.parameters ?? []).flatMap((parameter) => {
      const value = commandParameters[parameter.name]?.trim() ?? "";
      if (!value || isSensitiveCommandParameter(parameter)) return [];
      return [{
        id: crypto.randomUUID(),
        commandId: command.id,
        parameterName: parameter.name,
        value,
        createdAt,
      }];
    });
    if (additions.length === 0) return;
    setAppState((current) => {
      const replaced = new Set(additions.map((item) => `${item.commandId}\0${item.parameterName}\0${item.value}`));
      return {
        ...current,
        parameterHistory: [
          ...additions,
          ...current.parameterHistory.filter((item) =>
            !replaced.has(`${item.commandId}\0${item.parameterName}\0${item.value}`)
          ),
        ].slice(0, MAX_PARAMETER_HISTORY),
      };
    });
  }

  function chooseIntent(suggestion: IntentSuggestion) {
    setCommandInput("");
    if (suggestion.kind === "script") chooseScript(suggestion.item as ScriptRecipe);
    else chooseCommand(suggestion.item as CommandRecipe);
  }

  function handleMigrationImport(result: MigrationImportResult) {
    const hostKey = (host: HostProfile) => `${host.username}\0${host.host}\0${host.port}`;
    const importedByKey = new Map(result.profiles.map((host) => [hostKey(host), host]));
    const existingKeys = new Set(appState.hosts.map(hostKey));
    const additions = result.profiles.filter((host) => !existingKeys.has(hostKey(host)));
    const supersededReferences = new Set<string>();
    let updatedCredentials = 0;

    const mergedHosts = appState.hosts.map((host) => {
      const imported = importedByKey.get(hostKey(host));
      if (!imported) return host;
      if (imported.credentialRef && imported.credentialRef !== host.credentialRef) {
        updatedCredentials += 1;
        if (host.credentialRef) supersededReferences.add(host.credentialRef);
      }
      return {
        ...host,
        credentialRef: imported.credentialRef ?? host.credentialRef,
        source: imported.credentialRef ? "finalshell" as const : host.source,
        tags: [...new Set([...host.tags, ...imported.tags])],
      };
    });

    const nextHosts = [...mergedHosts, ...additions];
    setAppState((current) => ({ ...current, hosts: nextHosts }));
    if (isDesktopRuntime() && supersededReferences.size > 0) {
      const retainedReferences = new Set([
        ...nextHosts.map((host) => host.credentialRef),
        ...(appState.deletedHosts ?? []).map((item) => item.host.credentialRef),
      ].filter((reference): reference is string => Boolean(reference)));
      void Promise.all([...supersededReferences]
        .filter((reference) => !retainedReferences.has(reference))
        .map((reference) => invoke("delete_credential", { reference }).catch(() => undefined)));
    }
    setSidebarView("hosts");
    showToast(`${result.sourceLabel}：新增 ${additions.length} 台，更新 ${updatedCredentials} 台凭据，安全保存 ${result.credentialsImported} 个密码`);
  }

  async function runWindowAction(action: "minimize" | "toggleMaximize" | "close") {
    if (!isDesktopRuntime()) return;
    const { getCurrentWindow } = await import("@tauri-apps/api/window");
    await getCurrentWindow()[action]();
  }

  async function openExternal(url: string) {
    if (!url) return;
    if (isDesktopRuntime()) {
      const { openUrl } = await import("@tauri-apps/plugin-opener");
      await openUrl(url);
    } else {
      window.open(url, "_blank", "noopener,noreferrer");
    }
  }

  async function addHost(form: HTMLFormElement) {
    const data = new FormData(form);
    let credentialRef: string | undefined;
    let androidKeyRef: string | undefined;
    let androidKeyPassphraseRef: string | undefined;
    if (isAndroidRuntime()) {
      try {
        const value = String(data.get("androidCredential") || "");
        if (androidCredentialKind === "password") {
          if (value) {
            credentialRef = await invoke<string>("android_store_credential", {
              request: { kind: "password", value },
            });
          }
        } else {
          androidKeyRef = await invoke<string>("android_store_credential", {
            request: { kind: "privateKey", value },
          });
          const passphrase = String(data.get("androidPassphrase") || "");
          if (passphrase) {
            androidKeyPassphraseRef = await invoke<string>("android_store_credential", {
              request: { kind: "privateKeyPassphrase", value: passphrase },
            });
          }
        }
      } catch (error) {
        showToast(`Android 凭据保存失败：${String(error)}`);
        return;
      }
    }
    const host: HostProfile = {
      id: crypto.randomUUID(),
      name: String(data.get("name") || data.get("host")),
      group: String(data.get("group") || "我的主机"),
      host: String(data.get("host")),
      port: Number(data.get("port") || 22),
      username: String(data.get("username") || "root"),
      environment: String(data.get("environment") || "development") as EnvironmentKind,
      identityFile: String(data.get("identityFile") || "") || undefined,
      credentialRef,
      androidKeyRef,
      androidKeyPassphraseRef,
      hostKeySha256: String(data.get("hostKeySha256") || "") || undefined,
      jumpRoute: String(data.get("jumpHostId") || "")
        ? [String(data.get("jumpHostId"))]
        : undefined,
      tags: [],
      lastPath: "~",
    };
    setAppState((current) => ({ ...current, hosts: [...current.hosts, host] }));
    setDialog(null);
    setAndroidCredentialKind("password");
    openHost(host);
  }

  async function deleteHost(host: HostProfile) {
    const routeDependents = appState.hosts.filter(
      (candidate) => candidate.id !== host.id && candidate.jumpRoute?.includes(host.id),
    );
    if (routeDependents.length) {
      showToast(`该主机仍被 ${routeDependents.length} 条跳板路线引用，不能删除`);
      return;
    }
    const confirmed = window.confirm(
      `确定将主机“${host.name}”（${host.username}@${host.host}:${host.port}）移到回收站吗？\n\n相关连接记录和命令/路径历史将一并保留 30 天，可在回收站恢复。`,
    );
    if (!confirmed) return;

    const hostSessions = sessions.filter((session) => session.hostId === host.id);
    if (isAndroidRuntime()) {
      await Promise.all(hostSessions
        .filter((session) => session.state === "connected" || session.state === "connecting")
        .map((session) => invoke("android_disconnect_host", { sessionId: session.id }).catch(() => undefined)));
    } else if (isDesktopRuntime()) {
      await Promise.all(hostSessions
        .filter((session) => session.state === "connected" || session.state === "connecting")
        .map((session) => invoke("stop_terminal", { sessionId: session.id }).catch(() => undefined)));
    }

    const remainingHosts = appState.hosts.filter((item) => item.id !== host.id);
    const nextSessions = sessions.filter((session) => session.hostId !== host.id);
    if (nextSessions.length === 0) nextSessions.push(makeSession(remainingHosts[0] ?? emptyHost));
    setSessions(nextSessions);
    setActiveSessionId((current) => (
      nextSessions.some((session) => session.id === current) ? current : nextSessions[0].id
    ));
    setBroadcastTargets((current) => current.filter((sessionId) => !hostSessions.some((session) => session.id === sessionId)));
    setHostMetrics((current) => Object.fromEntries(
      Object.entries(current).filter(([sessionId]) => !hostSessions.some((session) => session.id === sessionId)),
    ));
    setAppState((current) => {
      const pathHistory = { ...current.pathHistory };
      const deletedAt = new Date();
      const expiresAt = new Date(deletedAt.getTime() + RECYCLE_BIN_DAYS * 24 * 60 * 60 * 1000);
      const deletedItem = {
        id: crypto.randomUUID(),
        host,
        deletedAt: deletedAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
        commandHistory: current.commandHistory.filter((item) => item.hostId === host.id),
        connectionHistory: (current.connectionHistory ?? []).filter((item) => item.hostId === host.id),
        pathHistory: pathHistory[host.id] ?? [],
      };
      delete pathHistory[host.id];
      return {
        ...current,
        hosts: current.hosts.filter((item) => item.id !== host.id),
        deletedHosts: [deletedItem, ...(current.deletedHosts ?? [])],
        commandHistory: current.commandHistory.filter((item) => item.hostId !== host.id),
        connectionHistory: (current.connectionHistory ?? []).filter((item) => item.hostId !== host.id),
        pathHistory,
        settings: current.settings,
      };
    });
    showToast(`已将 ${host.name} 移到回收站，保留 30 天`);
  }

  function restoreDeletedHost(itemId: string) {
    const deleted = deletedHosts.find((item) => item.id === itemId);
    if (!deleted) return;
    const restoredHost = appState.hosts.some((host) => host.id === deleted.host.id)
      ? { ...deleted.host, id: crypto.randomUUID() }
      : deleted.host;
    setAppState((current) => ({
      ...current,
      hosts: [...current.hosts, restoredHost],
      deletedHosts: (current.deletedHosts ?? []).filter((item) => item.id !== itemId),
      commandHistory: [
        ...deleted.commandHistory.map((item) => ({ ...item, hostId: restoredHost.id })),
        ...current.commandHistory,
      ],
      connectionHistory: [
        ...deleted.connectionHistory.map((item) => ({ ...item, hostId: restoredHost.id })),
        ...(current.connectionHistory ?? []),
      ],
      pathHistory: {
        ...current.pathHistory,
        [restoredHost.id]: deleted.pathHistory,
      },
    }));
    openHost(restoredHost);
    showToast(`已恢复主机 ${restoredHost.name}`);
  }

  async function permanentlyDeleteHost(itemId: string) {
    const deleted = deletedHosts.find((item) => item.id === itemId);
    if (!deleted || !window.confirm(`永久删除“${deleted.host.name}”吗？此操作无法恢复。`)) return;
    let credentialError: string | undefined;
    for (const reference of hostCredentialReferences(deleted.host)) {
      const referencedElsewhere = appState.hosts.some((host) => hostCredentialReferences(host).includes(reference))
        || deletedHosts.some((item) => item.id !== itemId && hostCredentialReferences(item.host).includes(reference));
      if (!referencedElsewhere && (isDesktopRuntime() || isAndroidRuntime())) {
        try {
          await invoke(isAndroidRuntime() ? "android_delete_credential" : "delete_credential", { reference });
        } catch (error) {
          credentialError = String(error);
        }
      }
    }
    setAppState((current) => ({
      ...current,
      deletedHosts: (current.deletedHosts ?? []).filter((item) => item.id !== itemId),
    }));
    showToast(credentialError ? `记录已永久删除；系统凭据清理失败：${credentialError}` : `已永久删除 ${deleted.host.name}`);
  }

  function closeGuide() {
    setAppState((current) => ({ ...current, onboardingCompleted: true }));
    setDialog(null);
  }

  function addCustomScript(form: HTMLFormElement) {
    const data = new FormData(form);
    const script: ScriptRecipe = {
      id: crypto.randomUUID(),
      title: String(data.get("title")),
      description: String(data.get("description") || "用户自建脚本"),
      category: String(data.get("category") || "我的脚本"),
      command: String(data.get("command")),
      sourceUrl: String(data.get("sourceUrl") || ""),
      risk: String(data.get("risk") || "medium") as ScriptRecipe["risk"],
      custom: true,
    };
    setAppState((current) => ({ ...current, scripts: [script, ...current.scripts] }));
    setDialog(null);
    setSidebarView("scripts");
  }

  async function registerFontAsset(asset: RenderAsset) {
    const font = new FontFace(CUSTOM_FONT_FAMILY, `url(${asset.dataUrl})`);
    const loaded = await font.load();
    document.fonts.add(loaded);
    setFontRevision((value) => value + 1);
  }

  async function chooseLocalWallpaper() {
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const selected = await open({
        title: "选择终端壁纸",
        multiple: false,
        directory: false,
        filters: [{ name: "图片", extensions: ["png", "jpg", "jpeg", "webp"] }],
      });
      if (typeof selected !== "string") return;
      const asset = await invoke<RenderAsset>("install_wallpaper_asset", {
        request: { source: "local", value: selected },
      });
      setRenderedWallpaper(asset.dataUrl);
      setAppState((current) => ({
        ...current,
        wallpaper: { ...current.wallpaper, source: "local", value: asset.label },
      }));
      showToast(`已启用本机壁纸 ${asset.label}`);
    } catch (error) {
      showToast(`壁纸安装失败：${String(error)}`);
    }
  }

  async function chooseWebDavCa() {
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const selected = await open({
        title: "选择 WebDAV CA 证书",
        multiple: false,
        directory: false,
        filters: [{ name: "PEM 证书", extensions: ["pem", "crt"] }],
      });
      if (typeof selected !== "string") return;
      const parts = selected.split(/[\\/]/);
      setWebDavCaPath(selected);
      setWebDavCaLabel(parts[parts.length - 1] || "已选择证书");
      setWebDavUseSystemCa(false);
    } catch (error) {
      showToast(`选择 WebDAV CA 失败：${String(error)}`);
    }
  }

  async function applyRemoteWallpaper() {
    try {
      const asset = await invoke<RenderAsset>("install_wallpaper_asset", {
        request: { source: "url", value: appState.wallpaper.value.trim() },
      });
      setRenderedWallpaper(asset.dataUrl);
      showToast("HTTPS 壁纸已由 Rust 下载并缓存");
    } catch (error) {
      showToast(`壁纸下载失败：${String(error)}`);
    }
  }

  async function chooseLocalFont() {
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const selected = await open({
        title: "选择终端字体",
        multiple: false,
        directory: false,
        filters: [{ name: "字体", extensions: ["ttf", "otf", "woff", "woff2"] }],
      });
      if (typeof selected !== "string") return;
      const asset = await invoke<RenderAsset>("install_font_asset", { request: { path: selected } });
      await registerFontAsset(asset);
      setAppState((current) => ({
        ...current,
        terminalAppearance: { ...current.terminalAppearance, fontFamily: CUSTOM_FONT_FAMILY, customFontName: asset.label },
      }));
      showToast(`已启用本机字体 ${asset.label}`);
    } catch (error) {
      showToast(`字体安装失败：${String(error)}`);
    }
  }

  async function readInstalledFonts() {
    if (!window.queryLocalFonts) {
      showToast("当前 WebView 不支持读取系统字体，请手动输入字体名称或选择字体文件");
      return;
    }
    try {
      const fonts = await window.queryLocalFonts();
      const families = [...new Set(fonts.map((font) => font.family).filter(Boolean))].sort((left, right) => left.localeCompare(right));
      setInstalledFonts(families);
      showToast(`已读取 ${families.length} 个字体家族`);
    } catch {
      showToast("未获得本机字体读取权限，可继续手动输入或选择字体文件");
    }
  }

  async function configureDesktopSync() {
    if (appState.sync.provider !== "local" && appState.sync.provider !== "webdav") {
      showToast("当前只开放 Local Folder 与 WebDAV 同步");
      return;
    }
    if (!appState.sync.endpoint.trim()) {
      showToast(appState.sync.provider === "local" ? "请输入已存在的同步目录" : "请输入 WebDAV HTTPS endpoint");
      return;
    }
    if (!syncPassword) {
      showToast("请输入二级同步密码");
      return;
    }
    setDesktopSyncBusy(true);
    let createdCredentialRef: string | undefined;
    let createdCaRef: string | undefined;
    try {
      const provider = appState.sync.provider;
      const username = appState.sync.username.trim();
      if (provider === "webdav" && webDavPassword && !username) {
        throw new Error("保存 WebDAV 密码前必须填写用户名");
      }
      if (provider === "webdav" && webDavPassword) {
        createdCredentialRef = await invoke<string>("store_webdav_credential", {
          request: { password: webDavPassword },
        });
      }
      if (provider === "webdav" && webDavCaPath) {
        createdCaRef = await invoke<string>("install_webdav_ca", {
          request: { path: webDavCaPath },
        });
      }
      const providerCredentialRef = provider === "webdav" && username
        ? createdCredentialRef ?? appState.sync.providerCredentialRef
        : undefined;
      const providerCaRef = provider === "webdav"
        ? createdCaRef ?? (webDavUseSystemCa ? undefined : appState.sync.providerCaRef)
        : undefined;
      if (provider === "webdav" && Boolean(username) !== Boolean(providerCredentialRef)) {
        throw new Error("WebDAV 用户名需要对应的已保存密码");
      }
      const status = provider === "local"
        ? await invoke<SyncCoordinatorStatus>("configure_local_folder_sync", {
          request: {
            rootPath: appState.sync.endpoint.trim(),
            password: syncPassword,
            mode: syncSetupMode,
          },
        })
        : await invoke<SyncCoordinatorStatus>("configure_webdav_sync", {
          request: {
            endpoint: appState.sync.endpoint.trim(),
            username,
            providerCredentialRef,
            providerCaRef,
            password: syncPassword,
            mode: syncSetupMode,
          },
        });
      setDesktopSyncStatus(status);
      setDesktopSyncError(null);
      setAppState((current) => ({
        ...current,
        sync: {
          ...current.sync,
          enabled: true,
          provider,
          username,
          providerCredentialRef: provider === "webdav"
            ? providerCredentialRef ?? current.sync.providerCredentialRef
            : current.sync.providerCredentialRef,
          providerCaRef: provider === "webdav" ? providerCaRef : current.sync.providerCaRef,
        },
      }));
      createdCredentialRef = undefined;
      createdCaRef = undefined;
      setSyncPassword("");
      setWebDavPassword("");
      setWebDavCaPath("");
      setWebDavCaLabel("");
      setWebDavUseSystemCa(false);
      showToast(syncSetupMode === "initialize" ? "同步 vault 已初始化并解锁" : "同步 vault 已解锁");
    } catch (error) {
      if (createdCredentialRef) {
        await invoke("delete_credential", { reference: createdCredentialRef }).catch(() => undefined);
      }
      if (createdCaRef) {
        await invoke("delete_webdav_ca", { reference: createdCaRef }).catch(() => undefined);
      }
      const message = invokeErrorMessage(error);
      setDesktopSyncError(message);
      showToast(`同步配置失败：${message}`);
    } finally {
      setDesktopSyncBusy(false);
    }
  }

  async function runDesktopSyncOnce() {
    if (appStoreStatus.saving) {
      showToast("请等待本地状态保存完成后再同步");
      return;
    }
    setDesktopSyncBusy(true);
    try {
      const result = await invoke<SyncCycleResult>("run_sync_once");
      const status = result.status;
      if (!applyAppStoreSnapshot(result.appStore)) {
        throw new Error("本地状态仍有未提交更改；Rust 快照未覆盖当前编辑");
      }
      setDesktopSyncStatus(status);
      setDesktopSyncError(null);
      if (status.lastErrorCode) {
        throw new Error(status.lastErrorCode);
      }
      showToast(`同步周期完成：上传 ${status.lastUploadedObjects}，下载 ${status.lastDownloadedObjects}`);
    } catch (error) {
      const message = invokeErrorMessage(error);
      setDesktopSyncError(message);
      showToast(`同步失败：${message}`);
      await refreshDesktopSyncStatus();
    } finally {
      setDesktopSyncBusy(false);
    }
  }

  async function resolveSyncConflict(conflictId: string, alternativeIndex: number) {
    if (!syncConflictCenter || appStoreStatus.saving || desktopSyncStatus?.running) {
      showToast("请等待当前本地保存或同步任务完成");
      return;
    }
    setResolvingConflictId(conflictId);
    try {
      const result = await invoke<SyncCycleResult>("resolve_sync_conflict", {
        request: {
          expectedRevision: syncConflictCenter.mergeRevision,
          conflictId,
          alternativeIndex,
        },
      });
      const applied = applyAppStoreSnapshot(result.appStore);
      setDesktopSyncStatus(result.status);
      setDesktopSyncError(result.status.lastErrorCode ?? (applied ? null : "local-state-busy"));
      showToast(
        result.status.lastErrorCode
          ? "同步冲突已解决并入队；本地投影将在下一周期重试"
          : applied
          ? "同步冲突已解决并加入加密发布队列"
          : "同步冲突已解决；当前未提交编辑保留，稍后刷新本地视图",
      );
      await refreshSyncConflicts(syncConflictOffset);
    } catch (error) {
      const message = invokeErrorMessage(error);
      setSyncConflictError(message);
      showToast(`冲突解决失败：${message}`);
      await refreshDesktopSyncStatus();
      await refreshSyncConflicts(syncConflictOffset);
    } finally {
      setResolvingConflictId(null);
    }
  }

  async function cancelDesktopSync() {
    try {
      const status = await invoke<SyncCoordinatorStatus>("cancel_sync");
      setDesktopSyncStatus(status);
      showToast("已请求取消同步");
    } catch (error) {
      showToast(`取消同步失败：${invokeErrorMessage(error)}`);
    }
  }

  async function lockDesktopSync() {
    setDesktopSyncBusy(true);
    try {
      const status = await invoke<SyncCoordinatorStatus>("lock_sync");
      setDesktopSyncStatus(status);
      setDesktopSyncError(null);
      setSyncConflictCenter(null);
      setSyncConflictError(null);
      setSyncConflictOffset(0);
      setSyncPassword("");
      setWebDavPassword("");
      setWebDavCaPath("");
      setWebDavCaLabel("");
      setWebDavUseSystemCa(false);
      setAppState((current) => ({
        ...current,
        sync: { ...current.sync, enabled: false },
      }));
      showToast("同步 vault 已锁定");
    } catch (error) {
      showToast(`锁定同步失败：${invokeErrorMessage(error)}`);
    } finally {
      setDesktopSyncBusy(false);
    }
  }

  const currentPathHistory = appState.pathHistory[activeHost.id] ?? [];
  const activeJumpHosts = (activeHost.jumpRoute ?? [])
    .map((hostId) => appState.hosts.find((host) => host.id === hostId))
    .filter((host): host is HostProfile => Boolean(host));
  const activeRouteLabel = activeJumpHosts.length
    ? activeJumpHosts.map((host) => host.name).join(" > ")
    : "直连";

  return (
    <div className={`app-shell ${sidebarOpen ? "" : "sidebar-collapsed"}`}>
      <header className="topbar" data-tauri-drag-region>
        <div className="brand-block" data-tauri-drag-region>
          <span className="brand-mark"><img src={brandMark} alt="" /></span>
          <strong>VPShell</strong>
          <button className="workspace-switcher" type="button">
            个人资料库 <ChevronDown size={14} />
          </button>
        </div>
        <div className="topbar-right">
          <div className="topbar-actions">
            <button
              className={`sync-status ${(isAndroidRuntime() ? androidSyncStatus?.phase === "idle" : desktopSyncStatus?.phase === "idle") ? "is-synced" : ""}`}
              type="button"
              onClick={() => setDialog("sync")}
            >
              {(isAndroidRuntime() ? androidSyncStatus?.configured : desktopSyncStatus?.configured) ? <Cloud size={15} /> : <CloudOff size={15} />}
              <span>{isAndroidRuntime()
                ? androidSyncError ? "同步状态不可用" : androidSyncStatus ? syncPhaseLabels[androidSyncStatus.phase] : "正在读取同步状态"
                : desktopSyncError ? "同步状态不可用" : desktopSyncStatus ? syncPhaseLabels[desktopSyncStatus.phase] : "正在读取同步状态"}</span>
            </button>
            <span className="route-status"><Route size={15} /> 路线：{activeRouteLabel}</span>
            <button className="icon-button" type="button" title="网络诊断" aria-label="网络诊断" onClick={() => { setNetworkMode("trace"); setDialog("network"); }}><Network size={17} /></button>
            {isDesktopRuntime() ? (
              <button
                className={`icon-button ${nativeLocalForwards.length + nativeRemoteForwards.length + nativeDynamicForwards.length ? "forward-active" : ""}`}
                type="button"
                title={`端口转发（本地 ${nativeLocalForwards.length} · 远端 ${nativeRemoteForwards.length} · SOCKS ${nativeDynamicForwards.length}）`}
                aria-label={`端口转发（本地 ${nativeLocalForwards.length} · 远端 ${nativeRemoteForwards.length} · SOCKS ${nativeDynamicForwards.length}）`}
                disabled={!hasActiveHost}
                onClick={() => setDialog("local-forward")}
              >
                <Cable size={17} />
              </button>
            ) : null}
            {isDesktopRuntime() ? (
              <button
                className="icon-button"
                type="button"
                title={nativeProbeOperationId ? "取消原生引擎检查" : nativeProbeInspecting ? "正在核验主机指纹" : "检查原生 SSH/SFTP 引擎"}
                aria-label={nativeProbeOperationId ? "取消原生引擎检查" : nativeProbeInspecting ? "正在核验主机指纹" : "检查原生 SSH/SFTP 引擎"}
                disabled={!hasActiveHost || nativeProbeInspecting}
                onClick={() => void probeNativeEngine()}
              >
                {nativeProbeOperationId ? <X size={17} /> : <ShieldCheck size={17} />}
              </button>
            ) : null}
            <button className="icon-button" type="button" title="SSH 密钥" aria-label="SSH 密钥" onClick={() => setDialog("key-manager")}><KeyRound size={17} /></button>
            <button className="icon-button" type="button" title="终端外观" aria-label="终端外观" onClick={() => setDialog("wallpaper")}><Image size={17} /></button>
            <button className="icon-button" type="button" title="使用指南" aria-label="使用指南" onClick={() => setDialog("guide")}><CircleHelp size={17} /></button>
            <button className="icon-button" type="button" title="设置与升级" aria-label="设置与升级" onClick={() => setDialog("settings")}><Settings2 size={17} /></button>
          </div>
          <div className="window-controls" aria-label="窗口控制">
            <button type="button" title="最小化" aria-label="最小化" onClick={() => void runWindowAction("minimize")}><Minus size={16} /></button>
            <button type="button" title="最大化或还原" aria-label="最大化或还原" onClick={() => void runWindowAction("toggleMaximize")}><Square size={13} /></button>
            <button className="window-close" type="button" title="关闭" aria-label="关闭" onClick={() => void runWindowAction("close")}><X size={16} /></button>
          </div>
        </div>
      </header>

      <aside className="left-rail">
        <div className="rail-tabs" role="tablist" aria-label="资源类型">
          <button className={sidebarView === "hosts" ? "active" : ""} type="button" title="主机" onClick={() => setSidebarView("hosts")}><Server size={18} /></button>
          <button className={sidebarView === "commands" ? "active" : ""} type="button" title="命令库" onClick={() => setSidebarView("commands")}><BookOpenText size={18} /></button>
          <button className={sidebarView === "scripts" ? "active" : ""} type="button" title="脚本中心" onClick={() => setSidebarView("scripts")}><Library size={18} /></button>
          <button className={sidebarView === "history" ? "active" : ""} type="button" title="历史" onClick={() => setSidebarView("history")}><History size={18} /></button>
        </div>
        <button className="rail-bottom" type="button" title={sidebarOpen ? "收起侧栏" : "展开侧栏"} onClick={() => setSidebarOpen((value) => !value)}>
          {sidebarOpen ? <PanelLeftClose size={18} /> : <PanelLeftOpen size={18} />}
        </button>
      </aside>

      {sidebarOpen ? (
        <aside className="sidebar">
          <div className="sidebar-heading">
            <div>
              <span className="eyebrow">{sidebarLabels[sidebarView].eyebrow}</span>
              <h1>{sidebarLabels[sidebarView].title}</h1>
            </div>
            <div className="sidebar-heading-actions">
              {sidebarView === "hosts" ? <button className="icon-button compact" type="button" title="从其他工具导入" aria-label="从其他工具导入" onClick={() => setDialog("migration")}><Download size={16} /></button> : null}
              {sidebarView === "hosts" || sidebarView === "scripts" ? (
                <button className="icon-button compact" type="button" title={sidebarView === "hosts" ? "添加主机" : "添加自建脚本"} aria-label={sidebarView === "hosts" ? "添加主机" : "添加自建脚本"} onClick={() => setDialog(sidebarView === "hosts" ? "host" : "custom-script")}><Plus size={17} /></button>
              ) : null}
            </div>
          </div>
          <label className="search-box">
            <Search size={15} />
            <input
              value={searchText}
              onChange={(event) => setSearchText(event.target.value)}
              placeholder={sidebarLabels[sidebarView].placeholder}
            />
            {searchText ? <button type="button" onClick={() => setSearchText("")}><X size={14} /></button> : null}
          </label>

          <div className="sidebar-content">
            {sidebarView === "hosts" ? (
              <>
                {recentConnections.length ? (
                  <section className="resource-group recent-connections">
                    <div className="group-title">
                      <Clock3 size={13} />
                      <span>最近连接</span>
                      <button type="button" title="清空最近连接" onClick={() => setAppState((current) => ({ ...current, connectionHistory: [] }))}>清空</button>
                    </div>
                    {recentConnections.map(({ item, host }) => (
                      <button className={`host-row ${activeHost.id === host.id ? "active" : ""}`} type="button" key={host.id} onClick={() => openHost(host)}>
                        <span className={`environment-dot ${host.environment}`} />
                        <span className="host-copy"><strong>{host.name}</strong><small>{item.path} · {host.username} · {relativeTime(item.connectedAt)}</small></span>
                        <ChevronRight size={13} />
                      </button>
                    ))}
                  </section>
                ) : null}
                {hostGroups.map(([group, hosts]) => (
                  <section className="resource-group" key={group}>
                    <div className="group-title"><ChevronDown size={13} /> <span>{group}</span><small>{hosts.length}</small></div>
                    {hosts.map((host) => {
                      const session = sessions.find((item) => item.hostId === host.id && item.state !== "closed");
                      return (
                        <div className="host-list-item" key={host.id}>
                          <button className={`host-row ${activeHost.id === host.id ? "active" : ""}`} type="button" onClick={() => openHost(host)}>
                            <span className={`environment-dot ${host.environment}`} />
                            <span className="host-copy"><strong>{host.name}</strong><small>{host.username}@{host.host}:{host.port}</small></span>
                            {session?.state === "connected" ? <Wifi size={14} className="connected-icon" /> : <span className="latency">{host.latency ? `${host.latency}ms` : "-"}</span>}
                          </button>
                          <button
                            className="host-delete-button"
                            type="button"
                            title={`删除 ${host.name}`}
                            aria-label={`删除 ${host.name}`}
                            onClick={() => void deleteHost(host)}
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      );
                    })}
                  </section>
                ))}
                {hostGroups.length === 0 ? (
                  <div className="host-list-empty">
                    <Server size={22} />
                    <strong>暂无主机配置</strong>
                    <span>添加一台主机，或从 FinalShell 导入现有配置。</span>
                    <div>
                      <button type="button" onClick={() => setDialog("host")}><Plus size={14} /> 添加主机</button>
                      <button type="button" onClick={() => setDialog("migration")}><Download size={14} /> 导入</button>
                    </div>
                  </div>
                ) : null}
                {deletedHosts.length > 0 ? (
                  <section className="resource-group recycle-bin">
                    <div className="group-title"><Trash2 size={13} /> <span>回收站</span><small>{deletedHosts.length}</small></div>
                    {deletedHosts.map((item) => {
                      const days = Math.max(1, Math.ceil((Date.parse(item.expiresAt) - Date.now()) / 86_400_000));
                      return (
                        <div className="recycle-row" key={item.id}>
                          <span><strong>{item.host.name}</strong><small>{item.host.username}@{item.host.host} · {days} 天后清理</small></span>
                          <button type="button" title={`恢复 ${item.host.name}`} aria-label={`恢复 ${item.host.name}`} onClick={() => restoreDeletedHost(item.id)}><RotateCcw size={13} /></button>
                          <button type="button" title={`永久删除 ${item.host.name}`} aria-label={`永久删除 ${item.host.name}`} onClick={() => void permanentlyDeleteHost(item.id)}><Trash2 size={13} /></button>
                        </div>
                      );
                    })}
                  </section>
                ) : null}
              </>
            ) : null}

            {sidebarView === "scripts" ? (
              <div className="script-list">
                {visibleScripts.map((script) => (
                  <button className="script-row" type="button" key={script.id} onClick={() => chooseScript(script)}>
                    <span className={`risk-marker ${script.risk}`}><Braces size={15} /></span>
                    <span><strong>{script.title}</strong><small>{script.category}</small></span>
                    {script.custom ? <span className="custom-badge">自建</span> : null}
                  </button>
                ))}
              </div>
            ) : null}

            {sidebarView === "commands" ? (
              <div className="command-library-list">
                {visibleCommands.map((command) => (
                  <button className="command-library-row" type="button" key={command.id} onClick={() => chooseCommand(command)}>
                    <span className={`risk-marker ${command.risk}`}><Command size={15} /></span>
                    <span><strong>{command.title}</strong><small>{command.category} · {command.action ? "工具" : "命令"}</small></span>
                  </button>
                ))}
              </div>
            ) : null}

            {sidebarView === "history" ? (
              <div className="history-list">
                {appState.commandHistory.length > 0 ? (
                  <div className="group-title">
                    <History size={13} />
                    <span>命令历史</span>
                    <button
                      type="button"
                      title="清空命令历史"
                      aria-label="清空命令历史"
                      onClick={() => {
                        if (window.confirm("清空全部命令历史吗？此变更会同步到其他设备。")) {
                          setAppState((current) => ({ ...current, commandHistory: [] }));
                        }
                      }}
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                ) : null}
                {appState.commandHistory.filter((item) => !searchText || item.command.toLocaleLowerCase().includes(searchText.toLocaleLowerCase())).map((item) => (
                  <button className="history-row" type="button" key={item.id} onClick={() => setCommandInput(item.command)}>
                    <Command size={14} />
                    <span><code>{item.command}</code><small>{appState.hosts.find((host) => host.id === item.hostId)?.name} · {relativeTime(item.createdAt)}</small></span>
                  </button>
                ))}
              </div>
            ) : null}
          </div>
          {sidebarView === "hosts" && hasActiveHost ? (
            <HostOverview
              host={activeHost}
              state={activeSession.state}
              metrics={hostMetrics[activeSession.id]?.metrics ? {
                cpuPercent: hostMetrics[activeSession.id].metrics?.cpuPercent,
                memoryPercent: hostMetrics[activeSession.id].metrics?.memoryPercent,
                diskPercent: hostMetrics[activeSession.id].metrics?.diskPercent,
                network: {
                  receiveBytesPerSecond: hostMetrics[activeSession.id].metrics?.rxBytesPerSecond,
                  transmitBytesPerSecond: hostMetrics[activeSession.id].metrics?.txBytesPerSecond,
                },
                load: [
                  hostMetrics[activeSession.id].metrics!.loadOne,
                  hostMetrics[activeSession.id].metrics!.loadFive,
                  hostMetrics[activeSession.id].metrics!.loadFifteen,
                ],
                uptimeSeconds: hostMetrics[activeSession.id].metrics?.uptimeSeconds,
                topProcesses: hostMetrics[activeSession.id].metrics?.topProcesses,
                sampledAt: hostMetrics[activeSession.id].sampledAt,
              } : undefined}
              currentIdentity={activeSession.state === "connected" ? {
                address: activeShellContext ? undefined : hostMetrics[activeSession.id]?.metrics?.primaryIp ?? activeHost.host,
                hostname: activeShellContext?.hostname ?? hostMetrics[activeSession.id]?.metrics?.hostname,
                username: activeShellContext?.username ?? activeHost.username,
                source: activeShellContext ? "shell-integration" : "transport",
              } : undefined}
              loading={hostMetrics[activeSession.id]?.loading}
              error={hostMetrics[activeSession.id]?.error}
              history={hostMetrics[activeSession.id]?.history}
              paused={hostMetrics[activeSession.id]?.paused}
              intervalSeconds={hostMetrics[activeSession.id]?.intervalSeconds}
              droppedSamples={hostMetrics[activeSession.id]?.droppedSamples}
              onPausedChange={(paused) => void setMonitorPaused(activeSession.id, paused)}
              onIntervalChange={(seconds) => void setMonitorInterval(activeSession.id, seconds)}
              onCopied={showToast}
            />
          ) : null}
        </aside>
      ) : null}

      <main className="workspace">
        <div className="session-tabs">
          <div className="tab-strip">
            {sessions.map((session) => {
              const host = appState.hosts.find((item) => item.id === session.hostId);
              return (
                <button className={`session-tab ${session.id === activeSession.id ? "active" : ""}`} type="button" key={session.id} onClick={() => setActiveSessionId(session.id)}>
                  <span className={`session-state ${session.state}`} />
                  <span>{host?.name ?? session.title}</span>
                  {sessions.length > 1 ? <span className="tab-close" onClick={(event) => { event.stopPropagation(); closeSession(session.id); }}><X size={13} /></span> : null}
                </button>
              );
            })}
            <button className="new-tab-button" type="button" title="新建终端" aria-label="新建终端" onClick={() => setDialog("host")}><Plus size={16} /></button>
          </div>
          <div className="terminal-actions">
            <button className="icon-button" type="button" title="分屏" aria-label="分屏"><Columns2 size={16} /></button>
            <button className={`icon-button ${broadcastOpen ? "active warning" : ""}`} type="button" disabled={isAndroidRuntime()} title={isAndroidRuntime() ? "Android Preview 不支持广播" : "多终端广播"} aria-label={isAndroidRuntime() ? "Android Preview 不支持广播" : "多终端广播"} onClick={() => broadcastOpen ? closeBroadcast() : setBroadcastOpen(true)}><RadioTower size={16} /></button>
            <button className={`icon-button ${filePanelOpen ? "active" : ""}`} type="button" title={filePanelOpen ? "关闭文件面板" : "打开文件面板"} aria-label="文件面板" onClick={() => setFilePanelOpen((value) => !value)}>
              {filePanelOpen ? <PanelRightClose size={16} /> : <PanelRightOpen size={16} />}
            </button>
            <button className="icon-button" type="button" title="更多" aria-label="更多"><MoreHorizontal size={17} /></button>
          </div>
        </div>

        <section className={`host-context ${activeHost.environment}`}>
          <div className="identity-breadcrumb">
            <Route size={17} />
            <span className="route-node local">本机</span>
            {hasActiveHost ? (
              <>
                {activeJumpHosts.map((jumpHost) => (
                  <span className="identity-breadcrumb-segment" key={jumpHost.id}>
                    <ChevronRight size={14} />
                    <strong className="route-node jump">{jumpHost.name}</strong>
                    <code>{jumpHost.username}@{jumpHost.host}</code>
                  </span>
                ))}
                <ChevronRight size={14} />
                <strong className={`route-node current ${activeHost.environment}`}>{activeHost.name}</strong>
                <code>{activeHost.username}@{activeHost.host}</code>
                {(activeSession.contextStack ?? []).map((context, index) => (
                  <span className="identity-breadcrumb-segment" key={`${context.username}@${context.hostname}-${index}`}>
                    <ChevronRight size={14} />
                    <strong className="route-node current">{context.hostname}</strong>
                    <code>{context.username}:{context.cwd}</code>
                  </span>
                ))}
              </>
            ) : <span className="empty-host-hint">请选择、添加或导入主机</span>}
          </div>
          <div className="context-meta">
            {hasActiveHost ? <span className={`environment-badge ${activeHost.environment}`}>{environmentLabels[activeHost.environment]}</span> : null}
            {hasActiveHost ? <span className="context-source"><Check size={13} /> 配置视图</span> : null}
            {activeSession.state === "connected" ? (
              <button className="secondary-button compact" type="button" onClick={() => void enableShellIntegration()}>
                <Braces size={13} /> 识别当前 Shell
              </button>
            ) : null}
            {hasActiveHost && isDesktopRuntime() && activeSession.state !== "connected" ? (
              <div className="engine-selector" role="group" aria-label="SSH 引擎">
                <button
                  className={activeSession.engine === "openssh" ? "active" : ""}
                  type="button"
                  title={activeJumpHosts.length ? "当前跳板路线使用原生引擎" : "系统 OpenSSH 兼容引擎"}
                  disabled={activeSession.state === "connecting" || activeJumpHosts.length > 0}
                  onClick={() => updateSession(activeSession.id, { engine: "openssh" })}
                >
                  <SquareTerminal size={12} /> OpenSSH
                </button>
                <button
                  className={activeSession.engine === "russh" ? "active" : ""}
                  type="button"
                  title="原生 russh 引擎"
                  disabled={activeSession.state === "connecting"}
                  onClick={() => updateSession(activeSession.id, { engine: "russh" })}
                >
                  <ShieldCheck size={12} /> 原生
                </button>
                <button
                  className={activeSession.engine === "mosh" ? "active" : ""}
                  type="button"
                  title={activeJumpHosts.length ? "Mosh 不支持跳板路线" : "需要本机 mosh、远端 mosh-server 和 UDP 60000–61000"}
                  disabled={activeSession.state === "connecting" || activeJumpHosts.length > 0}
                  onClick={() => updateSession(activeSession.id, { engine: "mosh" })}
                >
                  <RadioTower size={12} /> Mosh
                </button>
              </div>
            ) : null}
            {hasActiveHost ? <span>{activeHost.latency ? `${activeHost.latency} ms` : "未测速"}</span> : null}
            {activeSession.state === "connected" ? (
              <button className="disconnect-button" type="button" onClick={disconnectActiveSession}><WifiOff size={14} /> 断开</button>
            ) : (
              <button
                className="connect-button"
                type="button"
                disabled={activeSession.state === "connecting" && !nativeTerminalStartingIds.includes(activeSession.id)}
                onClick={() => activeSession.state === "connecting" && nativeTerminalStartingIds.includes(activeSession.id)
                  ? void cancelNativeTerminalStart()
                  : void connectActiveSession()}
              >
                {activeSession.state === "connecting"
                  ? nativeTerminalStartingIds.includes(activeSession.id) ? <X size={14} /> : <RefreshCw className="spin" size={14} />
                  : <Play size={14} />}
                {activeSession.state === "connecting" ? nativeTerminalStartingIds.includes(activeSession.id) ? "取消连接" : "连接中" : "连接"}
              </button>
            )}
          </div>
        </section>

        {broadcastOpen ? (
          <section className="broadcast-banner">
            <div><RadioTower size={17} /><strong>安全广播</strong><span>已选 {broadcastTargets.length} 台，发送前冻结目标并预览</span></div>
            <div className="broadcast-targets">
              {sessions.map((session) => (
                <label className={session.state !== "connected" ? "unavailable" : ""} key={session.id}>
                  <input
                    type="checkbox"
                    checked={broadcastTargets.includes(session.id)}
                    disabled={session.state !== "connected"}
                    onChange={(event) => {
                      setBroadcastPreview(null);
                      setBroadcastResult(null);
                      setBroadcastTargets((current) => event.target.checked ? [...current, session.id] : current.filter((id) => id !== session.id));
                    }}
                  />
                  <span className={`session-state ${session.state}`} />
                  <span>{session.title}</span>
                </label>
              ))}
            </div>
            <div className="broadcast-controls">
              <button type="button" onClick={() => { setBroadcastPreview(null); setBroadcastResult(null); setBroadcastTargets(sessions.filter((session) => session.state === "connected").map((session) => session.id)); }}>全选已连接</button>
              <button type="button" disabled={broadcastTargets.length === 0} onClick={() => { setBroadcastPreview(null); setBroadcastResult(null); setBroadcastTargets([]); }}>清空</button>
            </div>
            <button className="icon-button" type="button" title="关闭广播并清空目标" aria-label="关闭广播并清空目标" onClick={closeBroadcast}><X size={16} /></button>
          </section>
        ) : null}

        {broadcastPreview ? (
          <section className={`broadcast-preview ${broadcastPreview.productionTargets > 0 || broadcastPreview.risk === "high" ? "warning" : ""}`} aria-label="广播发送预览">
            <div className="broadcast-preview-heading">
              <ShieldCheck size={16} aria-hidden="true" />
              <strong>确认广播目标</strong>
              <span>{broadcastPreview.warning}</span>
            </div>
            <code>{broadcastPreview.command}</code>
            <div className="broadcast-preview-targets">
              {broadcastPreview.targets.map((target) => (
                <span className={target.environment} key={target.sessionId}>{target.label} · {environmentLabels[target.environment]}</span>
              ))}
            </div>
            <div className="broadcast-preview-actions">
              <button className="secondary-button" type="button" disabled={broadcastExecuting} onClick={() => setBroadcastPreview(null)}>取消</button>
              <button className="primary-button" type="button" disabled={broadcastExecuting} onClick={() => void confirmBroadcast()}>
                {broadcastExecuting ? <RefreshCw className="spin" size={14} /> : <RadioTower size={14} />} 确认发送一次
              </button>
            </div>
          </section>
        ) : null}

        {broadcastResult ? (
          <section className={`broadcast-result ${broadcastResult.outcome}`} aria-label="广播逐目标结果" aria-live="polite">
            <strong>成功 {broadcastResult.succeeded} · 失败 {broadcastResult.failed} · 跳过 {broadcastResult.skipped}</strong>
            {broadcastResult.items.map((item) => (
              <span className={item.outcome} key={item.sessionId}><b>{item.label}</b>{item.message}</span>
            ))}
            <button className="icon-button compact" type="button" title="关闭广播结果" aria-label="关闭广播结果" onClick={() => setBroadcastResult(null)}><X size={13} /></button>
          </section>
        ) : null}

        <div className="content-split">
          <section className="terminal-pane">
            <div className="terminal-stack">
              {sessions.map((session) => {
                const host = appState.hosts.find((candidate) => candidate.id === session.hostId) ?? emptyHost;
                return (
                  <div
                    className={`terminal-session-view ${session.id === activeSession.id ? "active" : ""}`}
                    aria-hidden={session.id !== activeSession.id}
                    key={session.id}
                  >
                    <TerminalView
                      session={session}
                      host={host}
                      wallpaper={{ ...appState.wallpaper, value: renderedWallpaper }}
                      appearance={appState.terminalAppearance}
                      appearanceRevision={fontRevision}
                      androidTerminalId={androidTerminalIds[session.id]}
                      onDisconnected={handleDisconnected}
                      onContextChanged={handleContextChanged}
                    />
                  </div>
                );
              })}
            </div>
            <div className="path-history-bar">
              <Clock3 size={14} />
              <span>路径</span>
              <div className="path-chips">
                {currentPathHistory.slice(0, 30).map((item) => (
                  <button type="button" key={item.id} onClick={() => setCommandInput(`cd ${item.path}`)}>{item.path}</button>
                ))}
              </div>
              {currentPathHistory.length > 0 ? (
                <button
                  className="icon-button compact"
                  type="button"
                  title="清空此主机的路径历史"
                  aria-label="清空此主机的路径历史"
                  onClick={() => {
                    if (!window.confirm(`清空“${activeHost.name}”的路径历史吗？`)) return;
                    setAppState((current) => ({
                      ...current,
                      pathHistory: { ...current.pathHistory, [activeHost.id]: [] },
                    }));
                  }}
                >
                  <Trash2 size={12} />
                </button>
              ) : null}
            </div>
            <div className="composer-shell">
              {intentSuggestions.length > 0 ? (
                <div className="intent-suggestions" role="listbox" aria-label="本地命令与脚本建议">
                  <div className="intent-heading"><Search size={13} /><span>本地匹配</span><small>点击后先预览</small></div>
                  {intentSuggestions.map((suggestion) => (
                    <button type="button" role="option" key={`${suggestion.kind}-${suggestion.item.id}`} onClick={() => chooseIntent(suggestion)}>
                      <span className={`intent-icon ${suggestion.kind}`}>{suggestion.kind === "command" ? <Command size={14} /> : <Braces size={14} />}</span>
                      <span><strong>{suggestion.item.title}</strong><small>{suggestion.item.category} · {suggestion.kind === "command" ? "命令/工具" : "脚本"}</small></span>
                      <ChevronRight size={14} />
                    </button>
                  ))}
                </div>
              ) : null}
              <form className={`command-composer ${broadcastOpen ? "broadcasting" : ""}`} onSubmit={(event) => { event.preventDefault(); void submitCommand(); }}>
                <Command size={16} />
                <input value={commandInput} onChange={(event) => { setCommandInput(event.target.value); setBroadcastPreview(null); setBroadcastResult(null); }} placeholder={broadcastOpen ? `发送到 ${broadcastTargets.length} 个终端` : "输入命令，或搜索想做的事"} />
                <button className="composer-history" type="button" title="命令历史" onClick={() => setSidebarView("history")}><History size={15} /></button>
                <button className="run-command-button" type="submit" title="执行命令"><Play size={14} /><span>执行</span></button>
              </form>
            </div>
          </section>

          {filePanelOpen ? (
            <FileTransferPanel
              connection={{
                host: activeHost.host,
                port: activeHost.port,
                username: activeHost.username,
                credentialRef: activeHost.credentialRef,
                identityFile: activeHost.identityFile,
                identityPassphraseRef: activeIdentityPassphraseRef,
              }}
              connected={activeSession.state === "connected"}
              androidSessionId={isAndroidRuntime() ? activeSession.id : undefined}
              nativeSessionId={isDesktopRuntime() && activeSession.engine === "russh" ? activeSession.id : undefined}
              initialPath={isAndroidRuntime() && !activeSession.currentPath.startsWith("/") ? "/" : activeSession.currentPath}
              externalEditorPath={appState.settings.externalEditorPath}
              autoUploadEditedFiles={appState.settings.autoUploadEditedFiles}
              packageTransfer={appState.settings.packageTransfersEnabled}
              onPackageTransferChanged={(packageTransfersEnabled) => setAppState((current) => ({
                ...current,
                settings: { ...current.settings, packageTransfersEnabled },
              }))}
              onPathChanged={(path) => {
                updateSession(activeSession.id, { currentPath: path });
                setAppState((current) => ({
                  ...current,
                  pathHistory: {
                    ...current.pathHistory,
                    [activeHost.id]: [
                      { id: crypto.randomUUID(), path, createdAt: new Date().toISOString() },
                      ...(current.pathHistory[activeHost.id] ?? []).filter((item) => item.path !== path),
                    ].slice(0, 100),
                  },
                }));
              }}
              showToast={showToast}
              onClose={() => setFilePanelOpen(false)}
            />
          ) : null}
        </div>

        <footer className="statusbar">
          <span><SquareTerminal size={13} /> {isAndroidRuntime() ? "Rust libssh2 移动引擎" : activeSession.engine === "russh" ? "Rust russh 原生引擎" : activeSession.engine === "mosh" ? "Mosh UDP 交互模式" : "OpenSSH 兼容引擎"}</span>
          <span><Database size={13} /> SQLite {appStoreStatus.saving ? "保存中" : appStoreStatus.ready ? "已同步" : "初始化失败"}</span>
          <span className="status-spacer" />
          <span>UTF-8</span><span>xterm-256color</span><span>{activeSession.currentPath}</span>
        </footer>
      </main>

      {dialog === "migration" ? (
        <MigrationDialog onClose={() => setDialog(null)} onImported={handleMigrationImport} showToast={showToast} />
      ) : null}

        {dialog === "host-key" && pendingHostKey ? (
          <Dialog
            title="确认 SSH 主机指纹"
            onClose={() => { if (!trustingHostKey) { setPendingHostKey(null); setDialog(null); } }}
            footer={(
              <>
                <button className="secondary-button" type="button" disabled={trustingHostKey} onClick={() => { setPendingHostKey(null); setDialog(null); }}>取消</button>
              <button className="primary-button" type="button" disabled={trustingHostKey} onClick={() => void trustPendingHostKey()}>
                {trustingHostKey ? <RefreshCw className="spin" size={14} /> : <ShieldCheck size={14} />}
                {trustingHostKey ? "正在复核" : "信任并连接"}
              </button>
            </>
          )}
        >
          <div className="host-key-callout">
            <AlertTriangle size={19} />
            <div><strong>这是此主机的首次连接</strong><span>请通过服务器控制台或服务商面板核对指纹。VPShell 不会自动接受未知或已变化的主机密钥。</span></div>
          </div>
          <dl className="host-key-details">
            <div><dt>目标</dt><dd>{pendingHostKey.host}:{pendingHostKey.port}</dd></div>
            <div><dt>算法</dt><dd>{pendingHostKey.algorithm}</dd></div>
            <div className="fingerprint-row"><dt>SHA256 指纹</dt><dd><code>{pendingHostKey.fingerprint}</code><button className="icon-button compact" type="button" title="复制指纹" aria-label="复制指纹" onClick={() => { void navigator.clipboard.writeText(pendingHostKey.fingerprint); showToast("指纹已复制"); }}><Copy size={14} /></button></dd></div>
          </dl>
        </Dialog>
      ) : null}

      {dialog === "guide" ? <OnboardingDialog onClose={closeGuide} /> : null}

      {dialog === "key-manager" ? (
        <KeyManagerDialog
          keys={appState.sshKeys}
          activeHostLabel={`${activeHost.name} (${activeHost.username}@${activeHost.host})`}
          activeSessionId={activeSession.id}
          connected={activeSession.state === "connected"}
          onGenerated={(key) => setAppState((current) => ({ ...current, sshKeys: [key, ...current.sshKeys] }))}
          onClose={() => setDialog(null)}
          showToast={showToast}
        />
      ) : null}

      {dialog === "network" ? (
        <NetworkToolsDialog
          initialMode={networkMode}
          defaultHost={activeHost.host}
          onClose={() => setDialog(null)}
          showToast={showToast}
          buildRouteMeasurementOptions={() => buildRouteMeasurementOptions(activeHost, appState.hosts, appState.sshKeys)}
        />
      ) : null}

      {dialog === "local-forward" ? (
        <Dialog
          title="端口转发"
          wide
          onClose={() => setDialog(null)}
          footer={(
            <>
              <button className="secondary-button" type="button" disabled={nativeLocalForwardBusy} onClick={() => void refreshNativeForwards()}><RefreshCw size={14} /> 刷新</button>
              <button className="primary-button" type="button" onClick={() => setDialog(null)}>关闭</button>
            </>
          )}
        >
          <div className="engine-selector forward-mode-switch" role="group" aria-label="转发模式">
            <button type="button" className={nativeForwardMode === "local" ? "active" : ""} aria-pressed={nativeForwardMode === "local"} onClick={() => { setNativeForwardMode("local"); setNativeLocalForwardError(null); }}><Cable size={14} /> 本地</button>
            <button type="button" className={nativeForwardMode === "remote" ? "active" : ""} aria-pressed={nativeForwardMode === "remote"} onClick={() => { setNativeForwardMode("remote"); setNativeLocalForwardError(null); }}><RadioTower size={14} /> 远端</button>
            <button type="button" className={nativeForwardMode === "dynamic" ? "active" : ""} aria-pressed={nativeForwardMode === "dynamic"} onClick={() => { setNativeForwardMode("dynamic"); setNativeLocalForwardError(null); }}><Network size={14} /> SOCKS</button>
          </div>
          {nativeForwardMode === "local" ? (
            <>
              <form
                id="local-forward-form"
                className="form-grid local-forward-form"
                onSubmit={(event) => { event.preventDefault(); void startNativeLocalForward(event.currentTarget); }}
              >
                <label className="field span-2"><span>本地端口</span><input name="bindPort" type="number" defaultValue="0" min="0" max="65535" required /></label>
                <label className="field span-2"><span>监听地址</span><input value="127.0.0.1" readOnly /></label>
                <label className="field span-2"><span>目标地址</span><input name="targetHost" defaultValue="127.0.0.1" maxLength={253} required /></label>
                <label className="field"><span>目标端口</span><input name="targetPort" type="number" defaultValue="80" min="1" max="65535" required /></label>
                <button className="primary-button local-forward-start" type="submit" disabled={nativeLocalForwardBusy}><Play size={14} /> 启动</button>
              </form>
              <div className="local-forward-heading"><strong>运行中的本地转发</strong><span>{nativeLocalForwards.length} / 8</span></div>
              {nativeLocalForwards.length ? (
                <div className="local-forward-list" aria-live="polite">
                  {nativeLocalForwards.map((forward) => (
                    <div className="local-forward-row" key={forward.forwardId}>
                      <span className={`session-state ${forward.state === "active" ? "connected" : "connecting"}`} />
                      <div>
                        <strong><code>{forward.bindHost}:{forward.bindPort}</code> <ChevronRight size={13} /> <code>{forward.targetHost}:{forward.targetPort}</code></strong>
                        <small>经 {forward.routeHost}（{forward.routeHops} 跳） · 当前 {forward.activeConnections} · 已接收 {forward.acceptedConnections} · 已拒绝 {forward.rejectedConnections}</small>
                      </div>
                      <button className="icon-button compact danger" type="button" title="停止本地转发" aria-label="停止本地转发" disabled={nativeLocalForwardBusy} onClick={() => void stopNativeLocalForward(forward.forwardId)}><Square size={13} /></button>
                    </div>
                  ))}
                </div>
              ) : <div className="local-forward-empty"><Cable size={18} /><span>没有运行中的本地转发</span></div>}
            </>
          ) : nativeForwardMode === "remote" ? (
            <>
              <form
                id="remote-forward-form"
                className="form-grid local-forward-form"
                onSubmit={(event) => { event.preventDefault(); void startNativeRemoteForward(event.currentTarget); }}
              >
                <label className="field span-2"><span>远端端口</span><input name="bindPort" type="number" defaultValue="0" min="0" max="65535" required /></label>
                <label className="field span-2"><span>远端监听</span><input value="127.0.0.1" readOnly /></label>
                <label className="field span-2"><span>本机目标</span><input value="127.0.0.1" readOnly /></label>
                <label className="field"><span>本机端口</span><input name="targetPort" type="number" defaultValue="3000" min="1" max="65535" required /></label>
                <button className="primary-button local-forward-start" type="submit" disabled={nativeLocalForwardBusy}><Play size={14} /> 启动</button>
              </form>
              <div className="local-forward-heading"><strong>运行中的远端转发</strong><span>{nativeRemoteForwards.length} / 8</span></div>
              {nativeRemoteForwards.length ? (
                <div className="local-forward-list" aria-live="polite">
                  {nativeRemoteForwards.map((forward) => (
                    <div className="local-forward-row" key={forward.forwardId}>
                      <span className={`session-state ${forward.state === "active" ? "connected" : "connecting"}`} />
                      <div>
                        <strong><code>{forward.bindHost}:{forward.bindPort}</code> <ChevronRight size={13} /> <code>{forward.targetHost}:{forward.targetPort}</code></strong>
                        <small>位于 {forward.routeHost}（{forward.routeHops} 跳） · 当前 {forward.activeConnections} · 已接收 {forward.acceptedConnections} · 已拒绝 {forward.rejectedConnections} · 目标失败 {forward.failedConnections}</small>
                      </div>
                      <button className="icon-button compact danger" type="button" title="停止远端转发" aria-label="停止远端转发" disabled={nativeLocalForwardBusy} onClick={() => void stopNativeRemoteForward(forward.forwardId)}><Square size={13} /></button>
                    </div>
                  ))}
                </div>
              ) : <div className="local-forward-empty"><RadioTower size={18} /><span>没有运行中的远端转发</span></div>}
            </>
          ) : (
            <>
              <form
                id="dynamic-forward-form"
                className="form-grid local-forward-form"
                onSubmit={(event) => { event.preventDefault(); void startNativeDynamicForward(event.currentTarget); }}
              >
                <label className="field span-2"><span>SOCKS 端口</span><input name="bindPort" type="number" defaultValue="0" min="0" max="65535" required /></label>
                <label className="field span-2"><span>监听地址</span><input value="127.0.0.1" readOnly /></label>
                <label className="field span-2"><span>协议</span><input value="SOCKS5 CONNECT" readOnly /></label>
                <button className="primary-button local-forward-start" type="submit" disabled={nativeLocalForwardBusy}><Play size={14} /> 启动</button>
              </form>
              <div className="local-forward-heading"><strong>运行中的 SOCKS5 转发</strong><span>{nativeDynamicForwards.length} / 8</span></div>
              {nativeDynamicForwards.length ? (
                <div className="local-forward-list" aria-live="polite">
                  {nativeDynamicForwards.map((forward) => (
                    <div className="local-forward-row" key={forward.forwardId}>
                      <span className={`session-state ${forward.state === "active" ? "connected" : "connecting"}`} />
                      <div>
                        <strong><code>{forward.bindHost}:{forward.bindPort}</code> <ChevronRight size={13} /> 按请求连接</strong>
                        <small>经 {forward.routeHost}（{forward.routeHops} 跳） · 当前 {forward.activeConnections} · 已接收 {forward.acceptedConnections} · 已拒绝 {forward.rejectedConnections}</small>
                      </div>
                      <button className="icon-button compact danger" type="button" title="停止 SOCKS5 转发" aria-label="停止 SOCKS5 转发" disabled={nativeLocalForwardBusy} onClick={() => void stopNativeDynamicForward(forward.forwardId)}><Square size={13} /></button>
                    </div>
                  ))}
                </div>
              ) : <div className="local-forward-empty"><Network size={18} /><span>没有运行中的 SOCKS5 转发</span></div>}
            </>
          )}
          {nativeLocalForwardError ? <p className="local-forward-error" role="alert"><AlertTriangle size={14} /> {nativeLocalForwardError}</p> : null}
        </Dialog>
      ) : null}

      {dialog === "settings" ? (
        <SettingsDialog
          externalEditorPath={appState.settings.externalEditorPath}
          autoUploadEditedFiles={appState.settings.autoUploadEditedFiles}
          monitorIntervalSeconds={appState.settings.monitorIntervalSeconds}
          onSave={(settings) => setAppState((current) => ({
            ...current,
            settings: { ...current.settings, ...settings },
          }))}
          onClose={() => setDialog(null)}
          showToast={showToast}
          androidSecurity={isAndroidRuntime() ? androidSecurityStatus : undefined}
          onAndroidBiometricChange={isAndroidRuntime() ? async (enabled) => {
            try {
              const status = await requestAndroidSecurity("setEnabled", enabled);
              setAndroidSecurityStatus(status);
              postAndroidVisibility(status.locked ? "failed" : "show");
              return status;
            } catch (error) {
              const status = await requestAndroidSecurity("status").catch(() => null);
              if (status) setAndroidSecurityStatus(status);
              postAndroidVisibility(status?.locked === false ? "show" : "failed");
              throw error;
            }
          } : undefined}
        />
      ) : null}

      {dialog === "host" ? (
        <Dialog title="添加 SSH 主机" onClose={() => setDialog(null)} footer={<><button className="secondary-button" type="button" onClick={() => setDialog(null)}>取消</button><button className="primary-button" type="submit" form="host-form">保存并打开</button></>}>
          <form id="host-form" className="form-grid" onSubmit={(event) => { event.preventDefault(); void addHost(event.currentTarget); }}>
            <label className="field full"><span>名称</span><input name="name" placeholder="例如：新加坡生产 03" required /></label>
            <label className="field span-2"><span>主机地址</span><input name="host" placeholder="IP 或域名" required /></label>
            <label className="field"><span>端口</span><input name="port" type="number" defaultValue="22" min="1" max="65535" required /></label>
            <label className="field"><span>用户名</span><input name="username" defaultValue="root" required /></label>
            <label className="field"><span>环境</span><select name="environment" defaultValue="development"><option value="production">生产</option><option value="staging">基础设施</option><option value="development">测试</option></select></label>
            <label className="field"><span>分组</span><input name="group" defaultValue="我的主机" /></label>
            {!isAndroidRuntime() ? <label className="field full"><span>私钥路径</span><input name="identityFile" placeholder="使用系统 OpenSSH 路径（可选）" /></label> : null}
            {!isAndroidRuntime() ? <label className="field full"><span>SHA256 主机指纹</span><input name="hostKeySha256" placeholder="SHA256:..." pattern="SHA256:[A-Za-z0-9+/]{43}" spellCheck={false} /></label> : null}
            {!isAndroidRuntime() && appState.hosts.length ? (
              <label className="field full"><span>跳板机</span><select name="jumpHostId" defaultValue=""><option value="">直连</option>{appState.hosts.map((host) => <option value={host.id} key={host.id}>{host.name} ({host.username}@{host.host})</option>)}</select></label>
            ) : null}
            {isAndroidRuntime() ? (
              <>
                <label className="field full"><span>Android 认证方式</span><select value={androidCredentialKind} onChange={(event) => setAndroidCredentialKind(event.target.value as "password" | "privateKey")}><option value="password">密码</option><option value="privateKey">OpenSSH 私钥</option></select></label>
                {androidCredentialKind === "password" ? <label className="field full"><span>密码（使用 Android Keystore 保存）</span><input name="androidCredential" type="password" autoComplete="new-password" /></label> : <>
                  <label className="field full"><span>OpenSSH 私钥正文（只在 Rust 内存中短暂使用）</span><textarea name="androidCredential" rows={6} spellCheck={false} autoComplete="off" /></label>
                  <label className="field full"><span>私钥口令（可选）</span><input name="androidPassphrase" type="password" autoComplete="new-password" /></label>
                </>}
              </>
            ) : null}
          </form>
        </Dialog>
      ) : null}

      {dialog === "custom-script" ? (
        <Dialog title="添加自建脚本" wide onClose={() => setDialog(null)} footer={<><button className="secondary-button" type="button" onClick={() => setDialog(null)}>取消</button><button className="primary-button" type="submit" form="script-form">保存到资料库</button></>}>
          <form id="script-form" className="form-grid" onSubmit={(event) => { event.preventDefault(); addCustomScript(event.currentTarget); }}>
            <label className="field span-2"><span>名称</span><input name="title" placeholder="脚本名称" required /></label>
            <label className="field"><span>分组</span><input name="category" defaultValue="我的脚本" /></label>
            <label className="field"><span>风险等级</span><select name="risk" defaultValue="medium"><option value="low">低</option><option value="medium">中</option><option value="high">高</option><option value="destructive">破坏性</option></select></label>
            <label className="field full"><span>说明</span><input name="description" placeholder="用途与适用系统" /></label>
            <label className="field full"><span>来源地址</span><input name="sourceUrl" type="url" placeholder="https://" /></label>
            <label className="field full"><span>命令或脚本正文</span><textarea name="command" rows={8} spellCheck={false} required /></label>
          </form>
        </Dialog>
      ) : null}

      {dialog === "script" && selectedScript ? (
        <Dialog title={selectedScript.title} wide onClose={() => setDialog(null)} footer={<><button className="secondary-button" type="button" disabled={!selectedScript.sourceUrl} onClick={() => void openExternal(selectedScript.sourceUrl)}><ExternalLink size={14} /> 查看来源</button><span className="footer-spacer" /><button className="secondary-button" type="button" disabled={!selectedScript.command} onClick={() => { if (selectedScript.command) void navigator.clipboard.writeText(selectedScript.command); showToast("命令已复制"); }}><Copy size={14} /> 复制</button><button className="primary-button" type="button" disabled={!selectedScript.command} onClick={() => { setCommandInput(selectedScript.command ?? ""); setDialog(null); }}><Command size={14} /> 加入命令栏</button></>}>
          <div className={`script-risk-callout ${selectedScript.risk}`}>
            <AlertTriangle size={18} />
            <div><strong>{selectedScript.risk === "destructive" ? "破坏性操作" : selectedScript.risk === "high" ? "高风险脚本" : "远程脚本"}</strong><span>{selectedScript.description}</span></div>
          </div>
          <div className="script-metadata"><span>分类：{selectedScript.category}</span><span>同步范围：资料库项</span><span>来源：{selectedScript.sourceUrl ? "已记录" : "待配置"}</span></div>
          {selectedScript.command ? <pre className="script-code"><code>{selectedScript.command}</code></pre> : <div className="empty-script"><Braces size={22} /><span>此配方需要先核对仓库安装方式或填写参数</span></div>}
        </Dialog>
      ) : null}

      {dialog === "command" && selectedCommand ? (
        <Dialog
          title={selectedCommand.title}
          wide
          onClose={() => setDialog(null)}
          footer={(
            <>
              <button className="secondary-button" type="button" onClick={() => setDialog(null)}>取消</button>
              <button
                className="primary-button"
                type="button"
                disabled={!selectedCommand.command || (selectedCommand.parameters ?? []).some((parameter) => parameter.required && !commandParameters[parameter.name]?.trim())}
                onClick={() => {
                  setCommandInput(materializeCommand(selectedCommand));
                  rememberCommandParameters(selectedCommand);
                  setDialog(null);
                }}
              >
                <Command size={14} /> 加入命令栏
              </button>
            </>
          )}
        >
          <div className={`script-risk-callout ${selectedCommand.risk}`}>
            {selectedCommand.risk === "low" ? <ShieldCheck size={18} /> : <AlertTriangle size={18} />}
            <div><strong>{selectedCommand.category}</strong><span>{selectedCommand.description}</span></div>
          </div>
          <div className="command-usage"><BookOpenText size={15} /><span>{selectedCommand.usage}</span></div>
          {(selectedCommand.parameters ?? []).length > 0 ? (
            <div className="form-grid command-parameters">
              {appState.parameterHistory.some((item) => item.commandId === selectedCommand.id) ? (
                <div className="group-title command-parameter-history-title">
                  <History size={13} />
                  <span>参数历史</span>
                  <button
                    type="button"
                    title="清空此命令的参数历史"
                    aria-label="清空此命令的参数历史"
                    onClick={() => {
                      if (!window.confirm("清空此命令的参数历史？")) return;
                      setAppState((current) => ({
                        ...current,
                        parameterHistory: current.parameterHistory.filter((item) => item.commandId !== selectedCommand.id),
                      }));
                      setCommandParameters(Object.fromEntries((selectedCommand.parameters ?? []).map((parameter) => [parameter.name, parameter.defaultValue ?? ""])));
                    }}
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              ) : null}
              {selectedCommand.parameters?.map((parameter, parameterIndex) => (
                <label className="field span-2" key={parameter.name}>
                  <span>{parameter.label}</span>
                  <input
                    type={isSensitiveCommandParameter(parameter) ? "password" : "text"}
                    autoComplete="off"
                    list={isSensitiveCommandParameter(parameter) ? undefined : `command-parameter-history-${parameterIndex}`}
                    value={commandParameters[parameter.name] ?? ""}
                    placeholder={parameter.placeholder}
                    required={parameter.required}
                    onChange={(event) => setCommandParameters((current) => ({ ...current, [parameter.name]: event.target.value }))}
                  />
                  {!isSensitiveCommandParameter(parameter) ? (
                    <datalist id={`command-parameter-history-${parameterIndex}`}>
                      {[...new Set(appState.parameterHistory
                        .filter((item) => item.commandId === selectedCommand.id && item.parameterName === parameter.name)
                        .map((item) => item.value))]
                        .slice(0, 20)
                        .map((value) => <option key={value} value={value} />)}
                    </datalist>
                  ) : null}
                </label>
              ))}
            </div>
          ) : null}
          {selectedCommand.command ? <pre className="script-code"><code>{materializeCommand(selectedCommand)}</code></pre> : null}
        </Dialog>
      ) : null}

      {dialog === "sync" ? (
        <Dialog title={isAndroidRuntime() ? "同步状态" : "加密同步"} wide onClose={() => setDialog(null)} footer={isAndroidRuntime() ? <><button className="secondary-button" type="button" onClick={() => void refreshAndroidSyncStatus()}><RefreshCw size={14} /> 刷新</button><button className="primary-button" type="button" onClick={() => setDialog(null)}>关闭</button></> : desktopSyncStatus?.configured ? <><button className="secondary-button" type="button" disabled={desktopSyncBusy} onClick={() => void lockDesktopSync()}><KeyRound size={14} /> 锁定</button>{desktopSyncStatus.running ? <button className="danger-button" type="button" onClick={() => void cancelDesktopSync()}><Square size={14} /> 取消同步</button> : <button className="primary-button" type="button" disabled={desktopSyncBusy || appStoreStatus.saving || desktopSyncStatus.recoveryRequired} onClick={() => void runDesktopSyncOnce()}><RefreshCw size={14} /> 立即同步</button>}</> : <><button className="secondary-button" type="button" onClick={() => setDialog(null)}>取消</button><button className="primary-button" type="button" disabled={desktopSyncBusy} onClick={() => void configureDesktopSync()}><ShieldCheck size={14} /> {syncSetupMode === "initialize" ? "初始化并解锁" : "解锁"}</button></>}>
          {isAndroidRuntime() ? (
            <div className="sync-readonly-status" aria-live="polite">
              <div><span>协调阶段</span><strong>{androidSyncError ? "状态读取失败" : androidSyncStatus ? syncPhaseLabels[androidSyncStatus.phase] : "正在读取"}</strong></div>
              <div><span>同步能力</span><strong>Android Preview 中禁用</strong></div>
              <div><span>待发布对象</span><strong>{androidSyncStatus ? `${androidSyncStatus.pendingObjects} 项 / ${androidSyncStatus.pendingBytes.toLocaleString("zh-CN")} B` : "-"}</strong></div>
              <div><span>合并状态</span><strong>{androidSyncStatus ? `revision ${androidSyncStatus.mergeRevision} / ${androidSyncStatus.openConflicts} 个冲突` : "-"}</strong></div>
              <div><span>恢复保护</span><strong>{androidSyncStatus?.recoveryRequired ? "需要人工核对" : "未触发"}</strong></div>
              <div><span>最近周期</span><strong>{androidSyncStatus?.lastCompletedAtMs ? new Date(androidSyncStatus.lastCompletedAtMs).toLocaleString("zh-CN", { hour12: false }) : "尚未运行"}</strong></div>
              {androidSyncStatus?.lastErrorCode ? <p className="sync-status-diagnostic"><AlertTriangle size={14} /> {androidSyncStatus.lastErrorCode}</p> : null}
              {androidSyncStatus?.recoveryNote ? <p className="sync-status-diagnostic"><AlertTriangle size={14} /> {androidSyncStatus.recoveryNote}</p> : null}
              {androidSyncError ? <p className="sync-status-diagnostic"><AlertTriangle size={14} /> {androidSyncError}</p> : null}
            </div>
          ) : <>
          <div className="sync-readonly-status" aria-live="polite">
            <div><span>协调阶段</span><strong>{desktopSyncError ? "状态读取失败" : desktopSyncStatus ? syncPhaseLabels[desktopSyncStatus.phase] : "正在读取"}</strong></div>
            <div><span>运行状态</span><strong>{desktopSyncStatus?.running ? "单周期执行中" : desktopSyncStatus?.configured ? "vault 已解锁" : "vault 已锁定"}</strong></div>
            <div><span>待发布对象</span><strong>{desktopSyncStatus ? `${desktopSyncStatus.pendingObjects} 项 / ${desktopSyncStatus.pendingBytes.toLocaleString("zh-CN")} B` : "-"}</strong></div>
            <div><span>合并状态</span><strong>{desktopSyncStatus ? `revision ${desktopSyncStatus.mergeRevision} / ${desktopSyncStatus.openConflicts} 个冲突` : "-"}</strong></div>
            <div><span>最近周期</span><strong>{desktopSyncStatus?.lastCompletedAtMs ? new Date(desktopSyncStatus.lastCompletedAtMs).toLocaleString("zh-CN", { hour12: false }) : "尚未运行"}</strong></div>
            <div><span>本周期对象</span><strong>{desktopSyncStatus ? `上传 ${desktopSyncStatus.lastUploadedObjects} / 下载 ${desktopSyncStatus.lastDownloadedObjects}` : "-"}</strong></div>
            {desktopSyncStatus?.lastErrorCode ? <p className="sync-status-diagnostic"><AlertTriangle size={14} /> {desktopSyncStatus.lastErrorCode}</p> : null}
            {desktopSyncStatus?.recoveryNote ? <p className="sync-status-diagnostic"><AlertTriangle size={14} /> {desktopSyncStatus.recoveryNote}</p> : null}
            {desktopSyncError ? <p className="sync-status-diagnostic"><AlertTriangle size={14} /> {desktopSyncError}</p> : null}
          </div>
          {desktopSyncStatus?.configured && desktopSyncStatus.openConflicts > 0 ? (
            <section className="sync-conflict-center" aria-live="polite">
              <div className="sync-conflict-header">
                <div><AlertTriangle size={16} /><strong>冲突中心</strong><span>{syncConflictCenter?.total ?? desktopSyncStatus.openConflicts} 项</span></div>
                <div className="sync-conflict-pagination">
                  <button type="button" title="上一页" disabled={syncConflictOffset === 0 || Boolean(resolvingConflictId)} onClick={() => setSyncConflictOffset(Math.max(0, syncConflictOffset - SYNC_CONFLICT_PAGE_SIZE))}><ChevronLeft size={16} /></button>
                  <span>{syncConflictCenter?.total ? `${syncConflictOffset + 1}-${Math.min(syncConflictOffset + syncConflictCenter.conflicts.length, syncConflictCenter.total)}` : "-"}</span>
                  <button type="button" title="下一页" disabled={!syncConflictCenter || syncConflictOffset + syncConflictCenter.conflicts.length >= syncConflictCenter.total || Boolean(resolvingConflictId)} onClick={() => setSyncConflictOffset(syncConflictOffset + SYNC_CONFLICT_PAGE_SIZE)}><ChevronRight size={16} /></button>
                </div>
              </div>
              {syncConflictError ? <p className="sync-status-diagnostic"><AlertTriangle size={14} /> {syncConflictError}</p> : null}
              <div className="sync-conflict-list">
                {syncConflictCenter?.conflicts.map((conflict) => (
                  <article className="sync-conflict-item" key={conflict.conflictId}>
                    <div className="sync-conflict-identity">
                      <strong>{syncConflictKindLabels[conflict.entityKind]} · {conflict.field}</strong>
                      <span>{syncConflictReasonLabels[conflict.reason]} · {conflict.entityId.slice(0, 8)}</span>
                    </div>
                    <div className="sync-conflict-alternatives">
                      {conflict.alternatives.map((alternative) => (
                        <button
                          type="button"
                          key={alternative.index}
                          disabled={Boolean(resolvingConflictId) || desktopSyncStatus?.running || desktopSyncStatus?.recoveryRequired || appStoreStatus.saving}
                          onClick={() => void resolveSyncConflict(conflict.conflictId, alternative.index)}
                        >
                          <Check size={15} />
                          <span>{syncConflictAlternativeLabel(alternative)}{alternative.truncated ? "…" : ""}</span>
                          <small>{alternative.contentHash ? `${alternative.byteLength} B · ${alternative.contentHash.slice(0, 12)}` : "删除"}</small>
                        </button>
                      ))}
                    </div>
                  </article>
                ))}
              </div>
            </section>
          ) : null}
          {!desktopSyncStatus?.configured ? <>
          <div className="provider-grid">
            {(Object.keys(providerLabels) as SyncProviderKind[]).map((provider) => (
              <button className={appState.sync.provider === provider ? "active" : ""} type="button" key={provider} disabled={provider !== "local" && provider !== "webdav"} onClick={() => setAppState((current) => ({ ...current, sync: { ...current.sync, provider } }))}>
                {provider === "local" ? <HardDrive size={18} /> : provider === "webdav" ? <Globe2 size={18} /> : provider === "sftp" ? <SquareTerminal size={18} /> : provider === "s3" ? <Database size={18} /> : <Cloud size={18} />}
                <span>{providerLabels[provider]}</span>
              </button>
            ))}
          </div>
          <div className="sync-mode-switch" role="group" aria-label="同步存储模式">
            <button type="button" className={syncSetupMode === "unlock" ? "active" : ""} onClick={() => setSyncSetupMode("unlock")}>解锁已有 vault</button>
            <button type="button" className={syncSetupMode === "initialize" ? "active" : ""} onClick={() => setSyncSetupMode("initialize")}>初始化新 vault</button>
          </div>
          <div className="form-grid sync-form">
            <label className="field span-2"><span>{appState.sync.provider === "local" ? "同步目录" : "WebDAV endpoint"}</span><input value={appState.sync.endpoint} onChange={(event) => setAppState((current) => ({ ...current, sync: { ...current.sync, endpoint: event.target.value } }))} placeholder={appState.sync.provider === "local" ? "D:\\VPShellSync" : "https://dav.example.com/vpshell/"} /></label>
            {appState.sync.provider === "webdav" ? <>
              <label className="field"><span>WebDAV 用户名</span><input maxLength={256} value={appState.sync.username} onChange={(event) => setAppState((current) => ({ ...current, sync: { ...current.sync, username: event.target.value } }))} autoComplete="username" placeholder="可留空使用无认证存储" /></label>
              <label className="field"><span>WebDAV 密码</span><input type="password" maxLength={1024} value={webDavPassword} onChange={(event) => setWebDavPassword(event.target.value)} autoComplete="current-password" placeholder={appState.sync.providerCredentialRef ? "留空使用系统已保存密码" : "仅保存到系统凭据管理器"} /></label>
              <label className="field span-2"><span>TLS 信任根</span><div className="path-picker"><input readOnly value={webDavCaLabel || (!webDavUseSystemCa && appState.sync.providerCaRef ? "已保存自定义 CA" : "系统 CA")} /><button className="secondary-button" type="button" onClick={() => void chooseWebDavCa()}><Upload size={14} /> 选择 PEM</button>{(webDavCaPath || appState.sync.providerCaRef) && !webDavUseSystemCa ? <button className="icon-button" type="button" title="改用系统 CA" aria-label="改用系统 CA" onClick={() => { setWebDavCaPath(""); setWebDavCaLabel(""); setWebDavUseSystemCa(true); }}><X size={15} /></button> : null}</div></label>
            </> : null}
            <label className="field span-2"><span>二级同步密码</span><input type="password" minLength={8} maxLength={1024} value={syncPassword} onChange={(event) => setSyncPassword(event.target.value)} autoComplete="new-password" placeholder="用于端到端加密" /></label>
          </div>
          </> : null}
          </>}
        </Dialog>
      ) : null}

      {dialog === "wallpaper" ? (
        <Dialog title="终端外观" wide onClose={() => setDialog(null)} footer={<button className="primary-button" type="button" onClick={() => setDialog(null)}>完成</button>}>
          <div className="wallpaper-options">
            <label className={appState.wallpaper.source === "none" ? "active" : ""}><input type="radio" name="wallpaper" checked={appState.wallpaper.source === "none"} onChange={() => { setRenderedWallpaper(""); setAppState((current) => ({ ...current, wallpaper: { ...current.wallpaper, source: "none", value: "" } })); }} /><span>纯色背景</span></label>
            <button className={appState.wallpaper.source === "local" ? "active" : ""} type="button" onClick={() => void chooseLocalWallpaper()}><Image size={15} /><span>本机图片</span></button>
            <label className={appState.wallpaper.source === "url" ? "active" : ""}><input type="radio" name="wallpaper" checked={appState.wallpaper.source === "url"} onChange={() => { setRenderedWallpaper(""); setAppState((current) => ({ ...current, wallpaper: { ...current.wallpaper, source: "url", value: "" } })); }} /><span>URL 图片</span></label>
          </div>
          <label className="field full"><span>图片地址</span><div className="path-picker"><input type="url" disabled={appState.wallpaper.source !== "url"} value={appState.wallpaper.source === "url" ? appState.wallpaper.value : ""} onChange={(event) => setAppState((current) => ({ ...current, wallpaper: { ...current.wallpaper, source: "url", value: event.target.value } }))} placeholder="https://image.example.com/background.webp" /><button className="secondary-button" type="button" disabled={appState.wallpaper.source !== "url" || !appState.wallpaper.value.trim()} onClick={() => void applyRemoteWallpaper()}><Download size={14} /> 应用</button></div></label>
          <label className="slider-field"><span>背景可见度</span><input type="range" min="0.05" max="0.65" step="0.05" value={appState.wallpaper.opacity} onChange={(event) => setAppState((current) => ({ ...current, wallpaper: { ...current.wallpaper, opacity: Number(event.target.value) } }))} /><output>{Math.round(appState.wallpaper.opacity * 100)}%</output></label>
          <div className="appearance-divider" />
          <div className="appearance-heading"><Type size={16} /><strong>终端字体</strong>{appState.terminalAppearance.customFontName ? <small>{appState.terminalAppearance.customFontName}</small> : null}</div>
          <div className="font-controls">
            <label className="field"><span>字体名称</span><input list="terminal-font-list" maxLength={100} value={appState.terminalAppearance.fontFamily} onChange={(event) => setAppState((current) => ({ ...current, terminalAppearance: { ...current.terminalAppearance, fontFamily: event.target.value } }))} /></label>
            <datalist id="terminal-font-list">
              {[...new Set(["Cascadia Code", "Cascadia Mono", "JetBrains Mono", "Consolas", "Fira Code", "Source Code Pro", ...installedFonts])].map((font) => <option value={font} key={font} />)}
            </datalist>
            <button className="secondary-button" type="button" onClick={() => void readInstalledFonts()}><Search size={14} /> 读取系统字体</button>
            <button className="secondary-button" type="button" onClick={() => void chooseLocalFont()}><Upload size={14} /> 选择字体文件</button>
          </div>
          <label className="slider-field"><span>字号</span><input type="range" min="9" max="28" step="1" value={appState.terminalAppearance.fontSize} onChange={(event) => setAppState((current) => ({ ...current, terminalAppearance: { ...current.terminalAppearance, fontSize: Number(event.target.value) } }))} /><output>{appState.terminalAppearance.fontSize}px</output></label>
          <label className="slider-field"><span>行高</span><input type="range" min="1" max="1.8" step="0.05" value={appState.terminalAppearance.lineHeight} onChange={(event) => setAppState((current) => ({ ...current, terminalAppearance: { ...current.terminalAppearance, lineHeight: Number(event.target.value) } }))} /><output>{appState.terminalAppearance.lineHeight.toFixed(2)}</output></label>
        </Dialog>
      ) : null}

      {toast ? <div className="toast" role="status"><Check size={15} />{toast}</div> : null}
    </div>
  );
}

export default App;
