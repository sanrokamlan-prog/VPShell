import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  AlertTriangle,
  BookOpenText,
  Braces,
  Check,
  ChevronDown,
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
  LockKeyhole,
  MoreHorizontal,
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
import { MigrationDialog, type FinalShellImportResult } from "./components/MigrationDialog";
import { NetworkToolsDialog, type NetworkToolMode } from "./components/NetworkToolsDialog";
import { OnboardingDialog } from "./components/OnboardingDialog";
import { SettingsDialog } from "./components/SettingsDialog";
import { TerminalView } from "./components/TerminalView";
import { usePersistedState } from "./hooks/usePersistedState";
import { loadStoredCustomFont, saveAndRegisterCustomFont } from "./fontStorage";
import brandMark from "./assets/vpshell.svg";
import type {
  AppState,
  CommandRecipe,
  EnvironmentKind,
  HostProfile,
  ScriptRecipe,
  SyncProviderKind,
  TerminalSession,
} from "./types";
import "./App.css";

type SidebarView = "hosts" | "commands" | "scripts" | "history";
type DialogKind = "host" | "sync" | "wallpaper" | "settings" | "guide" | "script" | "command" | "custom-script" | "migration" | "key-manager" | "network" | null;

const RECYCLE_BIN_DAYS = 30;

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
  loading: boolean;
  error?: string;
  sampledAt?: string;
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

const sidebarLabels: Record<SidebarView, { eyebrow: string; title: string; placeholder: string }> = {
  hosts: { eyebrow: "CONNECTIONS", title: "主机", placeholder: "搜索名称、IP、标签" },
  commands: { eyebrow: "COMMAND LIBRARY", title: "命令库", placeholder: "搜索想完成的操作" },
  scripts: { eyebrow: "SCRIPT LIBRARY", title: "脚本中心", placeholder: "搜索脚本、分组" },
  history: { eyebrow: "COMMAND HISTORY", title: "历史记录", placeholder: "搜索已执行命令" },
};

function makeSession(host: HostProfile): TerminalSession {
  return {
    id: `session-${host.id}-${Date.now()}`,
    hostId: host.id,
    title: host.name,
    state: "idle",
    currentPath: host.lastPath ?? "~",
    contextSource: "profile",
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
  return "__TAURI_INTERNALS__" in window;
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

function App() {
  const [appState, setAppState] = usePersistedState<AppState>(
    "vpshell-state-v1",
    initialState,
    ["opsshell-state-v6"],
    migratePersistedAppState,
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
  const [syncPassword, setSyncPassword] = useState("");
  const [toast, setToast] = useState<string | null>(null);
  const [installedFonts, setInstalledFonts] = useState<string[]>([]);
  const [fontRevision, setFontRevision] = useState(0);
  const [hostMetrics, setHostMetrics] = useState<Record<string, HostMetricsState>>({});

  const activeSession = sessions.find((session) => session.id === activeSessionId) ?? sessions[0];
  const activeHost = appState.hosts.find((host) => host.id === activeSession.hostId) ?? appState.hosts[0] ?? emptyHost;
  const hasActiveHost = appState.hosts.some((host) => host.id === activeHost.id);
  const activeIdentityPassphraseRef = appState.sshKeys.find(
    (key) => key.privateKeyPath === activeHost.identityFile,
  )?.passphraseRef;
  const deletedHosts = appState.deletedHosts ?? [];

  useEffect(() => {
    const now = Date.now();
    const expired = deletedHosts.filter((item) => Date.parse(item.expiresAt) <= now);
    if (expired.length === 0) return;

    void (async () => {
      if (isDesktopRuntime()) {
        const retainedReferences = new Set([
          ...appState.hosts.map((host) => host.credentialRef),
          ...deletedHosts
            .filter((item) => Date.parse(item.expiresAt) > now)
            .map((item) => item.host.credentialRef),
        ].filter((reference): reference is string => Boolean(reference)));
        await Promise.all(expired.map(async (item) => {
          const reference = item.host.credentialRef;
          if (reference && !retainedReferences.has(reference)) {
            await invoke("delete_credential", { reference }).catch(() => undefined);
          }
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

  useEffect(() => {
    if (!isDesktopRuntime() || activeSession.state !== "connected") return;
    let disposed = false;
    let timer: number | undefined;

    async function sample() {
      setHostMetrics((current) => ({
        ...current,
        [activeSession.id]: { ...current[activeSession.id], loading: true, error: undefined },
      }));
      try {
        const metrics = await invoke<RemoteMetricsResponse>("fetch_remote_metrics", {
          request: {
            host: activeHost.host,
            port: activeHost.port,
            username: activeHost.username,
            identityFile: activeHost.identityFile,
            credentialRef: activeHost.credentialRef,
            identityPassphraseRef: activeIdentityPassphraseRef,
          },
        });
        if (!disposed) {
          setHostMetrics((current) => ({
            ...current,
            [activeSession.id]: { metrics, loading: false, sampledAt: new Date().toLocaleTimeString("zh-CN", { hour12: false }) },
          }));
        }
      } catch (error) {
        if (!disposed) {
          setHostMetrics((current) => ({
            ...current,
            [activeSession.id]: { ...current[activeSession.id], loading: false, error: String(error) },
          }));
        }
      } finally {
        if (!disposed) timer = window.setTimeout(() => void sample(), 15_000);
      }
    }

    void sample();
    return () => {
      disposed = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [activeHost.credentialRef, activeHost.host, activeHost.identityFile, activeHost.port, activeHost.username, activeIdentityPassphraseRef, activeSession.id, activeSession.state]);

  useEffect(() => {
    void loadStoredCustomFont().then((family) => { if (family) setFontRevision((value) => value + 1); }).catch(() => undefined);
  }, []);

  const updateSession = useCallback((sessionId: string, patch: Partial<TerminalSession>) => {
    setSessions((current) => current.map((session) => session.id === sessionId ? { ...session, ...patch } : session));
  }, []);

  const handleDisconnected = useCallback((sessionId: string, message?: string) => {
    updateSession(sessionId, { state: message ? "error" : "closed" });
    if (message) showToast(message);
  }, [showToast, updateSession]);

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
    if (closing?.state === "connected" && isDesktopRuntime()) {
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

  async function connectActiveSession() {
    if (!hasActiveHost) {
      setDialog("host");
      showToast("请先添加或导入主机配置");
      return;
    }
    if (!isDesktopRuntime()) {
      showToast("浏览器预览不启动 SSH；桌面应用中可直接连接");
      return;
    }
    updateSession(activeSession.id, { state: "connecting" });
    try {
      await invoke("start_ssh_session", {
        request: {
          sessionId: activeSession.id,
          host: activeHost.host,
          port: activeHost.port,
          username: activeHost.username,
          identityFile: activeHost.identityFile,
          credentialRef: activeHost.credentialRef,
          identityPassphraseRef: activeIdentityPassphraseRef,
          cols: 120,
          rows: 32,
        },
      });
      updateSession(activeSession.id, { state: "connected" });
      setAppState((current) => ({
        ...current,
        connectionHistory: [{
          id: crypto.randomUUID(),
          hostId: activeHost.id,
          connectedAt: new Date().toISOString(),
          path: activeSession.currentPath,
        }, ...(current.connectionHistory ?? [])],
      }));
      showToast(`已连接 ${activeHost.name}`);
    } catch (error) {
      updateSession(activeSession.id, { state: "error" });
      showToast(String(error));
    }
  }

  async function disconnectActiveSession() {
    if (isDesktopRuntime()) {
      await invoke("stop_terminal", { sessionId: activeSession.id }).catch((error) => showToast(String(error)));
    }
    updateSession(activeSession.id, { state: "closed" });
  }

  async function writeToSessions(command: string, targetIds: string[]) {
    const targetSessions = sessions.filter((session) => targetIds.includes(session.id));
    if (isDesktopRuntime()) {
      await Promise.all(targetSessions.filter((session) => session.state === "connected").map((session) =>
        invoke("write_terminal", { sessionId: session.id, data: `${command}\r` }),
      ));
    }

    const now = new Date().toISOString();
    setAppState((current) => ({
      ...current,
      commandHistory: [
        ...targetSessions.map((session, index) => ({
          id: `history-${Date.now()}-${index}`,
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
    const targetIds = broadcastOpen && broadcastTargets.length > 0 ? broadcastTargets : [activeSession.id];
    await writeToSessions(command, targetIds);
    setCommandInput("");
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
    setCommandParameters(Object.fromEntries((command.parameters ?? []).map((parameter) => [parameter.name, parameter.defaultValue ?? ""])));
    setDialog("command");
  }

  function materializeCommand(command: CommandRecipe) {
    let value = command.command ?? "";
    for (const parameter of command.parameters ?? []) {
      value = value.split(`{{${parameter.name}}}`).join(shellQuote(commandParameters[parameter.name]?.trim() ?? ""));
    }
    return value;
  }

  function chooseIntent(suggestion: IntentSuggestion) {
    setCommandInput("");
    if (suggestion.kind === "script") chooseScript(suggestion.item as ScriptRecipe);
    else chooseCommand(suggestion.item as CommandRecipe);
  }

  function handleFinalShellImport(result: FinalShellImportResult) {
    const existing = new Set(appState.hosts.map((host) => `${host.username}\0${host.host}\0${host.port}`));
    const additions = result.profiles.filter((host) => !existing.has(`${host.username}\0${host.host}\0${host.port}`));
    setAppState((current) => ({ ...current, hosts: [...current.hosts, ...additions] }));
    setSidebarView("hosts");
    showToast(`已加入 ${additions.length} 个主机，安全保存 ${result.credentialsImported} 个密码`);
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

  function addHost(form: HTMLFormElement) {
    const data = new FormData(form);
    const host: HostProfile = {
      id: crypto.randomUUID(),
      name: String(data.get("name") || data.get("host")),
      group: String(data.get("group") || "我的主机"),
      host: String(data.get("host")),
      port: Number(data.get("port") || 22),
      username: String(data.get("username") || "root"),
      environment: String(data.get("environment") || "development") as EnvironmentKind,
      identityFile: String(data.get("identityFile") || "") || undefined,
      tags: [],
      lastPath: "~",
    };
    setAppState((current) => ({ ...current, hosts: [...current.hosts, host] }));
    setDialog(null);
    openHost(host);
  }

  async function deleteHost(host: HostProfile) {
    const confirmed = window.confirm(
      `确定将主机“${host.name}”（${host.username}@${host.host}:${host.port}）移到回收站吗？\n\n相关连接记录和命令/路径历史将一并保留 30 天，可在回收站恢复。`,
    );
    if (!confirmed) return;

    const hostSessions = sessions.filter((session) => session.hostId === host.id);
    if (isDesktopRuntime()) {
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
    const reference = deleted.host.credentialRef;
    const referencedElsewhere = reference && (
      appState.hosts.some((host) => host.credentialRef === reference)
      || deletedHosts.some((item) => item.id !== itemId && item.host.credentialRef === reference)
    );
    if (reference && !referencedElsewhere && isDesktopRuntime()) {
      try {
        await invoke("delete_credential", { reference });
      } catch (error) {
        credentialError = String(error);
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

  function applyLocalWallpaper(file?: File) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setAppState((current) => ({
        ...current,
        wallpaper: { ...current.wallpaper, source: "local", value: String(reader.result) },
      }));
      setFontRevision((value) => value + 1);
    };
    reader.readAsDataURL(file);
  }

  async function applyLocalFont(file?: File) {
    if (!file) return;
    try {
      const family = await saveAndRegisterCustomFont(file);
      setAppState((current) => ({
        ...current,
        terminalAppearance: { ...current.terminalAppearance, fontFamily: family, customFontName: file.name },
      }));
      showToast(`已启用本机字体 ${file.name}`);
    } catch (error) {
      showToast(String(error));
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

  function saveSyncSettings() {
    if (!syncPassword) {
      showToast("请输入二级同步密码");
      return;
    }
    setAppState((current) => ({
      ...current,
      sync: { ...current.sync, enabled: false, lastSyncedAt: undefined },
    }));
    setSyncPassword("");
    setDialog(null);
    showToast("同步配置草稿已保存；同步后端尚未启用");
  }

  const currentPathHistory = appState.pathHistory[activeHost.id] ?? [];

  return (
    <div className={`app-shell ${sidebarOpen ? "" : "sidebar-collapsed"}`}>
      <header className="topbar">
        <div className="brand-block">
          <span className="brand-mark"><img src={brandMark} alt="" /></span>
          <strong>VPShell</strong>
          <button className="workspace-switcher" type="button">
            个人资料库 <ChevronDown size={14} />
          </button>
        </div>
        <div className="topbar-actions">
          <button
            className={`sync-status ${appState.sync.enabled ? "is-synced" : ""}`}
            type="button"
            onClick={() => setDialog("sync")}
          >
            {appState.sync.enabled ? <Cloud size={15} /> : <CloudOff size={15} />}
            <span>{appState.sync.enabled ? relativeTime(appState.sync.lastSyncedAt) : appState.sync.endpoint ? "同步后端未启用" : "同步未配置"}</span>
          </button>
          <span className="route-status">
            <Route size={15} /> 路线：直连
          </span>
          <button className="icon-button" type="button" title="网络诊断" aria-label="网络诊断" onClick={() => { setNetworkMode("trace"); setDialog("network"); }}>
            <Network size={17} />
          </button>
          <button className="icon-button" type="button" title="SSH 密钥" aria-label="SSH 密钥" onClick={() => setDialog("key-manager")}>
            <KeyRound size={17} />
          </button>
          <button className="icon-button" type="button" title="终端外观" aria-label="终端外观" onClick={() => setDialog("wallpaper")}>
            <Image size={17} />
          </button>
          <button className="icon-button" type="button" title="使用指南" aria-label="使用指南" onClick={() => setDialog("guide")}>
            <CircleHelp size={17} />
          </button>
          <button className="icon-button" type="button" title="设置与升级" aria-label="设置与升级" onClick={() => setDialog("settings")}>
            <Settings2 size={17} />
          </button>
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
                address: hostMetrics[activeSession.id]?.metrics?.primaryIp ?? activeHost.host,
                hostname: hostMetrics[activeSession.id]?.metrics?.hostname,
                username: activeHost.username,
                source: "transport",
              } : undefined}
              loading={hostMetrics[activeSession.id]?.loading}
              error={hostMetrics[activeSession.id]?.error}
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
            <button className={`icon-button ${broadcastOpen ? "active warning" : ""}`} type="button" title="多终端广播" aria-label="多终端广播" onClick={() => setBroadcastOpen((value) => !value)}><RadioTower size={16} /></button>
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
                <ChevronRight size={14} />
                <strong className={`route-node current ${activeHost.environment}`}>{activeHost.name}</strong>
                <code>{activeHost.username}@{activeHost.host}</code>
              </>
            ) : <span className="empty-host-hint">请选择、添加或导入主机</span>}
          </div>
          <div className="context-meta">
            {hasActiveHost ? <span className={`environment-badge ${activeHost.environment}`}>{environmentLabels[activeHost.environment]}</span> : null}
            {hasActiveHost ? <span className="context-source"><Check size={13} /> 配置视图</span> : null}
            {hasActiveHost ? <span>{activeHost.latency ? `${activeHost.latency} ms` : "未测速"}</span> : null}
            {activeSession.state === "connected" ? (
              <button className="disconnect-button" type="button" onClick={disconnectActiveSession}><WifiOff size={14} /> 断开</button>
            ) : (
              <button className="connect-button" type="button" disabled={activeSession.state === "connecting"} onClick={connectActiveSession}>
                {activeSession.state === "connecting" ? <RefreshCw className="spin" size={14} /> : <Play size={14} />} {activeSession.state === "connecting" ? "连接中" : "连接"}
              </button>
            )}
          </div>
        </section>

        {broadcastOpen ? (
          <section className="broadcast-banner">
            <div><RadioTower size={17} /><strong>多终端广播</strong><span>已选 {broadcastTargets.length} 台，发送后保持选择</span></div>
            <div className="broadcast-targets">
              {sessions.map((session) => (
                <label className={session.state !== "connected" ? "unavailable" : ""} key={session.id}>
                  <input
                    type="checkbox"
                    checked={broadcastTargets.includes(session.id)}
                    disabled={session.state !== "connected"}
                    onChange={(event) => setBroadcastTargets((current) => event.target.checked ? [...current, session.id] : current.filter((id) => id !== session.id))}
                  />
                  <span className={`session-state ${session.state}`} />
                  <span>{session.title}</span>
                </label>
              ))}
            </div>
            <div className="broadcast-controls">
              <button type="button" onClick={() => setBroadcastTargets(sessions.filter((session) => session.state === "connected").map((session) => session.id))}>全选已连接</button>
              <button type="button" disabled={broadcastTargets.length === 0} onClick={() => setBroadcastTargets([])}>清空</button>
            </div>
            <button className="icon-button" type="button" title="关闭广播" aria-label="关闭广播" onClick={() => setBroadcastOpen(false)}><X size={16} /></button>
          </section>
        ) : null}

        <div className="content-split">
          <section className="terminal-pane">
            <TerminalView
              session={activeSession}
              host={activeHost}
              wallpaper={appState.wallpaper}
              appearance={appState.terminalAppearance}
              appearanceRevision={fontRevision}
              onDisconnected={handleDisconnected}
            />
            <div className="path-history-bar">
              <Clock3 size={14} />
              <span>路径</span>
              <div className="path-chips">
                {currentPathHistory.map((path) => <button type="button" key={path} onClick={() => setCommandInput(`cd ${path}`)}>{path}</button>)}
              </div>
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
                <input value={commandInput} onChange={(event) => setCommandInput(event.target.value)} placeholder={broadcastOpen ? `发送到 ${broadcastTargets.length} 个终端` : "输入命令，或搜索想做的事"} />
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
              initialPath={activeSession.currentPath}
              externalEditorPath={appState.settings.externalEditorPath}
              autoUploadEditedFiles={appState.settings.autoUploadEditedFiles}
              onPathChanged={(path) => {
                updateSession(activeSession.id, { currentPath: path });
                setAppState((current) => ({
                  ...current,
                  pathHistory: {
                    ...current.pathHistory,
                    [activeHost.id]: [path, ...(current.pathHistory[activeHost.id] ?? []).filter((item) => item !== path)].slice(0, 30),
                  },
                }));
              }}
              showToast={showToast}
              onClose={() => setFilePanelOpen(false)}
            />
          ) : null}
        </div>

        <footer className="statusbar">
          <span><SquareTerminal size={13} /> OpenSSH 兼容引擎</span>
          <span><LockKeyhole size={13} /> 本地资料库</span>
          <span className="status-spacer" />
          <span>UTF-8</span><span>xterm-256color</span><span>{activeSession.currentPath}</span>
        </footer>
      </main>

      {dialog === "migration" ? (
        <MigrationDialog onClose={() => setDialog(null)} onImported={handleFinalShellImport} showToast={showToast} />
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
        <NetworkToolsDialog initialMode={networkMode} defaultHost={activeHost.host} onClose={() => setDialog(null)} showToast={showToast} />
      ) : null}

      {dialog === "settings" ? (
        <SettingsDialog
          externalEditorPath={appState.settings.externalEditorPath}
          autoUploadEditedFiles={appState.settings.autoUploadEditedFiles}
          onSave={(settings) => setAppState((current) => ({ ...current, settings }))}
          onClose={() => setDialog(null)}
          showToast={showToast}
        />
      ) : null}

      {dialog === "host" ? (
        <Dialog title="添加 SSH 主机" onClose={() => setDialog(null)} footer={<><button className="secondary-button" type="button" onClick={() => setDialog(null)}>取消</button><button className="primary-button" type="submit" form="host-form">保存并打开</button></>}>
          <form id="host-form" className="form-grid" onSubmit={(event) => { event.preventDefault(); addHost(event.currentTarget); }}>
            <label className="field full"><span>名称</span><input name="name" placeholder="例如：新加坡生产 03" required /></label>
            <label className="field span-2"><span>主机地址</span><input name="host" placeholder="IP 或域名" required /></label>
            <label className="field"><span>端口</span><input name="port" type="number" defaultValue="22" min="1" max="65535" required /></label>
            <label className="field"><span>用户名</span><input name="username" defaultValue="root" required /></label>
            <label className="field"><span>环境</span><select name="environment" defaultValue="development"><option value="production">生产</option><option value="staging">基础设施</option><option value="development">测试</option></select></label>
            <label className="field"><span>分组</span><input name="group" defaultValue="我的主机" /></label>
            <label className="field full"><span>私钥路径</span><input name="identityFile" placeholder="使用系统 OpenSSH 路径（可选）" /></label>
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
                onClick={() => { setCommandInput(materializeCommand(selectedCommand)); setDialog(null); }}
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
              {selectedCommand.parameters?.map((parameter) => (
                <label className="field span-2" key={parameter.name}>
                  <span>{parameter.label}</span>
                  <input value={commandParameters[parameter.name] ?? ""} placeholder={parameter.placeholder} required={parameter.required} onChange={(event) => setCommandParameters((current) => ({ ...current, [parameter.name]: event.target.value }))} />
                </label>
              ))}
            </div>
          ) : null}
          {selectedCommand.command ? <pre className="script-code"><code>{materializeCommand(selectedCommand)}</code></pre> : null}
        </Dialog>
      ) : null}

      {dialog === "sync" ? (
        <Dialog title="加密同步（设计预览）" wide onClose={() => setDialog(null)} footer={<><button className="secondary-button" type="button" onClick={() => setDialog(null)}>取消</button><button className="primary-button" type="button" onClick={saveSyncSettings}><ShieldCheck size={14} /> 保存草稿</button></>}>
          <div className="provider-grid">
            {(Object.keys(providerLabels) as SyncProviderKind[]).map((provider) => (
              <button className={appState.sync.provider === provider ? "active" : ""} type="button" key={provider} onClick={() => setAppState((current) => ({ ...current, sync: { ...current.sync, provider } }))}>
                {provider === "local" ? <HardDrive size={18} /> : provider === "webdav" ? <Globe2 size={18} /> : provider === "sftp" ? <SquareTerminal size={18} /> : provider === "s3" ? <Database size={18} /> : <Cloud size={18} />}
                <span>{providerLabels[provider]}</span>
              </button>
            ))}
          </div>
          <div className="form-grid sync-form">
            <label className="field span-2"><span>同步地址</span><input value={appState.sync.endpoint} onChange={(event) => setAppState((current) => ({ ...current, sync: { ...current.sync, endpoint: event.target.value } }))} placeholder={appState.sync.provider === "local" ? "D:\\VPShellSync" : "https://example.com/dav/"} /></label>
            <label className="field span-2"><span>远端目录</span><input value={appState.sync.remotePath} onChange={(event) => setAppState((current) => ({ ...current, sync: { ...current.sync, remotePath: event.target.value } }))} /></label>
            <label className="field span-2"><span>账户</span><input value={appState.sync.username} onChange={(event) => setAppState((current) => ({ ...current, sync: { ...current.sync, username: event.target.value } }))} autoComplete="off" /></label>
            <label className="field span-2"><span>二级同步密码</span><input type="password" value={syncPassword} onChange={(event) => setSyncPassword(event.target.value)} autoComplete="new-password" placeholder="用于端到端加密" /></label>
          </div>
          <div className="sync-options">
            <label><input type="checkbox" checked readOnly /><span><strong>同步全部自建内容</strong><small>主机、脚本、命令、路径、参数、背景和附件</small></span></label>
            <label><input type="checkbox" checked={appState.sync.syncSecrets} onChange={(event) => setAppState((current) => ({ ...current, sync: { ...current.sync, syncSecrets: event.target.checked } }))} /><span><strong>同步主机凭据与私钥</strong><small>使用独立密钥域加密，默认关闭</small></span></label>
            <label className={appState.sync.provider !== "gateway" ? "disabled" : ""}><input type="checkbox" disabled={appState.sync.provider !== "gateway"} checked={appState.sync.totpEnabled} onChange={(event) => setAppState((current) => ({ ...current, sync: { ...current.sync, totpEnabled: event.target.checked } }))} /><span><strong>Google Authenticator</strong><small>仅自建同步网关支持 TOTP 身份验证</small></span></label>
          </div>
        </Dialog>
      ) : null}

      {dialog === "wallpaper" ? (
        <Dialog title="终端外观" wide onClose={() => setDialog(null)} footer={<button className="primary-button" type="button" onClick={() => setDialog(null)}>完成</button>}>
          <div className="wallpaper-options">
            <label className={appState.wallpaper.source === "none" ? "active" : ""}><input type="radio" name="wallpaper" checked={appState.wallpaper.source === "none"} onChange={() => setAppState((current) => ({ ...current, wallpaper: { ...current.wallpaper, source: "none", value: "" } }))} /><span>纯色背景</span></label>
            <label className={appState.wallpaper.source === "local" ? "active" : ""}><input type="radio" name="wallpaper" checked={appState.wallpaper.source === "local"} readOnly /><span>本机图片</span><input className="file-input" type="file" accept="image/png,image/jpeg,image/webp" onChange={(event) => applyLocalWallpaper(event.target.files?.[0])} /></label>
            <label className={appState.wallpaper.source === "url" ? "active" : ""}><input type="radio" name="wallpaper" checked={appState.wallpaper.source === "url"} onChange={() => setAppState((current) => ({ ...current, wallpaper: { ...current.wallpaper, source: "url" } }))} /><span>URL 图片</span></label>
          </div>
          <label className="field full"><span>图片地址</span><input type="url" disabled={appState.wallpaper.source !== "url"} value={appState.wallpaper.source === "url" ? appState.wallpaper.value : ""} onChange={(event) => setAppState((current) => ({ ...current, wallpaper: { ...current.wallpaper, source: "url", value: event.target.value } }))} placeholder="https://image.example.com/background.webp" /></label>
          <label className="slider-field"><span>背景可见度</span><input type="range" min="0.05" max="0.65" step="0.05" value={appState.wallpaper.opacity} onChange={(event) => setAppState((current) => ({ ...current, wallpaper: { ...current.wallpaper, opacity: Number(event.target.value) } }))} /><output>{Math.round(appState.wallpaper.opacity * 100)}%</output></label>
          <label className="sync-wallpaper"><input type="checkbox" disabled /><span>加密同步接通后可选择同步</span></label>
          <div className="appearance-divider" />
          <div className="appearance-heading"><Type size={16} /><strong>终端字体</strong>{appState.terminalAppearance.customFontName ? <small>{appState.terminalAppearance.customFontName}</small> : null}</div>
          <div className="font-controls">
            <label className="field"><span>字体名称</span><input list="terminal-font-list" maxLength={100} value={appState.terminalAppearance.fontFamily} onChange={(event) => setAppState((current) => ({ ...current, terminalAppearance: { ...current.terminalAppearance, fontFamily: event.target.value } }))} /></label>
            <datalist id="terminal-font-list">
              {[...new Set(["Cascadia Code", "Cascadia Mono", "JetBrains Mono", "Consolas", "Fira Code", "Source Code Pro", ...installedFonts])].map((font) => <option value={font} key={font} />)}
            </datalist>
            <button className="secondary-button" type="button" onClick={() => void readInstalledFonts()}><Search size={14} /> 读取系统字体</button>
            <label className="secondary-button font-file-button"><Upload size={14} /> 选择字体文件<input type="file" accept=".ttf,.otf,.woff,.woff2,font/ttf,font/otf,font/woff,font/woff2" onChange={(event) => void applyLocalFont(event.target.files?.[0])} /></label>
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
