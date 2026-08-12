import {
  Activity,
  Clock3,
  Copy,
  Cpu,
  HardDrive,
  MemoryStick,
  Network,
  Pause,
  Play,
  Server,
  UserRound,
} from "lucide-react";
import type { CSSProperties, ReactNode } from "react";
import type { ConnectionState, HostProfile } from "../types";

export interface HostOverviewMetrics {
  cpuPercent?: number;
  memoryPercent?: number;
  diskPercent?: number;
  network?: {
    receiveBytesPerSecond?: number;
    transmitBytesPerSecond?: number;
  };
  sampledAt?: string;
  load?: [number, number, number];
  uptimeSeconds?: number;
  topProcesses?: Array<{
    pid: number;
    name: string;
    cpuPercent: number;
    memoryPercent: number;
  }>;
}

export interface HostOverviewCurrentIdentity {
  address?: string;
  hostname?: string;
  username?: string;
  source: "transport" | "shell-integration";
}

export interface HostOverviewProps {
  host: HostProfile;
  state: ConnectionState;
  metrics?: HostOverviewMetrics;
  currentIdentity?: HostOverviewCurrentIdentity;
  loading?: boolean;
  error?: string;
  history?: Array<{
    sampledAtMs: number;
    cpuPercent: number;
    memoryPercent: number;
    diskPercent: number;
    loadOne: number;
    rxBytesPerSecond: number;
    txBytesPerSecond: number;
  }>;
  paused?: boolean;
  intervalSeconds?: number;
  droppedSamples?: number;
  onPausedChange?: (paused: boolean) => void;
  onIntervalChange?: (seconds: number) => void;
  onCopied?: (message: string) => void;
}

const stateDetails: Record<ConnectionState, { label: string; color: string }> = {
  idle: { label: "未连接", color: "#7b8794" },
  connecting: { label: "连接中", color: "#b87810" },
  connected: { label: "已连接", color: "#238636" },
  closed: { label: "已断开", color: "#7b8794" },
  error: { label: "连接错误", color: "#c13c37" },
};

const panelStyle: CSSProperties = {
  display: "grid",
  gap: 10,
  minWidth: 0,
  padding: "10px 9px",
  borderTop: "1px solid var(--border, #d8dee4)",
  color: "var(--text, #1f2328)",
  background: "var(--surface, #ffffff)",
  fontSize: 11,
};

const mutedStyle: CSSProperties = {
  color: "var(--text-muted, #66727f)",
};

function clampPercent(value: number | undefined) {
  if (value === undefined || !Number.isFinite(value)) return undefined;
  return Math.min(100, Math.max(0, value));
}

function formatRate(value: number | undefined) {
  if (value === undefined || !Number.isFinite(value) || value < 0) return undefined;
  const units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
  let amount = value;
  let unitIndex = 0;
  while (amount >= 1024 && unitIndex < units.length - 1) {
    amount /= 1024;
    unitIndex += 1;
  }
  const digits = amount >= 100 || unitIndex === 0 ? 0 : amount >= 10 ? 1 : 2;
  return `${amount.toFixed(digits)} ${units[unitIndex]}`;
}

function formatUptime(seconds: number | undefined) {
  if (seconds === undefined || !Number.isFinite(seconds) || seconds < 0) return undefined;
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor(seconds % 86_400 / 3_600);
  const minutes = Math.floor(seconds % 3_600 / 60);
  return days > 0 ? `${days} 天 ${hours} 小时` : `${hours} 小时 ${minutes} 分`;
}

function OverviewRow({ icon, label, children }: { icon: ReactNode; label: string; children: ReactNode }) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "18px minmax(56px, auto) minmax(0, 1fr)",
        minHeight: 20,
        alignItems: "center",
        columnGap: 5,
      }}
    >
      <span aria-hidden="true" style={{ display: "inline-grid", placeItems: "center", color: "var(--text-muted, #66727f)" }}>
        {icon}
      </span>
      <span style={mutedStyle}>{label}</span>
      <span style={{ minWidth: 0, overflow: "hidden", textAlign: "right", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {children}
      </span>
    </div>
  );
}

function MetricRow({ icon, label, percent }: { icon: ReactNode; label: string; percent?: number }) {
  const normalized = clampPercent(percent);
  return (
    <OverviewRow icon={icon} label={label}>
      {normalized === undefined ? (
        <span style={mutedStyle}>连接后采集</span>
      ) : (
        <span style={{ display: "grid", gridTemplateColumns: "minmax(28px, 1fr) 34px", alignItems: "center", gap: 6 }}>
          <meter
            aria-label={`${label}使用率`}
            min={0}
            max={100}
            value={normalized}
            style={{ width: "100%", height: 7 }}
          />
          <span>{normalized.toFixed(normalized >= 10 ? 0 : 1)}%</span>
        </span>
      )}
    </OverviewRow>
  );
}

function TrendLine({
  label,
  values,
  color,
}: {
  label: string;
  values: number[];
  color: string;
}) {
  if (values.length < 2) return null;
  const finite = values.filter((value) => Number.isFinite(value));
  if (finite.length < 2) return null;
  const maximum = Math.max(...finite, 1);
  const points = values.map((value, index) => {
    const normalized = Number.isFinite(value) ? value / maximum : 0;
    return `${(index / Math.max(values.length - 1, 1)) * 100},${28 - normalized * 24}`;
  }).join(" ");
  return (
    <div style={{ display: "grid", gridTemplateColumns: "38px minmax(0, 1fr)", alignItems: "center", gap: 5 }}>
      <span style={{ ...mutedStyle, fontSize: 10 }}>{label}</span>
      <svg
        role="img"
        aria-label={`${label}趋势，${values.length}个采样点`}
        viewBox="0 0 100 28"
        preserveAspectRatio="none"
        style={{ width: "100%", height: 28, overflow: "visible", borderBottom: "1px solid var(--border, #d8dee4)" }}
      >
        <polyline points={points} fill="none" stroke={color} strokeWidth="2" vectorEffect="non-scaling-stroke" />
      </svg>
    </div>
  );
}

export function HostOverview({
  host,
  state,
  metrics,
  currentIdentity,
  loading = false,
  error,
  history = [],
  paused = false,
  intervalSeconds = 15,
  droppedSamples = 0,
  onPausedChange,
  onIntervalChange,
  onCopied,
}: HostOverviewProps) {
  const stateDetail = stateDetails[state];
  const currentHost = currentIdentity?.address || currentIdentity?.hostname;
  const receiveRate = formatRate(metrics?.network?.receiveBytesPerSecond);
  const transmitRate = formatRate(metrics?.network?.transmitBytesPerSecond);
  const uptime = formatUptime(metrics?.uptimeSeconds);

  async function copyHost() {
    try {
      await navigator.clipboard.writeText(host.host);
      onCopied?.(`已复制主机地址 ${host.host}`);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      onCopied?.(`复制失败：${reason}`);
    }
  }

  return (
    <section className="host-overview" aria-labelledby={`host-overview-${host.id}`} style={panelStyle}>
      <header style={{ display: "flex", minWidth: 0, alignItems: "center", justifyContent: "space-between", gap: 8 }}>
        <span style={{ display: "inline-flex", minWidth: 0, alignItems: "center", gap: 6 }}>
          <Activity size={15} aria-hidden="true" />
          <strong id={`host-overview-${host.id}`} style={{ fontSize: 12 }}>主机概况</strong>
        </span>
        <span role="status" style={{ display: "inline-flex", alignItems: "center", gap: 5, color: stateDetail.color }}>
          <span aria-hidden="true" style={{ width: 7, height: 7, borderRadius: "50%", background: "currentColor" }} />
          {stateDetail.label}
        </span>
      </header>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "18px minmax(0, 1fr) 26px",
          minWidth: 0,
          alignItems: "center",
          gap: 6,
          padding: "7px 6px",
          border: "1px solid var(--border, #d8dee4)",
          borderRadius: 4,
          background: "var(--surface-subtle, #f6f8fa)",
        }}
      >
        <Server size={16} aria-hidden="true" style={{ color: "var(--green, #238636)" }} />
        <span style={{ display: "grid", minWidth: 0, gap: 1 }}>
          <span style={mutedStyle}>配置目标</span>
          <strong title={host.host} style={{ overflow: "hidden", fontSize: 13, textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {host.host}
          </strong>
        </span>
        <button
          className="icon-button compact"
          type="button"
          title="复制主机地址"
          aria-label={`复制主机地址 ${host.host}`}
          onClick={() => void copyHost()}
          style={{ display: "inline-grid", width: 26, height: 26, padding: 0, placeItems: "center" }}
        >
          <Copy size={14} aria-hidden="true" />
        </button>
      </div>

      <div aria-label="连接信息" style={{ display: "grid", gap: 2 }}>
        <OverviewRow icon={<Server size={13} />} label="当前会话">
          {currentHost ? (
            <span title={[currentIdentity?.hostname, currentIdentity?.address].filter(Boolean).join(" / ")}>
              {currentHost}
            </span>
          ) : (
            <span style={mutedStyle}>{state === "connected" ? "待会话识别" : "连接后识别"}</span>
          )}
        </OverviewRow>
        <OverviewRow icon={<UserRound size={13} />} label="用户">
          {currentIdentity?.username || host.username}
        </OverviewRow>
        <OverviewRow icon={<Network size={13} />} label="端口">
          {host.port}
        </OverviewRow>
      </div>

      <div aria-label="主机资源指标" style={{ display: "grid", gap: 2, paddingTop: 6, borderTop: "1px solid var(--border, #d8dee4)" }}>
        <MetricRow icon={<Cpu size={13} />} label="CPU" percent={metrics?.cpuPercent} />
        <MetricRow icon={<MemoryStick size={13} />} label="内存" percent={metrics?.memoryPercent} />
        <MetricRow icon={<HardDrive size={13} />} label="磁盘" percent={metrics?.diskPercent} />
        <OverviewRow icon={<Activity size={13} />} label="负载">
          {metrics?.load ? metrics.load.map((value) => value.toFixed(2)).join(" / ") : <span style={mutedStyle}>连接后采集</span>}
        </OverviewRow>
        <OverviewRow icon={<Clock3 size={13} />} label="运行">
          {uptime ?? <span style={mutedStyle}>连接后采集</span>}
        </OverviewRow>
        <OverviewRow icon={<Network size={13} />} label="网络">
          {receiveRate !== undefined || transmitRate !== undefined ? (
            <span title="接收 / 发送">↓ {receiveRate ?? "-"} · ↑ {transmitRate ?? "-"}</span>
          ) : (
            <span style={mutedStyle}>连接后采集</span>
          )}
        </OverviewRow>
        {metrics?.sampledAt ? (
          <small style={{ ...mutedStyle, paddingTop: 3, textAlign: "right" }}>采样于 {metrics.sampledAt}</small>
        ) : null}
        {loading ? <small style={{ ...mutedStyle, paddingTop: 3 }}>正在采样...</small> : null}
        {error ? <small title={error} style={{ color: "var(--red, #c13c37)", lineHeight: 1.4 }}>采样失败：{error}</small> : null}
      </div>

      <div aria-label="监控控制与趋势" style={{ display: "grid", gap: 7, paddingTop: 6, borderTop: "1px solid var(--border, #d8dee4)" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 6 }}>
          <strong style={{ fontSize: 10 }}>监控趋势</strong>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
            <label style={{ ...mutedStyle, fontSize: 10 }} htmlFor={`monitor-interval-${host.id}`}>频率</label>
            <select
              id={`monitor-interval-${host.id}`}
              aria-label="监控采样频率"
              value={intervalSeconds}
              onChange={(event) => onIntervalChange?.(Number(event.target.value))}
              style={{ maxWidth: 74, padding: "2px 3px", fontSize: 10 }}
            >
              {[5, 15, 30, 60, 120].map((seconds) => <option key={seconds} value={seconds}>{seconds} 秒</option>)}
            </select>
            <button
              className="icon-button compact"
              type="button"
              title={paused ? "恢复监控采样" : "暂停监控采样"}
              aria-label={paused ? "恢复监控采样" : "暂停监控采样"}
              onClick={() => onPausedChange?.(!paused)}
              style={{ display: "inline-grid", width: 26, height: 26, padding: 0, placeItems: "center" }}
            >
              {paused ? <Play size={13} aria-hidden="true" /> : <Pause size={13} aria-hidden="true" />}
            </button>
          </span>
        </div>
        {history.length >= 2 ? (
          <>
            <TrendLine label="CPU" values={history.map((point) => point.cpuPercent)} color="#238636" />
            <TrendLine label="内存" values={history.map((point) => point.memoryPercent)} color="#0969da" />
            <TrendLine label="磁盘" values={history.map((point) => point.diskPercent)} color="#b35900" />
            <TrendLine label="负载" values={history.map((point) => point.loadOne)} color="#8250df" />
            <TrendLine label="网络" values={history.map((point) => point.rxBytesPerSecond + point.txBytesPerSecond)} color="#cf222e" />
          </>
        ) : (
          <small style={mutedStyle}>{paused ? "监控已暂停" : "等待至少两个采样点"}</small>
        )}
        {droppedSamples > 0 ? <small style={mutedStyle}>历史已保留最近 120 点，已淘汰 {droppedSamples} 点</small> : null}
      </div>

      {metrics?.topProcesses?.length ? (
        <div aria-label="CPU 占用最高的进程" style={{ display: "grid", gap: 3, paddingTop: 6, borderTop: "1px solid var(--border, #d8dee4)" }}>
          <strong style={{ fontSize: 10 }}>进程摘要</strong>
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) 38px 38px", gap: 4, color: "var(--text-muted)", fontSize: 9 }}>
            <span>命令</span><span>CPU</span><span>内存</span>
          </div>
          {metrics.topProcesses.slice(0, 5).map((process) => (
            <div key={process.pid} title={`PID ${process.pid} · ${process.name}`} style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) 38px 38px", gap: 4, fontSize: 9 }}>
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{process.name}</span>
              <span>{process.cpuPercent.toFixed(1)}%</span>
              <span>{process.memoryPercent.toFixed(1)}%</span>
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
}
