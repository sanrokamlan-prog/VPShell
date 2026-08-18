import { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Activity, ArrowDownToLine, ArrowLeftRight, Copy, Gauge, Network, Play, RefreshCw, Route, Square, Waypoints } from "lucide-react";
import { Dialog } from "./Dialog";

export type NetworkToolMode = "trace" | "download" | "udp" | "route";

interface NativeRouteHop {
  hopId: string;
  host: string;
  port: number;
  username: string;
  hostKeySha256: string;
  timeoutSeconds: number;
  credentialRef?: string;
  identityFile?: string;
  identityPassphraseRef?: string;
}

export interface RouteMeasurementOption {
  candidateId: string;
  label: string;
  route: { hops: NativeRouteHop[] };
}

interface TraceResult {
  command: string;
  success: boolean;
  durationMs: number;
  stdout: string;
  stderr: string;
}

interface DownloadResult {
  status: number;
  bytesDownloaded: number;
  durationMs: number;
  megabitsPerSecond: number;
  contentLength?: number;
  reachedLimit: boolean;
}

interface UdpResult {
  command: string;
  success: boolean;
  durationMs: number;
  stdout: string;
  stderr: string;
}

interface UdpSummary {
  mbps?: number;
  jitterMs?: number;
  lostPercent?: number;
}

interface RouteCandidateSnapshot {
  candidateId: string;
  status: "pending" | "ready" | "failed";
  sampleCount: number;
  successfulSamples: number;
  successRatePercent: number;
  medianDurationMs?: number;
  p95DurationMs?: number;
  scoreMs?: number;
  eligible: boolean;
  lastSampledAtMs?: number;
  lastErrorCode?: string;
  lastErrorRetryable?: boolean;
  lastErrorHopIndex?: number;
  reasonCodes: string[];
}

interface RouteMeasurementSnapshot {
  schemaVersion: number;
  campaignId: string;
  running: boolean;
  sampling: boolean;
  intervalSeconds: number;
  windowSize: number;
  maxRounds: number;
  completedRounds: number;
  startedAtMs: number;
  selectedCandidateId?: string;
  selectionReasonCode: string;
  candidates: RouteCandidateSnapshot[];
}

interface NetworkToolsDialogProps {
  initialMode: NetworkToolMode;
  defaultHost: string;
  onClose: () => void;
  showToast: (message: string) => void;
  buildRouteMeasurementOptions: () => RouteMeasurementOption[];
}

function isDesktopRuntime() {
  return "__TAURI_INTERNALS__" in window && !/Android/i.test(navigator.userAgent);
}

function formatBytes(bytes: number) {
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

function parseUdpSummary(output?: string): UdpSummary | null {
  if (!output) return null;
  try {
    const value = JSON.parse(output) as { end?: Record<string, Record<string, unknown>> };
    const end = value.end ?? {};
    const summary = end.sum_received ?? end.sum ?? end.sum_sent;
    if (!summary) return null;
    return {
      mbps: typeof summary.bits_per_second === "number" ? summary.bits_per_second / 1_000_000 : undefined,
      jitterMs: typeof summary.jitter_ms === "number" ? summary.jitter_ms : undefined,
      lostPercent: typeof summary.lost_percent === "number" ? summary.lost_percent : undefined,
    };
  } catch {
    return null;
  }
}

const selectionReasonLabels: Record<string, string> = {
  "collecting-baseline": "正在收集基线",
  "no-reliable-candidate": "暂无可靠路线",
  "only-reliable-candidate": "唯一达到可靠性门槛",
  "lowest-observed-score": "观测评分最低",
  "retained-within-hysteresis": "差异小于 15%，保持当前推荐",
  "probe-worker-failed": "测量任务异常终止",
};

function formatRouteDuration(value?: number) {
  return typeof value === "number" ? `${value} ms` : "-";
}

function formatRouteError(error: unknown) {
  if (error && typeof error === "object") {
    const value = error as { code?: string; message?: string; candidateId?: string; hopIndex?: number };
    if (value.message) {
      const candidate = value.candidateId ? `${value.candidateId} · ` : "";
      const hop = value.hopIndex ? `第 ${value.hopIndex} 跳 · ` : "";
      return `${candidate}${hop}${value.message}${value.code ? ` (${value.code})` : ""}`;
    }
  }
  return String(error);
}

export function NetworkToolsDialog({ initialMode, defaultHost, onClose, showToast, buildRouteMeasurementOptions }: NetworkToolsDialogProps) {
  const [mode, setMode] = useState<NetworkToolMode>(initialMode);
  const [traceHost, setTraceHost] = useState(defaultHost);
  const [maxHops, setMaxHops] = useState(30);
  const [downloadUrl, setDownloadUrl] = useState("");
  const [downloadLimit, setDownloadLimit] = useState(25);
  const [downloadTimeout, setDownloadTimeout] = useState(30);
  const [udpHost, setUdpHost] = useState(defaultHost);
  const [udpPort, setUdpPort] = useState(5201);
  const [udpDuration, setUdpDuration] = useState(10);
  const [udpBandwidth, setUdpBandwidth] = useState(100);
  const [udpReverse, setUdpReverse] = useState(false);
  const [busy, setBusy] = useState(false);
  const [traceResult, setTraceResult] = useState<TraceResult | null>(null);
  const [downloadResult, setDownloadResult] = useState<DownloadResult | null>(null);
  const [udpResult, setUdpResult] = useState<UdpResult | null>(null);
  const [routeInterval, setRouteInterval] = useState(30);
  const [routeWindow, setRouteWindow] = useState(5);
  const [routeMaxRounds, setRouteMaxRounds] = useState(12);
  const [routeBusy, setRouteBusy] = useState(false);
  const [routeCampaignId, setRouteCampaignId] = useState<string | null>(null);
  const [routeSnapshot, setRouteSnapshot] = useState<RouteMeasurementSnapshot | null>(null);
  const [routeLabels, setRouteLabels] = useState<Record<string, string>>({});
  const routeCampaignRef = useRef<string | null>(null);
  const disposedRef = useRef(false);
  const udpSummary = useMemo(() => parseUdpSummary(udpResult?.stdout), [udpResult]);

  useEffect(() => {
    if (!routeCampaignId || routeSnapshot?.running === false) return;
    let disposed = false;
    async function refresh() {
      try {
        const snapshot = await invoke<RouteMeasurementSnapshot>("get_native_route_measurement_snapshot", {
          request: { campaignId: routeCampaignId },
        });
        if (!disposed) setRouteSnapshot(snapshot);
      } catch (error) {
        if (!disposed) showToast(formatRouteError(error));
      }
    }
    const timer = window.setInterval(() => void refresh(), 1000);
    void refresh();
    return () => {
      disposed = true;
      window.clearInterval(timer);
    };
  }, [routeCampaignId, routeSnapshot?.running, showToast]);

  useEffect(() => () => {
    disposedRef.current = true;
    const campaignId = routeCampaignRef.current;
    if (campaignId && isDesktopRuntime()) {
      void invoke("stop_native_route_measurement", { request: { campaignId } });
    }
  }, []);

  async function ensureDesktop() {
    if (isDesktopRuntime()) return true;
    showToast("网络诊断只在桌面应用中运行");
    return false;
  }

  async function runTrace() {
    if (!(await ensureDesktop())) return;
    setBusy(true);
    setTraceResult(null);
    try {
      setTraceResult(await invoke<TraceResult>("trace_route", { request: { host: traceHost, maxHops } }));
    } catch (error) {
      showToast(formatRouteError(error));
    } finally {
      setBusy(false);
    }
  }

  async function runDownload() {
    if (!(await ensureDesktop())) return;
    setBusy(true);
    setDownloadResult(null);
    try {
      setDownloadResult(await invoke<DownloadResult>("download_speed_test", {
        request: { url: downloadUrl, timeoutSecs: downloadTimeout, maxDownloadMb: downloadLimit },
      }));
    } catch (error) {
      showToast(String(error));
    } finally {
      setBusy(false);
    }
  }

  async function runUdp() {
    if (!(await ensureDesktop())) return;
    const estimatedMb = Math.ceil(udpBandwidth * udpDuration / 8);
    const { confirm } = await import("@tauri-apps/plugin-dialog");
    const approved = await confirm(`测试方向：${udpReverse ? "VPS 到本机" : "本机到 VPS"}\n目标：${udpHost}:${udpPort}\n按设定带宽最多约传输 ${estimatedMb} MB，继续吗？`, {
      title: "确认 UDP 测速",
      kind: "warning",
    });
    if (!approved) return;
    setBusy(true);
    setUdpResult(null);
    try {
      setUdpResult(await invoke<UdpResult>("udp_speed_test", {
        request: { host: udpHost, port: udpPort, durationSecs: udpDuration, bandwidthMbps: udpBandwidth, reverse: udpReverse },
      }));
    } catch (error) {
      showToast(String(error));
    } finally {
      setBusy(false);
    }
  }

  async function copyServerCommand() {
    await navigator.clipboard.writeText(`iperf3 -s -p ${udpPort}`);
    showToast("iperf3 服务端命令已复制");
  }

  async function startRouteMeasurement() {
    if (!(await ensureDesktop())) return;
    setRouteBusy(true);
    try {
      const options = buildRouteMeasurementOptions();
      if (!options.length) throw new Error("当前主机没有可测量的原生路线");
      const campaignId = crypto.randomUUID();
      const snapshot = await invoke<RouteMeasurementSnapshot>("start_native_route_measurement", {
        request: {
          campaignId,
          intervalSeconds: routeInterval,
          windowSize: routeWindow,
          maxRounds: routeMaxRounds,
          candidates: options.map(({ candidateId, route }) => ({ candidateId, route })),
        },
      });
      if (disposedRef.current) {
        await invoke("stop_native_route_measurement", { request: { campaignId } }).catch(() => undefined);
        return;
      }
      setRouteLabels(Object.fromEntries(options.map(({ candidateId, label }) => [candidateId, label])));
      routeCampaignRef.current = campaignId;
      setRouteCampaignId(campaignId);
      setRouteSnapshot(snapshot);
    } catch (error) {
      showToast(formatRouteError(error));
    } finally {
      setRouteBusy(false);
    }
  }

  async function stopRouteMeasurement(silent = false) {
    const campaignId = routeCampaignRef.current;
    if (!campaignId) return;
    setRouteBusy(true);
    try {
      await invoke("stop_native_route_measurement", { request: { campaignId } });
    } catch (error) {
      if (!silent) showToast(formatRouteError(error));
    } finally {
      routeCampaignRef.current = null;
      setRouteCampaignId(null);
      setRouteSnapshot((current) => current ? { ...current, running: false, sampling: false } : null);
      setRouteBusy(false);
    }
  }

  async function closeDialog() {
    await stopRouteMeasurement(true);
    onClose();
  }

  const selectedRouteLabel = routeSnapshot?.selectedCandidateId
    ? routeLabels[routeSnapshot.selectedCandidateId] ?? routeSnapshot.selectedCandidateId
    : null;

  return (
    <Dialog title="网络诊断" wide onClose={() => void closeDialog()} footer={<button className="secondary-button" type="button" onClick={() => void closeDialog()}>关闭</button>}>
      <div className="network-mode-picker" role="tablist" aria-label="诊断类型">
        <button className={mode === "trace" ? "active" : ""} type="button" onClick={() => setMode("trace")}><Route size={17} /><span>路由追踪</span></button>
        <button className={mode === "download" ? "active" : ""} type="button" onClick={() => setMode("download")}><ArrowDownToLine size={17} /><span>HTTP 下载</span></button>
        <button className={mode === "udp" ? "active" : ""} type="button" onClick={() => setMode("udp")}><ArrowLeftRight size={17} /><span>本机 ↔ VPS UDP</span></button>
        <button className={mode === "route" ? "active" : ""} type="button" onClick={() => setMode("route")}><Waypoints size={17} /><span>路线评估</span></button>
      </div>

      {mode === "trace" ? (
        <form className="network-tool-form" onSubmit={(event) => { event.preventDefault(); void runTrace(); }}>
          <div className="form-grid">
            <label className="field span-2"><span>目标域名或 IP</span><input value={traceHost} onChange={(event) => setTraceHost(event.target.value)} required /></label>
            <label className="field"><span>最大跳数</span><input type="number" min="1" max="64" value={maxHops} onChange={(event) => setMaxHops(Number(event.target.value))} /></label>
            <button className="primary-button network-run" type="submit" disabled={busy}>{busy ? <RefreshCw className="spin" size={14} /> : <Network size={14} />} 开始</button>
          </div>
          {traceResult ? <pre className="diagnostic-output"><code>{traceResult.stdout || traceResult.stderr || "没有输出"}</code></pre> : null}
        </form>
      ) : null}

      {mode === "download" ? (
        <form className="network-tool-form" onSubmit={(event) => { event.preventDefault(); void runDownload(); }}>
          <div className="form-grid">
            <label className="field full"><span>测速文件 URL</span><input type="url" value={downloadUrl} onChange={(event) => setDownloadUrl(event.target.value)} placeholder="https://你的站点/test.bin" required /></label>
            <label className="field"><span>最大下载量 (MB)</span><input type="number" min="1" max="1024" value={downloadLimit} onChange={(event) => setDownloadLimit(Number(event.target.value))} /></label>
            <label className="field"><span>超时 (秒)</span><input type="number" min="1" max="300" value={downloadTimeout} onChange={(event) => setDownloadTimeout(Number(event.target.value))} /></label>
            <button className="primary-button network-run span-2" type="submit" disabled={busy}>{busy ? <RefreshCw className="spin" size={14} /> : <Gauge size={14} />} 开始下载测速</button>
          </div>
          {downloadResult ? (
            <div className="speed-result" role="status">
              <span><b>{downloadResult.megabitsPerSecond.toFixed(2)}</b><small>Mbps</small></span>
              <span><b>{formatBytes(downloadResult.bytesDownloaded)}</b><small>已下载</small></span>
              <span><b>{(downloadResult.durationMs / 1000).toFixed(2)} s</b><small>耗时</small></span>
              <span><b>{downloadResult.status}</b><small>HTTP</small></span>
            </div>
          ) : null}
        </form>
      ) : null}

      {mode === "udp" ? (
        <form className="network-tool-form" onSubmit={(event) => { event.preventDefault(); void runUdp(); }}>
          <div className="iperf-server-command">
            <Activity size={16} /><span>测速 VPS 先运行 <code>iperf3 -s -p {udpPort}</code></span>
            <button className="icon-button compact" type="button" title="复制服务端命令" onClick={() => void copyServerCommand()}><Copy size={14} /></button>
          </div>
          <div className="form-grid">
            <label className="field span-2"><span>测速 VPS 地址</span><input value={udpHost} onChange={(event) => setUdpHost(event.target.value)} required /></label>
            <label className="field"><span>端口</span><input type="number" min="1" max="65535" value={udpPort} onChange={(event) => setUdpPort(Number(event.target.value))} /></label>
            <label className="field"><span>时长 (秒)</span><input type="number" min="1" max="60" value={udpDuration} onChange={(event) => setUdpDuration(Number(event.target.value))} /></label>
            <label className="field span-2"><span>目标带宽 (Mbps)</span><input type="number" min="1" max="10000" value={udpBandwidth} onChange={(event) => setUdpBandwidth(Number(event.target.value))} /></label>
            <label className="direction-toggle span-2"><input type="checkbox" checked={udpReverse} onChange={(event) => setUdpReverse(event.target.checked)} /><ArrowLeftRight size={15} /><span>{udpReverse ? "反向：VPS → 本机" : "正向：本机 → VPS"}</span></label>
            <button className="primary-button network-run full" type="submit" disabled={busy}>{busy ? <RefreshCw className="spin" size={14} /> : <Gauge size={14} />} 开始 UDP 测速</button>
          </div>
          {udpResult ? (
            <>
              {udpSummary ? <div className="speed-result" role="status"><span><b>{udpSummary.mbps?.toFixed(2) ?? "-"}</b><small>Mbps</small></span><span><b>{udpSummary.jitterMs?.toFixed(2) ?? "-"}</b><small>抖动 ms</small></span><span><b>{udpSummary.lostPercent?.toFixed(2) ?? "-"}%</b><small>丢包</small></span><span><b>{(udpResult.durationMs / 1000).toFixed(1)} s</b><small>总耗时</small></span></div> : null}
              <pre className="diagnostic-output"><code>{udpResult.stdout || udpResult.stderr || "没有输出"}</code></pre>
            </>
          ) : null}
        </form>
      ) : null}

      {mode === "route" ? (
        <div className="network-tool-form route-measurement-panel">
          <div className="form-grid route-measurement-controls">
            <label className="field"><span>间隔 (秒)</span><input type="number" min="30" max="300" value={routeInterval} disabled={Boolean(routeCampaignId)} onChange={(event) => setRouteInterval(Number(event.target.value))} /></label>
            <label className="field"><span>滚动窗口 (轮)</span><input type="number" min="3" max="20" value={routeWindow} disabled={Boolean(routeCampaignId)} onChange={(event) => { const value = Number(event.target.value); setRouteWindow(value); setRouteMaxRounds((current) => Math.max(current, value)); }} /></label>
            <label className="field"><span>最多轮数</span><input type="number" min={routeWindow} max="120" value={routeMaxRounds} disabled={Boolean(routeCampaignId)} onChange={(event) => setRouteMaxRounds(Number(event.target.value))} /></label>
            {routeCampaignId ? (
              <button className="secondary-button network-run" type="button" disabled={routeBusy} onClick={() => void stopRouteMeasurement()}><Square size={14} /> 停止</button>
            ) : (
              <button className="primary-button network-run" type="button" disabled={routeBusy} onClick={() => void startRouteMeasurement()}>{routeBusy ? <RefreshCw className="spin" size={14} /> : <Play size={14} />} 开始</button>
            )}
          </div>
          {routeSnapshot ? (
            <>
              <div className="route-measurement-summary" role="status">
                <div><span>推荐</span><strong>{selectedRouteLabel ?? "等待基线"}</strong><small>{selectionReasonLabels[routeSnapshot.selectionReasonCode] ?? routeSnapshot.selectionReasonCode}</small></div>
                <div><span>进度</span><strong>{routeSnapshot.completedRounds} / {routeSnapshot.maxRounds}</strong><small>{routeSnapshot.sampling ? "正在执行完整 SSH/SFTP probe" : routeSnapshot.running ? "等待下一轮" : "已停止"}</small></div>
              </div>
              <div className="route-measurement-table">
                <div className="route-measurement-heading"><span>候选</span><span>成功率</span><span>中位数</span><span>P95</span><span>评分</span></div>
                {routeSnapshot.candidates.map((candidate) => (
                  <div className={`route-measurement-row ${candidate.candidateId === routeSnapshot.selectedCandidateId ? "selected" : ""}`} key={candidate.candidateId}>
                    <span><strong>{routeLabels[candidate.candidateId] ?? candidate.candidateId}</strong><small>{candidate.status === "failed" ? `${candidate.lastErrorHopIndex ? `第 ${candidate.lastErrorHopIndex} 跳 · ` : ""}${candidate.lastErrorCode ?? "probe-failed"}` : `${candidate.successfulSamples}/${candidate.sampleCount} 就绪`}</small></span>
                    <b>{candidate.sampleCount ? `${candidate.successRatePercent}%` : "-"}</b>
                    <b>{formatRouteDuration(candidate.medianDurationMs)}</b>
                    <b>{formatRouteDuration(candidate.p95DurationMs)}</b>
                    <b>{formatRouteDuration(candidate.scoreMs)}</b>
                  </div>
                ))}
              </div>
            </>
          ) : null}
        </div>
      ) : null}
    </Dialog>
  );
}
