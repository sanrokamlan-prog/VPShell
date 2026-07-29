import { useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Activity, ArrowDownToLine, ArrowLeftRight, Copy, Gauge, Network, RefreshCw, Route } from "lucide-react";
import { Dialog } from "./Dialog";

export type NetworkToolMode = "trace" | "download" | "udp";

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

interface NetworkToolsDialogProps {
  initialMode: NetworkToolMode;
  defaultHost: string;
  onClose: () => void;
  showToast: (message: string) => void;
}

function isDesktopRuntime() {
  return "__TAURI_INTERNALS__" in window;
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

export function NetworkToolsDialog({ initialMode, defaultHost, onClose, showToast }: NetworkToolsDialogProps) {
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
  const udpSummary = useMemo(() => parseUdpSummary(udpResult?.stdout), [udpResult]);

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
      showToast(String(error));
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

  return (
    <Dialog title="网络诊断" wide onClose={onClose} footer={<button className="secondary-button" type="button" onClick={onClose}>关闭</button>}>
      <div className="network-mode-picker" role="tablist" aria-label="诊断类型">
        <button className={mode === "trace" ? "active" : ""} type="button" onClick={() => setMode("trace")}><Route size={17} /><span>路由追踪</span></button>
        <button className={mode === "download" ? "active" : ""} type="button" onClick={() => setMode("download")}><ArrowDownToLine size={17} /><span>HTTP 下载</span></button>
        <button className={mode === "udp" ? "active" : ""} type="button" onClick={() => setMode("udp")}><ArrowLeftRight size={17} /><span>本机 ↔ VPS UDP</span></button>
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
    </Dialog>
  );
}
