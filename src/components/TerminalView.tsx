import { useEffect, useRef } from "react";
import type { CSSProperties } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import type { HostProfile, TerminalAppearanceSettings, TerminalSession, WallpaperSettings } from "../types";

interface TerminalViewProps {
  session: TerminalSession;
  host: HostProfile;
  wallpaper: WallpaperSettings;
  appearance: TerminalAppearanceSettings;
  appearanceRevision: number;
  androidTerminalId?: string;
  onDisconnected: (sessionId: string, message?: string) => void;
  onContextChanged: (
    sessionId: string,
    stack: Array<{ hostname: string; username: string; cwd: string }>,
    warning?: string,
  ) => void;
}

interface TerminalOutputEvent {
  sessionId: string;
  data: string;
  deliveryId?: number;
}

interface TerminalExitEvent {
  sessionId: string;
  message?: string;
}

interface TerminalContextEvent {
  sessionId: string;
  stack: Array<{ hostname: string; username: string; cwd: string }>;
  warning?: string;
}

function decodeBase64(value: string) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function encodeBase64(value: string) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function welcomeText(host: HostProfile) {
  if (!host.host) {
    return [
      "\x1b[38;2;121;208;149mVPShell workspace\x1b[0m",
      "",
      "请从左侧添加或导入主机配置，然后点击连接。",
    ].join("\r\n");
  }
  return [
    "\x1b[38;2;121;208;149mVPShell workspace\x1b[0m",
    `Profile: ${host.name}  ${host.username}@${host.host}:${host.port}`,
    `Route: local > ${host.host}`,
    "",
    "This preview is offline. Connect to start the selected SSH engine.",
    "",
    `\x1b[38;2;121;208;149m${host.username}@${host.name.toLowerCase().split(" ").join("-")}\x1b[0m:\x1b[38;2;100;165;230m${host.lastPath ?? "~"}\x1b[0m$ `,
  ].join("\r\n");
}

export function TerminalView({ session, host, wallpaper, appearance, appearanceRevision, androidTerminalId, onDisconnected, onContextChanged }: TerminalViewProps) {
  const terminalElementRef = useRef<HTMLDivElement>(null);
  const connectionStateRef = useRef(session.state);
  const terminalRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const nativeDeliveryRef = useRef({ last: 0, pending: new Set<number>() });

  useEffect(() => {
    connectionStateRef.current = session.state;
    if (session.state === "connecting") {
      nativeDeliveryRef.current.last = 0;
      nativeDeliveryRef.current.pending.clear();
    }
  }, [session.state]);

  useEffect(() => {
    const terminal = terminalRef.current;
    if (!terminal) return;
    terminal.options.fontFamily = `"${appearance.fontFamily}", "Cascadia Code", Consolas, monospace`;
    terminal.options.fontSize = appearance.fontSize;
    terminal.options.lineHeight = appearance.lineHeight;
    fitAddonRef.current?.fit();
  }, [appearance.fontFamily, appearance.fontSize, appearance.lineHeight, appearanceRevision]);

  useEffect(() => {
    const element = terminalElementRef.current;
    if (!element) return;

    const terminal = new Terminal({
      allowProposedApi: false,
      allowTransparency: true,
      convertEol: false,
      cursorBlink: true,
      cursorStyle: "bar",
      fontFamily: `"${appearance.fontFamily}", "Cascadia Code", Consolas, monospace`,
      fontSize: appearance.fontSize,
      lineHeight: appearance.lineHeight,
      scrollback: 250_000,
      theme: {
        background: "rgba(11, 14, 13, 0.88)",
        foreground: "#d9ddd9",
        cursor: "#79d095",
        cursorAccent: "#101311",
        selectionBackground: "rgba(121, 208, 149, 0.26)",
        black: "#161a18",
        red: "#ef7d78",
        green: "#79d095",
        yellow: "#e0bb6a",
        blue: "#72a5dc",
        magenta: "#c395cc",
        cyan: "#73c7c3",
        white: "#d9ddd9",
        brightBlack: "#6f7772",
        brightRed: "#ff9a94",
        brightGreen: "#98e3ad",
        brightYellow: "#f0cf88",
        brightBlue: "#92bdec",
        brightMagenta: "#d9afe0",
        brightCyan: "#94ddd9",
        brightWhite: "#ffffff",
      },
    });
    const fitAddon = new FitAddon();
    terminalRef.current = terminal;
    fitAddonRef.current = fitAddon;
    terminal.loadAddon(fitAddon);
    terminal.open(element);
    fitAddon.fit();

    if (connectionStateRef.current !== "connected") {
      terminal.write(welcomeText(host));
    }

    let previewLine = "";
    const dataDisposable = terminal.onData((data) => {
      if (connectionStateRef.current === "connected" && androidTerminalId) {
        void invoke("android_write_terminal", {
          request: {
            sessionId: session.id,
            terminalId: androidTerminalId,
            dataBase64: encodeBase64(data),
          },
        }).catch((error) => onDisconnected(session.id, String(error)));
        return;
      }
      if (connectionStateRef.current === "connected" && "__TAURI_INTERNALS__" in window) {
        void invoke("write_terminal", { sessionId: session.id, data }).catch((error) => {
          onDisconnected(session.id, String(error));
        });
        return;
      }

      if (data === "\r") {
        terminal.write("\r\n");
        if (previewLine.trim() === "clear") {
          terminal.clear();
        } else if (previewLine.trim()) {
          terminal.write("\x1b[38;2;111;119;114m预览模式未连接远程主机\x1b[0m\r\n");
        }
        previewLine = "";
        terminal.write(`\x1b[38;2;121;208;149m${host.username}@${host.name.toLowerCase().split(" ").join("-")}\x1b[0m:\x1b[38;2;100;165;230m${host.lastPath ?? "~"}\x1b[0m$ `);
      } else if (data === "\u007f") {
        if (previewLine.length > 0) {
          previewLine = previewLine.slice(0, -1);
          terminal.write("\b \b");
        }
      } else if (data >= " ") {
        previewLine += data;
        terminal.write(data);
      }
    });

    let disposed = false;
    let stopOutputListener: (() => void) | undefined;
    let stopExitListener: (() => void) | undefined;
    let stopContextListener: (() => void) | undefined;
    let androidPollTimer: number | undefined;

    if (androidTerminalId) {
      const poll = async () => {
        if (disposed || connectionStateRef.current !== "connected") return;
        try {
          const output = await invoke<{ dataBase64: string; eof: boolean }>("android_read_terminal", {
            request: { sessionId: session.id, terminalId: androidTerminalId },
          });
          if (disposed) return;
          if (output.dataBase64) terminal.write(decodeBase64(output.dataBase64));
          if (output.eof) {
            onDisconnected(session.id, "Android SSH 终端已关闭");
            return;
          }
        } catch (error) {
          if (disposed) return;
          if (!String(error).includes("超时")) {
            onDisconnected(session.id, String(error));
            return;
          }
        }
        androidPollTimer = window.setTimeout(() => void poll(), 25);
      };
      void poll();
    } else if ("__TAURI_INTERNALS__" in window) {
      void import("@tauri-apps/api/event").then(async ({ listen }) => {
        if (disposed) return;
        const outputListener = await listen<TerminalOutputEvent>("terminal-output", (event) => {
          if (event.payload.sessionId === session.id) {
            const deliveryId = event.payload.deliveryId;
            if (deliveryId !== undefined) {
              if (deliveryId <= nativeDeliveryRef.current.last) {
                void invoke("ack_native_terminal_output", {
                  sessionId: session.id,
                  deliveryId,
                }).catch(() => undefined);
                return;
              }
              if (nativeDeliveryRef.current.pending.has(deliveryId)) return;
              nativeDeliveryRef.current.pending.add(deliveryId);
            }
            terminal.write(decodeBase64(event.payload.data), () => {
              if (deliveryId === undefined) return;
              nativeDeliveryRef.current.pending.delete(deliveryId);
              nativeDeliveryRef.current.last = Math.max(nativeDeliveryRef.current.last, deliveryId);
              void invoke("ack_native_terminal_output", {
                sessionId: session.id,
                deliveryId,
              }).catch(() => undefined);
            });
          }
        });
        if (disposed) {
          outputListener();
          return;
        }
        stopOutputListener = outputListener;
        const exitListener = await listen<TerminalExitEvent>("terminal-exit", (event) => {
          if (event.payload.sessionId === session.id) {
            terminal.write("\r\n\x1b[38;2;239;125;120m[连接已关闭]\x1b[0m\r\n");
            onDisconnected(session.id, event.payload.message);
          }
        });
        if (disposed) {
          exitListener();
          stopOutputListener?.();
          stopOutputListener = undefined;
          return;
        }
        stopExitListener = exitListener;
        const contextListener = await listen<TerminalContextEvent>("terminal-context", (event) => {
          if (event.payload.sessionId === session.id) {
            onContextChanged(session.id, event.payload.stack, event.payload.warning);
          }
        });
        if (disposed) {
          contextListener();
          stopOutputListener?.();
          stopExitListener?.();
          stopOutputListener = undefined;
          stopExitListener = undefined;
          return;
        }
        stopContextListener = contextListener;
      }).catch((error) => {
        if (!disposed) onDisconnected(session.id, String(error));
      });
    }

    const resizeObserver = new ResizeObserver(() => {
      fitAddon.fit();
      if (connectionStateRef.current === "connected" && androidTerminalId) {
        void invoke("android_resize_terminal", {
          request: { sessionId: session.id, terminalId: androidTerminalId, cols: terminal.cols, rows: terminal.rows },
        });
      } else if (connectionStateRef.current === "connected" && "__TAURI_INTERNALS__" in window) {
        void invoke("resize_terminal", {
          sessionId: session.id,
          cols: terminal.cols,
          rows: terminal.rows,
        });
      }
    });
    resizeObserver.observe(element);

    return () => {
      disposed = true;
      if (androidPollTimer !== undefined) window.clearTimeout(androidPollTimer);
      stopOutputListener?.();
      stopExitListener?.();
      stopContextListener?.();
      resizeObserver.disconnect();
      dataDisposable.dispose();
      terminal.dispose();
      if (terminalRef.current === terminal) terminalRef.current = null;
      if (fitAddonRef.current === fitAddon) fitAddonRef.current = null;
    };
  }, [androidTerminalId, host, onContextChanged, onDisconnected, session.id]);

  let backgroundImage: string | undefined;
  if (wallpaper.source !== "none" && wallpaper.value.startsWith("data:image/")) {
    try {
      backgroundImage = `url(${JSON.stringify(wallpaper.value)})`;
    } catch {
      backgroundImage = undefined;
    }
  }

  return (
    <div
      className="terminal-wallpaper"
      style={{
        backgroundImage,
        "--wallpaper-overlay": String(1 - wallpaper.opacity),
      } as CSSProperties}
      data-wallpaper-source={wallpaper.source}
    >
      <div ref={terminalElementRef} className="terminal-canvas" />
    </div>
  );
}
