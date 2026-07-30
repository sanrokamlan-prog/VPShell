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
  onDisconnected: (sessionId: string, message?: string) => void;
}

interface TerminalOutputEvent {
  sessionId: string;
  data: string;
}

interface TerminalExitEvent {
  sessionId: string;
  message?: string;
}

function decodeBase64(value: string) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
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
    "This preview is offline. Choose Connect to start the system OpenSSH session.",
    "",
    `\x1b[38;2;121;208;149m${host.username}@${host.name.toLowerCase().split(" ").join("-")}\x1b[0m:\x1b[38;2;100;165;230m${host.lastPath ?? "~"}\x1b[0m$ `,
  ].join("\r\n");
}

export function TerminalView({ session, host, wallpaper, appearance, appearanceRevision, onDisconnected }: TerminalViewProps) {
  const terminalElementRef = useRef<HTMLDivElement>(null);
  const connectionStateRef = useRef(session.state);
  const terminalRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);

  useEffect(() => {
    connectionStateRef.current = session.state;
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

    if ("__TAURI_INTERNALS__" in window) {
      void import("@tauri-apps/api/event").then(async ({ listen }) => {
        if (disposed) return;
        stopOutputListener = await listen<TerminalOutputEvent>("terminal-output", (event) => {
          if (event.payload.sessionId === session.id) {
            terminal.write(decodeBase64(event.payload.data));
          }
        });
        stopExitListener = await listen<TerminalExitEvent>("terminal-exit", (event) => {
          if (event.payload.sessionId === session.id) {
            terminal.write("\r\n\x1b[38;2;239;125;120m[连接已关闭]\x1b[0m\r\n");
            onDisconnected(session.id, event.payload.message);
          }
        });
      });
    }

    const resizeObserver = new ResizeObserver(() => {
      fitAddon.fit();
      if (connectionStateRef.current === "connected" && "__TAURI_INTERNALS__" in window) {
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
      stopOutputListener?.();
      stopExitListener?.();
      resizeObserver.disconnect();
      dataDisposable.dispose();
      terminal.dispose();
      if (terminalRef.current === terminal) terminalRef.current = null;
      if (fitAddonRef.current === fitAddon) fitAddonRef.current = null;
    };
  }, [host, onDisconnected, session.id]);

  let backgroundImage: string | undefined;
  if (wallpaper.source !== "none" && wallpaper.value) {
    try {
      if (wallpaper.source === "url") {
        const url = new URL(wallpaper.value);
        if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("Unsupported wallpaper URL");
      }
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
