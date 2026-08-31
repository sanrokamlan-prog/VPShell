import { invoke } from "@tauri-apps/api/core";

export interface AndroidSecurityStatus {
  available: boolean;
  enabled: boolean;
  locked: boolean;
  generation: number;
  code?: string;
}

interface AndroidVisibilityBridge {
  postMessage: (message: "show" | "hide" | "failed") => void;
}

declare global {
  interface Window {
    vpshellVisibility?: AndroidVisibilityBridge;
  }
}

export function postAndroidVisibility(action: "show" | "hide" | "failed") {
  window.vpshellVisibility?.postMessage(action);
}

export function requestAndroidSecurity(
  action: "status" | "setEnabled" | "unlock",
  enabled?: boolean,
): Promise<AndroidSecurityStatus> {
  if (action === "status") {
    return invoke<AndroidSecurityStatus>("android_security_status");
  }
  if (action === "setEnabled") {
    return invoke<AndroidSecurityStatus>("android_set_biometric_enabled", { enabled });
  }
  return invoke<AndroidSecurityStatus>("android_unlock");
}
