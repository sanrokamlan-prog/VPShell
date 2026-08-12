export type EnvironmentKind = "production" | "staging" | "development";
export type ConnectionState = "idle" | "connecting" | "connected" | "closed" | "error";
export type ScriptRisk = "low" | "medium" | "high" | "destructive";
export type SyncProviderKind = "local" | "webdav" | "sftp" | "s3" | "gateway";

export interface HostProfile {
  id: string;
  name: string;
  group: string;
  host: string;
  port: number;
  username: string;
  environment: EnvironmentKind;
  tags: string[];
  identityFile?: string;
  credentialRef?: string;
  androidKeyRef?: string;
  androidKeyPassphraseRef?: string;
  hostKeySha256?: string;
  source?: "manual" | "finalshell" | "openssh" | "putty" | "xshell" | "securecrt" | "mobaxterm" | "tabby" | "termius";
  lastPath?: string;
  latency?: number;
}

export interface TerminalSession {
  id: string;
  hostId: string;
  title: string;
  state: ConnectionState;
  currentPath: string;
  reportedHostname?: string;
  contextSource: "profile" | "shell-integration";
  contextStack?: Array<{
    hostname: string;
    username: string;
    cwd: string;
  }>;
}

export interface ScriptRecipe {
  id: string;
  title: string;
  description: string;
  category: string;
  command?: string;
  sourceUrl: string;
  risk: ScriptRisk;
  custom?: boolean;
  parameters?: string[];
}

export interface CommandParameter {
  name: string;
  label: string;
  placeholder?: string;
  defaultValue?: string;
  required?: boolean;
}

export interface CommandRecipe {
  id: string;
  title: string;
  description: string;
  category: string;
  command?: string;
  usage: string;
  keywords: string[];
  risk: ScriptRisk;
  action?: "install-public-key" | "trace-route" | "speed-test" | "udp-speed-test";
  parameters?: CommandParameter[];
  custom?: boolean;
}

export interface SshKeyProfile {
  id: string;
  name: string;
  algorithm: "ed25519" | "rsa4096";
  privateKeyPath: string;
  publicKeyPath: string;
  fingerprint: string;
  passphraseRef?: string;
}

export interface CommandHistoryItem {
  id: string;
  command: string;
  hostId: string;
  path: string;
  createdAt: string;
}

export interface ConnectionHistoryItem {
  id: string;
  hostId: string;
  connectedAt: string;
  path: string;
}

export interface DeletedHostItem {
  id: string;
  host: HostProfile;
  deletedAt: string;
  expiresAt: string;
  commandHistory: CommandHistoryItem[];
  connectionHistory: ConnectionHistoryItem[];
  pathHistory: string[];
}

export interface SyncSettings {
  enabled: boolean;
  provider: SyncProviderKind;
  endpoint: string;
  remotePath: string;
  username: string;
  lastSyncedAt?: string;
  totpEnabled: boolean;
  syncSecrets: boolean;
}

export interface WallpaperSettings {
  source: "none" | "local" | "url";
  value: string;
  opacity: number;
}

export interface TerminalAppearanceSettings {
  fontFamily: string;
  fontSize: number;
  lineHeight: number;
  customFontName?: string;
}

export interface ApplicationSettings {
  externalEditorPath: string;
  autoUploadEditedFiles: boolean;
  packageTransfersEnabled: boolean;
}

export interface AppState {
  hosts: HostProfile[];
  deletedHosts: DeletedHostItem[];
  scripts: ScriptRecipe[];
  commands: CommandRecipe[];
  sshKeys: SshKeyProfile[];
  commandHistory: CommandHistoryItem[];
  connectionHistory: ConnectionHistoryItem[];
  pathHistory: Record<string, string[]>;
  sync: SyncSettings;
  wallpaper: WallpaperSettings;
  terminalAppearance: TerminalAppearanceSettings;
  settings: ApplicationSettings;
  onboardingCompleted: boolean;
}
