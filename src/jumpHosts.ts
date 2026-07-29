import type { HostProfile, JumpMode } from "./types";

export type { JumpMode } from "./types";

export interface JumpRouteSettings {
  defaultJumpHostId?: string;
}

export interface JumpRouteHop {
  source: "profile" | "custom";
  address: string;
  label: string;
  hostId?: string;
  host?: string;
  port?: number;
  username?: string;
}

export interface ResolvedJumpRoute {
  /** A value suitable for passing as the single argument after OpenSSH `-J`. */
  proxyJump?: string;
  hops: JumpRouteHop[];
}

type JumpAwareHost = HostProfile & {
  jumpMode?: JumpMode;
  jumpHostId?: string;
};

const MAX_JUMPS = 4;

function describeHost(host: HostProfile): string {
  return `“${host.name || host.id}”`;
}

function hostAddress(host: HostProfile): string {
  const hostname = host.host.trim();
  const username = host.username.trim();
  const port = host.port;

  if (!hostname) {
    throw new Error(`主机${describeHost(host)}缺少地址，无法作为跳板机。`);
  }
  if (!username) {
    throw new Error(`主机${describeHost(host)}缺少用户名，无法作为跳板机。`);
  }
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`主机${describeHost(host)}的 SSH 端口无效，无法作为跳板机。`);
  }

  const formattedHost = hostname.includes(":") && !hostname.startsWith("[")
    ? `[${hostname}]`
    : hostname;
  return `${username}@${formattedHost}:${port}`;
}

function profileHop(host: HostProfile): JumpRouteHop {
  return {
    source: "profile",
    address: hostAddress(host),
    label: host.name || host.host,
    hostId: host.id,
    host: host.host,
    port: host.port,
    username: host.username,
  };
}

function comparableAddresses(host: HostProfile): Set<string> {
  const hostname = host.host.trim().toLowerCase();
  const username = host.username.trim().toLowerCase();
  const formattedHost = hostname.includes(":") && !hostname.startsWith("[")
    ? `[${hostname}]`
    : hostname;
  const values = new Set<string>([
    host.id.trim().toLowerCase(),
    hostname,
    formattedHost,
    `${hostname}:${host.port}`,
    `${formattedHost}:${host.port}`,
  ]);

  if (username) {
    values.add(`${username}@${hostname}`);
    values.add(`${username}@${formattedHost}`);
    values.add(`${username}@${hostname}:${host.port}`);
    values.add(`${username}@${formattedHost}:${host.port}`);
  }
  return values;
}

function customHops(
  value: string,
  currentHost: HostProfile,
  upstreamHosts: readonly HostProfile[],
): JumpRouteHop[] {
  const raw = value.trim();
  if (!raw) {
    throw new Error(`主机${describeHost(currentHost)}选择了自定义跳板，但未填写 ProxyJump 地址。`);
  }

  const parts = raw.split(",").map((part) => part.trim());
  if (parts.some((part) => !part)) {
    throw new Error(`主机${describeHost(currentHost)}的自定义 ProxyJump 含有空跳点。`);
  }
  if (parts.length > MAX_JUMPS) {
    throw new Error(`跳板链最多允许 ${MAX_JUMPS} 跳，当前自定义链包含 ${parts.length} 跳。`);
  }

  const upstreamAddresses = upstreamHosts.map((host) => ({
    host,
    addresses: comparableAddresses(host),
  }));
  return parts.map((address) => {
    if (/\s|[\u0000-\u001f\u007f]/u.test(address) || address.startsWith("-")) {
      throw new Error(`主机${describeHost(currentHost)}的自定义跳点“${address}”格式不安全。`);
    }
    const referencedUpstream = upstreamAddresses.find(({ addresses }) => (
      addresses.has(address.toLowerCase())
    ));
    if (referencedUpstream) {
      if (referencedUpstream.host.id === currentHost.id) {
        throw new Error(`主机${describeHost(currentHost)}不能把自己配置为跳板机。`);
      }
      throw new Error(
        `自定义跳点“${address}”指回上游主机${describeHost(referencedUpstream.host)}，形成跳板链循环。`,
      );
    }
    return {
      source: "custom" as const,
      address,
      label: address,
    };
  });
}

function configuredMode(host: JumpAwareHost): JumpMode {
  if (host.jumpMode) {
    return host.jumpMode;
  }
  // Old profiles stored their complete OpenSSH -J value directly in proxyJump.
  return host.proxyJump?.trim() ? "custom" : "inherit";
}

/**
 * Resolve the complete, ordered jump chain for a target host.
 *
 * `inherit` without a configured default means an explicitly direct route.
 * Invalid references and cycles always throw; they never downgrade to direct.
 */
export function resolveJumpRoute(
  target: HostProfile,
  hosts: readonly HostProfile[],
  settings: JumpRouteSettings,
): ResolvedJumpRoute {
  const byId = new Map<string, JumpAwareHost>();
  for (const item of hosts) {
    if (byId.has(item.id)) {
      throw new Error(`主机 ID“${item.id}”重复，无法可靠解析跳板链。`);
    }
    byId.set(item.id, item as JumpAwareHost);
  }

  const listedTarget = byId.get(target.id);
  if (!listedTarget) {
    throw new Error(`目标主机${describeHost(target)}不在主机列表中，无法解析跳板链。`);
  }

  const defaultJumpHostId = settings.defaultJumpHostId?.trim() || undefined;
  if (defaultJumpHostId && !byId.has(defaultJumpHostId)) {
    throw new Error(`默认跳板机引用“${defaultJumpHostId}”不存在，请先修正设置。`);
  }

  const resolving: string[] = [];

  const resolveFor = (host: JumpAwareHost): JumpRouteHop[] => {
    const cycleStart = resolving.indexOf(host.id);
    if (cycleStart >= 0) {
      const cycleIds = [...resolving.slice(cycleStart), host.id];
      const cycleNames = cycleIds.map((id) => byId.get(id)?.name || id);
      throw new Error(`检测到跳板链循环：${cycleNames.join(" -> ")}。`);
    }

    resolving.push(host.id);
    try {
      const mode = configuredMode(host);
      if (mode === "direct") {
        return [];
      }
      if (mode === "inherit" && host.id === defaultJumpHostId) {
        return [];
      }
      if (mode === "custom") {
        const upstreamHosts = resolving
          .map((id) => byId.get(id))
          .filter((item): item is JumpAwareHost => item !== undefined);
        return customHops(host.proxyJump || "", host, upstreamHosts);
      }

      const referencedId = mode === "host"
        ? host.jumpHostId?.trim()
        : defaultJumpHostId;

      if (!referencedId) {
        if (mode === "inherit") {
          return [];
        }
        throw new Error(`主机${describeHost(host)}选择了指定跳板机，但未选择主机。`);
      }
      if (referencedId === host.id) {
        const kind = mode === "inherit" ? "默认跳板机" : "跳板机";
        throw new Error(`主机${describeHost(host)}不能把自己设为${kind}。`);
      }

      const referenced = byId.get(referencedId);
      if (!referenced) {
        const kind = mode === "inherit" ? "默认跳板机" : "跳板机";
        throw new Error(`主机${describeHost(host)}引用的${kind}“${referencedId}”不存在。`);
      }

      const hops = [...resolveFor(referenced), profileHop(referenced)];
      if (hops.length > MAX_JUMPS) {
        throw new Error(`跳板链最多允许 ${MAX_JUMPS} 跳，解析结果已有 ${hops.length} 跳。`);
      }
      return hops;
    } finally {
      resolving.pop();
    }
  };

  const hops = resolveFor(listedTarget);
  if (hops.length > MAX_JUMPS) {
    throw new Error(`跳板链最多允许 ${MAX_JUMPS} 跳，解析结果已有 ${hops.length} 跳。`);
  }

  return {
    proxyJump: hops.length ? hops.map((hop) => hop.address).join(",") : undefined,
    hops,
  };
}
