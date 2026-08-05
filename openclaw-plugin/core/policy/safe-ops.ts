const SAFE_READ_COMMAND_PATTERNS = [
  /^(?:pwd|whoami|id|hostname|date|uptime)$/i,
  /^uname\s+-a$/i,
  /^free(?:\s+-h)?$/i,
  /^df(?:\s+-h)?(?:\s+(?:\/|\/home|\.)){0,3}$/i,
  /^df\s+-h\s+--total$/i,
  /^df\s+-h\s+--output=[a-z,]+\s+(?:-x\s+\w+\s*){0,4}(?:\/|\/home|\.)?$/i,
  /^du\s+-sh(?:\s+\.?)?$/i,
  /^ls(?:\s+-(?:l|a|la|al))?(?:\s+\.?)?$/i,
  /^find\s+\.?\s+-maxdepth\s+[0-3](?:\s+-type\s+[fd])?(?:\s+-name\s+["']?[A-Za-z0-9_.@* -]{1,80}["']?)?$/i,
  /^stat\s+[-\w./~*]+$/i,
  /^wc\s+[-\w\s./~*]+$/i,
  /^rg\s+--?[A-Za-z0-9_-]+(?:\s+--?[A-Za-z0-9_-]+)*\s+[A-Za-z0-9_.@-]{1,80}(?:\s+[-\w./~*]+)?$/i,
  /^rg\s+["']?[^"';&|<>`$]{1,120}["']?(?:\s+[-\w./~*]+)?$/i,
  /^cat\s+\/etc\/(?:os-release|issue|hostname|hosts)$/i,
  /^(?:cat|head|tail)\s+\/proc\/(?:cpuinfo|meminfo|loadavg|uptime)$/i,
  /^(?:echo|printf)\s+["'][^"']{0,160}["']$/i,
  /^(?:echo|printf)\s+[A-Za-z0-9 _:=./-]{0,160}$/i,
  /^echo$/i,
];

const PIPELESS_TEXT_COMMANDS = new Set(["pwd", "whoami", "id", "hostname", "date", "uptime"]);

export function isLowRiskShellReadCommand(command: string): boolean {
  const trimmed = command.trim().replace(/\s+(?:1|2)?>\s*\/dev\/null\b/g, "");
  if (!trimmed) return false;
  if (/[`$<>]/.test(trimmed)) return false;
  if (/(^|[^|])\|([^|]|$)/.test(trimmed)) return false;
  const segments = trimmed
    .split(/\s*(?:&&|\|\||;)\s*/)
    .map((item) => item.trim())
    .filter(Boolean);
  if (!segments.length || segments.length > 16) return false;
  return segments.every(isLowRiskShellReadSegment);
}

export function isLowRiskShellReadSegment(segment: string): boolean {
  const normalized = segment.trim();
  if (!normalized) return false;
  if (PIPELESS_TEXT_COMMANDS.has(normalized.toLowerCase())) return true;
  return SAFE_READ_COMMAND_PATTERNS.some((pattern) => pattern.test(normalized));
}

export function isSafeSystemReadPath(path: string): boolean {
  const normalized = path.replace(/\\/g, "/").toLowerCase();
  return [
    "/etc/os-release",
    "/etc/issue",
    "/etc/hostname",
    "/etc/hosts",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/loadavg",
    "/proc/uptime",
  ].includes(normalized);
}
