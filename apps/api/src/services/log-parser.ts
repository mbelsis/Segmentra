/**
 * Parse firewall audit logs to extract communication flows
 */

export type FlowDirection = 'IN' | 'OUT' | 'FORWARD';

export interface ParsedLogEntry {
  timestamp: string;
  direction: FlowDirection;
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  sourcePort?: number;
  destinationPort?: number;
  action: string;
  /** Rule comment / baseline label from the "FW-AUDIT: <ACTION> <comment>: " prefix */
  ruleLabel?: string;
  /** Logged by the baseline established/related rule (reply traffic) */
  established?: boolean;
  /** Logged by the baseline loopback rule */
  loopback?: boolean;
  inInterface?: string;
  outInterface?: string;
  rawLine: string;
}

export interface CommunicationFlow {
  direction: FlowDirection;
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  sourcePort?: number;
  destinationPort?: number;
  count: number;
  firstSeen: string;
  lastSeen: string;
  /** True when the flow was only seen via the baseline established/related rule */
  established?: boolean;
  /** Kernel IN= / OUT= interface of the packets (part of the flow key; absent when not logged) */
  inInterface?: string;
  outInterface?: string;
}

/**
 * IP protocol numbers as the kernel logs them when it has no name (PROTO=2) → names. Only tcp, udp
 * and icmp (incl. ICMPv6, which the compiler maps per family) can be expressed in a policy rule; see
 * COMPILER_PROTOCOLS.
 */
const PROTOCOL_NUMBERS: Record<string, string> = {
  '1': 'icmp', '2': 'igmp', '4': 'ipip', '6': 'tcp', '17': 'udp', '41': 'ipv6', '47': 'gre', '50': 'esp',
  '51': 'ah', '58': 'icmp', '89': 'ospf', '103': 'pim', '112': 'vrrp', '132': 'sctp', '136': 'udplite',
};

/** Protocols a policy rule (and so a recommendation) can express. */
export const COMPILER_PROTOCOLS = new Set(['tcp', 'udp', 'icmp']);

/** Normalise a logged protocol: names lower-cased, numbers mapped, icmpv6 → icmp. */
export function normalizeProtocol(raw: string | undefined | null): string {
  const p = String(raw ?? '').trim().toLowerCase();
  if (!p) return 'unknown';
  if (/^\d+$/.test(p)) return PROTOCOL_NUMBERS[String(Number(p))] ?? `proto-${Number(p)}`;
  if (p === 'icmpv6' || p === 'ipv6-icmp' || p === 'icmp6') return 'icmp';
  return p;
}

const MONTHS: Record<string, number> = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

/**
 * Parse a log timestamp to epoch milliseconds: RFC 3339 / ISO 8601, or the classic syslog
 * "Mmm dd HH:MM:SS" (no year, local time). For the latter the current year is assumed, or the
 * previous year when that would put the stamp more than a day into the future (a December line read
 * in January). Returns null when the text is not a timestamp.
 */
export function parseLogTimestamp(ts: string, now: Date = new Date()): number | null {
  const s = String(ts ?? '').trim();
  const sys = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})$/.exec(s);
  if (sys) {
    const month = MONTHS[sys[1].toLowerCase()];
    if (month === undefined) return null;
    const build = (year: number) => new Date(year, month, Number(sys[2]), Number(sys[3]), Number(sys[4]), Number(sys[5])).getTime();
    let t = build(now.getFullYear());
    if (t > now.getTime() + 24 * 3600 * 1000) t = build(now.getFullYear() - 1);
    return Number.isFinite(t) ? t : null;
  }
  if (/^\d{4}-\d{2}-\d{2}T/.test(s)) {
    // "+0100" → "+01:00" for Date.parse
    const t = Date.parse(s.replace(/([+-]\d{2})(\d{2})$/, '$1:$2'));
    return Number.isFinite(t) ? t : null;
  }
  return null;
}

/**
 * Parse firewall log file and extract communication flows
 */
export function parseFirewallLogs(logContent: string): ParsedLogEntry[] {
  const lines = logContent.split('\n').filter(line => line.trim().length > 0);
  const entries: ParsedLogEntry[] = [];

  for (const line of lines) {
    try {
      const entry = parseLogLine(line);
      if (entry) {
        entries.push(entry);
      }
    } catch (error) {
      // Skip unparseable lines
      continue;
    }
  }

  return entries;
}

const IPV4 = String.raw`\d{1,3}(?:\.\d{1,3}){3}`;
const IPV6 = String.raw`[0-9a-fA-F:]*:[0-9a-fA-F:.]+`;

function lastMatch(text: string, re: RegExp): RegExpExecArray | null {
  const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
  let m: RegExpExecArray | null;
  let last: RegExpExecArray | null = null;
  while ((m = g.exec(text)) !== null) {
    last = m;
    if (m[0].length === 0) g.lastIndex++;
  }
  return last;
}

/**
 * Parse a single log line.
 *
 * Kernel netfilter log lines (both nftables `log prefix` and iptables `-j LOG`) look like:
 *   ... FW-AUDIT: ALLOW <comment>: IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP SPT=5555 DPT=22 ...
 * The compiler's prefixes are "FW-AUDIT: <ALLOW|DENY> <comment>: " for policy rules and
 * "FW-AUDIT: ALLOW: <loopback|established|mgmt_ssh|catch-all>: " for baseline/catch-all rules.
 * Direction comes from the kernel IN=/OUT= fields (never from the free-text comment):
 * IN set + OUT empty → inbound, IN empty + OUT set → outbound, both set → forwarded.
 */
function parseLogLine(line: string): ParsedLogEntry | null {
  const prefixIdx = line.indexOf('FW-AUDIT');
  if (prefixIdx < 0) return null;

  // Extract timestamp (format varies by system). Keep the zone offset of RFC 3339 stamps
  // (rsyslog high-precision, journalctl short-iso) so the UI shows the correct local time.
  const timestampMatch = line.match(/^(\w+\s+\d+\s+\d+:\d+:\d+)|(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/);
  const timestamp = timestampMatch ? timestampMatch[0] : new Date().toISOString();

  // Prefix: "FW-AUDIT: ALLOW: established: " or "FW-AUDIT: DENY my comment: "
  const afterPrefix = line.slice(prefixIdx);
  let action = 'ALLOW';
  let ruleLabel: string | undefined;
  const prefixMatch = afterPrefix.match(/^FW-AUDIT:\s*(ALLOW|ACCEPT|DENY|DROP)\b:?\s*(.*?):\s*(?=IN=|$)/);
  if (prefixMatch) {
    action = prefixMatch[1] === 'DENY' || prefixMatch[1] === 'DROP' ? 'DENY' : 'ALLOW';
    ruleLabel = prefixMatch[2]?.trim() || undefined;
  } else if (/^FW-AUDIT:\s*(DENY|DROP)\b/.test(afterPrefix)) {
    action = 'DENY';
  }

  // Kernel fields follow the prefix; take the LAST IN=/OUT= pair so a rule comment can't spoof it.
  const ifaceMatch = lastMatch(afterPrefix, /\bIN=(\S*)\s+OUT=(\S*)/);
  const inIf = ifaceMatch ? ifaceMatch[1] : undefined;
  const outIf = ifaceMatch ? ifaceMatch[2] : undefined;
  // ICMP error messages quote the offending packet's header in brackets
  // ("... PROTO=ICMP TYPE=3 CODE=3 [SRC=... PROTO=UDP SPT=53 DPT=40000 ...]"): those fields describe the
  // inner packet, not this one, so they are removed before any field is extracted.
  const kernel = (ifaceMatch ? afterPrefix.slice(ifaceMatch.index) : afterPrefix).replace(/\[[^\]]*\]/g, ' ');

  let direction: FlowDirection;
  if (ifaceMatch) {
    if (inIf && !outIf) direction = 'IN';
    else if (!inIf && outIf) direction = 'OUT';
    else if (inIf && outIf) direction = 'FORWARD';
    else return null;
  } else {
    // Non-kernel formats (e.g. nft monitor trace): fall back to chain hints.
    direction = /\b(chain\s+output|OUTPUT)\b/i.test(afterPrefix) ? 'OUT' : 'IN';
  }

  // Extract IP addresses (kernel SRC=/DST= first; IPv4 and IPv6)
  let sourceIp = '';
  let destinationIp = '';
  const srcMatch = kernel.match(new RegExp(String.raw`\bSRC=(${IPV4}|${IPV6})`));
  const dstMatch = kernel.match(new RegExp(String.raw`\bDST=(${IPV4}|${IPV6})`));
  if (srcMatch) sourceIp = srcMatch[1];
  if (dstMatch) destinationIp = dstMatch[1];
  if (!sourceIp) {
    const m = kernel.match(new RegExp(String.raw`(?:ip6?\s+saddr|\bsrc[=:\s]+)\s*(${IPV4}|${IPV6})`, 'i'));
    if (m) sourceIp = m[1];
  }
  if (!destinationIp) {
    const m = kernel.match(new RegExp(String.raw`(?:ip6?\s+daddr|\bdst[=:\s]+)\s*(${IPV4}|${IPV6})`, 'i'));
    if (m) destinationIp = m[1];
  }

  // Extract protocol (kernel PROTO= field first; numeric values such as PROTO=2 are mapped to names)
  let protocol = 'unknown';
  const protoMatch = kernel.match(/\bPROTO=(\w+)/);
  if (protoMatch) protocol = normalizeProtocol(protoMatch[1]);
  else if (/\b(meta l4proto|ip protocol)\s+tcp\b/i.test(kernel)) protocol = 'tcp';
  else if (/\b(meta l4proto|ip protocol)\s+udp\b/i.test(kernel)) protocol = 'udp';
  else if (/\b(meta l4proto|ip protocol)\s+(icmp|ipv6-icmp|icmpv6)\b/i.test(kernel)) protocol = 'icmp';

  // Extract ports (SPT=12345 DPT=80 or sport 12345 dport 80) — only tcp/udp have ports a rule can match.
  let sourcePort: number | undefined;
  let destinationPort: number | undefined;
  if (protocol === 'tcp' || protocol === 'udp') {
    const sptMatch = kernel.match(/\b(?:SPT=|sport[=\s]+)(\d+)/i);
    if (sptMatch) sourcePort = parseInt(sptMatch[1], 10);
    const dptMatch = kernel.match(/\b(?:DPT=|dport[=\s]+)(\d+)/i);
    if (dptMatch) destinationPort = parseInt(dptMatch[1], 10);
  }

  // If we couldn't extract IPs, skip this entry
  if (!sourceIp && !destinationIp) {
    return null;
  }

  const label = (ruleLabel ?? '').toLowerCase();
  // iptables log prefixes are truncated to 29 chars ("FW-AUDIT: ALLOW: establishe").
  const established = label.startsWith('establish');
  const loopback = label === 'loopback' || inIf === 'lo' || outIf === 'lo';

  return {
    timestamp,
    direction,
    sourceIp: sourceIp || 'unknown',
    destinationIp: destinationIp || 'unknown',
    protocol,
    sourcePort,
    destinationPort,
    action,
    ruleLabel,
    established,
    loopback,
    inInterface: inIf || undefined,
    outInterface: outIf || undefined,
    rawLine: line
  };
}

/**
 * Group parsed log entries into communication flows
 */
export function groupCommunicationFlows(entries: ParsedLogEntry[], now: Date = new Date()): CommunicationFlow[] {
  const flowMap = new Map<string, CommunicationFlow & { firstMs: number | null; lastMs: number | null }>();

  for (const entry of entries) {
    // Loopback packets are never filtered by Segmentra. Forwarded packets are kept (direction FORWARD):
    // gateways filter them with FORWARD rules, and consumers that only handle IN/OUT skip them.
    if (entry.loopback) continue;

    // Create a key for this flow (the interfaces are part of it: interface-scoped rules depend on them)
    const key = [
      entry.direction, entry.sourceIp, entry.destinationIp, entry.protocol,
      entry.sourcePort || '*', entry.destinationPort || '*', entry.inInterface ?? '', entry.outInterface ?? '',
    ].join('|');
    const ms = parseLogTimestamp(entry.timestamp, now);

    let flow = flowMap.get(key);
    if (!flow) {
      flow = {
        direction: entry.direction,
        sourceIp: entry.sourceIp,
        destinationIp: entry.destinationIp,
        protocol: entry.protocol,
        sourcePort: entry.sourcePort,
        destinationPort: entry.destinationPort,
        count: 0,
        firstSeen: entry.timestamp,
        lastSeen: entry.timestamp,
        established: !!entry.established,
        ...(entry.inInterface ? { inInterface: entry.inInterface } : {}),
        ...(entry.outInterface ? { outInterface: entry.outInterface } : {}),
        firstMs: ms,
        lastMs: ms,
      };
      flowMap.set(key, flow);
    }

    flow.count++;
    // A flow is "established-only" if every packet came through the established baseline rule.
    if (!entry.established) flow.established = false;
    // Compare as points in time ("Dec  1" is later than "Nov 30"); fall back to text only when unparseable.
    const earlier = ms !== null && flow.firstMs !== null ? ms < flow.firstMs : entry.timestamp < flow.firstSeen;
    const later = ms !== null && flow.lastMs !== null ? ms > flow.lastMs : entry.timestamp > flow.lastSeen;
    if (earlier) {
      flow.firstSeen = entry.timestamp;
      flow.firstMs = ms;
    }
    if (later) {
      flow.lastSeen = entry.timestamp;
      flow.lastMs = ms;
    }
  }

  return Array.from(flowMap.values())
    .map(({ firstMs: _f, lastMs: _l, ...flow }) => flow)
    .sort((a, b) => b.count - a.count);
}
