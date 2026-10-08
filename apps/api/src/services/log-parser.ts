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

  // Extract timestamp (format varies by system)
  const timestampMatch = line.match(/^(\w+\s+\d+\s+\d+:\d+:\d+)|(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/);
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
  const kernel = ifaceMatch ? afterPrefix.slice(ifaceMatch.index) : afterPrefix;

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

  // Extract protocol (kernel PROTO= field first)
  let protocol = 'unknown';
  const protoMatch = kernel.match(/\bPROTO=(\w+)/);
  const protoRaw = protoMatch ? protoMatch[1].toLowerCase() : '';
  if (protoRaw === 'tcp' || /\b(meta l4proto|ip protocol)\s+tcp\b/i.test(kernel)) protocol = 'tcp';
  else if (protoRaw === 'udp' || /\b(meta l4proto|ip protocol)\s+udp\b/i.test(kernel)) protocol = 'udp';
  else if (protoRaw === 'icmp' || protoRaw === 'icmpv6' || /\bicmp\b/i.test(protoRaw)) protocol = 'icmp';
  else if (protoRaw) protocol = protoRaw;

  // Extract ports: SPT=12345 DPT=80 or sport 12345 dport 80
  let sourcePort: number | undefined;
  let destinationPort: number | undefined;
  const sptMatch = kernel.match(/\b(?:SPT=|sport[=\s]+)(\d+)/i);
  if (sptMatch) sourcePort = parseInt(sptMatch[1], 10);
  const dptMatch = kernel.match(/\b(?:DPT=|dport[=\s]+)(\d+)/i);
  if (dptMatch) destinationPort = parseInt(dptMatch[1], 10);

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
export function groupCommunicationFlows(entries: ParsedLogEntry[]): CommunicationFlow[] {
  const flowMap = new Map<string, CommunicationFlow>();

  for (const entry of entries) {
    // Host firewalls only enforce input/output: drop forwarded and loopback packets.
    if (entry.direction === 'FORWARD' || entry.loopback) continue;

    // Create a key for this flow
    const key = `${entry.direction}:${entry.sourceIp}:${entry.destinationIp}:${entry.protocol}:${entry.sourcePort || '*'}:${entry.destinationPort || '*'}`;

    if (!flowMap.has(key)) {
      flowMap.set(key, {
        direction: entry.direction,
        sourceIp: entry.sourceIp,
        destinationIp: entry.destinationIp,
        protocol: entry.protocol,
        sourcePort: entry.sourcePort,
        destinationPort: entry.destinationPort,
        count: 0,
        firstSeen: entry.timestamp,
        lastSeen: entry.timestamp,
        established: !!entry.established
      });
    }

    const flow = flowMap.get(key)!;
    flow.count++;
    // A flow is "established-only" if every packet came through the established baseline rule.
    if (!entry.established) flow.established = false;
    if (entry.timestamp < flow.firstSeen) {
      flow.firstSeen = entry.timestamp;
    }
    if (entry.timestamp > flow.lastSeen) {
      flow.lastSeen = entry.timestamp;
    }
  }

  return Array.from(flowMap.values()).sort((a, b) => b.count - a.count);
}
