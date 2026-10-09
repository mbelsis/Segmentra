import crypto from 'node:crypto';
import { isIP } from 'node:net';

export type FirewallBackend = 'nftables' | 'iptables' | 'firewalld' | 'ufw';

export function firewallBackend(value: unknown): FirewallBackend {
  if (value === 'iptables' || value === 'firewalld' || value === 'ufw') return value;
  return 'nftables';
}

export type InterfaceScope =
  | { type: 'ALL_INTERFACES' }
  | { type: 'INTERFACE_ROLE'; roles: string[] }
  | { type: 'INTERFACE_NAME'; names: string[] };

export type RuleDirection = 'IN' | 'OUT' | 'BOTH' | 'FORWARD';

export type DestinationType = 'CIDR' | 'TAG' | 'VLAN' | 'HOST' | 'IOT_ASSET';

export type PolicyRule = {
  orderIndex: number;
  /**
   * IN/OUT/BOTH: traffic to/from the host itself (input/output chains).
   * FORWARD: traffic routed THROUGH the host (forward chain); requires `destination`.
   * Interface scopes do not apply to FORWARD rules.
   */
  direction: RuleDirection;
  action: 'ALLOW' | 'DENY';
  protocol: 'tcp' | 'udp' | 'icmp' | 'any';
  ports?: string | null;
  sourceType: 'CIDR' | 'TAG' | 'VLAN' | 'HOST';
  sourceValue: string; // CIDR string OR UUID for tag/vlan/host
  logMode: 'NONE' | 'LOG' | 'LOG_RATE_LIMITED';
  comment?: string | null;
  usePolicyInterfaceScope: boolean;
  interfaceScope?: InterfaceScope;
  remote: { kind: 'CIDR' } | { kind: 'SET'; setName: string };
  /** FORWARD rules only: destination type/value as stored on the rule. */
  destinationType?: DestinationType | null;
  /** CIDR (or comma-separated CIDRs / "any") for destinationType CIDR; otherwise the entity id. */
  destinationValue?: string | null;
  /**
   * FORWARD rules only (required there, must be absent otherwise): CIDR = use destinationValue,
   * SET = resolved addresses in `sets[setName]` (and `${setName}_v6` in nft).
   */
  destination?: { kind: 'CIDR' } | { kind: 'SET'; setName: string } | null;
};

export type Host = {
  id: string;
  hostname: string;
  mgmtIp: string | null;
  firewallBackend: FirewallBackend;
  interfaces: Array<{ name: string; role: string; enabled: boolean }>;
  /** SSH port used for the management baseline rule. Defaults to 22. */
  sshPort?: number | null;
};

/**
 * Docker Swarm node profile. A Swarm node must always reach its peers on the cluster ports,
 * otherwise the overlay network breaks (nodes keep showing Ready while traffic through the routing
 * mesh fails), so these are allowed in the baseline, ahead of any policy rule.
 */
export type SwarmProfile = {
  role: 'manager' | 'worker';
  /** Addresses (IPs/CIDRs) of the OTHER nodes of the same swarm. */
  peerCidrs: string[];
  /** Overlay networks created with --opt encrypted use IPsec ESP (IP protocol 50) between nodes. */
  encryptedOverlay?: boolean;
};

export type CompileInput = {
  host: Host;
  policyInterfaceScope: InterfaceScope;
  rules: PolicyRule[];
  sets: Record<string, string[]>; // setName -> IP/CIDR elements (IPv4 and/or IPv6)
  baseline: {
    mgmtSshCidrs: string[];
  };
  logOnlyMode?: boolean; // When true, log all traffic but don't block
  /**
   * Verdict for inbound traffic no rule matched (default 'DROP'). With 'ACCEPT'
   * the nft input chain policy is accept and the iptables SEGMENTRA-IN chain
   * ends with RETURN (the rest of INPUT and its policy decide).
   */
  defaultInputAction?: 'DROP' | 'ACCEPT';
  /**
   * Addresses (IPs/CIDRs) of devices protected by this host acting as a gateway (IoT assets
   * assigned to it). Forwarded traffic TO these addresses is dropped unless a FORWARD rule
   * allows it; other forwarded traffic is not affected. Forwarding is only filtered when the
   * host has FORWARD rules or protected destinations; otherwise the output is unchanged.
   */
  protectedDestinations?: string[];
  /** Docker Swarm node: always allow the cluster ports from the other nodes (see SwarmProfile). */
  swarm?: SwarmProfile | null;
  /**
   * Apply the inbound (IN/BOTH) rules also to traffic that Docker publishes with DNAT (published
   * container ports and the Swarm routing mesh). Those packets are forwarded, never reach INPUT,
   * so INPUT rules cannot restrict them. Traffic from Docker's own bridges is not affected, and
   * unmatched DNAT traffic follows defaultInputAction. Not applied in log-only mode.
   */
  dockerPublishedPorts?: boolean;
};

export type CompileOutput = {
  backend: FirewallBackend;
  /**
   * nft -f script (nftables, replaces only table inet segmentra) or an
   * `iptables-restore --noflush` fragment declaring only the SEGMENTRA-IN /
   * SEGMENTRA-OUT (and, when forwarding is filtered, SEGMENTRA-FWD) chains
   * (iptables, IPv4 only). The executor adds the INPUT/OUTPUT(/FORWARD) jumps.
   */
  text: string;
  /** sha256 of `text`. */
  sha256: string;
  /**
   * iptables backend only: `ip6tables-restore --noflush` fragment for IPv6 traffic.
   * Undefined for the nftables backend (the inet table covers both families).
   */
  ip6tablesRules?: string;
};

/** Thrown when policy input is invalid or cannot be compiled safely. */
export class CompileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CompileError';
  }
}

/** Name of the nftables table Segmentra owns. Nothing outside this table is touched. */
export const NFT_TABLE_NAME = 'segmentra';

function sha256(text: string): string {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

// ---------------------------------------------------------------------------
// Validation / sanitization helpers
// ---------------------------------------------------------------------------

type Family = 4 | 6;
type Addr = { text: string; family: Family };

function ipv4ToInt(a: string): number {
  return a.split('.').reduce((acc, o) => ((acc << 8) | Number(o)) >>> 0, 0) >>> 0;
}
function intToIpv4(n: number): string {
  return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
}

function ipv6ToBigInt(addr: string): bigint {
  let s = addr;
  if (s.includes('.')) {
    const i = s.lastIndexOf(':');
    const n = ipv4ToInt(s.slice(i + 1));
    s = s.slice(0, i + 1) + (n >>> 16).toString(16) + ':' + (n & 0xffff).toString(16);
  }
  let groups: string[];
  if (s.includes('::')) {
    const [head, tail] = s.split('::');
    const h = head ? head.split(':') : [];
    const t = tail ? tail.split(':') : [];
    groups = [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  } else {
    groups = s.split(':');
  }
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16)), 0n);
}

function bigIntToIpv6(n: bigint): string {
  const groups: number[] = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((n >> BigInt(i * 16)) & 0xffffn));
  // Find the longest run of zero groups (length >= 2) to compress
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart === -1) return hex.join(':');
  const left = hex.slice(0, bestStart).join(':');
  const right = hex.slice(bestStart + bestLen).join(':');
  return `${left}::${right}`;
}

/**
 * Strictly parse an IPv4/IPv6 address with optional prefix length.
 * Host bits are masked off so nft interval sets accept the element.
 */
function parseAddr(raw: string, what: string): Addr {
  const value = String(raw ?? '').trim();
  const m = /^([0-9A-Fa-f.:]+)(?:\/(\d{1,3}))?$/.exec(value);
  if (!m) throw new CompileError(`Invalid ${what}: "${value}"`);
  const ip = m[1];
  const family = isIP(ip);
  if (family !== 4 && family !== 6) throw new CompileError(`Invalid ${what}: "${value}"`);
  const max = family === 4 ? 32 : 128;
  if (m[2] === undefined) {
    return { family, text: family === 4 ? ip : bigIntToIpv6(ipv6ToBigInt(ip)) };
  }
  const prefix = Number(m[2]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > max) {
    throw new CompileError(`Invalid prefix length in ${what}: "${value}"`);
  }
  if (family === 4) {
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return { family, text: `${intToIpv4((ipv4ToInt(ip) & mask) >>> 0)}/${prefix}` };
  }
  const mask = prefix === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - prefix)) - 1n);
  return { family, text: `${bigIntToIpv6(ipv6ToBigInt(ip) & mask)}/${prefix}` };
}

/**
 * Sanitize/validate a single CIDR/IP value. Never returns an empty string and
 * never allows separators; throws CompileError on anything that is not a
 * strict IPv4/IPv6 address with optional prefix.
 */
function sanitizeCidr(value: string): string {
  return parseAddr(value, 'address').text;
}

/**
 * Parse a CIDR-type rule source/destination. Accepts a single address, a comma-separated
 * list of addresses, or the keyword "any" (returns null = no address match).
 */
function parseAddrList(value: string, what: string): Addr[] | null {
  const v = String(value ?? '').trim();
  if (/^(any|\*)$/i.test(v)) return null;
  const parts = v.split(',').map((p) => p.trim()).filter((p) => p.length > 0);
  if (parts.length === 0) throw new CompileError(`Invalid ${what}: "${v}"`);
  return dedupeAddrs(parts.map((p) => parseAddr(p, what)));
}

function dedupeAddrs(addrs: Addr[]): Addr[] {
  const seen = new Set<string>();
  return addrs.filter((a) => (seen.has(a.text) ? false : (seen.add(a.text), true)));
}

const PORTS_RE = /^\d{1,5}(-\d{1,5})?(\s*,\s*\d{1,5}(-\d{1,5})?)*$/;

/** Validate a port spec and return merged, sorted [low, high] ranges. */
function parsePorts(spec: string): Array<[number, number]> {
  const s = String(spec).trim();
  if (!PORTS_RE.test(s)) throw new CompileError(`Invalid port specification: "${s}"`);
  const ranges: Array<[number, number]> = s.split(',').map((p) => {
    const [a, b] = p.trim().split('-');
    const lo = Number(a);
    const hi = b === undefined ? lo : Number(b);
    if (lo < 1 || lo > 65535 || hi < 1 || hi > 65535) {
      throw new CompileError(`Port out of range (1-65535): "${p.trim()}"`);
    }
    if (lo > hi) throw new CompileError(`Invalid port range (low > high): "${p.trim()}"`);
    return [lo, hi];
  });
  ranges.sort((x, y) => x[0] - y[0]);
  const merged: Array<[number, number]> = [];
  for (const r of ranges) {
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
    else merged.push([r[0], r[1]]);
  }
  return merged;
}

const IFACE_RE = /^[A-Za-z0-9_.:@-]{1,15}$/;
function validateInterfaceName(name: string): string {
  if (!IFACE_RE.test(String(name))) throw new CompileError(`Invalid interface name: "${name}"`);
  return name;
}

const SET_NAME_RE = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
function validateSetName(name: string): string {
  if (!SET_NAME_RE.test(String(name))) throw new CompileError(`Invalid set name: "${name}"`);
  return name;
}

/** Strip quotes, backslashes, newlines and control chars; limit length. */
function sanitizeText(value: string | null | undefined, maxLen: number): string {
  return String(value ?? '')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f"'`\\]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLen)
    .trim();
}

function validateSshPort(port: number | null | undefined): number {
  if (port === undefined || port === null) return 22;
  const p = Number(port);
  if (!Number.isInteger(p) || p < 1 || p > 65535) throw new CompileError(`Invalid SSH port: "${port}"`);
  return p;
}

function resolveInterfaceNames(host: Host, scope: InterfaceScope): string[] {
  let names: string[];
  if (scope.type === 'ALL_INTERFACES') return [];
  if (scope.type === 'INTERFACE_NAME') names = scope.names;
  else {
    names = host.interfaces
      .filter((i) => i.enabled && scope.roles.includes(i.role))
      .map((i) => i.name);
  }
  return Array.from(new Set(names.map(validateInterfaceName)));
}

// ---------------------------------------------------------------------------
// Shared pre-processing
// ---------------------------------------------------------------------------

type PreparedSets = Record<string, { v4: string[]; v6: string[] }>;

function prepareSets(sets: Record<string, string[]>): PreparedSets {
  const out: PreparedSets = {};
  for (const [name, elements] of Object.entries(sets ?? {})) {
    validateSetName(name);
    const addrs = dedupeAddrs((elements ?? []).map((e) => parseAddr(e, `element of set ${name}`)));
    out[name] = {
      v4: addrs.filter((a) => a.family === 4).map((a) => a.text),
      v6: addrs.filter((a) => a.family === 6).map((a) => a.text)
    };
  }
  return out;
}

type MgmtBaseline = { port: number; v4: string[]; v6: string[]; fallbackV4: boolean; fallbackV6: boolean };

function prepareMgmt(input: CompileInput): MgmtBaseline {
  const port = validateSshPort(input.host.sshPort);
  const addrs = dedupeAddrs((input.baseline?.mgmtSshCidrs ?? []).map((c) => parseAddr(c, 'management SSH CIDR')));
  const v4 = addrs.filter((a) => a.family === 4).map((a) => a.text);
  const v6 = addrs.filter((a) => a.family === 6).map((a) => a.text);
  let mgmtFamily: number = 0;
  if (input.host.mgmtIp) {
    const ip = String(input.host.mgmtIp).replace(/\/\d+$/, '').trim();
    mgmtFamily = isIP(ip);
  }
  // Never lock the host out: if no management CIDRs are configured, allow the
  // SSH port from anywhere. Also do so for the management IP's address family
  // if no management CIDR of that family exists.
  const none = addrs.length === 0;
  return {
    port,
    v4,
    v6,
    fallbackV4: none || (mgmtFamily === 4 && v4.length === 0),
    fallbackV6: none || (mgmtFamily === 6 && v6.length === 0)
  };
}

type RuleTarget = {
  family: Family | null; // null = family-agnostic (source "any")
  /** nft address match without direction keyword, e.g. "@set" or "10.0.0.0/8" or "{ a, b }" */
  nftAddr: string | null;
  /** iptables address list for this target (empty array = no address match) */
  iptAddrs: string[];
};

/**
 * Resolve a rule's remote side into per-family targets. Empty sets produce no
 * target (a rule matching an empty set matches nothing, so it is skipped).
 */
function resolveTargets(r: PolicyRule, sets: PreparedSets): RuleTarget[] {
  return resolveAddressSpec(r.remote, r.sourceValue, sets, 'source address');
}

/** Destination side of a FORWARD rule (same semantics as resolveTargets). */
function resolveDestTargets(r: PolicyRule, sets: PreparedSets): RuleTarget[] {
  if (!r.destination) throw new CompileError(`Rule #${r.orderIndex}: FORWARD rules require a destination`);
  return resolveAddressSpec(r.destination, String(r.destinationValue ?? ''), sets, 'destination address');
}

function resolveAddressSpec(
  spec: { kind: 'CIDR' } | { kind: 'SET'; setName: string },
  cidrValue: string,
  sets: PreparedSets,
  what: string
): RuleTarget[] {
  if (spec.kind === 'SET') {
    const name = validateSetName(spec.setName);
    const s = sets[name] ?? { v4: [], v6: [] };
    const targets: RuleTarget[] = [];
    if (s.v4.length > 0) targets.push({ family: 4, nftAddr: `@${name}`, iptAddrs: s.v4 });
    if (s.v6.length > 0) targets.push({ family: 6, nftAddr: `@${name}_v6`, iptAddrs: s.v6 });
    return targets;
  }
  const list = parseAddrList(cidrValue, what);
  if (list === null) return [{ family: null, nftAddr: null, iptAddrs: [] }];
  const targets: RuleTarget[] = [];
  for (const fam of [4, 6] as Family[]) {
    const items = list.filter((a) => a.family === fam).map((a) => a.text);
    if (items.length === 0) continue;
    targets.push({
      family: fam,
      nftAddr: items.length === 1 ? items[0] : `{ ${items.join(', ')} }`,
      iptAddrs: items
    });
  }
  return targets;
}

function ruleScope(r: PolicyRule, input: CompileInput): InterfaceScope {
  return r.usePolicyInterfaceScope ? input.policyInterfaceScope : r.interfaceScope ?? input.policyInterfaceScope;
}

function rulePorts(r: PolicyRule): Array<[number, number]> | null {
  const raw = r.ports == null ? '' : String(r.ports).trim();
  if (raw === '') return null;
  if (r.protocol !== 'tcp' && r.protocol !== 'udp') {
    throw new CompileError(
      `Rule #${r.orderIndex}: ports "${raw}" require protocol tcp or udp (got "${r.protocol}"); ` +
        'refusing to silently widen the rule to all ports'
    );
  }
  return parsePorts(raw);
}

function validateRuleEnums(r: PolicyRule): void {
  if (!['IN', 'OUT', 'BOTH', 'FORWARD'].includes(r.direction)) throw new CompileError(`Rule #${r.orderIndex}: invalid direction "${r.direction}"`);
  if (r.direction === 'FORWARD') {
    if (!r.destination || (r.destination.kind !== 'CIDR' && r.destination.kind !== 'SET')) {
      throw new CompileError(`Rule #${r.orderIndex}: FORWARD rules require a destination`);
    }
    if (r.destination.kind === 'CIDR' && String(r.destinationValue ?? '').trim() === '') {
      throw new CompileError(`Rule #${r.orderIndex}: FORWARD rule has an empty destination address`);
    }
  } else if (r.destination) {
    throw new CompileError(`Rule #${r.orderIndex}: only FORWARD rules may have a destination (direction "${r.direction}")`);
  }
  if (!['ALLOW', 'DENY'].includes(r.action)) throw new CompileError(`Rule #${r.orderIndex}: invalid action "${r.action}"`);
  if (!['tcp', 'udp', 'icmp', 'any'].includes(r.protocol)) throw new CompileError(`Rule #${r.orderIndex}: invalid protocol "${r.protocol}"`);
}

// ---------------------------------------------------------------------------
// Forwarding (FORWARD rules + protected destinations)
// ---------------------------------------------------------------------------

/** nft set names holding the protected destinations (declared only when non-empty). */
export const NFT_PROTECTED_SET_V4 = 'protected_v4';
export const NFT_PROTECTED_SET_V6 = 'protected_v6';

type ProtectedDests = { v4: string[]; v6: string[] };

function prepareProtected(input: CompileInput, sets: PreparedSets): ProtectedDests {
  for (const reserved of ['protected', NFT_PROTECTED_SET_V4, NFT_PROTECTED_SET_V6]) {
    if (Object.prototype.hasOwnProperty.call(sets, reserved)) {
      throw new CompileError(`Set name "${reserved}" is reserved for protected destinations`);
    }
  }
  const raw = input.protectedDestinations ?? [];
  if (!Array.isArray(raw)) throw new CompileError('protectedDestinations must be an array of addresses');
  const addrs = dedupeAddrs(raw.map((a) => parseAddr(a, 'protected destination address')));
  return {
    v4: addrs.filter((a) => a.family === 4).map((a) => a.text),
    v6: addrs.filter((a) => a.family === 6).map((a) => a.text)
  };
}

/** Forwarding is filtered when the host has FORWARD rules, protected destinations or published-port rules. */
function forwardingEnabled(input: CompileInput, prot: ProtectedDests): boolean {
  return (
    input.rules.some((r) => r.direction === 'FORWARD') ||
    prot.v4.length > 0 ||
    prot.v6.length > 0 ||
    input.dockerPublishedPorts === true
  );
}

// --- Docker Swarm / published ports ------------------------------------------------------------

type SwarmAllow = { label: string; proto: 'tcp' | 'udp' | 'esp'; port?: number };

/** Ports a Swarm node needs from its peers: 2377/tcp (managers), 7946/tcp+udp, 4789/udp, ESP if encrypted. */
function swarmAllows(sw: SwarmProfile): SwarmAllow[] {
  const allows: SwarmAllow[] = [
    { label: 'swarm_gossip_tcp', proto: 'tcp', port: 7946 },
    { label: 'swarm_gossip_udp', proto: 'udp', port: 7946 },
    { label: 'swarm_vxlan', proto: 'udp', port: 4789 }
  ];
  if (sw.role === 'manager') allows.unshift({ label: 'swarm_manager', proto: 'tcp', port: 2377 });
  if (sw.encryptedOverlay) allows.push({ label: 'swarm_overlay_esp', proto: 'esp' });
  return allows;
}

/** Peer addresses of one family (validated, deduplicated). */
function swarmPeers(sw: SwarmProfile | null | undefined, fam: Family): string[] {
  if (!sw) return [];
  if (sw.role !== 'manager' && sw.role !== 'worker') throw new CompileError(`Invalid Swarm role "${String(sw.role)}"`);
  return dedupeAddrs(sw.peerCidrs.map((p) => parseAddr(p, 'Swarm peer address')))
    .filter((a) => a.family === fam)
    .map((a) => a.text);
}

/** Interfaces of Docker's own bridges: traffic from containers/overlay gateways is not "external". */
const DOCKER_INTERNAL_IFACES = { ipt: ['docker0', 'docker_gwbridge', 'br-+'], nft: ['docker0', 'docker_gwbridge', 'br-*'] };

/** conntrack original-destination-port arguments (iptables): one per range, or a single empty string. */
function iptCtPortArgs(ports: Array<[number, number]> | null): string[] {
  if (!ports) return [''];
  return ports.map(([lo, hi]) => `--ctorigdstport ${lo === hi ? lo : `${lo}:${hi}`}`);
}

type ForwardMatch = { family: Family | null; src: RuleTarget; dst: RuleTarget };

/**
 * Source x destination pairs of a FORWARD rule with compatible address families.
 * Empty sets on either side produce no pairs (the rule can never match).
 */
function forwardMatches(r: PolicyRule, sets: PreparedSets): ForwardMatch[] {
  const src = resolveTargets(r, sets);
  const dst = resolveDestTargets(r, sets);
  const out: ForwardMatch[] = [];
  for (const s of src) {
    for (const d of dst) {
      if (s.family !== null && d.family !== null && s.family !== d.family) continue;
      out.push({ family: s.family ?? d.family, src: s, dst: d });
    }
  }
  return out;
}

function nftProtoExpr(r: PolicyRule, ports: Array<[number, number]> | null, family: Family | null): string {
  if (ports) {
    const elems = ports.map(([lo, hi]) => (lo === hi ? String(lo) : `${lo}-${hi}`)).join(', ');
    return `${r.protocol} dport { ${elems} }`;
  }
  if (r.protocol === 'tcp' || r.protocol === 'udp') return `meta l4proto ${r.protocol}`;
  if (r.protocol === 'icmp') {
    if (family === 6) return 'meta l4proto ipv6-icmp';
    if (family === 4) return 'meta l4proto icmp';
    return 'meta l4proto { icmp, ipv6-icmp }';
  }
  return '';
}

/**
 * Inbound rules applied to Docker-published (DNAT) traffic: matched on the ORIGINAL destination port,
 * because the destination has already been rewritten to the container when the packet is forwarded.
 */
function nftPublishedPortRules(input: CompileInput, sets: PreparedSets): string[] {
  const out: string[] = [];
  const rulesSorted = [...input.rules].sort((a, b) => a.orderIndex - b.orderIndex);
  for (const r of rulesSorted) {
    if (r.direction !== 'IN' && r.direction !== 'BOTH') continue;
    if (r.protocol === 'icmp') continue;
    const ports = rulePorts(r);
    const commentText = sanitizeText(r.comment, 120);
    const comment = `comment "${sanitizeText(`published rule${r.orderIndex}${commentText ? ` ${commentText}` : ''}`, 120)}"`;
    const ifs = resolveInterfaceNames(input.host, ruleScope(r, input));
    const ifExpr = ifs.length === 0 ? '' : `iifname { ${ifs.map((n) => `"${n}"`).join(', ')} }`;
    for (const t of resolveTargets(r, sets)) {
      const addrExpr = t.nftAddr === null ? '' : `${t.family === 6 ? 'ip6' : 'ip'} saddr ${t.nftAddr}`;
      let protoExpr = '';
      if (r.protocol === 'tcp' || r.protocol === 'udp') {
        protoExpr = `meta l4proto ${r.protocol}`;
        if (ports) protoExpr += ` ct original proto-dst { ${ports.map(([lo, hi]) => (lo === hi ? String(lo) : `${lo}-${hi}`)).join(', ')} }`;
      }
      out.push(['ct status dnat', ifExpr, addrExpr, protoExpr, r.action === 'ALLOW' ? 'accept' : 'drop', comment].filter(Boolean).join(' '));
    }
  }
  const external = DOCKER_INTERNAL_IFACES.nft.map((n) => `iifname != "${n}"`).join(' ');
  out.push(`ct status dnat ${external} ${(input.defaultInputAction ?? 'DROP') === 'ACCEPT' ? 'accept' : 'drop'} comment "published_default"`);
  return out;
}

/** Lines of the nft forward chain (without the chain header). */
function nftForwardRules(input: CompileInput, sets: PreparedSets, prot: ProtectedDests, logOnly: boolean): string[] {
  const lines: string[] = [];
  // Replies of allowed connections (and related ICMP) always pass.
  lines.push('ct state established,related accept');
  if (input.dockerPublishedPorts && !logOnly) lines.push(...nftPublishedPortRules(input, sets));
  const rulesSorted = [...input.rules].filter((r) => r.direction === 'FORWARD').sort((a, b) => a.orderIndex - b.orderIndex);
  for (const r of rulesSorted) {
    const ports = rulePorts(r);
    const commentText = sanitizeText(r.comment, 120);
    const comment = commentText ? `comment "${commentText}"` : '';
    for (const m of forwardMatches(r, sets)) {
      const fam = m.family === 6 ? 'ip6' : 'ip';
      const srcExpr = m.src.nftAddr === null ? '' : `${fam} saddr ${m.src.nftAddr}`;
      const dstExpr = m.dst.nftAddr === null ? '' : `${fam} daddr ${m.dst.nftAddr}`;
      const tail = logOnly
        ? [`log prefix "${sanitizeText(`FW-AUDIT: ${r.action} ${commentText || 'forward rule'}`, 120)}: "`, 'accept']
        : [r.action === 'ALLOW' ? 'accept' : 'drop'];
      lines.push([srcExpr, dstExpr, nftProtoExpr(r, ports, m.family), ...tail, comment].filter(Boolean).join(' '));
    }
  }
  // Default deny for traffic to protected devices; everything else forwarded is untouched.
  const verdict = logOnly ? 'log prefix "FW-AUDIT: DENY: protected-default: " accept' : 'drop';
  if (prot.v4.length > 0) lines.push(`ip daddr @${NFT_PROTECTED_SET_V4} ${verdict} comment "protected_default_deny"`);
  if (prot.v6.length > 0) lines.push(`ip6 daddr @${NFT_PROTECTED_SET_V6} ${verdict} comment "protected_default_deny"`);
  return lines;
}

// ---------------------------------------------------------------------------
// nftables
// ---------------------------------------------------------------------------

function compileNft(input: CompileInput, logOnly: boolean): string {
  const sets = prepareSets(input.sets);
  const mgmt = prepareMgmt(input);
  const T = NFT_TABLE_NAME;
  const inputRules: string[] = [];
  const outputRules: string[] = [];
  const logStmt = (label: string) => (logOnly ? `log prefix "${sanitizeText(`FW-AUDIT: ${label}`, 120)}: " ` : '');

  // --- Baseline ---
  inputRules.push(`iif "lo" ${logStmt('ALLOW: loopback')}accept`);
  inputRules.push(`ct state established,related ${logStmt('ALLOW: established')}accept`);
  // IPv6 neighbor discovery must never be dropped or IPv6 connectivity breaks.
  inputRules.push(
    `icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept comment "ipv6_nd"`
  );
  // Log-only: replies to inbound connections (and later packets of outbound ones) are not new
  // flows; without this they are logged by the output catch-all as outbound traffic to
  // ephemeral ports and turned into bogus OUT recommendations.
  if (logOnly) outputRules.push('ct state established,related accept');
  for (const cidr of mgmt.v4) {
    inputRules.push(`ip saddr ${cidr} tcp dport ${mgmt.port} ${logStmt('ALLOW: mgmt_ssh')}accept comment "mgmt_ssh"`);
  }
  for (const cidr of mgmt.v6) {
    inputRules.push(`ip6 saddr ${cidr} tcp dport ${mgmt.port} ${logStmt('ALLOW: mgmt_ssh')}accept comment "mgmt_ssh"`);
  }
  if (mgmt.fallbackV4 && mgmt.fallbackV6) {
    inputRules.push(`tcp dport ${mgmt.port} ${logStmt('ALLOW: mgmt_ssh_fallback')}accept comment "mgmt_ssh_fallback"`);
  } else if (mgmt.fallbackV4) {
    inputRules.push(`meta nfproto ipv4 tcp dport ${mgmt.port} ${logStmt('ALLOW: mgmt_ssh_fallback')}accept comment "mgmt_ssh_fallback"`);
  } else if (mgmt.fallbackV6) {
    inputRules.push(`meta nfproto ipv6 tcp dport ${mgmt.port} ${logStmt('ALLOW: mgmt_ssh_fallback')}accept comment "mgmt_ssh_fallback"`);
  }

  // --- Docker Swarm cluster ports from the other nodes (always, ahead of policy rules) ---
  if (input.swarm) {
    for (const fam of [4, 6] as Family[]) {
      const peers = swarmPeers(input.swarm, fam);
      if (peers.length === 0) continue;
      const addr = `${fam === 6 ? 'ip6' : 'ip'} saddr ${peers.length === 1 ? peers[0] : `{ ${peers.join(', ')} }`}`;
      for (const a of swarmAllows(input.swarm)) {
        const proto = a.proto === 'esp' ? 'meta l4proto esp' : `${a.proto} dport ${a.port}`;
        inputRules.push(`${addr} ${proto} ${logStmt(`ALLOW: ${a.label}`)}accept comment "${a.label}"`);
      }
    }
  }

  // --- Policy rules, in user-defined order_index order (no reordering) ---
  const rulesSorted = [...input.rules].sort((a, b) => a.orderIndex - b.orderIndex);
  for (const r of rulesSorted) {
    validateRuleEnums(r);
    if (r.direction === 'FORWARD') continue; // forward chain, see nftForwardRules
    const scope = ruleScope(r, input);
    const ifs = resolveInterfaceNames(input.host, scope);
    const ports = rulePorts(r);
    const action = r.action === 'ALLOW' ? 'accept' : 'drop';
    const commentText = sanitizeText(r.comment, 120);
    const comment = commentText ? `comment "${commentText}"` : '';
    const targets = resolveTargets(r, sets);
    if (targets.length === 0) {
      // Rule references an empty (or unknown) address set: it can never match,
      // so it is omitted rather than referencing an undeclared set.
      continue;
    }

    for (const t of targets) {
      const protoExpr = nftProtoExpr(r, ports, t.family);

      const emit = (chain: 'input' | 'output') => {
        const ifExpr = ifs.length === 0 ? '' : `${chain === 'input' ? 'iifname' : 'oifname'} { ${ifs.map((n) => `"${n}"`).join(', ')} }`;
        const dir = chain === 'input' ? 'saddr' : 'daddr';
        const addrExpr = t.nftAddr === null ? '' : `${t.family === 6 ? 'ip6' : 'ip'} ${dir} ${t.nftAddr}`;
        const tail = logOnly
          ? [`log prefix "${sanitizeText(`FW-AUDIT: ${r.action} ${commentText || 'rule'}`, 120)}: "`, 'accept']
          : [action];
        const line = [ifExpr, addrExpr, protoExpr, ...tail, comment].filter(Boolean).join(' ');
        (chain === 'input' ? inputRules : outputRules).push(line);
      };
      if (r.direction === 'IN' || r.direction === 'BOTH') emit('input');
      if (r.direction === 'OUT' || r.direction === 'BOTH') emit('output');
    }
  }

  // In log-only mode, add catch-all rules to log all remaining traffic
  if (logOnly) {
    inputRules.push('log prefix "FW-AUDIT: ALLOW: catch-all: " accept');
    outputRules.push('log prefix "FW-AUDIT: ALLOW: catch-all: " accept');
  }

  const prot = prepareProtected(input, sets);
  const forwardRules = forwardingEnabled(input, prot) ? nftForwardRules(input, sets, prot, logOnly) : null;

  const lines: string[] = [];
  lines.push('#!/usr/sbin/nft -f');
  lines.push(`# Managed by Segmentra. Only table inet ${T} is replaced; other tables`);
  lines.push('# (Docker, Kubernetes, fail2ban, ...) are left untouched.');
  lines.push('# The add+delete+define sequence is applied atomically by nft -f.');
  lines.push(`add table inet ${T}`);
  lines.push(`delete table inet ${T}`);
  lines.push(`table inet ${T} {`);
  // Address sets. Empty sets are not declared; rules referencing them are skipped.
  for (const [name, s] of Object.entries(sets)) {
    if (s.v4.length > 0) {
      lines.push(`  set ${name} {`, '    type ipv4_addr', '    flags interval', '    auto-merge', `    elements = { ${s.v4.join(', ')} }`, '  }');
    }
    if (s.v6.length > 0) {
      lines.push(`  set ${name}_v6 {`, '    type ipv6_addr', '    flags interval', '    auto-merge', `    elements = { ${s.v6.join(', ')} }`, '  }');
    }
  }
  if (forwardRules) {
    if (prot.v4.length > 0) {
      lines.push(`  set ${NFT_PROTECTED_SET_V4} {`, '    type ipv4_addr', '    flags interval', '    auto-merge', `    elements = { ${prot.v4.join(', ')} }`, '  }');
    }
    if (prot.v6.length > 0) {
      lines.push(`  set ${NFT_PROTECTED_SET_V6} {`, '    type ipv6_addr', '    flags interval', '    auto-merge', `    elements = { ${prot.v6.join(', ')} }`, '  }');
    }
  }
  const inputPolicy = logOnly || (input.defaultInputAction ?? 'DROP') === 'ACCEPT' ? 'accept' : 'drop';
  lines.push('  chain input {', `    type filter hook input priority 0; policy ${inputPolicy};`);
  for (const r of inputRules) lines.push(`    ${r}`);
  lines.push('  }');
  lines.push('  chain output {', '    type filter hook output priority 0; policy accept;');
  for (const r of outputRules) lines.push(`    ${r}`);
  lines.push('  }');
  if (forwardRules) {
    // Policy accept: only traffic to protected devices is default-denied; other routed
    // traffic (Docker, Kubernetes, plain routing) passes as before.
    lines.push('  chain forward {', '    type filter hook forward priority 0; policy accept;');
    for (const r of forwardRules) lines.push(`    ${r}`);
    lines.push('  }');
  }
  lines.push('}');
  return lines.join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// iptables / ip6tables
// ---------------------------------------------------------------------------

/** iptables --log-prefix is limited to 29 characters. */
function iptLogPrefix(label: string): string {
  const body = sanitizeText(`FW-AUDIT: ${label}`, 27);
  return `"${body}: "`;
}

/** Split port ranges into multiport-compatible chunks (max 15 slots, a range uses 2). */
function iptPortArgs(ports: Array<[number, number]> | null): string[] {
  if (!ports) return [''];
  if (ports.length === 1) {
    const [lo, hi] = ports[0];
    return [`--dport ${lo === hi ? lo : `${lo}:${hi}`}`];
  }
  const chunks: string[] = [];
  let cur: string[] = [];
  let slots = 0;
  for (const [lo, hi] of ports) {
    const cost = lo === hi ? 1 : 2;
    if (slots + cost > 15) {
      chunks.push(cur.join(','));
      cur = [];
      slots = 0;
    }
    cur.push(lo === hi ? String(lo) : `${lo}:${hi}`);
    slots += cost;
  }
  if (cur.length) chunks.push(cur.join(','));
  return chunks.map((c) => `-m multiport --dports ${c}`);
}

/** User chains Segmentra owns in the iptables/ip6tables filter table. */
export const IPT_INPUT_CHAIN = 'SEGMENTRA-IN';
export const IPT_OUTPUT_CHAIN = 'SEGMENTRA-OUT';
/** Forward chain, declared only when the host filters forwarded traffic (FORWARD rules / protected destinations). */
export const IPT_FORWARD_CHAIN = 'SEGMENTRA-FWD';
/** Prefix of the `-m comment` marker carried by every rule Segmentra emits. */
export const IPT_COMMENT_PREFIX = 'segmentra';
/** Header line identifying the chain-scoped iptables fragment format. */
export const IPT_FORMAT_MARKER = '# segmentra-format: iptables-chains-v2';

/** `-m comment --comment "segmentra:<label>"` (label sanitized, comment max 256 chars). */
function iptComment(label: string): string {
  const body = sanitizeText(`${IPT_COMMENT_PREFIX}:${label}`, 200);
  return `-m comment --comment "${body}"`;
}

/**
 * iptables/ip6tables output is an `iptables-restore --noflush` fragment that
 * declares ONLY Segmentra's own chains (SEGMENTRA-IN / SEGMENTRA-OUT, plus
 * SEGMENTRA-FWD when the host filters forwarded traffic). With
 * --noflush, declaring a user chain creates it or flushes just that chain;
 * every other chain (DOCKER*, KUBE-*, f2b-*, ...) and the built-in chain
 * policies are left untouched. The executor inserts the INPUT/OUTPUT(/FORWARD) jumps
 * (idempotently) in the same restore transaction.
 */
function compileIptablesFamily(input: CompileInput, logOnly: boolean, fam: Family): string {
  const sets = prepareSets(input.sets);
  const mgmt = prepareMgmt(input);
  const IN = IPT_INPUT_CHAIN;
  const OUT = IPT_OUTPUT_CHAIN;
  const lines: string[] = [];
  const push = (s: string) => lines.push(s.replace(/\s+/g, ' ').trim());
  const icmpProto = fam === 6 ? 'ipv6-icmp' : 'icmp';
  const defaultAccept = (input.defaultInputAction ?? 'DROP') === 'ACCEPT';
  const FWD = IPT_FORWARD_CHAIN;
  const prot = prepareProtected(input, sets);
  const withForward = forwardingEnabled(input, prot);

  lines.push(IPT_FORMAT_MARKER);
  lines.push(`# Managed by Segmentra (${fam === 6 ? 'ip6tables' : 'iptables'}). Apply with ${fam === 6 ? 'ip6tables' : 'iptables'}-restore --noflush.`);
  if (withForward) {
    lines.push(`# Only chains ${IN}, ${OUT} and ${FWD} are replaced; other chains and built-in policies are untouched.`);
  } else {
    lines.push(`# Only chains ${IN} and ${OUT} are replaced; other chains and built-in policies are untouched.`);
  }
  lines.push('*filter');
  lines.push(`:${IN} - [0:0]`);
  lines.push(`:${OUT} - [0:0]`);
  if (withForward) lines.push(`:${FWD} - [0:0]`);

  // "Allow" in our chains is RETURN, not ACCEPT: the packet goes back to the built-in chain so
  // rules of other tools after our jump (fail2ban bans, Docker, admins' own rules) still apply.
  // This matches nftables semantics, where an accept in table segmentra doesn't override a drop
  // in another table. Only our final DROP is terminal.
  // Native UFW rules are authoritative before UFW's default-deny chains. RETURN
  // would leave every Segmentra allow dependent on a second UFW user rule.
  const ALLOW = input.host.firewallBackend === 'ufw' ? 'ACCEPT' : 'RETURN';

  // Baseline traffic is always allowed (also in log-only mode, where it is logged first).
  const baselineAccept = (match: string, label: string) => {
    if (logOnly) push(`-A ${IN} ${match} ${iptComment(label)} -j LOG --log-prefix ${iptLogPrefix(`ALLOW: ${label}`)}`);
    push(`-A ${IN} ${match} ${iptComment(label)} -j ${ALLOW}`);
  };

  baselineAccept('-i lo', 'loopback');
  baselineAccept('-m conntrack --ctstate ESTABLISHED,RELATED', 'established');
  if (fam === 6 && input.host.firewallBackend === 'ufw') {
    for (const type of [1, 2, 3, 4]) {
      baselineAccept(`-p ipv6-icmp --icmpv6-type ${type}`, 'ipv6-control');
    }
  }
  // Log-only: don't log reply traffic as new outbound flows (see compileNft).
  if (logOnly) push(`-A ${OUT} -m conntrack --ctstate ESTABLISHED,RELATED ${iptComment('established')} -j RETURN`);
  if (fam === 6) {
    // IPv6 neighbor discovery must never be dropped or IPv6 connectivity breaks.
    for (const t of ['neighbour-solicitation', 'neighbour-advertisement', 'router-solicitation', 'router-advertisement']) {
      push(`-A ${IN} -p ipv6-icmp -m icmp6 --icmpv6-type ${t} ${iptComment('ipv6_nd')} -j ${ALLOW}`);
    }
  }
  for (const cidr of fam === 4 ? mgmt.v4 : mgmt.v6) {
    baselineAccept(`-p tcp -s ${cidr} --dport ${mgmt.port}`, 'mgmt_ssh');
  }
  if (fam === 4 ? mgmt.fallbackV4 : mgmt.fallbackV6) {
    baselineAccept(`-p tcp --dport ${mgmt.port}`, 'mgmt_ssh_fallback');
  }

  // Docker Swarm cluster ports from the other nodes (always, ahead of policy rules).
  if (input.swarm) {
    for (const peer of swarmPeers(input.swarm, fam)) {
      for (const a of swarmAllows(input.swarm)) {
        baselineAccept(a.proto === 'esp' ? `-p esp -s ${peer}` : `-p ${a.proto} -s ${peer} --dport ${a.port}`, a.label);
      }
    }
  }

  const rulesSorted = [...input.rules].sort((a, b) => a.orderIndex - b.orderIndex);
  for (const r of rulesSorted) {
    validateRuleEnums(r);
    if (r.direction === 'FORWARD') continue; // SEGMENTRA-FWD, emitted below
    const scope = ruleScope(r, input);
    const ifNames = resolveInterfaceNames(input.host, scope);
    const ports = rulePorts(r);
    const action = r.action === 'ALLOW' ? ALLOW : 'DROP';
    const proto = r.protocol === 'any' ? '' : `-p ${r.protocol === 'icmp' ? icmpProto : r.protocol}`;
    const portArgs = iptPortArgs(ports);
    const commentText = sanitizeText(r.comment, 120);
    const comment = iptComment(`rule${r.orderIndex}${commentText ? ` ${commentText}` : ''}`);
    const targets = resolveTargets(r, sets).filter((t) => t.family === null || t.family === fam);
    // Empty sets / sources of the other family produce no rules here.
    const ifaceList = ifNames.length === 0 ? [''] : ifNames;

    const emit = (chain: 'IN' | 'OUT') => {
      const chainName = chain === 'IN' ? IN : OUT;
      for (const t of targets) {
        const addrs = t.iptAddrs.length === 0 ? [''] : t.iptAddrs;
        for (const iface of ifaceList) {
          const ifaceFlag = iface ? (chain === 'IN' ? `-i ${iface}` : `-o ${iface}`) : '';
          for (const addr of addrs) {
            const remote = addr ? (chain === 'IN' ? `-s ${addr}` : `-d ${addr}`) : '';
            for (const p of portArgs) {
              const match = `-A ${chainName} ${ifaceFlag} ${proto} ${remote} ${p} ${comment}`;
              if (logOnly) {
                // Log-only never changes the verdict: log, then hand the packet
                // back to the rest of the built-in chain.
                push(`${match} -j LOG --log-prefix ${iptLogPrefix(`${r.action} ${commentText || 'rule'}`)}`);
                push(`${match} -j RETURN`);
              } else {
                push(`${match} -j ${action}`);
              }
            }
          }
        }
      }
    };
    if (r.direction === 'IN' || r.direction === 'BOTH') emit('IN');
    if (r.direction === 'OUT' || r.direction === 'BOTH') emit('OUT');
  }

  if (logOnly) {
    push(`-A ${IN} ${iptComment('catch_all')} -j LOG --log-prefix "FW-AUDIT: ALLOW: catch-all: "`);
    push(`-A ${IN} ${iptComment('default')} -j RETURN`);
    push(`-A ${OUT} ${iptComment('catch_all')} -j LOG --log-prefix "FW-AUDIT: ALLOW: catch-all: "`);
  } else {
    push(`-A ${IN} ${iptComment('default')} -j ${defaultAccept ? 'RETURN' : 'DROP'}`);
  }
  // Output default is accept: hand back to the rest of OUTPUT.
  push(`-A ${OUT} ${iptComment('default')} -j RETURN`);

  if (withForward) {
    // Forwarded traffic: allow = RETURN (the rest of FORWARD, e.g. DOCKER-USER, still applies),
    // deny = DROP; traffic to protected devices no rule allowed is dropped; anything else
    // forwarded is handed back to FORWARD unchanged.
    push(`-A ${FWD} -m conntrack --ctstate ESTABLISHED,RELATED ${iptComment('established')} -j ${ALLOW}`);
    if (input.dockerPublishedPorts && !logOnly) {
      // Docker-published ports and the Swarm routing mesh: DNAT'd packets are forwarded, never INPUT.
      // Same rules as INPUT, matched on the original destination port; unmatched DNAT traffic from
      // outside Docker's own bridges follows the default verdict.
      for (const r of rulesSorted) {
        if (r.direction !== 'IN' && r.direction !== 'BOTH') continue;
        if (r.protocol === 'icmp') continue;
        const ports = rulePorts(r);
        const pubProto = r.protocol === 'any' ? '' : `-p ${r.protocol}`;
        const commentText = sanitizeText(r.comment, 120);
        const pubComment = iptComment(`published rule${r.orderIndex}${commentText ? ` ${commentText}` : ''}`);
        const ifNames = resolveInterfaceNames(input.host, ruleScope(r, input));
        for (const t of resolveTargets(r, sets).filter((x) => x.family === null || x.family === fam)) {
          for (const iface of ifNames.length === 0 ? [''] : ifNames) {
            for (const addr of t.iptAddrs.length === 0 ? [''] : t.iptAddrs) {
              for (const p of iptCtPortArgs(ports)) {
                push(`-A ${FWD} ${iface ? `-i ${iface}` : ''} ${pubProto} ${addr ? `-s ${addr}` : ''} -m conntrack --ctstate DNAT ${p} ${pubComment} -j ${r.action === 'ALLOW' ? ALLOW : 'DROP'}`);
              }
            }
          }
        }
      }
      // iptables accepts one -i per rule, so each Docker bridge gets its own exemption: traffic that
      // containers/overlay gateways send to published ports is not an external client.
      for (const iface of DOCKER_INTERNAL_IFACES.ipt) {
        push(`-A ${FWD} -i ${iface} -m conntrack --ctstate DNAT ${iptComment('published_docker_internal')} -j RETURN`);
      }
      push(`-A ${FWD} -m conntrack --ctstate DNAT ${iptComment('published_default')} -j ${defaultAccept ? 'RETURN' : 'DROP'}`);
    }
    const fwdRules = rulesSorted.filter((r) => r.direction === 'FORWARD');
    for (const r of fwdRules) {
      const ports = rulePorts(r);
      const proto = r.protocol === 'any' ? '' : `-p ${r.protocol === 'icmp' ? icmpProto : r.protocol}`;
      const commentText = sanitizeText(r.comment, 120);
      const comment = iptComment(`fwd${r.orderIndex}${commentText ? ` ${commentText}` : ''}`);
      for (const m of forwardMatches(r, sets)) {
        if (m.family !== null && m.family !== fam) continue;
        const srcs = m.src.iptAddrs.length === 0 ? [''] : m.src.iptAddrs;
        const dsts = m.dst.iptAddrs.length === 0 ? [''] : m.dst.iptAddrs;
        for (const sa of srcs) {
          for (const da of dsts) {
            for (const p of iptPortArgs(ports)) {
              const match = `-A ${FWD} ${proto} ${sa ? `-s ${sa}` : ''} ${da ? `-d ${da}` : ''} ${p} ${comment}`;
              if (logOnly) {
                push(`${match} -j LOG --log-prefix ${iptLogPrefix(`${r.action} ${commentText || 'fwd rule'}`)}`);
                push(`${match} -j RETURN`);
              } else {
                push(`${match} -j ${r.action === 'ALLOW' ? ALLOW : 'DROP'}`);
              }
            }
          }
        }
      }
    }
    for (const addr of fam === 4 ? prot.v4 : prot.v6) {
      const match = `-A ${FWD} -d ${addr} ${iptComment('protected_default_deny')}`;
      if (logOnly) {
        push(`${match} -j LOG --log-prefix "FW-AUDIT: DENY: protected: "`);
        push(`${match} -j RETURN`);
      } else {
        push(`${match} -j DROP`);
      }
    }
    push(`-A ${FWD} ${iptComment('default')} -j RETURN`);
  }
  lines.push('COMMIT');
  return lines.join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function xml(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function compileFirewalld(input: CompileInput): string {
  if (input.logOnlyMode) throw new CompileError('firewalld learning mode is not supported; enforced policies are never replaced by a persisted learning policy');
  const sets = prepareSets(input.sets);
  const mgmt = prepareMgmt(input);
  const prot = prepareProtected(input, sets);
  const rules: Record<string, string[]> = { 'segmentra-in': [], 'segmentra-out': [], 'segmentra-fwd': [] };
  let priority = -32000;
  const emit = (name: string, family: Family, source: string | null, destination: string | null,
    protocol: string, ports: Array<[number, number]> | null, action: 'ALLOW' | 'DENY', log = 'NONE') => {
    for (const port of ports ?? [null]) {
      if (priority >= 30000) throw new CompileError('firewalld policy expansion exceeds rich-rule priority capacity');
      const element = port ? `<port port="${port[0] === port[1] ? port[0] : `${port[0]}-${port[1]}`}" protocol="${protocol}"/>`
        : protocol === 'any' ? '' : `<protocol value="${protocol === 'icmp' && family === 6 ? 'ipv6-icmp' : protocol}"/>`;
      rules[name].push(`<rule family="ipv${family}" priority="${priority++}">${source ? `<source address="${xml(source)}"/>` : ''}${destination ? `<destination address="${xml(destination)}"/>` : ''}${element}${log === 'NONE' ? '' : `<log prefix="FW-AUDIT: ${action}: ">${log === 'LOG_RATE_LIMITED' ? '<limit value="5/s"/>' : ''}</log>`}<${action === 'ALLOW' ? 'accept' : 'drop'}/></rule>`);
    }
  };
  for (const family of [4, 6] as Family[]) {
    for (const address of family === 4 ? mgmt.v4 : mgmt.v6) emit('segmentra-in', family, address, null, 'tcp', [[mgmt.port, mgmt.port]], 'ALLOW');
    if (family === 4 ? mgmt.fallbackV4 : mgmt.fallbackV6) emit('segmentra-in', family, null, null, 'tcp', [[mgmt.port, mgmt.port]], 'ALLOW');
  }
  for (const r of [...input.rules].sort((a, b) => a.orderIndex - b.orderIndex)) {
    validateRuleEnums(r);
    const ports = rulePorts(r);
    if (r.direction !== 'FORWARD' && ruleScope(r, input).type !== 'ALL_INTERFACES') {
      throw new CompileError(`Rule #${r.orderIndex}: firewalld policies require ALL_INTERFACES; interface-scoped rules cannot be translated safely`);
    }
    if (r.direction === 'FORWARD') {
      for (const match of forwardMatches(r, sets)) {
        for (const fam of match.family ? [match.family] : [4, 6] as Family[]) {
          for (const source of match.src.iptAddrs.length ? match.src.iptAddrs : [null]) {
            for (const dest of match.dst.iptAddrs.length ? match.dst.iptAddrs : [null]) emit('segmentra-fwd', fam, source, dest, r.protocol, ports, r.action, r.logMode);
          }
        }
      }
    } else {
      for (const target of resolveTargets(r, sets)) {
        for (const fam of target.family ? [target.family] : [4, 6] as Family[]) {
          for (const address of target.iptAddrs.length ? target.iptAddrs : [null]) {
            if (r.direction === 'IN' || r.direction === 'BOTH') emit('segmentra-in', fam, address, null, r.protocol, ports, r.action, r.logMode);
            if (r.direction === 'OUT' || r.direction === 'BOTH') emit('segmentra-out', fam, null, address, r.protocol, ports, r.action, r.logMode);
          }
        }
      }
    }
  }
  for (const fam of [4, 6] as Family[]) {
    for (const dest of fam === 4 ? prot.v4 : prot.v6) emit('segmentra-fwd', fam, null, dest, 'any', null, 'DENY');
  }
  const policies: Record<string, string> = {};
  for (const [name, ingress, egress, target] of [
    ['segmentra-in', 'ANY', 'HOST', (input.defaultInputAction ?? 'DROP') === 'DROP' ? 'DROP' : 'CONTINUE'],
    ['segmentra-out', 'HOST', 'ANY', 'CONTINUE'],
    ['segmentra-fwd', 'ANY', 'ANY', 'CONTINUE']
  ]) {
    if (name === 'segmentra-fwd' && !forwardingEnabled(input, prot)) continue;
    policies[name] = `<?xml version="1.0" encoding="utf-8"?>\n<policy target="${target}" priority="-500"><short>Segmentra managed policy</short><ingress-zone name="${ingress}"/><egress-zone name="${egress}"/>${rules[name].join('')}</policy>\n`;
  }
  return JSON.stringify({ format: 1, backend: 'firewalld', policies }) + '\n';
}

/**
 * Compile a host policy. Throws CompileError on invalid input (bad ports,
 * addresses, interface/set names, or ports combined with protocol "any"/"icmp").
 */
export function compileHostPolicy(input: CompileInput): CompileOutput {
  const backend = input.host.firewallBackend;
  const logOnly = input.logOnlyMode ?? false;

  // Docker support is implemented for the iptables and nftables backends. The native managers would silently
  // ignore it (firewalld) or apply only half of it (UFW has no DOCKER-USER integration), which leaves the
  // cluster ports or published ports unprotected without any warning, so refuse instead.
  if (backend === 'firewalld' && (input.swarm || input.dockerPublishedPorts)) {
    throw new CompileError('Docker Swarm / published-port support needs the iptables or nftables backend; firewalld is not supported for it');
  }
  if (backend === 'ufw' && input.dockerPublishedPorts) {
    throw new CompileError('Docker published-port enforcement needs the iptables or nftables backend; UFW is not supported for it');
  }

  if (backend === 'firewalld') {
    const text = compileFirewalld(input);
    return { backend, text, sha256: sha256(text) };
  }
  if (backend === 'ufw') {
    if (logOnly) throw new CompileError('UFW learning mode is not supported; enforced policies are never replaced by a persisted learning policy');
    const text = JSON.stringify({ format: 1, backend, ipv4: compileIptablesFamily(input, false, 4), ipv6: compileIptablesFamily(input, false, 6) }) + '\n';
    return { backend, text, sha256: sha256(text) };
  }

  if (backend === 'nftables') {
    const text = compileNft(input, logOnly);
    return { backend, text, sha256: sha256(text) };
  }
  if (backend !== 'iptables') throw new CompileError(`Unsupported firewall backend: "${backend}"`);
  const text = compileIptablesFamily(input, logOnly, 4);
  const ip6tablesRules = compileIptablesFamily(input, logOnly, 6);
  return { backend, text, sha256: sha256(text), ip6tablesRules };
}

/** Exposed for callers that need to validate a single address the same way the compiler does. */
export function normalizeCidr(value: string): string {
  return sanitizeCidr(value);
}
