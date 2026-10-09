/**
 * Passive discovery of devices behind an IoT gateway from its neighbour (ARP / NDP) table, plus the helpers around it:
 * parsing, MAC normalisation, vendor lookup from an imported IEEE OUI list, and a type suggestion. Nothing is scanned or
 * sent to the devices: only what the gateway already learned is read.
 */
import net from 'node:net';

export type Neighbor = { ip: string; mac: string; iface: string | null; state: string | null };

export function normalizeMac(raw: string): string | null {
  const hex = raw.toLowerCase().replace(/[^0-9a-f]/g, '');
  if (hex.length !== 12) return null;
  return hex.match(/../g)!.join(':');
}

/** True for MACs that are not a single device: multicast/broadcast (low bit of the first octet) and all zeros. */
function isUsableMac(mac: string): boolean {
  if (mac === '00:00:00:00:00:00') return false;
  return (parseInt(mac.slice(0, 2), 16) & 1) === 0;
}

function isUsableIp(ip: string): boolean {
  const v = net.isIP(ip);
  if (v === 4) {
    const [a, b] = ip.split('.').map(Number);
    return !(a === 0 || a >= 224 || a === 127 || (a === 169 && b === 254));
  }
  if (v === 6) {
    const low = ip.toLowerCase();
    return !(low.startsWith('fe80') || low.startsWith('ff') || low === '::1');
  }
  return false;
}

/**
 * Parse the output of `ip -o neigh show` and of `cat /proc/net/arp`, separated by a line "---". Entries without a MAC
 * (FAILED, INCOMPLETE), multicast/broadcast and link-local addresses are dropped. `ip neigh` wins over /proc/net/arp.
 */
export function parseNeighbors(text: string): Neighbor[] {
  const [ipPart = '', arpPart = ''] = text.split(/^---\s*$/m);
  const byIp = new Map<string, Neighbor>();
  for (const line of ipPart.split('\n')) {
    // 192.168.1.10 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE   |   fe80::1 dev eth0 lladdr .. router STALE
    const m = /^(\S+)\s+dev\s+(\S+)(?:\s+lladdr\s+(\S+))?(?:\s+(?:router|proxy|extern_learn|use|managed|locked|sticky))*\s*([A-Z]+)?\s*$/.exec(line.trim());
    if (!m || !m[3]) continue;
    const state = m[4] ?? null;
    if (state === 'FAILED' || state === 'INCOMPLETE') continue;
    const mac = normalizeMac(m[3]);
    if (!mac || !isUsableMac(mac) || !isUsableIp(m[1])) continue;
    byIp.set(m[1], { ip: m[1], mac, iface: m[2], state });
  }
  for (const line of arpPart.split('\n').slice(1)) {
    // IP address  HW type  Flags  HW address  Mask  Device
    const f = line.trim().split(/\s+/);
    if (f.length < 6 || f[2] === '0x0') continue;
    const mac = normalizeMac(f[3]);
    if (!mac || !isUsableMac(mac) || !isUsableIp(f[0]) || byIp.has(f[0])) continue;
    byIp.set(f[0], { ip: f[0], mac, iface: f[5], state: null });
  }
  return [...byIp.values()].sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
}

/** Read-only command run on the gateway (no sudo: the neighbour table is world-readable). */
export const NEIGHBOR_COMMAND = "PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH; ip -o neigh show 2>/dev/null; echo '---'; cat /proc/net/arp 2>/dev/null; true";

// ---- Active probe (opt-in) ------------------------------------------------------------------------------------------

/** The largest subnet a probe may cover: a /24 (254 hosts). Bigger sweeps belong in a real scanner, not in a web click. */
export const MAX_SWEEP_PREFIX = 24;

/**
 * Validate the subnet of an active probe and list its host addresses (network and broadcast addresses left out).
 * Only IPv4 CIDRs of /24 to /32 are accepted; the addresses are produced here, never copied from the input, so the
 * list is safe to put into a shell command.
 */
export function parseSweepCidr(value: string): { ok: true; cidr: string; ips: string[] } | { ok: false; error: string } {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(String(value ?? '').trim());
  if (!m) return { ok: false, error: 'Enter an IPv4 subnet such as 192.168.10.0/24' };
  const o = m.slice(1, 5).map(Number);
  if (o.some((n) => n > 255)) return { ok: false, error: 'Not a valid IPv4 address' };
  const prefix = m[5] === undefined ? 32 : Number(m[5]);
  if (prefix > 32) return { ok: false, error: 'The prefix length must be between 24 and 32' };
  if (prefix < MAX_SWEEP_PREFIX) return { ok: false, error: `A probe covers at most a /${MAX_SWEEP_PREFIX} (254 addresses); ${value} is larger` };
  const base = (((o[0] * 256 + o[1]) * 256 + o[2]) * 256 + o[3]) >>> 0;
  const size = 2 ** (32 - prefix);
  const first = Math.floor(base / size) * size;
  const ips: string[] = [];
  for (let i = 0; i < size; i += 1) {
    if (prefix < 31 && (i === 0 || i === size - 1)) continue; // network and broadcast address
    const n = first + i;
    ips.push([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'));
  }
  const n0 = first;
  return { ok: true, cidr: `${[(n0 >>> 24) & 255, (n0 >>> 16) & 255, (n0 >>> 8) & 255, n0 & 255].join('.')}/${prefix}`, ips };
}

/**
 * Shell command for the gateway: one ICMP echo per address (32 at a time, 1 second each), then the neighbour table. Even a
 * device that does not answer ping is learned through the ARP request the gateway sends; unused addresses stay out of the table.
 */
export function buildSweepCommand(ips: string[]): string {
  if (!ips.every((ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip))) throw new Error('invalid address in the sweep list');
  return `PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH; n=0; for ip in ${ips.join(' ')}; do (ping -c 1 -W 1 $ip >/dev/null 2>&1) & n=$((n+1)); if [ $((n % 32)) -eq 0 ]; then wait; fi; done; wait; ${NEIGHBOR_COMMAND}`;
}

// ---- OUI vendor list ----------------------------------------------------------------------------------------------

function csvRows(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [], cell = '', quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { cell += '"'; i += 1; } else if (c === '"') quoted = false; else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { row.push(cell); cell = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i += 1;
      row.push(cell); cell = '';
      if (row.some((x) => x !== '')) rows.push(row);
      row = [];
    } else cell += c;
  }
  row.push(cell);
  if (row.some((x) => x !== '')) rows.push(row);
  return rows;
}

/** Parse the IEEE registry as CSV (oui.csv: Registry,Assignment,Organization Name,...) or text (oui.txt: "00-00-0C   (hex)   Cisco"). */
export function parseOuiList(text: string): Array<{ prefix: string; vendor: string }> {
  const out = new Map<string, string>();
  const head = text.slice(0, 200).toLowerCase();
  if (head.includes('assignment') || head.includes('registry,')) {
    for (const r of csvRows(text)) {
      const prefix = (r[1] ?? '').trim().toLowerCase();
      const vendor = (r[2] ?? '').trim();
      if (/^[0-9a-f]{6}$/.test(prefix) && vendor) out.set(prefix, vendor);
    }
  } else {
    for (const line of text.split('\n')) {
      const m = /^\s*([0-9A-Fa-f]{2})[-:]([0-9A-Fa-f]{2})[-:]([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$/.exec(line);
      if (m) out.set((m[1] + m[2] + m[3]).toLowerCase(), m[4]);
    }
  }
  return [...out].map(([prefix, vendor]) => ({ prefix, vendor }));
}

export const ouiPrefix = (mac: string) => mac.replace(/:/g, '').slice(0, 6).toLowerCase();
/** Locally administered MACs (virtual machines, containers, privacy addresses) belong to no vendor. */
export const isLocallyAdministered = (mac: string) => (parseInt(mac.slice(0, 2), 16) & 2) !== 0;

// ---- type suggestion ----------------------------------------------------------------------------------------------

const TYPE_HINTS: Array<{ type: string; words: RegExp }> = [
  { type: 'plc', words: /siemens|rockwell|allen[- ]?bradley|schneider|telemecanique|omron|mitsubishi electric|beckhoff|phoenix contact|wago|moxa|b&r|bosch rexroth|festo|pilz|sick ag|keyence|yokogawa|emerson|abb\b|hirschmann|weidm/i },
  { type: 'camera', words: /axis comm|hikvision|dahua|hanwha|vivotek|mobotix|uniview|avigilon|flir|bosch security/i },
  { type: 'hvac', words: /honeywell|johnson controls|trane|carrier|daikin|lennox|belimo|siemens building|distech|tridium|delta controls/i },
  { type: 'printer', words: /hewlett|hp inc|canon|brother|epson|xerox|ricoh|lexmark|kyocera|konica|sharp|oki data|zebra tech/i },
  { type: 'medical', words: /philips medical|ge healthcare|medtronic|draeger|dräger|mindray|baxter|siemens healthineers|b\. braun|fresenius|masimo|natus/i },
];
/** A suggestion from the vendor name only; the operator decides. */
export function suggestAssetType(vendor: string | null | undefined): string {
  if (!vendor) return 'other';
  return TYPE_HINTS.find((h) => h.words.test(vendor))?.type ?? 'other';
}
