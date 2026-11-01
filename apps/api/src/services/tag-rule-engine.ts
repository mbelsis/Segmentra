import { Worker } from 'node:worker_threads';

import type { PoolClient } from 'pg';

import { pool } from '../db/pool.js';
import { cidrContains, isValidCidr } from './ip-utils.js';
import { triggerTemplateAutoApply } from './template-engine.js';

// Helper: check if IP matches a CIDR range (IPv4 and IPv6)
function ipMatchesCidr(ip: string, cidr: string): boolean {
  return cidrContains(cidr, String(ip).split('/')[0]);
}

/** Max length of a user-supplied regex and of the string it is tested against. */
export const MAX_REGEX_LENGTH = 200;
export const MAX_REGEX_INPUT_LENGTH = 256;
/** Max number of quantifiers (*, +, ?, {n,m}) in a user-supplied regex. */
export const MAX_REGEX_QUANTIFIERS = 10;
/** Wall-clock budget for one regex evaluation batch (one pattern against a list of inputs). */
export const REGEX_TIME_BUDGET_MS = 100;
/** Budget for the validation probe run on create/update. */
const REGEX_VALIDATION_BUDGET_MS = 50;

// ---------------------------------------------------------------------------
// Budgeted regex execution
// ---------------------------------------------------------------------------
//
// User regexes never run on the API's main thread. They run in a dedicated worker thread; the main
// thread hands over (pattern, inputs) and waits on a SharedArrayBuffer with Atomics.wait and a hard
// timeout. On timeout the worker is terminated (it may take a moment to die, but it is a separate
// thread) and a fresh one is started for the next call. So a catastrophic-backtracking pattern that
// slipped past the static check costs at most REGEX_TIME_BUDGET_MS of wall-clock time, instead of
// blocking the event loop (V8 only checks for interrupts sporadically inside irregexp, so vm/
// worker "timeouts" executed on the main thread can overrun by seconds).

const REGEX_WORKER_SOURCE = `
const { parentPort, workerData } = require('node:worker_threads');
const ready = new Int32Array(workerData.ready);
Atomics.store(ready, 0, 1);
Atomics.notify(ready, 0);
const cache = new Map();
parentPort.on('message', (m) => {
  const state = new Int32Array(m.sab, 0, 1);
  const out = new Uint8Array(m.sab, 4);
  try {
    let re = cache.get(m.pattern);
    if (!re) {
      re = new RegExp(m.pattern, 'i');
      if (cache.size > 500) cache.clear();
      cache.set(m.pattern, re);
    }
    for (let i = 0; i < m.inputs.length; i++) { re.lastIndex = 0; out[i] = re.test(m.inputs[i]) ? 1 : 0; }
    Atomics.store(state, 0, 1);
  } catch (e) {
    Atomics.store(state, 0, 2);
  }
  Atomics.notify(state, 0);
});
`;

let regexWorker: Worker | null = null;

function ensureRegexWorker(): Worker | null {
  if (regexWorker) return regexWorker;
  const ready = new SharedArrayBuffer(4);
  let w: Worker;
  try {
    w = new Worker(REGEX_WORKER_SOURCE, { eval: true, workerData: { ready } });
  } catch {
    return null;
  }
  w.unref();
  w.on('error', () => {
    if (regexWorker === w) regexWorker = null;
  });
  w.on('exit', () => {
    if (regexWorker === w) regexWorker = null;
  });
  const flag = new Int32Array(ready);
  Atomics.wait(flag, 0, 0, 5000);
  if (Atomics.load(flag, 0) !== 1) {
    void w.terminate();
    return null;
  }
  regexWorker = w;
  return w;
}

export type RegexBatchResult = { ok: true; results: boolean[] } | { ok: false; reason: 'timeout' | 'invalid' | 'unavailable' };

/**
 * Test one (case-insensitive) pattern against several inputs within a hard wall-clock budget.
 * Inputs are truncated to MAX_REGEX_INPUT_LENGTH. Never runs the regex on the calling thread.
 */
export function regexTestBatch(pattern: string, inputs: string[], budgetMs = REGEX_TIME_BUDGET_MS): RegexBatchResult {
  if (inputs.length === 0) return { ok: true, results: [] };
  const w = ensureRegexWorker();
  if (!w) return { ok: false, reason: 'unavailable' };
  const sab = new SharedArrayBuffer(4 + inputs.length);
  const state = new Int32Array(sab, 0, 1);
  w.postMessage({ sab, pattern, inputs: inputs.map((s) => String(s ?? '').slice(0, MAX_REGEX_INPUT_LENGTH)) });
  Atomics.wait(state, 0, 0, budgetMs);
  const s = Atomics.load(state, 0);
  if (s === 1) return { ok: true, results: Array.from(new Uint8Array(sab, 4), (b) => b === 1) };
  if (s === 2) return { ok: false, reason: 'invalid' };
  // Timed out: abandon this worker (terminate is asynchronous and does not block us).
  if (regexWorker === w) regexWorker = null;
  void w.terminate().catch(() => {});
  return { ok: false, reason: 'timeout' };
}

/**
 * Per-evaluation regex matcher: memoises results, primes whole batches per pattern, and treats a
 * pattern that is rejected by the static check, invalid or exceeds the time budget as matching
 * nothing (for the rest of this matcher's life).
 */
export class RegexMatcher {
  private memo = new Map<string, Map<string, boolean>>();
  private poisoned = new Set<string>();
  readonly problems: string[] = [];

  prime(pattern: string, inputs: Iterable<string>): void {
    if (this.poisoned.has(pattern)) return;
    const danger = cachedDangerReason(pattern);
    if (danger) {
      this.poison(pattern, danger);
      return;
    }
    let m = this.memo.get(pattern);
    if (!m) this.memo.set(pattern, (m = new Map()));
    const todo = Array.from(new Set(Array.from(inputs, (s) => String(s ?? '').slice(0, MAX_REGEX_INPUT_LENGTH)))).filter((s) => !m!.has(s));
    if (todo.length === 0) return;
    const r = regexTestBatch(pattern, todo, REGEX_TIME_BUDGET_MS + todo.length);
    if (!r.ok) {
      this.poison(pattern, r.reason === 'timeout' ? 'regex exceeded its time budget' : r.reason === 'invalid' ? 'invalid regex' : 'regex engine unavailable');
      return;
    }
    todo.forEach((s, i) => m!.set(s, r.results[i]));
  }

  test(pattern: string, input: string): boolean {
    const value = String(input ?? '').slice(0, MAX_REGEX_INPUT_LENGTH);
    if (this.poisoned.has(pattern)) return false;
    const hit = this.memo.get(pattern)?.get(value);
    if (hit !== undefined) return hit;
    this.prime(pattern, [value]);
    return this.memo.get(pattern)?.get(value) ?? false;
  }

  private poison(pattern: string, reason: string) {
    this.poisoned.add(pattern);
    this.memo.delete(pattern);
    this.problems.push(`pattern ${JSON.stringify(pattern.slice(0, 60))}: ${reason}; it matches nothing`);
  }
}

const dangerCache = new Map<string, string | null>();
function cachedDangerReason(pattern: string): string | null {
  if (dangerCache.has(pattern)) return dangerCache.get(pattern)!;
  const r = regexDangerReason(pattern);
  if (dangerCache.size > 1000) dangerCache.clear();
  dangerCache.set(pattern, r);
  return r;
}

// ---------------------------------------------------------------------------
// Static ReDoS check
// ---------------------------------------------------------------------------

/** Representative characters used to decide whether two atoms can match the same character. */
const PROBE_CHARS: string[] = (() => {
  const out: string[] = [];
  for (let c = 0x20; c <= 0x7e; c++) out.push(String.fromCharCode(c));
  out.push('\t', '\n', ' ', 'é', 'Ω', '中', '\u{1F600}');
  return out;
})();

type CharSet = Set<number>; // indexes into PROBE_CHARS
type Quant = { min: number; max: number }; // max = Infinity for unbounded
type SeqItem =
  | { kind: 'atom'; chars: CharSet; quant: Quant | null; containsVariable: boolean; group?: boolean }
  | { kind: 'zero' }; // anchors / lookarounds: zero-width, transparent for the chain analysis

class RegexShapeError extends Error {}

function charsOfToken(token: string): CharSet {
  const set: CharSet = new Set();
  let re: RegExp;
  try {
    re = new RegExp(`^(?:${token})$`, 'iu');
  } catch {
    try {
      re = new RegExp(`^(?:${token})$`, 'i');
    } catch {
      // Unknown token: assume it can match anything (conservative).
      PROBE_CHARS.forEach((_, i) => set.add(i));
      return set;
    }
  }
  PROBE_CHARS.forEach((c, i) => {
    if (re.test(c)) set.add(i);
  });
  return set;
}

function overlaps(a: CharSet, b: CharSet): boolean {
  for (const x of a) if (b.has(x)) return true;
  return false;
}

function isVariable(q: Quant | null): boolean {
  return !!q && q.max !== q.min;
}

/**
 * Small recursive-descent parser producing, per alternative, the sequence of atoms with their
 * quantifiers and character sets. Groups are flattened when they are a single unquantified
 * alternative; otherwise they become one atom whose character set is the union of their content.
 */
class RegexShape {
  quantifierCount = 0;
  /** Every alternative of every group (and of the whole pattern), for the chain analysis. */
  readonly sequences: SeqItem[][] = [];
  private i = 0;
  constructor(private p: string) {}

  parse(): SeqItem[][] {
    const branches = this.parseAlternation();
    if (this.i < this.p.length) throw new RegexShapeError('unbalanced parenthesis');
    return branches;
  }

  private parseAlternation(): SeqItem[][] {
    const branches: SeqItem[][] = [this.parseSequence()];
    while (this.p[this.i] === '|') {
      this.i++;
      branches.push(this.parseSequence());
    }
    this.sequences.push(...branches);
    return branches;
  }

  private parseSequence(): SeqItem[] {
    const seq: SeqItem[] = [];
    while (this.i < this.p.length && this.p[this.i] !== '|' && this.p[this.i] !== ')') {
      const before = this.p[this.i];
      if (before === '^' || before === '$') {
        this.i++;
        seq.push({ kind: 'zero' });
        continue;
      }
      if (before === '\\' && /[bB]/.test(this.p[this.i + 1] ?? '')) {
        this.i += 2;
        seq.push({ kind: 'zero' });
        continue;
      }
      const atom = this.parseAtom();
      const quant = this.parseQuantifier();
      if (atom.kind === 'zero') {
        seq.push(atom);
        continue;
      }
      if (atom.kind === 'inline') {
        if (quant) {
          // Quantified group: one atom (nested quantifier checks happen in regexDangerReason).
          seq.push({ kind: 'atom', chars: atom.chars, quant, containsVariable: atom.containsVariable, group: true });
        } else {
          seq.push(...atom.items);
        }
        continue;
      }
      seq.push({ kind: 'atom', chars: atom.chars, quant, containsVariable: atom.containsVariable });
    }
    return seq;
  }

  private parseQuantifier(): Quant | null {
    const rest = this.p.slice(this.i);
    let q: Quant | null = null;
    let len = 0;
    const brace = /^\{(\d+)(,(\d*))?\}/.exec(rest);
    if (rest[0] === '*') (q = { min: 0, max: Infinity }), (len = 1);
    else if (rest[0] === '+') (q = { min: 1, max: Infinity }), (len = 1);
    else if (rest[0] === '?') (q = { min: 0, max: 1 }), (len = 1);
    else if (brace) {
      const min = Number(brace[1]);
      const max = brace[2] === undefined ? min : brace[3] === '' ? Infinity : Number(brace[3]);
      q = { min, max };
      len = brace[0].length;
    }
    if (!q) return null;
    this.i += len;
    if (this.p[this.i] === '?') this.i++; // lazy modifier
    this.quantifierCount++;
    return q;
  }

  private parseAtom():
    | { kind: 'zero' }
    | { kind: 'char'; chars: CharSet; containsVariable: false }
    | { kind: 'inline'; items: SeqItem[]; chars: CharSet; containsVariable: boolean } {
    const p = this.p;
    const c = p[this.i];
    if (c === '(') {
      this.i++;
      let lookaround = false;
      if (p[this.i] === '?') {
        const mod = /^\?(?::|=|!|<=|<!|<[A-Za-z_$][\w$]*>)/.exec(p.slice(this.i));
        if (!mod) throw new RegexShapeError('unsupported group syntax');
        lookaround = /^\?(=|!|<=|<!)/.test(mod[0]);
        this.i += mod[0].length;
      }
      const branches = this.parseAlternation();
      if (p[this.i] !== ')') throw new RegexShapeError('unbalanced parenthesis');
      this.i++;
      if (lookaround) return { kind: 'zero' };
      const chars: CharSet = new Set();
      let containsVariable = false;
      for (const b of branches) {
        for (const it of b) {
          if (it.kind !== 'atom') continue;
          it.chars.forEach((x) => chars.add(x));
          if (isVariable(it.quant) || it.containsVariable) containsVariable = true;
        }
      }
      // Several alternatives that differ in length behave like a variable-length atom.
      if (branches.length > 1) containsVariable = true;
      if (branches.length === 1) return { kind: 'inline', items: branches[0], chars, containsVariable };
      return { kind: 'inline', items: [{ kind: 'atom', chars, quant: containsVariable ? { min: 0, max: Infinity } : null, containsVariable, group: true }], chars, containsVariable };
    }
    if (c === '[') {
      let j = this.i + 1;
      if (p[j] === '^') j++;
      if (p[j] === ']') j++;
      while (j < p.length && p[j] !== ']') j += p[j] === '\\' ? 2 : 1;
      if (j >= p.length) throw new RegexShapeError('unterminated character class');
      const token = p.slice(this.i, j + 1);
      this.i = j + 1;
      return { kind: 'char', chars: charsOfToken(token), containsVariable: false };
    }
    if (c === '\\') {
      const m = /^\\(?:u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|c[A-Za-z]|[pP]\{[^}]*\}|0|.)/s.exec(p.slice(this.i));
      const token = m ? m[0] : '\\';
      this.i += token.length;
      return { kind: 'char', chars: charsOfToken(token), containsVariable: false };
    }
    if (c === '*' || c === '+' || c === '?' || c === '{') {
      // A quantifier with nothing to repeat ("{" not forming a quantifier is a literal).
      if (c === '{' && !/^\{\d+(,\d*)?\}/.test(p.slice(this.i))) {
        this.i++;
        return { kind: 'char', chars: charsOfToken('\\{'), containsVariable: false };
      }
      throw new RegexShapeError('nothing to repeat');
    }
    this.i += 1;
    const token = c === '.' ? '.' : c.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
    return { kind: 'char', chars: charsOfToken(token), containsVariable: false };
  }
}

/**
 * Within one alternative, find variable-length atoms that can match the same characters without a
 * disjoint mandatory atom between them (e.g. \w*\w*, a?a?a?, .*x.*y.*). Each such pair multiplies the
 * backtracking work by the input length, so three or more of them are rejected.
 */
function ambiguousChainReason(seq: SeqItem[]): string | null {
  let open: CharSet[] = [];
  let prev: SeqItem | null = null;
  for (const it of seq) {
    if (it.kind === 'zero') continue;
    const variable = isVariable(it.quant) || it.containsVariable;
    if (variable) {
      const overlapping = open.filter((o) => overlaps(o, it.chars)).length;
      if (overlapping >= 2) {
        return 'three or more repeated parts can match the same characters (e.g. \\w*\\w*\\w* or .*a.*b.*); ' +
          'simplify the pattern (matching is unanchored, so leading/trailing .* are not needed)';
      }
      // Two directly adjacent single-character repeats that overlap (\w*\w*, a?a?) never add meaning.
      if (
        prev && prev.kind === 'atom' && isVariable(prev.quant) && !prev.group && !it.group && overlaps(prev.chars, it.chars)
      ) {
        return 'adjacent repeated parts that can match the same characters (e.g. \\w*\\w* or a?a?) are not allowed';
      }
      open.push(it.chars);
    } else {
      // A mandatory atom ends the ambiguity for every open repeat it cannot overlap with.
      open = open.filter((o) => overlaps(o, it.chars));
    }
    prev = it;
  }
  return null;
}

/**
 * Static ReDoS guard for user-supplied regexes (a first line of defence; evaluation additionally
 * runs off-thread with a hard time budget, see regexTestBatch). Rejects:
 *  - backreferences (\1, \k<name>)
 *  - nested quantifiers: a quantified group that itself contains a quantifier, e.g. (a+)+, (.*)*, (\w+\d*){2,}
 *  - quantified groups with alternation, e.g. (a|aa)+ (overlapping alternatives backtrack exponentially)
 *  - more than MAX_REGEX_QUANTIFIERS quantifiers
 *  - adjacent repeats that can match the same characters (\w*\w*, a?a?), and chains of three or more
 *    such repeats not separated by a disjoint mandatory character (\w*a\w*a\w*, .*x.*y.*)
 * Returns a reason string when the pattern is rejected, otherwise null.
 */
export function regexDangerReason(pattern: string): string | null {
  if (pattern.length > MAX_REGEX_LENGTH) return `regex longer than ${MAX_REGEX_LENGTH} characters`;
  if (/\\[1-9]|\\k<[^>]+>/.test(pattern)) return 'backreferences are not allowed';
  try {
    new RegExp(pattern, 'i');
  } catch (e: any) {
    return `invalid regex: ${e?.message ?? 'syntax error'}`;
  }

  // Strip escaped characters and character classes so only structural tokens remain.
  const stripped = pattern.replace(/\\./g, 'x').replace(/\[(?:\\.|[^\]])*\]/g, 'x');
  // Repeats that can match many times (*, +, {n,}, {n,m}); "?" and {n} only add bounded work.
  const multiAfter = /^(?:[+*]|\{\d+,\d*\})/;
  const anyQuantAfter = /^(?:[+*?]|\{\d+(?:,\d*)?\})/;
  const stack: Array<{ hasQuant: boolean; hasAlt: boolean }> = [];
  for (let i = 0; i < stripped.length; i++) {
    const c = stripped[i];
    if (c === '(') {
      stack.push({ hasQuant: false, hasAlt: false });
      if (stripped[i + 1] === '?') i++; // group modifier, not a quantifier
    } else if (c === ')') {
      const group = stack.pop();
      if (!group) continue;
      const rest = stripped.slice(i + 1);
      const multi = multiAfter.test(rest);
      const quantified = anyQuantAfter.test(rest);
      if (multi && group.hasQuant) return 'nested quantifiers (e.g. (a+)+) are not allowed';
      if (multi && group.hasAlt) return 'quantified alternation (e.g. (a|aa)+) is not allowed';
      // Propagate to the parent: a quantified group (or one containing quantifiers) counts as a quantifier.
      if (stack.length > 0 && (group.hasQuant || quantified)) stack[stack.length - 1].hasQuant = true;
    } else if (c === '|') {
      if (stack.length > 0) stack[stack.length - 1].hasAlt = true;
    } else if (c === '+' || c === '*' || c === '?' || c === '{') {
      if (c === '{' && !/^\{\d+(?:,\d*)?\}/.test(stripped.slice(i))) continue;
      if (stack.length > 0) stack[stack.length - 1].hasQuant = true;
    }
  }

  const shape = new RegexShape(pattern);
  try {
    shape.parse();
  } catch (e: any) {
    return `unsupported regex: ${e?.message ?? 'syntax error'}`;
  }
  if (shape.quantifierCount > MAX_REGEX_QUANTIFIERS) return `more than ${MAX_REGEX_QUANTIFIERS} quantifiers are not allowed`;
  for (const b of shape.sequences) {
    const reason = ambiguousChainReason(b);
    if (reason) return reason;
  }
  return null;
}

/** Inputs used to probe a new pattern within the time budget before it is stored. */
function probeInputs(): string[] {
  const n = MAX_REGEX_INPUT_LENGTH - 1;
  return ['a', '0', '-', '.', ' ', '_', 'A', 'z', '9', ':'].flatMap((c) => [c.repeat(n) + '!', c.repeat(n)]).concat(['web-01.prod.example.com', '10.0.0.1', 'fe80::1']);
}

/**
 * Validate a regex for storage: the static check plus a budgeted trial run against adversarial
 * sample inputs. Returns a reason string when rejected.
 */
export function validateRegexPattern(pattern: string): string | null {
  const reason = regexDangerReason(pattern);
  if (reason) return reason;
  const r = regexTestBatch(pattern, probeInputs(), REGEX_VALIDATION_BUDGET_MS);
  if (!r.ok) {
    if (r.reason === 'timeout') return 'regex is too slow (catastrophic backtracking) on test inputs';
    if (r.reason === 'invalid') return 'invalid regex';
    return 'regex engine unavailable; try again';
  }
  return null;
}

/** Validate tag-rule criteria before storing it. Returns a list of problems (empty = valid). */
export function validateCriteria(criteria: TagRuleCriteria): string[] {
  const problems: string[] = [];
  (criteria?.conditions ?? []).forEach((c, idx) => {
    if (c.operator === 'matches') {
      const reason = validateRegexPattern(String(c.value ?? ''));
      if (reason) problems.push(`condition ${idx + 1}: ${reason}`);
    }
    if (c.operator === 'in_cidr' && !isValidCidr(String(c.value ?? ''))) {
      problems.push(`condition ${idx + 1}: "${c.value}" is not a valid CIDR`);
    }
  });
  return problems;
}

export interface TagRuleCondition {
  field: string;      // hostname, mgmt_ip, vlan_id, vlan_tag, os_family, environment, firewall_backend, tag
  operator: string;   // equals, not_equals, matches, contains, in_cidr, has_tag
  value: string;
}

export interface TagRuleCriteria {
  conditions: TagRuleCondition[];
  logic: 'AND' | 'OR';
}

export interface HostTagInfo {
  id: string;
  name: string;
  /** 'manual' or 'rule' */
  source: string;
  ruleId: string | null;
}

export interface HostData {
  id: string;
  hostname: string;
  mgmt_ip: string;
  vlan_id: string | null;
  vlan_tag: number | null;
  os_family: string | null;
  environment: string | null;
  firewall_backend: string | null;
  tag_ids: string[];
  /** Tag names the conditions are evaluated against (see reconcileRuleTags for which tags are included). */
  tag_names: string[];
  /** Stored tags with their origin (only filled by getHostData). */
  tags?: HostTagInfo[];
}

async function getHostData(hostId?: string, db: Pick<PoolClient, 'query'> = pool): Promise<HostData[]> {
  const { rows } = await db.query(
    `SELECT h.id, h.hostname, host(h.mgmt_ip) AS mgmt_ip, h.vlan_id, v.vlan_tag, h.os_family, h.environment,
            h.firewall_backend,
            COALESCE(array_agg(t.id ORDER BY t.name, t.id) FILTER (WHERE t.id IS NOT NULL), '{}') AS tag_ids,
            COALESCE(array_agg(t.name ORDER BY t.name, t.id) FILTER (WHERE t.id IS NOT NULL), '{}') AS tag_names,
            COALESCE(json_agg(json_build_object('id', t.id, 'name', t.name, 'source', ht.source, 'ruleId', ht.source_rule_id)
                              ORDER BY t.name, t.id) FILTER (WHERE t.id IS NOT NULL), '[]') AS tags
       FROM hosts h
       LEFT JOIN vlans v ON h.vlan_id = v.id
       LEFT JOIN host_tags ht ON ht.host_id = h.id
       LEFT JOIN tags t ON t.id = ht.tag_id
      WHERE ${hostId ? 'h.id = $1' : 'h.enabled = true'}
      GROUP BY h.id, v.vlan_tag
      ORDER BY h.hostname ASC, h.id ASC`,
    hostId ? [hostId] : []
  );
  return rows.map((host: any) => ({
    id: host.id,
    hostname: host.hostname,
    mgmt_ip: host.mgmt_ip,
    vlan_id: host.vlan_id,
    vlan_tag: host.vlan_tag,
    os_family: host.os_family,
    environment: host.environment,
    firewall_backend: host.firewall_backend,
    tag_ids: host.tag_ids ?? [],
    tag_names: host.tag_names ?? [],
    tags: (typeof host.tags === 'string' ? JSON.parse(host.tags) : host.tags) ?? [],
  }));
}

function scalarField(field: string, host: HostData): string | null | undefined {
  switch (field) {
    case 'hostname': return host.hostname;
    case 'mgmt_ip': return host.mgmt_ip;
    case 'vlan_id': return host.vlan_id;
    case 'vlan_tag': return host.vlan_tag?.toString() ?? null;
    case 'os_family': return host.os_family;
    case 'environment': return host.environment;
    case 'firewall_backend': return host.firewall_backend;
    default: return undefined;
  }
}

function evaluateCondition(condition: TagRuleCondition, host: HostData, matcher: RegexMatcher): boolean {
  const { field, operator } = condition;
  const value = String(condition.value ?? '');
  const lower = value.toLowerCase();

  if (field === 'tag') {
    // Tags are a set: each operator applies per tag name.
    //  equals / has_tag → some tag equals; not_equals → no tag equals; contains → some tag contains;
    //  matches → some tag matches. in_cidr never matches a tag.
    const names = host.tag_names.map((t) => String(t));
    switch (operator) {
      case 'has_tag':
      case 'equals':
        return names.some((t) => t.toLowerCase() === lower);
      case 'not_equals':
        return !names.some((t) => t.toLowerCase() === lower);
      case 'contains':
        return names.some((t) => t.toLowerCase().includes(lower));
      case 'matches':
        return names.some((t) => matcher.test(value, t));
      default:
        return false;
    }
  }

  const fieldValue = scalarField(field, host);
  if (fieldValue === undefined) return false; // unknown field

  if (operator === 'has_tag') {
    return host.tag_names.some((t) => t.toLowerCase() === lower);
  }

  if (fieldValue === null) {
    return operator === 'not_equals';
  }

  switch (operator) {
    case 'equals':
      return fieldValue.toLowerCase() === lower;
    case 'not_equals':
      return fieldValue.toLowerCase() !== lower;
    case 'matches':
      return matcher.test(value, fieldValue);
    case 'contains':
      return fieldValue.toLowerCase().includes(lower);
    case 'in_cidr':
      return ipMatchesCidr(fieldValue, value);
    default:
      return false;
  }
}

/** Pure matcher: does a host satisfy the criteria? (regexes run off-thread with a time budget) */
export function evaluateCriteria(criteria: TagRuleCriteria, host: HostData, matcher: RegexMatcher = new RegexMatcher()): boolean {
  if (!criteria?.conditions || criteria.conditions.length === 0) return false;

  if (criteria.logic === 'OR') {
    return criteria.conditions.some(c => evaluateCondition(c, host, matcher));
  }
  // Default AND
  return criteria.conditions.every(c => evaluateCondition(c, host, matcher));
}

/** Run every regex of the criteria once, in one batch per pattern, against all values it can see. */
function primeMatcher(matcher: RegexMatcher, criteriaList: TagRuleCriteria[], hosts: HostData[], tagNames: string[]) {
  const byPattern = new Map<string, Set<string>>();
  for (const criteria of criteriaList) {
    for (const c of criteria?.conditions ?? []) {
      if (c.operator !== 'matches') continue;
      const pattern = String(c.value ?? '');
      let inputs = byPattern.get(pattern);
      if (!inputs) byPattern.set(pattern, (inputs = new Set()));
      if (c.field === 'tag') {
        tagNames.forEach((t) => inputs!.add(t));
      } else {
        for (const h of hosts) {
          const v = scalarField(c.field, h);
          if (typeof v === 'string') inputs.add(v);
        }
      }
    }
  }
  for (const [pattern, inputs] of byPattern) matcher.prime(pattern, inputs);
}

/**
 * Hosts that would match the criteria right now (against the hosts' stored tags). Performs no
 * writes (used by POST /api/tag-rules/preview).
 */
export async function previewCriteria(criteria: TagRuleCriteria): Promise<Array<{ id: string; hostname: string }>> {
  const hosts = await getHostData();
  const matcher = new RegexMatcher();
  const tagNames = Array.from(new Set(hosts.flatMap((h) => h.tag_names)));
  primeMatcher(matcher, [criteria], hosts, tagNames);
  return hosts.filter((h) => evaluateCriteria(criteria, h, matcher)).map((h) => ({ id: h.id, hostname: h.hostname }));
}

/** Remove every host_tags row a rule assigned (used when a rule is disabled, retargeted or deleted). */
export async function removeRuleAssignedTags(ruleId: string, db: Pick<PoolClient, 'query'> = pool): Promise<number> {
  const { rowCount } = await db.query(`DELETE FROM host_tags WHERE source = 'rule' AND source_rule_id = $1`, [ruleId]);
  await db.query(`UPDATE tag_rule_results SET matched = false, evaluated_at = now() WHERE tag_rule_id = $1`, [ruleId]);
  return rowCount ?? 0;
}

type ReconcileResult = {
  perRule: Map<string, number>;
  hostsEvaluated: number;
  rulesEvaluated: number;
  assigned: Array<{ hostId: string; tagId: string; ruleId: string }>;
};

export type EvalRule = { id: string; tag_id: string; criteria: TagRuleCriteria; enabled: boolean };

/** Max rounds of the per-host fixed-point evaluation (rule chains longer than this are cut off). */
const MAX_RULE_ROUNDS = 10;

/**
 * Decide which rules match which hosts. Pure (no I/O apart from the budgeted regex worker).
 *
 * Semantics of `tag` conditions (deterministic, independent of what a previous run stored):
 *  - Evaluation starts from the host's MANUAL tags only; tags stored with source 'rule' are ignored.
 *  - Rules are evaluated in rounds. In round k a rule sees the manual tags plus the tags assigned in
 *    round k-1 by OTHER rules (never tags that only it assigned itself). This lets rules chain
 *    ("has_tag db" assigned by another rule) while a rule like "has_tag T → assign T" can never keep
 *    itself true, and "tag not_equals T → assign T" does not oscillate.
 *  - Rounds repeat until the assignment is stable, at most MAX_RULE_ROUNDS times (mutually negating
 *    rules may not converge; the last round wins).
 */
export function computeRuleMatches(
  rules: EvalRule[],
  hosts: HostData[],
  tagNameById: Map<string, string>,
  matcher: RegexMatcher
): { matchedByRule: Map<string, Set<string>>; unconverged: string[] } {
  const matchedByRule = new Map<string, Set<string>>(rules.map((r) => [r.id, new Set<string>()]));
  const unconverged: string[] = [];
  for (const host of hosts) {
    const stored = host.tags ?? host.tag_names.map((name, i) => ({ id: host.tag_ids[i] ?? name, name, source: 'manual', ruleId: null }));
    const manual = stored.filter((t) => t.source !== 'rule').map((t) => t.name);
    // matched = rules matching in the previous round (initially none, i.e. manual tags only).
    let matched = new Set<string>();
    let converged = false;
    for (let round = 0; round < MAX_RULE_ROUNDS; round++) {
      const assigned = new Map<string, string[]>(); // tagId -> rules assigning it in the previous round
      for (const rule of rules) {
        if (!matched.has(rule.id)) continue;
        const list = assigned.get(rule.tag_id) ?? [];
        list.push(rule.id);
        assigned.set(rule.tag_id, list);
      }
      const nextMatched = new Set<string>();
      for (const rule of rules) {
        const names = new Set(manual);
        for (const [tagId, by] of assigned) {
          if (by.some((rid) => rid !== rule.id)) names.add(tagNameById.get(tagId) ?? tagId);
        }
        if (evaluateCriteria(rule.criteria, { ...host, tag_names: [...names] }, matcher)) nextMatched.add(rule.id);
      }
      const same = nextMatched.size === matched.size && [...nextMatched].every((id) => matched.has(id));
      matched = nextMatched;
      if (same) {
        converged = true;
        break;
      }
    }
    if (!converged) unconverged.push(host.hostname);
    for (const id of matched) matchedByRule.get(id)!.add(host.id);
  }
  return { matchedByRule, unconverged };
}

type EvaluationState = { rules: EvalRule[]; disabledIds: string[]; hosts: HostData[]; tagNameById: Map<string, string>; fingerprint: string };

async function loadEvaluationState(db: Pick<PoolClient, 'query'>, hostId?: string): Promise<EvaluationState> {
  const { rows } = await db.query(
    `SELECT id, tag_id, criteria, enabled FROM tag_rules ORDER BY priority DESC, created_at ASC, id ASC`
  );
  const all: EvalRule[] = rows.map((r: any) => ({
    id: r.id,
    tag_id: r.tag_id,
    enabled: !!r.enabled,
    criteria: (typeof r.criteria === 'string' ? JSON.parse(r.criteria) : r.criteria) as TagRuleCriteria,
  }));
  const hosts = await getHostData(hostId, db);
  const { rows: tagRows } = await db.query(`SELECT id, name FROM tags ORDER BY id`);
  const tagNameById = new Map<string, string>(tagRows.map((t: any) => [t.id, t.name]));
  const rules = all.filter((r) => r.enabled);
  const disabledIds = all.filter((r) => !r.enabled).map((r) => r.id);
  const fingerprint = JSON.stringify([all, hosts, tagRows]);
  return { rules, disabledIds, hosts, tagNameById, fingerprint };
}

function evaluateState(state: EvaluationState) {
  const matcher = new RegexMatcher();
  primeMatcher(matcher, state.rules.map((r) => r.criteria), state.hosts, [...state.tagNameById.values()]);
  const result = computeRuleMatches(state.rules, state.hosts, state.tagNameById, matcher);
  if (matcher.problems.length) {
    // eslint-disable-next-line no-console
    console.warn('[tag-rules] regex problems:', matcher.problems.join('; '));
  }
  if (result.unconverged.length) {
    // eslint-disable-next-line no-console
    console.warn(`[tag-rules] rule evaluation did not converge for: ${result.unconverged.slice(0, 10).join(', ')}`);
  }
  return result;
}

/**
 * Bring rule-assigned host tags in line with the ENABLED rules (disabled rules assign nothing).
 * For each (host, tag) the highest-priority matching rule owns the assignment. Manual tags are
 * never touched; a manual tag also satisfies a rule (no duplicate row is created).
 *
 * The CPU work (criteria / regex evaluation) runs BEFORE the transaction and the advisory lock; under
 * the lock the inputs are re-read and only re-evaluated if they changed in the meantime.
 */
async function reconcileRuleTags(opts: { hostId?: string } = {}): Promise<ReconcileResult> {
  const pre = await loadEvaluationState(pool, opts.hostId);
  const preResult = evaluateState(pre);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Serialize concurrent reconciliations (interval job vs. API calls).
    await client.query(`SELECT pg_advisory_xact_lock(hashtext('segmentra_tag_rule_reconcile'))`);

    const state = await loadEvaluationState(client, opts.hostId);
    const { matchedByRule } = state.fingerprint === pre.fingerprint ? preResult : evaluateState(state);
    const { rules: enabledRules, disabledIds, hosts } = state;
    const hostIds = hosts.map((h) => h.id);

    const perRule = new Map<string, number>();
    const desired = new Map<string, string>(); // `${hostId}|${tagId}` -> ruleId

    for (const rule of enabledRules) {
      const matchedSet = matchedByRule.get(rule.id) ?? new Set<string>();
      const matchedIds: string[] = [];
      const unmatchedIds: string[] = [];
      for (const host of hosts) {
        if (matchedSet.has(host.id)) {
          matchedIds.push(host.id);
          const key = `${host.id}|${rule.tag_id}`;
          if (!desired.has(key)) desired.set(key, rule.id);
        } else {
          unmatchedIds.push(host.id);
        }
      }
      perRule.set(rule.id, matchedIds.length);
      if (hosts.length > 0) {
        await client.query(
          `INSERT INTO tag_rule_results (tag_rule_id, host_id, matched, evaluated_at)
           SELECT $1, x.host_id, x.matched, now()
             FROM unnest($2::uuid[], $3::boolean[]) AS x(host_id, matched)
           ON CONFLICT (tag_rule_id, host_id) DO UPDATE SET matched = EXCLUDED.matched, evaluated_at = now()`,
          [rule.id, [...matchedIds, ...unmatchedIds], [...matchedIds.map(() => true), ...unmatchedIds.map(() => false)]]
        );
      }
    }

    // Disabled rules match nothing.
    if (disabledIds.length > 0 && hostIds.length > 0) {
      await client.query(
        `UPDATE tag_rule_results SET matched = false, evaluated_at = now()
          WHERE tag_rule_id = ANY($1::uuid[]) AND host_id = ANY($2::uuid[])`,
        [disabledIds, hostIds]
      );
    }

    // Existing rule-assigned tags for the evaluated hosts.
    const { rows: existing } = hostIds.length
      ? await client.query(
          `SELECT host_id, tag_id, source_rule_id FROM host_tags WHERE source = 'rule' AND host_id = ANY($1::uuid[])`,
          [hostIds]
        )
      : { rows: [] as any[] };

    const existingKeys = new Set<string>();
    for (const row of existing) {
      const key = `${row.host_id}|${row.tag_id}`;
      existingKeys.add(key);
      const owner = desired.get(key);
      if (!owner) {
        await client.query(
          `DELETE FROM host_tags WHERE host_id = $1 AND tag_id = $2 AND source = 'rule'`,
          [row.host_id, row.tag_id]
        );
      } else if (owner !== row.source_rule_id) {
        await client.query(
          `UPDATE host_tags SET source_rule_id = $3 WHERE host_id = $1 AND tag_id = $2 AND source = 'rule'`,
          [row.host_id, row.tag_id, owner]
        );
      }
    }

    const assigned: ReconcileResult['assigned'] = [];
    for (const [key, ruleId] of desired) {
      if (existingKeys.has(key)) continue;
      const [hostId, tagId] = key.split('|');
      const { rowCount } = await client.query(
        `INSERT INTO host_tags (host_id, tag_id, source, source_rule_id)
         VALUES ($1, $2, 'rule', $3)
         ON CONFLICT (host_id, tag_id) DO NOTHING`,
        [hostId, tagId, ruleId]
      );
      if (rowCount) assigned.push({ hostId, tagId, ruleId });
    }

    await client.query('COMMIT');
    triggerTemplateAutoApply(assigned.map((a) => a.tagId));
    return { perRule, hostsEvaluated: hosts.length, rulesEvaluated: enabledRules.length, assigned };
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

export async function evaluateRule(ruleId: string): Promise<{ matched: number; total: number; enabled: boolean }> {
  const { rows: rules } = await pool.query(`SELECT id, enabled FROM tag_rules WHERE id = $1`, [ruleId]);
  if (!rules[0]) throw new Error('Tag rule not found');
  const result = await reconcileRuleTags();
  return { matched: result.perRule.get(ruleId) ?? 0, total: result.hostsEvaluated, enabled: !!rules[0].enabled };
}

export async function evaluateAllRules(): Promise<{ rulesEvaluated: number; totalMatches: number }> {
  const result = await reconcileRuleTags();
  let totalMatches = 0;
  for (const n of result.perRule.values()) totalMatches += n;
  return { rulesEvaluated: result.rulesEvaluated, totalMatches };
}

export async function evaluateHostAgainstRules(hostId: string): Promise<{ rulesMatched: number; tagsAssigned: string[] }> {
  const { rows } = await pool.query(`SELECT id FROM hosts WHERE id = $1`, [hostId]);
  if (!rows[0]) throw new Error('Host not found');
  const result = await reconcileRuleTags({ hostId });
  let rulesMatched = 0;
  for (const n of result.perRule.values()) if (n > 0) rulesMatched++;
  return { rulesMatched, tagsAssigned: result.assigned.map((a) => a.tagId) };
}
