/**
 * Reboot persistence of Segmentra's rules with the distribution's OWN mechanism.
 *
 * Segmentra is agentless: nothing of Segmentra runs at boot. After a deployment (and after
 * every restore / rollback / removal) the host scripts copy Segmentra's live state into the
 * files the distribution's firewall service loads at boot:
 *
 *   nftables (Debian/Ubuntu): /etc/nftables.d/segmentra.nft + one include line in /etc/nftables.conf,
 *                             nftables.service enabled (never started/restarted)
 *   nftables (RHEL family):   /etc/nftables/segmentra.nft + one include line in /etc/sysconfig/nftables.conf,
 *                             nftables.service enabled unless firewalld is active/enabled
 *   iptables (Debian/Ubuntu): SEGMENTRA lines merged into /etc/iptables/rules.v4 / rules.v6
 *                             (iptables-persistent), netfilter-persistent.service enabled
 *   iptables (RHEL family):   SEGMENTRA lines merged into /etc/sysconfig/iptables / ip6tables
 *                             (iptables-services), iptables/ip6tables.service enabled unless firewalld
 *
 * Packages are never installed and firewalld is never disabled: missing pieces are reported as
 * warnings. A log-only (Firewall Learning / policy test) policy is never persisted, so the boot
 * configuration always holds the last ENFORCED policy.
 *
 * This file only holds the shell code shared by SEGMENTRA_NFT_SH and SEGMENTRA_IPTABLES_SH
 * (it is interpolated into both; see the regeneration note in nft-scripts.ts /
 * iptables-scripts.ts) and the parser of its output.
 *
 * Output protocol (stdout, one line each):
 *   SEGMENTRA_PERSIST status=<persisted|not_persisted|removed> method=<m|none> distro=<debian|rhel|unsupported> family=<nft|iptables|ip6tables> state=<s>
 *   SEGMENTRA_PERSIST_WARN <code> <message>     (persistence is missing or incomplete)
 *   SEGMENTRA_PERSIST_NOTE <code> <message>     (informational)
 * state: in_sync | differs | missing | none | learning | unsupported | error
 */

/** Marker line written above Segmentra's include line in the distribution's nftables config. */
export const PERSIST_MARK = '# managed by Segmentra (reboot persistence) - do not edit this line or the next';

/**
 * POSIX sh functions shared by both host scripts. Requires $tmpd (scratch dir) to exist.
 * No `${` sequences and no backslashes except the escaped ones below (TS template literal).
 */
export const PERSIST_COMMON_SH = `# ---- reboot persistence with the distribution's own service (nothing of Segmentra runs at boot) ----
PMARK='${PERSIST_MARK}'
PBK=/var/backups/segmentra/persist
P_DISTRO=unsupported
P_FAMILY=
pwarn() { echo "SEGMENTRA_PERSIST_WARN $1 $2"; }
pnote() { echo "SEGMENTRA_PERSIST_NOTE $1 $2"; }
presult() { echo "SEGMENTRA_PERSIST status=$1 method=$2 distro=$P_DISTRO family=$P_FAMILY state=$3"; }

detect_distro() {
  P_DISTRO=unsupported
  [ -r /etc/os-release ] || return 0
  ids=" $(sed -n -e 's/^ID=//p' -e 's/^ID_LIKE=//p' /etc/os-release | tr -d '"' | tr -d "'" | tr '\\n' ' ') "
  case "$ids" in
    *" debian "*|*" ubuntu "*) P_DISTRO=debian ;;
    *" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*|*" fedora "*) P_DISTRO=rhel ;;
  esac
}

have_systemctl() { command -v systemctl >/dev/null 2>&1; }
unit_exists() {
  for d in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
    if [ -f "$d/$1" ]; then return 0; fi
  done
  return 1
}
unit_enabled() { have_systemctl && [ "$(systemctl is-enabled "$1" 2>/dev/null)" = enabled ]; }
firewalld_on() {
  have_systemctl || return 1
  if systemctl is-active --quiet firewalld.service 2>/dev/null; then return 0; fi
  unit_enabled firewalld.service
}
# Enable (never start or restart) a unit: starting it now would reload the whole saved
# configuration, which may flush the rules of Docker, Kubernetes, fail2ban, ...
enable_unit() {
  if unit_enabled "$1"; then return 0; fi
  systemctl enable "$1" >/dev/null 2>"$tmpd/enerr" || { pwarn enable_failed "systemctl enable $1 failed: $(tr '\\n' ' ' < "$tmpd/enerr")"; return 1; }
  unit_enabled "$1"
}

same_file() { [ -f "$1" ] && [ -f "$2" ] && [ "$(cksum < "$1")" = "$(cksum < "$2")" ]; }

# replace_file <dest> <new-content> <mode-if-new>: atomic replace when the content differs.
# An existing file keeps its owner/mode; its previous content is kept in $PBK.
replace_file() {
  if same_file "$1" "$2"; then return 0; fi
  if [ -f "$1" ]; then
    mkdir -p "$PBK" 2>/dev/null && chmod 700 "$PBK" 2>/dev/null
    cp -p "$1" "$PBK/$(echo "$1" | tr / _).prev" 2>/dev/null
    cp -p "$1" "$1.segmentra-tmp" || return 1
  else
    mkdir -p "$(dirname "$1")" || return 1
    : > "$1.segmentra-tmp" || return 1
    chmod "$3" "$1.segmentra-tmp"
  fi
  if ! cat "$2" > "$1.segmentra-tmp" || ! mv -f "$1.segmentra-tmp" "$1"; then rm -f "$1.segmentra-tmp"; return 1; fi
  if command -v restorecon >/dev/null 2>&1; then restorecon "$1" >/dev/null 2>&1; fi
  return 0
}

# ensure_include <conf> <line>: <conf> contains <line> exactly once, preceded by PMARK, appended
# at the end; every other line is left as it is. A missing <conf> is created WITHOUT flush ruleset.
ensure_include() {
  if [ -f "$1" ]; then
    if [ "$(grep -cxF -- "$2" "$1")" = 1 ] && [ "$(grep -cxF -- "$PMARK" "$1")" = 1 ]; then return 0; fi
    awk -v l="$2" -v m="$PMARK" '$0 != l && $0 != m' "$1" > "$tmpd/pconf" || return 1
    printf '%s\\n%s\\n' "$PMARK" "$2" >> "$tmpd/pconf"
  else
    printf '#!/usr/sbin/nft -f\\n%s\\n%s\\n' "$PMARK" "$2" > "$tmpd/pconf"
  fi
  replace_file "$1" "$tmpd/pconf" 755
}

# drop_include <conf> <line>: remove <line> and PMARK from <conf> (other lines untouched).
drop_include() {
  [ -f "$1" ] || return 0
  if ! grep -qxF -- "$2" "$1" && ! grep -qxF -- "$PMARK" "$1"; then return 0; fi
  awk -v l="$2" -v m="$PMARK" '$0 != l && $0 != m' "$1" > "$tmpd/pconf" || return 1
  replace_file "$1" "$tmpd/pconf" 755
}
`;

export type PersistenceStatus = 'persisted' | 'not_persisted' | 'removed' | 'unknown';
export type PersistenceMethod = 'nftables.service' | 'netfilter-persistent' | 'iptables-services';

export interface PersistenceFamilyResult {
  family: 'nft' | 'iptables' | 'ip6tables';
  status: Exclude<PersistenceStatus, 'unknown'>;
  method: PersistenceMethod | null;
  state: string;
}

/** Reboot persistence outcome of one host (see the output protocol above). */
export interface PersistenceResult {
  /**
   * persisted: the distro service loads Segmentra's current (enforced) state at boot;
   * not_persisted: it does not (see warnings); removed: no Segmentra state, persistence removed;
   * unknown: the host scripts reported nothing (e.g. SSH failed).
   */
  status: PersistenceStatus;
  method: PersistenceMethod | null;
  distro: 'debian' | 'rhel' | 'unsupported' | null;
  /** Persisted copy vs live state: in_sync | differs | missing | none | learning | unsupported | error (worst family). */
  state: string | null;
  /** Human-readable warnings, each prefixed with its code ("firewalld_active: ..."). */
  warnings: string[];
  /** Informational notes, same format. */
  notes: string[];
  families: PersistenceFamilyResult[];
}

const STATE_RANK = ['in_sync', 'none', 'learning', 'differs', 'missing', 'unsupported', 'error'];

/** Parse the SEGMENTRA_PERSIST* lines of a host script run. Multiple families are combined. */
export function parsePersistenceOutput(stdout: string): PersistenceResult {
  const families: PersistenceFamilyResult[] = [];
  const warnings: string[] = [];
  const notes: string[] = [];
  let distro: PersistenceResult['distro'] = null;
  for (const raw of stdout.split(/\r?\n/)) {
    const line = raw.trim();
    let m = /^SEGMENTRA_PERSIST status=(\S+) method=(\S+) distro=(\S+) family=(\S*) state=(\S+)$/.exec(line);
    if (m) {
      const status = (['persisted', 'not_persisted', 'removed'].includes(m[1]) ? m[1] : 'not_persisted') as PersistenceFamilyResult['status'];
      const method = (['nftables.service', 'netfilter-persistent', 'iptables-services'].includes(m[2]) ? m[2] : null) as PersistenceMethod | null;
      distro = (['debian', 'rhel', 'unsupported'].includes(m[3]) ? m[3] : 'unsupported') as PersistenceResult['distro'];
      const family = (['nft', 'iptables', 'ip6tables'].includes(m[4]) ? m[4] : 'nft') as PersistenceFamilyResult['family'];
      families.push({ family, status, method, state: m[5] });
      continue;
    }
    m = /^SEGMENTRA_PERSIST_(WARN|NOTE) (\S+) (.*)$/.exec(line);
    if (m) {
      const text = `${m[2]}: ${m[3]}`;
      const list = m[1] === 'WARN' ? warnings : notes;
      if (!list.includes(text)) list.push(text);
    }
  }
  if (families.length === 0) {
    return { status: 'unknown', method: null, distro, state: null, warnings, notes, families };
  }
  let status: PersistenceStatus;
  if (families.some((f) => f.status === 'not_persisted')) status = 'not_persisted';
  else if (families.some((f) => f.status === 'persisted')) status = 'persisted';
  else status = 'removed';
  const method = families.find((f) => f.method)?.method ?? null;
  const state = families
    .map((f) => f.state)
    .reduce((a, b) => (STATE_RANK.indexOf(b) > STATE_RANK.indexOf(a) ? b : a), families[0].state);
  return { status, method, distro, state, warnings, notes, families };
}

/** One-line summary for deployment_hosts.persistence_message / UI tooltips. */
export function persistenceSummary(p: PersistenceResult): string {
  const parts: string[] = [];
  if (p.status === 'persisted') parts.push(`Survives reboot via ${p.method ?? 'the distribution service'} (${p.distro ?? 'unknown distro'})`);
  else if (p.status === 'removed') parts.push('Segmentra rules removed from the boot configuration');
  else if (p.status === 'unknown') parts.push('Reboot persistence status unknown');
  else parts.push('Rules will NOT survive a reboot');
  parts.push(...p.warnings, ...p.notes);
  return parts.join(' | ');
}
