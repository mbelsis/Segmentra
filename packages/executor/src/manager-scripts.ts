import { shq } from './ssh-options.js';

export type ManagedFirewallBackend = 'firewalld' | 'ufw';
export const HOST_MANAGER_SCRIPT = '/var/backups/segmentra/segmentra-manager.py';

/** One-shot native-manager helper. No daemon or Segmentra service is installed. */
export const SEGMENTRA_MANAGER_PY = String.raw`import fcntl
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

NAMES = ('segmentra-in', 'segmentra-out', 'segmentra-fwd')
BEGIN = '# BEGIN SEGMENTRA MANAGED RULES'
END = '# END SEGMENTRA MANAGED RULES'
UFW_FILES = (Path('/etc/ufw/before.rules'), Path('/etc/ufw/before6.rules'))
POLICY_DIR = Path('/etc/firewalld/policies')
os.environ['LC_ALL'] = 'C'

def run(*args, optional=False):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if result.returncode and not optional:
        raise RuntimeError(' '.join(args) + ': ' + (result.stderr or result.stdout).strip())
    return result.stdout.strip() if result.returncode == 0 else None

def atomic(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.segmentra-', dir=str(path.parent))
    try:
        os.fchmod(fd, path.stat().st_mode & 0o777 if path.exists() else 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        if shutil.which('restorecon'):
            run('restorecon', str(path))
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def fw(*args, permanent=False, optional=False):
    return run('firewall-cmd', *(['--permanent'] if permanent else []), *args, optional=optional)

def block(text):
    if text.count(BEGIN) != text.count(END) or text.count(BEGIN) > 1:
        raise RuntimeError('Malformed or duplicate Segmentra UFW block')
    if BEGIN not in text:
        return ''
    return text[text.index(BEGIN):text.index(END) + len(END)] + '\n'

def replace_block(text, replacement):
    old = block(text)
    if old:
        text = text.replace(old, '', 1)
    if not replacement:
        return text
    lines = text.splitlines(keepends=True)
    start = next((i for i, line in enumerate(lines) if line.strip() == '*filter'), None)
    if start is None:
        raise RuntimeError('UFW before-rules file has no filter table')
    end = next((i for i in range(start + 1, len(lines)) if lines[i].strip() == 'COMMIT'), None)
    if end is None:
        raise RuntimeError('UFW before-rules filter table has no COMMIT')
    at = next((i for i in range(start + 1, end) if lines[i].startswith('-')), end)
    lines.insert(at, replacement)
    return ''.join(lines)

def ufw_block(fragment, ipv6=False):
    lines = fragment.splitlines()
    if '*filter' not in lines or 'COMMIT' not in lines:
        raise RuntimeError('Invalid UFW compiled fragment')
    owned = [line for line in lines if line.startswith(':SEGMENTRA-') or line.startswith('-A SEGMENTRA-')]
    if not any(line.startswith(':SEGMENTRA-IN ') for line in owned):
        raise RuntimeError('UFW policy must contain SEGMENTRA-IN')
    prefix = 'ufw6' if ipv6 else 'ufw'
    jumps = ['-A ' + prefix + '-before-input -j SEGMENTRA-IN', '-A ' + prefix + '-before-output -j SEGMENTRA-OUT']
    if any(line.startswith(':SEGMENTRA-FWD ') for line in owned):
        jumps.append('-A ' + prefix + '-before-forward -j SEGMENTRA-FWD')
    return BEGIN + '\n' + '\n'.join(owned + jumps) + '\n' + END + '\n'

def permanent_state(backend):
    if backend == 'ufw':
        return {str(path): block(path.read_text()) for path in UFW_FILES}
    return {name: (POLICY_DIR / (name + '.xml')).read_text() if (POLICY_DIR / (name + '.xml')).exists() else None for name in NAMES}

def fw_info(name, permanent=False):
    value = fw('--info-policy=' + name, permanent=permanent, optional=True)
    if value is None:
        return None
    return normalize_info(value)

def normalize_info(value):
    lines = value.splitlines()
    # CLI headers annotate runtime objects with "active" and "default" flags;
    # these are display metadata, not configuration differences.
    return sorted([lines[0].split(' (')[0]] + [line.strip() for line in lines[1:] if line.strip()])

def kernel_state(backend):
    if backend == 'ufw':
        out = []
        for tool in ('iptables-save', 'ip6tables-save'):
            text = run(tool)
            out.append([re.sub(r'\[\d+:\d+\]', '[0:0]', line) for line in text.splitlines() if line.startswith(':SEGMENTRA-') or
                line.startswith('-A SEGMENTRA-') or re.search(r'-j SEGMENTRA-(IN|OUT|FWD)$', line)])
        return out
    # Only firewalld's Segmentra policy chains and jumps, ignoring unrelated tables/counters.
    objects = json.loads(run('nft', '-j', 'list', 'ruleset'))['nftables']
    def clean(value):
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items() if k not in ('handle', 'packets', 'bytes')}
        if isinstance(value, list):
            return [clean(v) for v in value]
        return value
    chains = []
    rules = {}
    for item in objects:
        body = item.get('chain') or item.get('rule')
        if body and body.get('table') == 'firewalld' and 'segmentra-' in json.dumps(body):
            if 'chain' in item:
                chains.append(clean(item))
            else:
                key = body['family'] + ':' + body['table'] + ':' + body['chain']
                # Order within a chain changes enforcement and must remain in the hash.
                rules.setdefault(key, []).append(clean(item))
    return {'chains': sorted(chains, key=lambda item: json.dumps(item, sort_keys=True)), 'rules': rules}

def read_state(backend):
    permanent = permanent_state(backend)
    runtime = kernel_state(backend)
    if backend == 'firewalld':
        native = {name: fw_info(name) for name in NAMES}
        present = native['segmentra-in'] is not None and native['segmentra-out'] is not None and bool(runtime['rules'])
    else:
        native = None
        present = all(any(re.search(r'^-A ufw6?-before-input -j SEGMENTRA-IN$', line) for line in family)
            and any(re.search(r'^-A ufw6?-before-output -j SEGMENTRA-OUT$', line) for line in family) for family in runtime)
    return {'backend': backend, 'present': present, 'permanent': permanent, 'runtime': runtime, 'native': native}

def require_manager(backend):
    if shutil.which('nft') and run('nft', 'list', 'table', 'inet', 'segmentra', optional=True) is not None:
        raise RuntimeError('An existing raw nftables Segmentra policy must be removed before switching to a native manager')
    for tool in ('iptables-save', 'ip6tables-save'):
        if shutil.which(tool):
            raw = run(tool)
            if re.search(r'^-A (INPUT|OUTPUT|FORWARD) .*?-j SEGMENTRA-', raw, re.M):
                raise RuntimeError('An existing raw iptables Segmentra policy must be removed before switching to a native manager')
    run('systemctl', 'is-active', '--quiet', backend)
    if backend == 'firewalld':
        if fw('--state') != 'running':
            raise RuntimeError('firewalld must already be running')
        fw('--get-policies')
        if not shutil.which('nft'):
            raise RuntimeError('firewalld requires nft for live-state verification')
        conf = Path('/etc/firewalld/firewalld.conf').read_text()
        if re.search(r'^FirewallBackend=iptables\s*$', conf, re.M):
            raise RuntimeError('Segmentra firewalld policies require its nftables backend')
    else:
        if not re.search(r'^Status: active$', run('ufw', 'status'), re.M):
            raise RuntimeError('UFW must already be enabled')
        if not re.search(r'^IPV6=yes\s*$', Path('/etc/default/ufw').read_text(), re.M):
            raise RuntimeError('UFW requires IPV6=yes to enforce both address families')
        for path in UFW_FILES:
            block(path.read_text())
        for tool in ('iptables-save', 'ip6tables-save', 'iptables-restore', 'ip6tables-restore'):
            if not shutil.which(tool):
                raise RuntimeError(tool + ' is required')

def ensure_reload_safe():
    # Reload would discard unsaved settings. Refuse before modifying any configuration.
    for kind in ('zones', 'policies', 'ipsets'):
        live = set(fw('--get-' + kind).split())
        saved = set(fw('--get-' + kind, permanent=True).split())
        if kind == 'policies':
            live -= set(NAMES)
            saved -= set(NAMES)
        if live != saved:
            raise RuntimeError('firewalld has unsaved runtime ' + kind + '; save or reconcile them before deploying')
        singular = {'zones': 'zone', 'policies': 'policy', 'ipsets': 'ipset'}[kind]
        for name in sorted(live):
            def info(permanent):
                result = fw('--info-' + singular + '=' + name, permanent=permanent)
                return normalize_info(result)
            if info(False) != info(True):
                raise RuntimeError('firewalld has unsaved runtime settings for ' + name + '; refusing reload')
    for option in ('--get-all-chains', '--get-all-rules', '--get-all-passthroughs'):
        if fw('--direct', option) != fw('--direct', option, permanent=True):
            raise RuntimeError('firewalld has unsaved direct rules; refusing reload')

def restore_state(backend, state):
    if backend == 'ufw':
        changes = [(path, replace_block(path.read_text(), state[str(path)])) for path in UFW_FILES]
        for path, content in changes:
            atomic(path, content)
        run('ufw', 'reload')
    else:
        for name in NAMES:
            path = POLICY_DIR / (name + '.xml')
            if state[name] is None:
                path.unlink(missing_ok=True)
            else:
                atomic(path, state[name])
        fw('--check-config')
        fw('--reload')

def apply_policy(backend, policy):
    if policy.get('format') != 1 or policy.get('backend') != backend:
        raise RuntimeError('Policy format/backend mismatch')
    if backend == 'ufw':
        changes = [(path, replace_block(path.read_text(), ufw_block(policy[key], path == UFW_FILES[1])))
            for path, key in zip(UFW_FILES, ('ipv4', 'ipv6'))]
        # Validate both complete files before changing either family.
        for path, content in changes:
            fd, tmp = tempfile.mkstemp()
            try:
                with os.fdopen(fd, 'w') as stream:
                    stream.write(content)
                run('ip6tables-restore' if path == UFW_FILES[1] else 'iptables-restore', '--test', tmp)
            finally:
                os.unlink(tmp)
        for path, content in changes:
            atomic(path, content)
        run('ufw', 'reload')
    else:
        policies = policy['policies']
        if not set(policies).issubset(NAMES) or not {'segmentra-in', 'segmentra-out'}.issubset(policies):
            raise RuntimeError('Invalid Segmentra policy names')
        for name, content in policies.items():
            root = ET.fromstring(content)
            if root.tag != 'policy':
                raise RuntimeError('Invalid firewalld policy XML')
        for name in NAMES:
            path = POLICY_DIR / (name + '.xml')
            if name in policies:
                atomic(path, policies[name])
            else:
                path.unlink(missing_ok=True)
        fw('--check-config')
        fw('--reload')
    run('systemctl', 'enable', backend)
    run('systemctl', 'is-enabled', '--quiet', backend)
    if not read_state(backend)['present']:
        raise RuntimeError('Native manager did not activate Segmentra rules')

def normalize_iptables(line):
    tokens = shlex.split(line)
    parts = []
    i = 0
    while i < len(tokens):
        option = tokens[i]
        if i + 1 >= len(tokens):
            parts.append((option, ''))
            break
        value = tokens[i + 1]
        if option == '-m' and value in ('tcp', 'udp', 'icmp', 'icmp6'):
            i += 2
            continue
        if option == '--ctstate':
            value = ','.join(sorted(value.split(',')))
        if option == '--icmpv6-type':
            value = {'neighbour-solicitation': '135', 'neighbor-solicitation': '135',
                     'neighbour-advertisement': '136', 'neighbor-advertisement': '136',
                     'router-solicitation': '133', 'router-advertisement': '134'}.get(value, value)
        if option in ('-s', '-d'):
            value = str(ipaddress.ip_network(value, strict=False))
        parts.append((option, value))
        i += 2
    return sorted(parts)

def persistence(backend):
    enabled = run('systemctl', 'is-enabled', '--quiet', backend, optional=True) is not None
    active = run('systemctl', 'is-active', '--quiet', backend, optional=True) is not None
    state = read_state(backend)
    saved = state['permanent']
    exists = all(bool(saved[name]) for name in ('segmentra-in', 'segmentra-out')) if backend == 'firewalld' else all(saved.values())
    synced = exists and state['present']
    if backend == 'ufw' and synced:
        def grouped(lines):
            chains = {}
            for line in lines:
                if line.startswith('-A SEGMENTRA-'):
                    name = shlex.split(line)[1]
                    chains.setdefault(name, []).append(normalize_iptables(line))
            return chains
        for path, live in zip(UFW_FILES, state['runtime']):
            expected = grouped(saved[str(path)].splitlines())
            actual = grouped(live)
            if expected != actual:
                synced = False
    if backend == 'firewalld' and synced:
        synced = all(fw_info(name) == fw_info(name, permanent=True) for name in NAMES)
    status = 'persisted' if enabled and active and synced else 'not_persisted' if exists or state['present'] else 'removed'
    print('SEGMENTRA_PERSIST status=' + status + ' method=' + backend + ' distro=unsupported family=' + backend +
          ' state=' + ('in_sync' if synced else 'differs' if exists else 'none'))
    if not enabled:
        print('SEGMENTRA_PERSIST_WARN service_disabled ' + backend + ' boot service is not enabled')
    if exists and not synced:
        print('SEGMENTRA_PERSIST_WARN manager_state_differs Runtime and permanent Segmentra rules differ')
    if state['present'] and not exists:
        print('SEGMENTRA_PERSIST_WARN manager_state_differs Runtime Segmentra rules have no complete permanent copy')
    return status

def main():
    backend, mode = sys.argv[1:3]
    if backend not in ('firewalld', 'ufw'):
        raise RuntimeError('Unsupported native manager')
    if mode == 'read':
        print(json.dumps(read_state(backend), sort_keys=True))
        return
    if mode in ('check', 'persist'):
        require_manager(backend)
        status = persistence(backend)
        if mode == 'persist' and status != 'persisted':
            raise RuntimeError('Reboot persistence verification failed')
        return
    require_manager(backend)
    if mode == 'backup':
        if backend == 'firewalld':
            ensure_reload_safe()
        atomic(Path(sys.argv[3]), json.dumps({'backend': backend, 'state': permanent_state(backend)}, sort_keys=True))
        return
    if mode == 'restore':
        data = json.loads(Path(sys.argv[3]).read_text())
        if data['backend'] != backend:
            raise RuntimeError('Backup backend mismatch')
        restore_state(backend, data['state'])
        return
    if backend == 'firewalld':
        ensure_reload_safe()
    previous = permanent_state(backend)
    try:
        if mode == 'apply':
            apply_policy(backend, json.loads(Path(sys.argv[3]).read_text()))
            if persistence(backend) != 'persisted':
                raise RuntimeError('Reboot persistence verification failed')
        elif mode == 'remove':
            empty = {str(path): '' for path in UFW_FILES} if backend == 'ufw' else {name: None for name in NAMES}
            restore_state(backend, empty)
            persistence(backend)
        else:
            raise RuntimeError('Unsupported manager operation')
    except Exception:
        restore_state(backend, previous)
        raise

if __name__ == '__main__':
    try:
        if len(sys.argv) >= 3 and sys.argv[2] in ('read', 'check'):
            main()
        else:
            Path('/var/backups/segmentra').mkdir(mode=0o700, parents=True, exist_ok=True)
            with open('/var/backups/segmentra/manager.lock', 'a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                main()
    except Exception as error:
        print('Segmentra native manager: ' + str(error), file=sys.stderr)
        sys.exit(1)
`;

export function isManagedBackend(value: unknown): value is ManagedFirewallBackend {
  return value === 'firewalld' || value === 'ufw';
}

export function managerCommand(backend: ManagedFirewallBackend, mode: string, file?: string, installed = false): string {
  const args = [backend, mode, ...(file ? [file] : [])].map(shq).join(' ');
  if (installed) return `python3 ${shq(HOST_MANAGER_SCRIPT)} ${args}`;
  return `python3 -c ${shq(SEGMENTRA_MANAGER_PY)} ${args}`;
}

/** Active managers take precedence over installed low-level binaries. Run as root. */
export const DETECT_FIREWALL_BACKEND = `
PATH="$PATH:/usr/sbin:/sbin"; export PATH
LC_ALL=C; export LC_ALL
fw=0; uf=0
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then fw=1; fi
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then uf=1; fi
if [ "$fw" = 1 ] && [ "$uf" = 1 ]; then echo 'Both firewalld and UFW are active' >&2; exit 1; fi
if [ "$fw" = 1 ]; then echo firewalld
elif [ "$uf" = 1 ]; then echo ufw
elif command -v nft >/dev/null 2>&1; then echo nftables
elif command -v iptables-restore >/dev/null 2>&1; then echo iptables
else echo unknown; fi`;
