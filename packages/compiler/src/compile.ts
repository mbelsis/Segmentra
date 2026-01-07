import crypto from 'node:crypto';

export type FirewallBackend = 'nftables' | 'iptables';

export type InterfaceScope =
  | { type: 'ALL_INTERFACES' }
  | { type: 'INTERFACE_ROLE'; roles: string[] }
  | { type: 'INTERFACE_NAME'; names: string[] };

export type PolicyRule = {
  orderIndex: number;
  direction: 'IN' | 'OUT' | 'BOTH';
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
};

export type Host = {
  id: string;
  hostname: string;
  mgmtIp: string | null;
  firewallBackend: FirewallBackend;
  interfaces: Array<{ name: string; role: string; enabled: boolean }>;
};

export type CompileInput = {
  host: Host;
  policyInterfaceScope: InterfaceScope;
  rules: PolicyRule[];
  sets: Record<string, string[]>; // setName -> IP/CIDR elements
  baseline: {
    mgmtSshCidrs: string[];
  };
};

export type CompileOutput = {
  backend: FirewallBackend;
  text: string;
  sha256: string;
};

function sha256(text: string): string {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function resolveInterfaceNames(host: Host, scope: InterfaceScope): string[] {
  if (scope.type === 'ALL_INTERFACES') return [];
  if (scope.type === 'INTERFACE_NAME') return scope.names;
  const names = host.interfaces
    .filter((i) => i.enabled && scope.roles.includes(i.role))
    .map((i) => i.name);
  return names;
}

export function compileHostPolicy(input: CompileInput): CompileOutput {
  const backend = input.host.firewallBackend;
  const lines: string[] = [];

  if (backend === 'nftables') {
    lines.push('flush ruleset');
    lines.push('table inet segmentra {');
    lines.push('  chain input { type filter hook input priority 0; policy drop; }');
    lines.push('  chain output { type filter hook output priority 0; policy accept; }');

    // address sets (resolved by API)
    for (const [name, elements] of Object.entries(input.sets)) {
      const elems = elements.join(', ');
      lines.push(`  set ${name} { type ipv4_addr; elements = { ${elems} } }`);
    }
    lines.push('}');
    // Baseline
    lines.push('add rule inet segmentra input iif lo accept');
    lines.push('add rule inet segmentra input ct state established,related accept');
    for (const cidr of input.baseline.mgmtSshCidrs) {
      lines.push(`add rule inet segmentra input ip saddr ${cidr} tcp dport 22 accept comment \"mgmt_ssh\"`);
    }

    // Policy rules (very v1: source resolution is performed by API; here we treat sourceValue as cidr/ipset name)
    const policyScopeNames = resolveInterfaceNames(input.host, input.policyInterfaceScope);
    const rulesSorted = [...input.rules].sort((a, b) => {
      if (a.action !== b.action) return a.action === 'ALLOW' ? -1 : 1;
      return a.orderIndex - b.orderIndex;
    });
    for (const r of rulesSorted) {
      const scope = r.usePolicyInterfaceScope ? input.policyInterfaceScope : r.interfaceScope ?? input.policyInterfaceScope;
      const iifs = resolveInterfaceNames(input.host, scope);
      const action = r.action === 'ALLOW' ? 'accept' : 'drop';

      const proto = r.protocol === 'any' ? '' : r.protocol;
      const portExpr =
        r.protocol === 'tcp' || r.protocol === 'udp'
          ? r.ports
            ? `${r.protocol} dport { ${r.ports} }`
            : ''
          : '';

      const iifExpr =
        scope.type === 'ALL_INTERFACES' || iifs.length === 0
          ? ''
          : `iifname { ${iifs.map((n) => `"${n}"`).join(', ')} }`;
      const oifExpr =
        scope.type === 'ALL_INTERFACES' || iifs.length === 0
          ? ''
          : `oifname { ${iifs.map((n) => `"${n}"`).join(', ')} }`;

      const remoteIn =
        r.remote.kind === 'SET' ? `ip saddr @${r.remote.setName}` : `ip saddr ${r.sourceValue}`;
      const remoteOut =
        r.remote.kind === 'SET' ? `ip daddr @${r.remote.setName}` : `ip daddr ${r.sourceValue}`;
      const comment = r.comment ? ` comment \"${r.comment.replace(/\"/g, '')}\"` : '';

      const emit = (chain: 'input' | 'output') => {
        const ifExpr = chain === 'input' ? iifExpr : oifExpr;
        const remoteExpr = chain === 'input' ? remoteIn : remoteOut;
        const parts = ['add rule inet segmentra', chain, ifExpr, remoteExpr, proto, portExpr, action, comment].filter(Boolean);
        lines.push(parts.join(' '));
      };

      if (r.direction === 'IN') emit('input');
      else if (r.direction === 'OUT') emit('output');
      else {
        emit('input');
        emit('output');
      }
    }
  } else {
    // iptables-restore format
    lines.push('*filter');
    lines.push(':INPUT DROP [0:0]');
    lines.push(':FORWARD DROP [0:0]');
    lines.push(':OUTPUT ACCEPT [0:0]');
    lines.push('-A INPUT -i lo -j ACCEPT');
    lines.push('-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT');
    for (const cidr of input.baseline.mgmtSshCidrs) {
      lines.push(`-A INPUT -p tcp -s ${cidr} --dport 22 -j ACCEPT`);
    }

    const rulesSorted = [...input.rules].sort((a, b) => {
      if (a.action !== b.action) return a.action === 'ALLOW' ? -1 : 1;
      return a.orderIndex - b.orderIndex;
    });
    for (const r of rulesSorted) {
      const scope = r.usePolicyInterfaceScope ? input.policyInterfaceScope : r.interfaceScope ?? input.policyInterfaceScope;
      const ifNames = resolveInterfaceNames(input.host, scope);
      const action = r.action === 'ALLOW' ? 'ACCEPT' : 'DROP';
      const proto = r.protocol === 'any' ? '' : `-p ${r.protocol}`;
      const ports =
        r.protocol === 'tcp' || r.protocol === 'udp'
          ? r.ports
            ? `--dport ${r.ports}`
            : ''
          : '';
      const inIface = scope.type === 'ALL_INTERFACES' || ifNames.length === 0 ? '' : `-i ${ifNames[0]}`; // v1: pick first
      const outIface = scope.type === 'ALL_INTERFACES' || ifNames.length === 0 ? '' : `-o ${ifNames[0]}`;

      const elements =
        r.remote.kind === 'SET' ? input.sets[r.remote.setName] ?? [] : [r.sourceValue];
      const emit = (chain: 'INPUT' | 'OUTPUT') => {
        for (const elem of elements) {
          const remote = chain === 'INPUT' ? `-s ${elem}` : `-d ${elem}`;
          const iface = chain === 'INPUT' ? inIface : outIface;
          lines.push(
            `-A ${chain} ${iface} ${proto} ${remote} ${ports} -j ${action}`.replace(/\s+/g, ' ').trim()
          );
        }
      };

      if (r.direction === 'IN') emit('INPUT');
      else if (r.direction === 'OUT') emit('OUTPUT');
      else {
        emit('INPUT');
        emit('OUTPUT');
      }
    }
    lines.push('COMMIT');
  }

  const text = lines.join('\n') + '\n';
  return { backend, text, sha256: sha256(text) };
}


