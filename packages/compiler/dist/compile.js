import crypto from 'node:crypto';
function sha256(text) {
    return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}
/** Sanitize a CIDR/IP value to prevent injection into nftables/iptables rules */
function sanitizeCidr(value) {
    // Only allow: digits, dots, colons (IPv6), slashes (CIDR), and commas
    return value.replace(/[^0-9a-fA-F.:\/,]/g, '');
}
function resolveInterfaceNames(host, scope) {
    if (scope.type === 'ALL_INTERFACES')
        return [];
    if (scope.type === 'INTERFACE_NAME')
        return scope.names;
    const names = host.interfaces
        .filter((i) => i.enabled && scope.roles.includes(i.role))
        .map((i) => i.name);
    return names;
}
export function compileHostPolicy(input) {
    const backend = input.host.firewallBackend;
    const lines = [];
    const logOnly = input.logOnlyMode ?? false;
    if (backend === 'nftables') {
        lines.push('flush ruleset');
        lines.push('table inet segmentra {');
        // In log-only mode, change default policy to accept so nothing is blocked
        const inputPolicy = logOnly ? 'accept' : 'drop';
        lines.push(`  chain input { type filter hook input priority 0; policy ${inputPolicy}; }`);
        lines.push('  chain output { type filter hook output priority 0; policy accept; }');
        // address sets (resolved by API) — skip empty sets
        for (const [name, elements] of Object.entries(input.sets)) {
            if (elements.length === 0)
                continue; // Skip empty sets to avoid invalid nftables syntax
            const elems = elements.map(e => sanitizeCidr(e)).join(', ');
            lines.push(`  set ${name} { type ipv4_addr; elements = { ${elems} } }`);
        }
        lines.push('}');
        // Baseline
        if (logOnly) {
            // In log-only mode, log baseline traffic too
            lines.push('add rule inet segmentra input iif lo log prefix "FW-AUDIT: ALLOW: loopback: " accept');
            lines.push('add rule inet segmentra input ct state established,related log prefix "FW-AUDIT: ALLOW: established: " accept');
            for (const cidr of input.baseline.mgmtSshCidrs) {
                lines.push(`add rule inet segmentra input ip saddr ${cidr} tcp dport 22 log prefix "FW-AUDIT: ALLOW: mgmt_ssh: " accept comment \"mgmt_ssh\"`);
            }
        }
        else {
            lines.push('add rule inet segmentra input iif lo accept');
            lines.push('add rule inet segmentra input ct state established,related accept');
            for (const cidr of input.baseline.mgmtSshCidrs) {
                lines.push(`add rule inet segmentra input ip saddr ${cidr} tcp dport 22 accept comment \"mgmt_ssh\"`);
            }
        }
        // Policy rules — emitted in user-defined order_index order (no reordering)
        const policyScopeNames = resolveInterfaceNames(input.host, input.policyInterfaceScope);
        const rulesSorted = [...input.rules].sort((a, b) => a.orderIndex - b.orderIndex);
        for (const r of rulesSorted) {
            const scope = r.usePolicyInterfaceScope ? input.policyInterfaceScope : r.interfaceScope ?? input.policyInterfaceScope;
            const iifs = resolveInterfaceNames(input.host, scope);
            const action = r.action === 'ALLOW' ? 'accept' : 'drop';
            const proto = r.protocol === 'any' ? '' : r.protocol;
            const portExpr = r.protocol === 'tcp' || r.protocol === 'udp'
                ? r.ports
                    ? `${r.protocol} dport { ${r.ports} }`
                    : ''
                : '';
            const iifExpr = scope.type === 'ALL_INTERFACES' || iifs.length === 0
                ? ''
                : `iifname { ${iifs.map((n) => `"${n}"`).join(', ')} }`;
            const oifExpr = scope.type === 'ALL_INTERFACES' || iifs.length === 0
                ? ''
                : `oifname { ${iifs.map((n) => `"${n}"`).join(', ')} }`;
            const remoteIn = r.remote.kind === 'SET' ? `ip saddr @${r.remote.setName}` : `ip saddr ${sanitizeCidr(r.sourceValue)}`;
            const remoteOut = r.remote.kind === 'SET' ? `ip daddr @${r.remote.setName}` : `ip daddr ${sanitizeCidr(r.sourceValue)}`;
            const comment = r.comment ? ` comment \"${r.comment.replace(/\"/g, '')}\"` : '';
            const emit = (chain) => {
                const ifExpr = chain === 'input' ? iifExpr : oifExpr;
                const remoteExpr = chain === 'input' ? remoteIn : remoteOut;
                if (logOnly) {
                    // In log-only mode, log the traffic then accept it
                    const logPrefix = `log prefix "FW-AUDIT: ${r.action} ${r.comment ? r.comment.replace(/\"/g, '') : 'rule'}: "`;
                    const logParts = ['add rule inet segmentra', chain, ifExpr, remoteExpr, proto, portExpr, logPrefix, 'accept', comment].filter(Boolean);
                    lines.push(logParts.join(' '));
                }
                else {
                    // Normal mode - apply the action
                    const parts = ['add rule inet segmentra', chain, ifExpr, remoteExpr, proto, portExpr, action, comment].filter(Boolean);
                    lines.push(parts.join(' '));
                }
            };
            if (r.direction === 'IN')
                emit('input');
            else if (r.direction === 'OUT')
                emit('output');
            else {
                emit('input');
                emit('output');
            }
        }
        // In log-only mode, add catch-all rules to log all remaining traffic
        if (logOnly) {
            lines.push('add rule inet segmentra input log prefix "FW-AUDIT: ALLOW: catch-all: " accept');
            lines.push('add rule inet segmentra output log prefix "FW-AUDIT: ALLOW: catch-all: " accept');
        }
    }
    else {
        // iptables-restore format
        lines.push('*filter');
        // In log-only mode, change default policy to ACCEPT
        const inputPolicy = logOnly ? 'ACCEPT' : 'DROP';
        lines.push(`:INPUT ${inputPolicy} [0:0]`);
        lines.push(`:FORWARD ${inputPolicy} [0:0]`);
        lines.push(':OUTPUT ACCEPT [0:0]');
        if (logOnly) {
            // In log-only mode, log baseline traffic too
            lines.push('-A INPUT -i lo -j LOG --log-prefix "FW-AUDIT: ALLOW: loopback: "');
            lines.push('-A INPUT -i lo -j ACCEPT');
            lines.push('-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j LOG --log-prefix "FW-AUDIT: ALLOW: established: "');
            lines.push('-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT');
            for (const cidr of input.baseline.mgmtSshCidrs) {
                lines.push(`-A INPUT -p tcp -s ${cidr} --dport 22 -j LOG --log-prefix "FW-AUDIT: ALLOW: mgmt_ssh: "`);
                lines.push(`-A INPUT -p tcp -s ${cidr} --dport 22 -j ACCEPT`);
            }
        }
        else {
            lines.push('-A INPUT -i lo -j ACCEPT');
            lines.push('-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT');
            for (const cidr of input.baseline.mgmtSshCidrs) {
                lines.push(`-A INPUT -p tcp -s ${cidr} --dport 22 -j ACCEPT`);
            }
        }
        // iptables rules — emitted in user-defined order_index order (no reordering)
        const rulesSorted = [...input.rules].sort((a, b) => a.orderIndex - b.orderIndex);
        for (const r of rulesSorted) {
            const scope = r.usePolicyInterfaceScope ? input.policyInterfaceScope : r.interfaceScope ?? input.policyInterfaceScope;
            const ifNames = resolveInterfaceNames(input.host, scope);
            const action = r.action === 'ALLOW' ? 'ACCEPT' : 'DROP';
            const proto = r.protocol === 'any' ? '' : `-p ${r.protocol}`;
            // Handle ports for iptables:
            // - Comma-separated (80,443): -m multiport --dports 80,443
            // - Ranges (8000-9000): --dport 8000:9000 (iptables uses colon for ranges)
            // - Single port (22): --dport 22
            // - Comma + range mix (80,443,8000-9000): -m multiport --dports 80,443,8000:9000
            let ports = '';
            if ((r.protocol === 'tcp' || r.protocol === 'udp') && r.ports) {
                // Normalize dash ranges to colon ranges for iptables
                const normalizedPorts = r.ports.replace(/(\d+)-(\d+)/g, '$1:$2');
                if (normalizedPorts.includes(',')) {
                    ports = `-m multiport --dports ${normalizedPorts}`;
                }
                else {
                    ports = `--dport ${normalizedPorts}`;
                }
            }
            // Emit rules for ALL matching interfaces (not just the first)
            const ifaceList = scope.type === 'ALL_INTERFACES' || ifNames.length === 0 ? [''] : ifNames;
            const elements = r.remote.kind === 'SET' ? input.sets[r.remote.setName] ?? [] : [r.sourceValue];
            const emit = (chain) => {
                for (const iface of ifaceList) {
                    const ifaceFlag = iface ? (chain === 'INPUT' ? `-i ${iface}` : `-o ${iface}`) : '';
                    for (const elem of elements) {
                        const remote = chain === 'INPUT' ? `-s ${sanitizeCidr(elem)}` : `-d ${sanitizeCidr(elem)}`;
                        if (logOnly) {
                            const logPrefix = `-j LOG --log-prefix "FW-AUDIT: ${r.action} ${r.comment ? r.comment.replace(/"/g, '') : 'rule'}: "`;
                            const logLine = `-A ${chain} ${ifaceFlag} ${proto} ${remote} ${ports} ${logPrefix}`.replace(/\s+/g, ' ').trim();
                            lines.push(logLine);
                            const acceptLine = `-A ${chain} ${ifaceFlag} ${proto} ${remote} ${ports} -j ACCEPT`.replace(/\s+/g, ' ').trim();
                            lines.push(acceptLine);
                        }
                        else {
                            lines.push(`-A ${chain} ${ifaceFlag} ${proto} ${remote} ${ports} -j ${action}`.replace(/\s+/g, ' ').trim());
                        }
                    }
                }
            };
            if (r.direction === 'IN')
                emit('INPUT');
            else if (r.direction === 'OUT')
                emit('OUTPUT');
            else {
                emit('INPUT');
                emit('OUTPUT');
            }
        }
        // In log-only mode, add catch-all rules to log all remaining traffic
        if (logOnly) {
            lines.push('-A INPUT -j LOG --log-prefix "FW-AUDIT: ALLOW: catch-all: "');
            lines.push('-A INPUT -j ACCEPT');
            lines.push('-A OUTPUT -j LOG --log-prefix "FW-AUDIT: ALLOW: catch-all: "');
            lines.push('-A OUTPUT -j ACCEPT');
        }
        lines.push('COMMIT');
    }
    const text = lines.join('\n') + '\n';
    return { backend, text, sha256: sha256(text) };
}
