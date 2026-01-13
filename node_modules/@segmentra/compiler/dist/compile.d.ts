export type FirewallBackend = 'nftables' | 'iptables';
export type InterfaceScope = {
    type: 'ALL_INTERFACES';
} | {
    type: 'INTERFACE_ROLE';
    roles: string[];
} | {
    type: 'INTERFACE_NAME';
    names: string[];
};
export type PolicyRule = {
    orderIndex: number;
    direction: 'IN' | 'OUT' | 'BOTH';
    action: 'ALLOW' | 'DENY';
    protocol: 'tcp' | 'udp' | 'icmp' | 'any';
    ports?: string | null;
    sourceType: 'CIDR' | 'TAG' | 'VLAN' | 'HOST';
    sourceValue: string;
    logMode: 'NONE' | 'LOG' | 'LOG_RATE_LIMITED';
    comment?: string | null;
    usePolicyInterfaceScope: boolean;
    interfaceScope?: InterfaceScope;
    remote: {
        kind: 'CIDR';
    } | {
        kind: 'SET';
        setName: string;
    };
};
export type Host = {
    id: string;
    hostname: string;
    mgmtIp: string | null;
    firewallBackend: FirewallBackend;
    interfaces: Array<{
        name: string;
        role: string;
        enabled: boolean;
    }>;
};
export type CompileInput = {
    host: Host;
    policyInterfaceScope: InterfaceScope;
    rules: PolicyRule[];
    sets: Record<string, string[]>;
    baseline: {
        mgmtSshCidrs: string[];
    };
    logOnlyMode?: boolean;
};
export type CompileOutput = {
    backend: FirewallBackend;
    text: string;
    sha256: string;
};
export declare function compileHostPolicy(input: CompileInput): CompileOutput;
