import type { SshHostInfo } from './types.js';
export interface ReadRulesResult {
    hostname: string;
    success: boolean;
    rulesText: string;
    rulesHash: string;
    backend: 'nftables' | 'iptables';
    error?: string;
}
/**
 * Read current firewall rules from a host via SSH and compute hash.
 * Normalizes the output for consistent hashing.
 */
export declare function readHostFirewallRules(host: SshHostInfo): Promise<ReadRulesResult>;
