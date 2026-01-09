import type { SshHostInfo } from './types.js';
export interface HostReadinessResult {
    hostname: string;
    ready: boolean;
    backend: 'nftables' | 'iptables' | 'unknown';
    nftVersion?: string;
    iptablesVersion?: string;
    sudoAccess: boolean;
    kernelSupport: boolean;
    errors: string[];
    warnings: string[];
}
/**
 * Check if a host is ready for firewall deployments.
 * Verifies:
 * - Presence and versions of nft/iptables
 * - Passwordless sudo access for firewall commands
 * - Kernel/module support for nftables (if applicable)
 */
export declare function checkHostReadiness(host: SshHostInfo): Promise<HostReadinessResult>;
