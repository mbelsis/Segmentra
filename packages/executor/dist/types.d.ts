/**
 * Shared types for executor package
 */
export interface SshHostInfo {
    hostname: string;
    ip: string;
    port: number;
    username: string;
    authMethod?: 'key' | 'password';
    privateKeyPath?: string;
    password?: string;
    backend?: 'nftables' | 'iptables' | 'auto';
}
