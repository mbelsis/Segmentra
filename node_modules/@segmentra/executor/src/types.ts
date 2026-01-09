/**
 * Shared types for executor package
 */

export interface SshHostInfo {
  hostname: string;
  ip: string;
  port: number;
  username: string;
  privateKeyPath: string;
  backend?: 'nftables' | 'iptables' | 'auto';
}
