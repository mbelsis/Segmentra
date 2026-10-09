/**
 * Shared types for executor package
 */

export type FirewallBackend = 'nftables' | 'iptables' | 'firewalld' | 'ufw';

export interface SshHostInfo {
  hostname: string;
  ip: string;
  port: number;
  username: string;
  authMethod?: 'key' | 'password';
  privateKeyPath?: string;
  password?: string;
  /** Passphrase of the private key (key auth); undefined for unencrypted keys. */
  keyPassphrase?: string;
  /** sudo password; undefined = passwordless sudo (sudo -n). */
  sudoPassword?: string;
  backend?: FirewallBackend | 'auto';
}
