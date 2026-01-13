export interface AuditSshHost {
    hostname: string;
    ip: string;
    port: number;
    username: string;
    privateKeyPath: string;
    backend: 'nftables' | 'iptables';
}
export interface AuditSessionResult {
    hostname: string;
    success: boolean;
    exitCode: number;
    stdout: string;
    stderr: string;
    backupPath?: string;
    logFilePath?: string;
}
/**
 * Start an audit session: backup rules, deploy log-only policy, configure logging
 */
export declare function startAuditSession(host: AuditSshHost, logFilePath: string): Promise<AuditSessionResult>;
/**
 * Deploy log-only firewall policy
 */
export declare function deployLogOnlyPolicy(host: AuditSshHost, policyText: string, policyFilePath: string): Promise<AuditSessionResult>;
/**
 * Restore original firewall rules from backup
 */
export declare function restoreAuditSession(host: AuditSshHost, backupPath: string): Promise<AuditSessionResult>;
/**
 * Retrieve audit log file from remote server
 */
export declare function retrieveAuditLogs(host: AuditSshHost, remoteLogPath: string, localLogPath: string): Promise<AuditSessionResult>;
