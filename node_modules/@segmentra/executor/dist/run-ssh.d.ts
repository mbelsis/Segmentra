export interface SshHost {
    hostname: string;
    ip: string;
    port: number;
    username: string;
    privateKeyPath: string;
    policyFilePath: string;
    backend: 'nftables' | 'iptables';
}
export interface SshExecutionResult {
    hostname: string;
    success: boolean;
    exitCode: number;
    stdout: string;
    stderr: string;
}
/**
 * Execute SSH commands directly on a host to apply firewall rules.
 * Uses sudo for all privileged operations.
 */
export declare function runSshDeployment(params: {
    hosts: SshHost[];
    stdoutPath?: string;
    stderrPath?: string;
}): Promise<SshExecutionResult[]>;
