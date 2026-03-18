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
    skipped?: boolean;
}
/**
 * Execute SSH deployment to multiple hosts.
 *
 * @param shouldContinue - Optional callback checked between hosts. Return false to stop.
 *                         This allows the deployment to be cancelled/stopped mid-execution.
 * @param knownHostsPath - Optional path to a known_hosts file for SSH host key verification.
 */
export declare function runSshDeployment(params: {
    hosts: SshHost[];
    stdoutPath?: string;
    stderrPath?: string;
    shouldContinue?: () => Promise<boolean>;
    knownHostsPath?: string;
}): Promise<SshExecutionResult[]>;
