export declare function runAnsiblePlaybook(params: {
    runnerContainer: string;
    inventoryPath: string;
    playbookPath: string;
    extraEnv?: Record<string, string>;
    stdoutPath?: string;
    stderrPath?: string;
}): Promise<{
    exitCode: number;
    command: string;
}>;
