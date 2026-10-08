import { mkdirSync, existsSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import process from 'node:process';
import { setTimeout as delay } from 'node:timers/promises';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');
const composeFile = path.join(repoRoot, 'tests', 'docker-ssh-integration', 'docker-compose.yml');
const runtimeDir = path.join(repoRoot, 'tests', 'docker-ssh-integration', '.runtime');
const keyDir = path.join(runtimeDir, 'keys');
const privateKeyPath = path.join(keyDir, 'id_ed25519');
const publicKeyPath = `${privateKeyPath}.pub`;
const projectName = 'segmentra-it';
const apiBase = 'http://127.0.0.1:18080/api';
const keepStack = process.argv.includes('--keep');

const users = {
  admin: { username: 'admin', password: 'admin123' },
  operator: { username: 'operator-it', password: 'Operator123!' },
  approver: { username: 'approver-it', password: 'Approver123!' }
};

const hosts = [
  { name: 'target-a', ip: '172.29.0.31', service: 'target-a', allowFrom: '172.29.0.32/32' },
  { name: 'target-b', ip: '172.29.0.32', service: 'target-b', allowFrom: '172.29.0.33/32' },
  { name: 'target-c', ip: '172.29.0.33', service: 'target-c', allowFrom: null }
];

function log(message) {
  console.log(`[integration] ${message}`);
}

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: repoRoot,
      stdio: options.stdio ?? ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, ...(options.env ?? {}) }
    });

    let stdout = '';
    let stderr = '';

    if (child.stdout) child.stdout.on('data', (data) => { stdout += data.toString(); });
    if (child.stderr) child.stderr.on('data', (data) => { stderr += data.toString(); });

    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0 || options.allowFailure) {
        resolve({ code: code ?? 0, stdout, stderr });
      } else {
        const error = new Error(`${command} ${args.join(' ')} failed with exit code ${code}\n${stderr || stdout}`);
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
      }
    });
  });
}

function composeArgs(...args) {
  return ['compose', '-f', composeFile, '-p', projectName, ...args];
}

async function dockerCompose(...args) {
  return run('docker', composeArgs(...args));
}

async function dockerComposeAllowFailure(...args) {
  return run('docker', composeArgs(...args), { allowFailure: true });
}

async function ensureDocker() {
  log('Checking Docker CLI and daemon availability');
  await run('docker', ['version']);
  await run('docker', ['compose', 'version']);
}

async function ensureSshKey() {
  mkdirSync(keyDir, { recursive: true });
  if (existsSync(privateKeyPath) && existsSync(publicKeyPath)) return;

  log('Generating an ephemeral integration SSH keypair');
  await run('ssh-keygen', ['-t', 'ed25519', '-N', '', '-f', privateKeyPath, '-C', 'segmentra-integration']);
}

async function resetStack() {
  log('Removing any previous integration stack');
  await dockerComposeAllowFailure('down', '-v', '--remove-orphans');
  rmSync(runtimeDir, { recursive: true, force: true });
  mkdirSync(runtimeDir, { recursive: true });
}

async function pullBaseImage() {
  log('Pulling alpine:3.20');
  try {
    await run('docker', ['pull', 'alpine:3.20']);
  } catch (error) {
    const inspect = await run('docker', ['image', 'inspect', 'alpine:3.20'], { allowFailure: true });
    if (inspect.code === 0) {
      log('Docker registry is unavailable, continuing with the locally cached alpine:3.20 image');
      return;
    }
    throw error;
  }
}

async function startInfrastructure() {
  log('Building and starting the Docker integration stack');
  await dockerCompose('up', '-d', '--build', 'db', 'target-a', 'target-b', 'target-c');
  await dockerCompose('build', 'api');
  await dockerCompose('run', '--rm', 'api', 'npm', 'run', 'migrate:up', '-w', '@segmentra/db');
  await dockerCompose('run', '--rm', 'api', 'npm', 'run', 'seed', '-w', '@segmentra/db');
  await dockerCompose('up', '-d', '--build', 'api');
}

async function waitForApi() {
  log('Waiting for the API health endpoint');
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetch(`${apiBase}/health`);
      if (response.ok) return;
    } catch {
      // keep polling
    }
    await delay(2000);
  }
  throw new Error('API did not become healthy within 120 seconds');
}

async function apiRequest(method, pathname, { token, body, expectedStatus } = {}) {
  const response = await fetch(`${apiBase}${pathname}`, {
    method,
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {})
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  });

  if (expectedStatus && response.status !== expectedStatus) {
    const text = await response.text();
    throw new Error(`${method} ${pathname} expected ${expectedStatus} but got ${response.status}: ${text}`);
  }

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${method} ${pathname} failed with ${response.status}: ${text}`);
  }

  return response.json();
}

async function login(username, password) {
  const data = await apiRequest('POST', '/auth/login', {
    body: { username, password }
  });
  return data.token;
}

async function ensureLocalUser(adminToken, user, roles) {
  const response = await fetch(`${apiBase}/admin/users`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${adminToken}`,
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      username: user.username,
      displayName: user.username,
      password: user.password,
      roles,
      isActive: true
    })
  });

  if (response.status === 201 || response.status === 409) return;
  const text = await response.text();
  throw new Error(`Failed to ensure local user ${user.username}: ${response.status} ${text}`);
}

async function prepareUsersAndSettings() {
  const adminToken = await login(users.admin.username, users.admin.password);
  await ensureLocalUser(adminToken, users.operator, ['operator']);
  await ensureLocalUser(adminToken, users.approver, ['approver']);

  const operatorToken = await login(users.operator.username, users.operator.password);
  const approverToken = await login(users.approver.username, users.approver.password);

  const vlan = await apiRequest('POST', '/vlans', {
    token: adminToken,
    body: {
      vlanTag: 999,
      name: 'integration-mgmt',
      description: 'Integration management subnet',
      subnet: '172.29.0.0/24'
    }
  });

  await apiRequest('PUT', '/admin/management-vlan-setting', {
    token: adminToken,
    body: { vlanId: vlan.vlan.id }
  });

  await apiRequest('PUT', '/admin/executor-setting', {
    token: adminToken,
    body: { executor: 'ssh' }
  });

  return { adminToken, operatorToken, approverToken };
}

async function createHosts(operatorToken) {
  const createdHosts = [];
  for (const host of hosts) {
    const response = await apiRequest('POST', '/hosts', {
      token: operatorToken,
      body: {
        hostname: host.name,
        mgmtIp: host.ip,
        sshPort: 22,
        firewallBackend: 'iptables',
        enabled: true
      }
    });
    createdHosts.push({ ...host, id: response.host.id });
  }
  return createdHosts;
}

async function createPolicies(operatorToken, approverToken, createdHosts) {
  const policies = [];

  for (const host of createdHosts) {
    const policySetResponse = await apiRequest('POST', '/policy-sets', {
      token: operatorToken,
      body: {
        name: `Integration policy ${host.name}`,
        description: `Integration ACL for ${host.name}`,
        scopeType: 'HOST_LIST',
        hostIds: [host.id]
      }
    });

    const versionResponse = await apiRequest('POST', `/policy-sets/${policySetResponse.policySet.id}/versions`, {
      token: operatorToken,
      body: {
        changeSummary: `Integration ACL for ${host.name}`,
        interfaceScopeType: 'ALL_INTERFACES'
      }
    });

    if (host.allowFrom) {
      await apiRequest('POST', `/policy-versions/${versionResponse.version.id}/rules`, {
        token: operatorToken,
        body: {
          orderIndex: 10,
          direction: 'IN',
          action: 'ALLOW',
          protocol: 'icmp',
          sourceType: 'CIDR',
          sourceValue: host.allowFrom,
          logMode: 'NONE',
          comment: `allow-${host.allowFrom.replace('/', '-')}`,
          usePolicyInterfaceScope: true
        }
      });
    }

    await apiRequest('POST', `/policy-versions/${versionResponse.version.id}/submit-approval`, {
      token: operatorToken,
      body: {}
    });

    await apiRequest('POST', `/policy-versions/${versionResponse.version.id}/approve`, {
      token: approverToken,
      body: {}
    });

    policies.push({
      hostName: host.name,
      hostId: host.id,
      hostIp: host.ip,
      hostService: host.service,
      allowFrom: host.allowFrom,
      versionId: versionResponse.version.id
    });
  }

  return policies;
}

async function createGlobalCredential(adminToken, authMode) {
  if (authMode === 'PASSWORD') {
    await apiRequest('POST', '/ssh-credentials', {
      token: adminToken,
      body: {
        name: `integration-password-${Date.now()}`,
        username: 'segmentra',
        authMethod: 'PASSWORD',
        password: 'segmentra123!',
        scopeType: 'GLOBAL'
      }
    });
    return;
  }

  await apiRequest('POST', '/ssh-credentials', {
    token: adminToken,
    body: {
      name: `integration-key-${Date.now()}`,
      username: 'segmentra',
      authMethod: 'KEY',
      privateKeyPem: readFileSync(privateKeyPath, 'utf8'),
      scopeType: 'GLOBAL'
    }
  });
}

async function startDeployment(operatorToken, versionId, hostId) {
  const created = await apiRequest('POST', '/deployments', {
    token: operatorToken,
    body: {
      policyVersionId: versionId,
      mode: 'FULL',
      targetQuery: {
        hosts: [hostId],
        tags: [],
        vlans: []
      }
    }
  });

  await apiRequest('POST', `/deployments/${created.deployment.id}/start`, {
    token: operatorToken,
    body: {}
  });

  return created.deployment.id;
}

async function waitForDeployment(operatorToken, deploymentId) {
  for (let attempt = 0; attempt < 90; attempt += 1) {
    const current = await apiRequest('GET', `/deployments/${deploymentId}`, { token: operatorToken });
    const status = current.deployment.status;
    if (['SUCCEEDED', 'FAILED', 'PARTIAL'].includes(status)) {
      const hostStatuses = await apiRequest('GET', `/deployments/${deploymentId}/hosts`, { token: operatorToken });
      return { deployment: current.deployment, hostStatuses: hostStatuses.hosts };
    }
    await delay(2000);
  }
  throw new Error(`Deployment ${deploymentId} did not finish in time`);
}

async function runDeploymentRound(name, adminToken, operatorToken, policies) {
  log(`Running ${name} deployment round`);
  await createGlobalCredential(adminToken, name);

  for (const policy of policies) {
    const deploymentId = await startDeployment(operatorToken, policy.versionId, policy.hostId);
    const result = await waitForDeployment(operatorToken, deploymentId);

    if (result.deployment.status !== 'SUCCEEDED') {
      throw new Error(`${name} deployment for ${policy.hostName} finished as ${result.deployment.status}`);
    }

    const hostFailures = result.hostStatuses.filter((hostStatus) => hostStatus.status !== 'SUCCEEDED');
    if (hostFailures.length > 0) {
      throw new Error(`${name} deployment for ${policy.hostName} did not succeed on all hosts`);
    }
  }
}

async function execInService(service, ...args) {
  return dockerCompose('exec', '-T', service, ...args);
}

const FOREIGN_RULE_PATTERNS = [
  /^:DOCKER-USER /m,
  /^-A FORWARD -j DOCKER-USER$/m,
  /^-A DOCKER-USER -j RETURN$/m,
  /^:f2b-sshd /m,
  /^-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd$/m,
  /^-A f2b-sshd -j RETURN$/m
];

/** Simulate other tools (Docker, fail2ban) owning rules on the targets; Segmentra must leave them alone. */
async function seedForeignRules(policies) {
  log('Seeding fake Docker / fail2ban chains on each target');
  for (const policy of policies) {
    const script = [
      'iptables -N DOCKER-USER',
      'iptables -A DOCKER-USER -j RETURN',
      'iptables -A FORWARD -j DOCKER-USER',
      'iptables -N f2b-sshd',
      'iptables -A f2b-sshd -j RETURN',
      'iptables -I INPUT 1 -p tcp -m multiport --dports 22 -j f2b-sshd'
    ].join(' && ');
    await execInService(policy.hostService, 'sh', '-c', script);
  }
}

function countLines(text, line) {
  return text.split('\n').filter((l) => l.trim() === line).length;
}

async function verifyIptablesState(policies) {
  log('Inspecting deployed iptables rules in each target');
  for (const policy of policies) {
    const { stdout } = await execInService(policy.hostService, 'iptables-save');
    if (!/-A SEGMENTRA-IN\b[^\n]*-s 172\.29\.0\.0\/24\b[^\n]*-p tcp\b[^\n]*--dport 22\b[^\n]*-j RETURN/.test(stdout)) {
      throw new Error(`Missing management SSH baseline on ${policy.hostName}`);
    }
    if (countLines(stdout, '-A INPUT -j SEGMENTRA-IN') !== 1 || countLines(stdout, '-A OUTPUT -j SEGMENTRA-OUT') !== 1) {
      throw new Error(`INPUT/OUTPUT jumps to SEGMENTRA-IN/OUT must exist exactly once on ${policy.hostName}`);
    }
    if (!/^:INPUT ACCEPT /m.test(stdout)) {
      throw new Error(`Built-in INPUT policy was changed on ${policy.hostName}`);
    }
    if (!/^-A SEGMENTRA-IN [^\n]*-j DROP$/m.test(stdout.split('\n').filter((l) => l.startsWith('-A SEGMENTRA-IN ')).pop() ?? '')) {
      throw new Error(`SEGMENTRA-IN must end with the default DROP on ${policy.hostName}`);
    }
    for (const re of FOREIGN_RULE_PATTERNS) {
      if (!re.test(stdout)) throw new Error(`Foreign (Docker/fail2ban) rule ${re} was removed on ${policy.hostName}`);
    }

    if (policy.allowFrom) {
      const escapedSource = policy.allowFrom.replaceAll('.', '\\.').replace('/', '\\/');
      if (!new RegExp(`-A SEGMENTRA-IN\\b[^\\n]*-s ${escapedSource}\\b[^\\n]*-p icmp\\b[^\\n]*-j RETURN`).test(stdout)) {
        throw new Error(`Missing expected ICMP allow rule on ${policy.hostName}`);
      }
    } else if (/-A SEGMENTRA-IN [^\n]*-p icmp [^\n]*-j RETURN/.test(stdout)) {
      throw new Error(`Unexpected ICMP allow rule found on ${policy.hostName}`);
    }
  }
}

async function complianceStatus(token, hostId) {
  const result = await apiRequest('GET', `/compliance/hosts/${hostId}`, { token });
  return result;
}

async function verifyCompliance(operatorToken, policies) {
  log('Checking drift detection (compliance) for each target');
  for (const policy of policies) {
    const before = await complianceStatus(operatorToken, policy.hostId);
    if (before.status !== 'compliant') {
      throw new Error(`Expected ${policy.hostName} to be compliant right after deployment, got ${before.status}: ${before.message ?? before.error ?? ''}`);
    }
    // Churn by other tools must not count as drift
    await execInService(policy.hostService, 'sh', '-c', 'iptables -I DOCKER-USER 1 -s 10.99.0.0/16 -j RETURN && iptables -N DOCKER-ISOLATION-STAGE-1 && iptables -A FORWARD -j DOCKER-ISOLATION-STAGE-1');
    const churned = await complianceStatus(operatorToken, policy.hostId);
    if (churned.status !== 'compliant') {
      throw new Error(`Docker chain churn was reported as drift on ${policy.hostName}: ${churned.status} ${churned.message ?? ''}`);
    }
    await execInService(policy.hostService, 'sh', '-c', 'iptables -D DOCKER-USER -s 10.99.0.0/16 -j RETURN && iptables -D FORWARD -j DOCKER-ISOLATION-STAGE-1 && iptables -X DOCKER-ISOLATION-STAGE-1');
  }
}

async function verifyDriftOnMissingJump(operatorToken, policy) {
  log(`Removing the OUTPUT jump on ${policy.hostName} to confirm drift is reported`);
  await execInService(policy.hostService, 'iptables', '-D', 'OUTPUT', '-j', 'SEGMENTRA-OUT');
  const drifted = await complianceStatus(operatorToken, policy.hostId);
  if (drifted.status !== 'drifted') {
    throw new Error(`Expected drifted after removing the OUTPUT jump on ${policy.hostName}, got ${drifted.status}`);
  }
  await execInService(policy.hostService, 'iptables', '-I', 'OUTPUT', '1', '-j', 'SEGMENTRA-OUT');
}

async function assertPing(sourceService, destinationIp, shouldSucceed) {
  const result = await dockerComposeAllowFailure('exec', '-T', sourceService, 'ping', '-c', '1', '-W', '1', destinationIp);
  const succeeded = result.code === 0;
  if (succeeded !== shouldSucceed) {
    throw new Error(`Ping ${sourceService} -> ${destinationIp} expected ${shouldSucceed ? 'success' : 'failure'} but got ${succeeded ? 'success' : 'failure'}`);
  }
}

async function verifyPingMatrix() {
  log('Running live ping checks between the targets');
  await assertPing('target-b', '172.29.0.31', true);
  await assertPing('target-a', '172.29.0.32', false);
  await assertPing('target-c', '172.29.0.32', true);
  await assertPing('target-b', '172.29.0.33', false);
  await assertPing('target-a', '172.29.0.33', false);
}

async function cleanup() {
  if (keepStack) {
    log('Leaving the integration stack running because --keep was passed');
    return;
  }

  log('Tearing down the integration stack');
  await dockerComposeAllowFailure('down', '-v', '--remove-orphans');
}

async function main() {
  try {
    await ensureDocker();
    await resetStack();
    await ensureSshKey();
    await pullBaseImage();
    await startInfrastructure();
    await waitForApi();

    const { adminToken, operatorToken, approverToken } = await prepareUsersAndSettings();
    const createdHosts = await createHosts(operatorToken);
    const policies = await createPolicies(operatorToken, approverToken, createdHosts);

    await seedForeignRules(policies);

    await runDeploymentRound('PASSWORD', adminToken, operatorToken, policies);
    await verifyIptablesState(policies);
    await verifyPingMatrix();

    await runDeploymentRound('KEY', adminToken, operatorToken, policies);
    await verifyIptablesState(policies);
    await verifyPingMatrix();
    await verifyCompliance(operatorToken, policies);
    await verifyDriftOnMissingJump(operatorToken, policies[0]);

    log('Docker SSH integration test completed successfully');
  } finally {
    await cleanup();
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
