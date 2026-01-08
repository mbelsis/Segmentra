import { getToken } from './auth';

const API_BASE = (import.meta as any).env?.VITE_API_URL ?? 'http://localhost:8080/api';

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers = new Headers(init.headers);
  if (init.body !== undefined) headers.set('content-type', 'application/json');
  if (token) headers.set('authorization', `Bearer ${token}`);

  const resp = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!resp.ok) {
    let errorMessage = `${resp.status} ${resp.statusText}`;
    try {
      const json = await resp.json();
      if (json.error) {
        errorMessage = json.message || json.error;
      } else if (json.message) {
        errorMessage = json.message;
      }
    } catch {
      const text = await resp.text().catch(() => '');
      if (text) errorMessage = `${errorMessage}: ${text}`;
    }
    throw new Error(errorMessage);
  }
  return (await resp.json()) as T;
}

export const api = {
  login: (username: string, password: string) =>
    request<{ token: string }>('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  me: () => request<{ user: any; roles: string[] }>('/auth/me'),
  changePassword: (currentPassword: string, newPassword: string) =>
    request<{ ok: boolean }>('/auth/change-password', { method: 'POST', body: JSON.stringify({ currentPassword, newPassword }) }),

  hosts: (params?: { hostname?: string; ip?: string; tag?: string; vlan?: string; enabled?: boolean; page?: number; limit?: number }) => {
    const query = new URLSearchParams();
    if (params?.hostname) query.append('hostname', params.hostname);
    if (params?.ip) query.append('ip', params.ip);
    if (params?.tag) query.append('tag', params.tag);
    if (params?.vlan) query.append('vlan', params.vlan);
    if (params?.enabled !== undefined) query.append('enabled', String(params.enabled));
    if (params?.page) query.append('page', String(params.page));
    if (params?.limit) query.append('limit', String(params.limit));
    const queryString = query.toString();
    return request<{ hosts: any[]; pagination: { page: number; limit: number; total: number; totalPages: number } }>(`/hosts${queryString ? `?${queryString}` : ''}`);
  },
  createHost: (b: any) => request<{ host: any }>('/hosts', { method: 'POST', body: JSON.stringify(b) }),
  updateHost: (id: string, b: any) => request<{ host: any }>(`/hosts/${id}`, { method: 'PUT', body: JSON.stringify(b) }),
  deleteHost: (id: string) => request<{ ok: boolean }>(`/hosts/${id}`, { method: 'DELETE' }),
  bulkDeleteHosts: (hostIds: string[]) => request<{ ok: boolean; deleted: number }>('/hosts/bulk/delete', { method: 'POST', body: JSON.stringify({ hostIds }) }),
  bulkAssignVlan: (hostIds: string[], vlanId: string | null) => request<{ ok: boolean; updated: number }>('/hosts/bulk/assign-vlan', { method: 'POST', body: JSON.stringify({ hostIds, vlanId }) }),
  bulkAssignTag: (hostIds: string[], tagId: string) => request<{ ok: boolean; added: number }>('/hosts/bulk/assign-tag', { method: 'POST', body: JSON.stringify({ hostIds, tagId }) }),
  bulkSetEnabled: (hostIds: string[], enabled: boolean) => request<{ ok: boolean; updated: number }>('/hosts/bulk/set-enabled', { method: 'POST', body: JSON.stringify({ hostIds, enabled }) }),

  tags: () => request<{ tags: any[] }>('/tags'),
  createTag: (b: any) => request<{ tag: any }>('/tags', { method: 'POST', body: JSON.stringify(b) }),
  updateTag: (id: string, b: any) => request<{ tag: any }>(`/tags/${id}`, { method: 'PUT', body: JSON.stringify(b) }),
  deleteTag: (id: string) => request<{ ok: boolean }>(`/tags/${id}`, { method: 'DELETE' }),
  vlans: () => request<{ vlans: any[] }>('/vlans'),
  createVlan: (b: any) => request<{ vlan: any }>('/vlans', { method: 'POST', body: JSON.stringify(b) }),
  updateVlan: (id: string, b: any) => request<{ vlan: any }>(`/vlans/${id}`, { method: 'PUT', body: JSON.stringify(b) }),
  deleteVlan: (id: string) => request<{ ok: boolean }>(`/vlans/${id}`, { method: 'DELETE' }),

  policySets: () => request<{ policySets: any[] }>('/policy-sets'),
  policySet: (id: string) => request<{ policySet: any }>(`/policy-sets/${id}`),
  createPolicySet: (b: any) => request<{ policySet: any }>('/policy-sets', { method: 'POST', body: JSON.stringify(b) }),
  versions: (policySetId: string) => request<{ versions: any[] }>(`/policy-sets/${policySetId}/versions`),
  createVersion: (policySetId: string, b: any) =>
    request<{ version: any }>(`/policy-sets/${policySetId}/versions`, { method: 'POST', body: JSON.stringify(b) }),
  version: (versionId: string) => request<{ version: any }>(`/policy-versions/${versionId}`),
  updateVersion: (versionId: string, b: any) =>
    request<{ version: any }>(`/policy-versions/${versionId}`, { method: 'PUT', body: JSON.stringify(b) }),
  rules: (versionId: string) => request<{ rules: any[] }>(`/policy-versions/${versionId}/rules`),
  addRule: (versionId: string, b: any) =>
    request<{ rule: any }>(`/policy-versions/${versionId}/rules`, { method: 'POST', body: JSON.stringify(b) }),
  updateRule: (ruleId: string, b: any) =>
    request<{ rule: any }>(`/policy-rules/${ruleId}`, { method: 'PUT', body: JSON.stringify(b) }),
  deleteRule: (ruleId: string) =>
    request<{ ok: boolean }>(`/policy-rules/${ruleId}`, { method: 'DELETE' }),
  submitApproval: (versionId: string) =>
    request<{ version: any }>(`/policy-versions/${versionId}/submit-approval`, { method: 'POST' }),
  approve: (versionId: string) => request<{ version: any }>(`/policy-versions/${versionId}/approve`, { method: 'POST' }),
  reject: (versionId: string, reason: string) =>
    request<{ version: any }>(`/policy-versions/${versionId}/reject`, { method: 'POST', body: JSON.stringify({ reason }) }),
  cloneVersion: (versionId: string) =>
    request<{ version: any }>(`/policy-versions/${versionId}/clone`, { method: 'POST' }),

  render: (versionId: string, hostId: string) =>
    request<{ backend: string; sha256: string; text: string }>(`/policy-versions/${versionId}/render/host/${hostId}`),

  deployments: () => request<{ deployments: any[] }>('/deployments'),
  deployment: (deploymentId: string) => request<{ deployment: any }>(`/deployments/${deploymentId}`),
  createDeployment: (b: any) => request<{ deployment: any }>('/deployments', { method: 'POST', body: JSON.stringify(b) }),
  startDeployment: (deploymentId: string) => request<any>(`/deployments/${deploymentId}/start`, { method: 'POST' }),
  deploymentHosts: (deploymentId: string) => request<{ hosts: any[] }>(`/deployments/${deploymentId}/hosts`),

  audit: (params?: { actor?: string; action?: string; entityType?: string; from?: string; to?: string }) => {
    const query = new URLSearchParams();
    if (params?.actor) query.append('actor', params.actor);
    if (params?.action) query.append('action', params.action);
    if (params?.entityType) query.append('entityType', params.entityType);
    if (params?.from) query.append('from', params.from);
    if (params?.to) query.append('to', params.to);
    const queryString = query.toString();
    return request<{ events: any[] }>(`/audit${queryString ? `?${queryString}` : ''}`);
  },

  ldapSettings: () => request<{ ldapSettings: any }>('/admin/ldap-settings'),
  putLdapSettings: (b: any) => request<{ ldapSettings: any }>('/admin/ldap-settings', { method: 'PUT', body: JSON.stringify(b) }),
  addGroupMap: (b: any) => request<{ map: any }>('/admin/ad-group-role-map', { method: 'POST', body: JSON.stringify(b) }),
  executorSetting: () => request<{ executor: string }>('/admin/executor-setting'),
  putExecutorSetting: (b: any) => request<{ executor: string }>('/admin/executor-setting', { method: 'PUT', body: JSON.stringify(b) }),

  sshCredentials: () => request<{ sshCredentials: any[] }>('/ssh-credentials'),
  createSshCredential: (b: any) => request<{ sshCredential: any }>('/ssh-credentials', { method: 'POST', body: JSON.stringify(b) }),

  dashboardStats: () => request<{
    totalDeployments: number;
    runningDeployments: number;
    successRate: number;
    statusBreakdown: Array<{ status: string; count: number }>;
    topDeployers: Array<{ userId: string; username: string; displayName: string | null; deploymentCount: number }>;
    recentDeployments: any[];
    currentDeployments: Array<{
      id: string;
      status: string;
      mode: string;
      targetCount: number;
      createdAt: string;
      startedAt: string | null;
      policySetName: string | null;
      versionNumber: number | null;
      totalHosts: number;
      succeededHosts: number;
      failedHosts: number;
      runningHosts: number;
      progressPercent: number;
    }>;
  }>('/dashboard/stats'),

  troubleshoot: {
    policiesByIp: (ip: string) => request<{
      ip: string;
      results: Array<{
        rule: any;
        policyVersion: any;
        deployedHosts: any[];
      }>;
    }>(`/troubleshoot/policies/by-ip?ip=${encodeURIComponent(ip)}`),
    hostPolicies: (hostId: string) => request<{
      host: any;
      policies: Array<{
        deployment: any;
        policyVersion: any;
        hostDeploymentStatus: string;
        hostDeploymentMessage: string | null;
        rules: any[];
      }>;
    }>(`/troubleshoot/hosts/${hostId}/policies`),
    policyVersionHosts: (versionId: string) => request<{
      policyVersion: any;
      hosts: Array<{
        host: any;
        deployments: any[];
      }>;
    }>(`/troubleshoot/policy-versions/${versionId}/hosts`)
  }
};


