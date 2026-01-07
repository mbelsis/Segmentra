import { getToken } from './auth';

const API_BASE = (import.meta as any).env?.VITE_API_URL ?? 'http://localhost:8080/api';

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers = new Headers(init.headers);
  headers.set('content-type', 'application/json');
  if (token) headers.set('authorization', `Bearer ${token}`);

  const resp = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`${resp.status} ${resp.statusText} ${text}`);
  }
  return (await resp.json()) as T;
}

export const api = {
  login: (username: string, password: string) =>
    request<{ token: string }>('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  me: () => request<{ user: any; roles: string[] }>('/auth/me'),

  hosts: () => request<{ hosts: any[] }>('/hosts'),
  createHost: (b: any) => request<{ host: any }>('/hosts', { method: 'POST', body: JSON.stringify(b) }),

  tags: () => request<{ tags: any[] }>('/tags'),
  vlans: () => request<{ vlans: any[] }>('/vlans'),

  policySets: () => request<{ policySets: any[] }>('/policy-sets'),
  createPolicySet: (b: any) => request<{ policySet: any }>('/policy-sets', { method: 'POST', body: JSON.stringify(b) }),
  versions: (policySetId: string) => request<{ versions: any[] }>(`/policy-sets/${policySetId}/versions`),
  createVersion: (policySetId: string, b: any) =>
    request<{ version: any }>(`/policy-sets/${policySetId}/versions`, { method: 'POST', body: JSON.stringify(b) }),
  rules: (versionId: string) => request<{ rules: any[] }>(`/policy-versions/${versionId}/rules`),
  addRule: (versionId: string, b: any) =>
    request<{ rule: any }>(`/policy-versions/${versionId}/rules`, { method: 'POST', body: JSON.stringify(b) }),
  submitApproval: (versionId: string) =>
    request<{ version: any }>(`/policy-versions/${versionId}/submit-approval`, { method: 'POST' }),
  approve: (versionId: string) => request<{ version: any }>(`/policy-versions/${versionId}/approve`, { method: 'POST' }),
  reject: (versionId: string, reason: string) =>
    request<{ version: any }>(`/policy-versions/${versionId}/reject`, { method: 'POST', body: JSON.stringify({ reason }) }),

  render: (versionId: string, hostId: string) =>
    request<{ backend: string; sha256: string; text: string }>(`/policy-versions/${versionId}/render/host/${hostId}`),

  deployments: () => request<{ deployments: any[] }>('/deployments'),
  createDeployment: (b: any) => request<{ deployment: any }>('/deployments', { method: 'POST', body: JSON.stringify(b) }),
  startDeployment: (deploymentId: string) => request<any>(`/deployments/${deploymentId}/start`, { method: 'POST' }),
  deploymentHosts: (deploymentId: string) => request<{ hosts: any[] }>(`/deployments/${deploymentId}/hosts`),

  audit: () => request<{ events: any[] }>('/audit'),

  ldapSettings: () => request<{ ldapSettings: any }>('/admin/ldap-settings'),
  putLdapSettings: (b: any) => request<{ ldapSettings: any }>('/admin/ldap-settings', { method: 'PUT', body: JSON.stringify(b) }),
  addGroupMap: (b: any) => request<{ map: any }>('/admin/ad-group-role-map', { method: 'POST', body: JSON.stringify(b) }),

  sshCredentials: () => request<{ sshCredentials: any[] }>('/ssh-credentials'),
  createSshCredential: (b: any) => request<{ sshCredential: any }>('/ssh-credentials', { method: 'POST', body: JSON.stringify(b) })
};


