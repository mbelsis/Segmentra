import { clearToken, getToken } from './auth';

const API_BASE = (import.meta as any).env?.VITE_API_URL || '/api';

/**
 * Error thrown for non-2xx API responses. `message` stays a human-readable
 * string (so existing `e.message` usages keep working) while the structured
 * response is available via `status`, `code`, `details` and `body`.
 */
export class ApiError extends Error {
  status: number;
  code: string | undefined;
  details: any;
  body: any;

  constructor(message: string, status: number, body: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
    this.code = body && typeof body === 'object' ? body.error : undefined;
    this.details = body && typeof body === 'object' ? body.details : undefined;
  }
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError;
}

/** Format zod-style `details` (array of issues) into a readable string, if present. */
export function formatErrorDetails(e: unknown): string | null {
  if (!isApiError(e) || !e.details) return null;
  const d = e.details;
  if (Array.isArray(d)) {
    const parts = d.map((issue: any) => {
      if (issue && typeof issue === 'object') {
        const path = Array.isArray(issue.path) && issue.path.length ? `${issue.path.join('.')}: ` : '';
        return `${path}${issue.message ?? JSON.stringify(issue)}`;
      }
      return String(issue);
    });
    return parts.join('; ');
  }
  if (typeof d === 'object') {
    // zod flatten() shape: { formErrors: [], fieldErrors: { field: [msg] } }
    if (d.fieldErrors || d.formErrors) {
      const parts: string[] = [...(d.formErrors ?? [])];
      for (const [k, v] of Object.entries(d.fieldErrors ?? {})) {
        parts.push(`${k}: ${(v as string[]).join(', ')}`);
      }
      return parts.join('; ') || null;
    }
    return JSON.stringify(d);
  }
  return String(d);
}

/** Human-readable message including validation details when available. */
export function errorMessage(e: unknown): string {
  const base = String((e as any)?.message ?? e);
  const details = formatErrorDetails(e);
  return details ? `${base} (${details})` : base;
}

let redirectingToLogin = false;

function handleUnauthorized(path: string) {
  // Login failures are 401s too; let the login page show the error.
  if (path.startsWith('/auth/login')) return;
  clearToken();
  if (redirectingToLogin) return;
  if (typeof window === 'undefined') return;
  if (window.location.pathname.startsWith('/login')) return;
  redirectingToLogin = true;
  const next = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  window.location.assign(`/login?next=${encodeURIComponent(next)}`);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers = new Headers(init.headers);
  if (init.body !== undefined) headers.set('content-type', 'application/json');
  if (token) headers.set('authorization', `Bearer ${token}`);

  const resp = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!resp.ok) {
    let errorMessage = `${resp.status} ${resp.statusText}`;
    let body: any = undefined;
    try {
      const text = await resp.text();
      try {
        const json = JSON.parse(text);
        body = json;
        if (json && json.error) {
          errorMessage = json.message || json.error;
        } else if (json && json.message) {
          errorMessage = json.message;
        }
      } catch {
        body = text || undefined;
        if (text) errorMessage = `${errorMessage}: ${text}`;
      }
    } catch {
      // Could not read response body
    }
    // Only treat auth-middleware failures as session expiry (not e.g. a wrong
    // current password on change-password, which is also a 401).
    const code = body && typeof body === 'object' ? body.error : undefined;
    if (resp.status === 401 && token && code !== 'invalid_current_password' && code !== 'invalid_credentials') {
      handleUnauthorized(path);
    }
    throw new ApiError(errorMessage, resp.status, body);
  }
  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

type HostListParams = { hostname?: string; ip?: string; tag?: string; vlan?: string; enabled?: boolean; page?: number; limit?: number };

function fetchHosts(params?: HostListParams) {
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
}

/** Fetch every host matching the filters by paging through the hosts endpoint. */
async function fetchAllHosts(params?: Omit<HostListParams, 'page' | 'limit'>): Promise<{ hosts: any[] }> {
  const limit = 100;
  const all: any[] = [];
  let page = 1;
  // Hard stop to avoid infinite loops if the server misbehaves.
  for (let i = 0; i < 1000; i++) {
    const res = await fetchHosts({ ...params, page, limit });
    all.push(...(res.hosts ?? []));
    const totalPages = res.pagination?.totalPages ?? 1;
    if (page >= totalPages || (res.hosts ?? []).length === 0) break;
    page++;
  }
  return { hosts: all };
}

export const api = {
  login: (username: string, password: string) =>
    request<{ token: string }>('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  me: () => request<{ user: any; roles: string[] }>('/auth/me'),
  changePassword: (currentPassword: string, newPassword: string) =>
    request<{ ok: boolean }>('/auth/change-password', { method: 'POST', body: JSON.stringify({ currentPassword, newPassword }) }),

  hosts: (params?: HostListParams) => fetchHosts(params),
  /** All hosts (pages through the API). Use for pickers. */
  allHosts: (params?: Omit<HostListParams, 'page' | 'limit'>) => fetchAllHosts(params),
  createHost: (b: any) => request<{ host: any }>('/hosts', { method: 'POST', body: JSON.stringify(b) }),
  updateHost: (id: string, b: any) => request<{ host: any }>(`/hosts/${id}`, { method: 'PUT', body: JSON.stringify(b) }),
  deleteHost: (id: string) => request<{ ok: boolean }>(`/hosts/${id}`, { method: 'DELETE' }),
  bulkDeleteHosts: (hostIds: string[]) => request<{ ok: boolean; deleted: number }>('/hosts/bulk/delete', { method: 'POST', body: JSON.stringify({ hostIds }) }),
  bulkAssignVlan: (hostIds: string[], vlanId: string | null) => request<{ ok: boolean; updated: number }>('/hosts/bulk/assign-vlan', { method: 'POST', body: JSON.stringify({ hostIds, vlanId }) }),
  bulkAssignTag: (hostIds: string[], tagId: string) => request<{ ok: boolean; added: number }>('/hosts/bulk/assign-tag', { method: 'POST', body: JSON.stringify({ hostIds, tagId }) }),
  bulkSetEnabled: (hostIds: string[], enabled: boolean) => request<{ ok: boolean; updated: number }>('/hosts/bulk/set-enabled', { method: 'POST', body: JSON.stringify({ hostIds, enabled }) }),
  bulkImportHosts: (csvData: string) => request<{ imported: number; failed: number; results: Array<{ hostname: string; success: boolean; error?: string }> }>('/hosts/bulk/import', { method: 'POST', body: JSON.stringify({ csvData }) }),

  tags: () => request<{ tags: any[] }>('/tags'),
  createTag: (b: any) => request<{ tag: any }>('/tags', { method: 'POST', body: JSON.stringify(b) }),
  updateTag: (id: string, b: any) => request<{ tag: any }>(`/tags/${id}`, { method: 'PUT', body: JSON.stringify(b) }),
  deleteTag: (id: string) => request<{ ok: boolean }>(`/tags/${id}`, { method: 'DELETE' }),
  vlans: () => request<{ vlans: any[] }>('/vlans'),
  createVlan: (b: any) => request<{ vlan: any }>('/vlans', { method: 'POST', body: JSON.stringify(b) }),
  updateVlan: (id: string, b: any) => request<{ vlan: any }>(`/vlans/${id}`, { method: 'PUT', body: JSON.stringify(b) }),
  deleteVlan: (id: string) => request<{ ok: boolean }>(`/vlans/${id}`, { method: 'DELETE' }),

  policySets: () => request<{ policySets: any[] }>('/policy-sets'),
  // === Compliance evidence reports ===
  complianceReports: () => request<{ reports: any[] }>('/compliance/reports'),
  complianceReport: (id: string) => request<any>(`/compliance/reports/${id}`),
  generateComplianceReport: (body: any) => request<any>('/compliance/reports', { method: 'POST', body: JSON.stringify(body) }),
  /** Fetch a report in another format (html, csv) with the session token; returns the text and the file name. */
  complianceReportFile: async (id: string, format: 'html' | 'csv', dataset?: string) => {
    const token = getToken();
    const q = `format=${format}${dataset ? `&dataset=${encodeURIComponent(dataset)}` : ''}`;
    const resp = await fetch(`${API_BASE}/compliance/reports/${id}?${q}`, { headers: token ? { authorization: `Bearer ${token}` } : {} });
    if (!resp.ok) throw new ApiError(`${resp.status} ${resp.statusText}`, resp.status, undefined);
    const disposition = resp.headers.get('content-disposition') || '';
    return { text: await resp.text(), filename: /filename="([^"]+)"/.exec(disposition)?.[1] ?? `report.${format}` };
  },
  /** Download a policy set (or one version) as a policy-as-code document (YAML or JSON). */
  exportPolicySet: async (id: string, format: 'yaml' | 'json' = 'yaml', version?: number | string) => {
    const token = getToken();
    const q = `format=${format}${version !== undefined ? `&version=${encodeURIComponent(String(version))}` : ''}`;
    const resp = await fetch(`${API_BASE}/policy-sets/${id}/export?${q}`, { headers: token ? { authorization: `Bearer ${token}` } : {} });
    if (!resp.ok) throw new ApiError(`${resp.status} ${resp.statusText}`, resp.status, undefined);
    const disposition = resp.headers.get('content-disposition') || '';
    return {
      text: await resp.text(),
      filename: /filename="([^"]+)"/.exec(disposition)?.[1] ?? `policy.${format}`,
      versionNumber: resp.headers.get('x-segmentra-version'),
    };
  },
  /** Validate (dryRun) or import a policy-as-code document; creates a DRAFT version, never approves. */
  importPolicy: (content: string, opts: { dryRun?: boolean; updateScope?: boolean } = {}) =>
    request<any>(`/policy-sets/import?dryRun=${!!opts.dryRun}&updateScope=${!!opts.updateScope}`, { method: 'POST', body: JSON.stringify({ content }) }),
  policySet: (id: string) => request<{ policySet: any }>(`/policy-sets/${id}`),
  createPolicySet: (b: any) => request<{ policySet: any }>('/policy-sets', { method: 'POST', body: JSON.stringify(b) }),
  deletePolicySet: (id: string) => request<{ ok: boolean }>(`/policy-sets/${id}`, { method: 'DELETE' }),
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
  submitApproval: (versionId: string, reason?: string) =>
    request<{ version: any }>(`/policy-versions/${versionId}/submit-approval`, { method: 'POST', body: JSON.stringify(reason?.trim() ? { reason: reason.trim() } : {}) }),
  deploymentCreators: () => request<{ creators: Array<{ username: string; display_name: string | null; deployments: number }> }>(`/deployments/creators`),
  myApprovalRequests: () => request<{ requests: any[] }>(`/policy-versions/my-requests`),
  pendingApprovals: () => request<{ versions: any[] }>(`/policy-versions/pending-approval`),
  approve: (versionId: string) => request<{ version: any }>(`/policy-versions/${versionId}/approve`, { method: 'POST' }),
  reject: (versionId: string, reason: string) =>
    request<{ version: any }>(`/policy-versions/${versionId}/reject`, { method: 'POST', body: JSON.stringify({ reason }) }),
  cloneVersion: (versionId: string) =>
    request<{ version: any }>(`/policy-versions/${versionId}/clone`, { method: 'POST' }),
  deleteVersion: (versionId: string) =>
    request<{ ok: boolean }>(`/policy-versions/${versionId}`, { method: 'DELETE' }),
  archiveVersion: (versionId: string) =>
    request<{ version: any }>(`/policy-versions/${versionId}/archive`, { method: 'POST' }),

  render: (versionId: string, hostId: string) =>
    request<{ backend: string; sha256: string; text: string }>(`/policy-versions/${versionId}/render/host/${hostId}`),

  deployments: (params?: {
    search?: string;
    mode?: string;
    status?: string;
    createdBy?: string;
    tag?: string;
    vlan?: string;
    fromDate?: string;
    toDate?: string;
    sortBy?: string;
    sortOrder?: 'ASC' | 'DESC';
    page?: number;
    limit?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.search) query.append('search', params.search);
    if (params?.mode) query.append('mode', params.mode);
    if (params?.status) query.append('status', params.status);
    if (params?.createdBy) query.append('createdBy', params.createdBy);
    if (params?.tag) query.append('tag', params.tag);
    if (params?.vlan) query.append('vlan', params.vlan);
    if (params?.fromDate) query.append('fromDate', params.fromDate);
    if (params?.toDate) query.append('toDate', params.toDate);
    if (params?.sortBy) query.append('sortBy', params.sortBy);
    if (params?.sortOrder) query.append('sortOrder', params.sortOrder);
    if (params?.page) query.append('page', String(params.page));
    if (params?.limit) query.append('limit', String(params.limit));
    const queryString = query.toString();
    return request<{ deployments: any[]; pagination: { page: number; limit: number; total: number; totalPages: number } }>(`/deployments${queryString ? `?${queryString}` : ''}`);
  },
  deployment: (deploymentId: string) => request<{ deployment: any }>(`/deployments/${deploymentId}`),
  createDeployment: (b: any) => request<{ deployment: any }>('/deployments', { method: 'POST', body: JSON.stringify(b) }),
  startDeployment: (deploymentId: string) => request<any>(`/deployments/${deploymentId}/start`, { method: 'POST' }),
  pauseDeployment: (deploymentId: string) => request<{ ok: boolean }>(`/deployments/${deploymentId}/pause`, { method: 'POST' }),
  resumeDeployment: (deploymentId: string) => request<{ ok: boolean }>(`/deployments/${deploymentId}/resume`, { method: 'POST' }),
  stopDeployment: (deploymentId: string) => request<{ ok: boolean }>(`/deployments/${deploymentId}/stop`, { method: 'POST' }),
  cancelDeployment: (deploymentId: string) => request<{ ok: boolean }>(`/deployments/${deploymentId}/cancel`, { method: 'POST' }),
  retryFailedHosts: (deploymentId: string) => request<{ ok: boolean; deployment: any; hostsReset: number }>(`/deployments/${deploymentId}/retry-failed`, { method: 'POST' }),
  approveDeployment: (deploymentId: string) => request<{ deployment: any }>(`/deployments/${deploymentId}/approve`, { method: 'POST' }),
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
  groupMaps: () => request<{ maps: Array<{ id: string; ad_group_dn: string; role_name: string }> }>('/admin/ad-group-role-map'),
  deleteGroupMap: (id: string) => request<{ ok: boolean }>(`/admin/ad-group-role-map/${id}`, { method: 'DELETE' }),
  executorSetting: () => request<{ executor: string }>('/admin/executor-setting'),
  putExecutorSetting: (b: any) => request<{ executor: string }>('/admin/executor-setting', { method: 'PUT', body: JSON.stringify(b) }),
  managementVlanSetting: () => request<{ managementVlan: any }>('/admin/management-vlan-setting'),
  putManagementVlanSetting: (b: any) => request<{ managementVlan: any }>('/admin/management-vlan-setting', { method: 'PUT', body: JSON.stringify(b) }),

  sshCredentials: () => request<{ sshCredentials: any[] }>('/ssh-credentials'),
  createSshCredential: (b: any) => request<{ sshCredential: any }>('/ssh-credentials', { method: 'POST', body: JSON.stringify(b) }),
  updateSshCredential: (id: string, b: any) => request<{ sshCredential: any }>(`/ssh-credentials/${id}`, { method: 'PUT', body: JSON.stringify(b) }),
  deleteSshCredential: (id: string) => request<{ ok: boolean }>(`/ssh-credentials/${id}`, { method: 'DELETE' }),

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
    deploymentActivity: Array<{
      date: string;
      total: number;
      succeeded: number;
      failed: number;
      running: number;
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
        /** True for the deployment whose rules are currently active on the host. */
        current?: boolean;
        rules: any[];
      }>;
    }>(`/troubleshoot/hosts/${hostId}/policies`),
    policyVersionHosts: (versionId: string) => request<{
      policyVersion: any;
      hosts: Array<{
        host: any;
        deployments: any[];
      }>;
    }>(`/troubleshoot/policy-versions/${versionId}/hosts`),
    simulateCommunication: (params: {
      sourceIp: string;
      sourcePort?: number | null;
      destIp: string;
      destPort?: number | null;
      protocol?: string;
    }) => request<{
      sourceIp: string;
      sourcePort: number | null;
      destIp: string;
      destPort: number | null;
      protocol: string;
      sourceHost: any | null;
      destHost: any | null;
      wouldBlock: boolean;
      blockingRule: any | null;
      blockingRules: any[];
      allowingRules: any[];
      allRules: any[];
    }>('/troubleshoot/simulate-communication', {
      method: 'POST',
      body: JSON.stringify(params)
    }),
    audit: {
      start: (params: { hosts: string[]; durationMinutes: number }) =>
        request<{ sessions: any[] }>('/troubleshoot/audit/start', {
          method: 'POST',
          body: JSON.stringify(params)
        }),
      listSessions: () => request<{ sessions: any[] }>('/troubleshoot/audit/sessions'),
      getSession: (id: string) => request<{ session: any }>(`/troubleshoot/audit/sessions/${id}`),
      restoreSession: (id: string) =>
        request<{ success: boolean; flows: any[]; entryCount: number }>(`/troubleshoot/audit/sessions/${id}/restore`, {
          method: 'POST'
        }),
      getSessionLogs: (id: string) => request<{ logData: any }>(`/troubleshoot/audit/sessions/${id}/logs`),
      cancelSession: (id: string) =>
        request<{ success: boolean }>(`/troubleshoot/audit/sessions/${id}/cancel`, {
          method: 'POST'
        })
    }
  },

  // Compliance/Drift Detection
  checkHostCompliance: (hostId: string) => request<{
    hostId: string;
    hostname: string;
    status: 'compliant' | 'drifted' | 'unknown' | 'error';
    currentHash: string | null;
    expectedHash: string | null;
    backend: 'nftables' | 'iptables' | 'firewalld' | 'ufw';
    lastDeployment: {
      hash: string;
      createdAt: string;
      policyVersion: number;
      policySetName: string;
    } | null;
    error?: string;
  }>(`/compliance/hosts/${hostId}`),
  bulkCheckCompliance: (hostIds: string[]) => request<{
    results: Array<{
      hostId: string;
      hostname: string;
      status: 'compliant' | 'drifted' | 'unknown' | 'error';
      currentHash: string | null;
      expectedHash: string | null;
      error?: string;
    }>;
  }>('/compliance/hosts/bulk', {
    method: 'POST',
    body: JSON.stringify({ hostIds })
  }),

  // Host Readiness
  checkHostReadiness: (hostId: string) => request<{
    hostname: string;
    ready: boolean;
    backend: 'nftables' | 'iptables' | 'firewalld' | 'ufw' | 'unknown';
    nftVersion?: string;
    iptablesVersion?: string;
    sudoAccess: boolean;
    kernelSupport: boolean;
    errors: string[];
    warnings: string[];
    /** Reboot persistence with the distribution's own service (only when sudo works). */
    persistence?: {
      distro: 'debian' | 'rhel' | 'unsupported' | null;
      method: 'nftables.service' | 'netfilter-persistent' | 'iptables-services' | 'firewalld' | 'ufw' | null;
      available: boolean;
      status: string;
      warnings: string[];
      notes: string[];
    };
  }>(`/host-readiness/hosts/${hostId}/check`, { method: 'POST' }),

  // Policy Diff
  policyImpactDiff: (candidateVersionId: string, currentVersionId: string, hostIds: string[]) =>
    request<{
      diff: Array<{
        hostId: string;
        hostname: string;
        changes: {
          newAllows: Array<{
            type: 'added';
            orderIndex: number;
            direction: string;
            action: string;
            protocol: string;
            ports?: string;
            sourceType: string;
            sourceValue: string;
            comment?: string;
          }>;
          removedAllows: Array<{
            type: 'removed';
            orderIndex: number;
            direction: string;
            action: string;
            protocol: string;
            ports?: string;
            sourceType: string;
            sourceValue: string;
            comment?: string;
          }>;
          newDenies: Array<{
            type: 'added';
            orderIndex: number;
            direction: string;
            action: string;
            protocol: string;
            ports?: string;
            sourceType: string;
            sourceValue: string;
            comment?: string;
          }>;
          removedDenies: Array<{
            type: 'removed';
            orderIndex: number;
            direction: string;
            action: string;
            protocol: string;
            ports?: string;
            sourceType: string;
            sourceValue: string;
            comment?: string;
          }>;
        };
        summary: {
          totalNewAllows: number;
          totalRemovedAllows: number;
          totalNewDenies: number;
          totalRemovedDenies: number;
        };
      }>;
    }>(`/policy-versions/${candidateVersionId}/impact-diff`, {
      method: 'POST',
      body: JSON.stringify({ currentVersionId, hostIds })
    }),

  // === Capability 1: Tag Rules (Auto-Tagging) ===
  // === Inventory discovery (/api/discovery) ===
  discovery: {
    profiles: () => request<{ profiles: any[]; limits: { maxAddressesPerRun: number; minPrefix: number } }>('/discovery/profiles'),
    profile: (id: string) => request<{ profile: any }>(`/discovery/profiles/${id}`),
    createProfile: (b: any) => request<{ profile: any }>('/discovery/profiles', { method: 'POST', body: JSON.stringify(b) }),
    updateProfile: (id: string, b: any) => request<{ profile: any }>(`/discovery/profiles/${id}`, { method: 'PUT', body: JSON.stringify(b) }),
    deleteProfile: (id: string) => request<{ ok: boolean }>(`/discovery/profiles/${id}`, { method: 'DELETE' }),
    run: (id: string) => request<{ runId: string; status: string }>(`/discovery/profiles/${id}/run`, { method: 'POST' }),
    runs: (id: string, limit = 20) => request<{ runs: any[] }>(`/discovery/profiles/${id}/runs?limit=${limit}`),
    getRun: (runId: string) => request<{ run: any }>(`/discovery/runs/${runId}`),
  },

  tagRules: {
    list: () => request<{ tagRules: any[] }>('/tag-rules'),
    get: (id: string) => request<{ tagRule: any; matchedHosts: any[] }>(`/tag-rules/${id}`),
    create: (b: any) => request<{ tagRule: any }>('/tag-rules', { method: 'POST', body: JSON.stringify(b) }),
    /** Dry-run: which hosts would match this rule (no writes). */
    preview: (b: any) => request<{ hosts: Array<{ id: string; hostname: string }> }>('/tag-rules/preview', { method: 'POST', body: JSON.stringify(b) }),
    update: (id: string, b: any) => request<{ tagRule: any }>(`/tag-rules/${id}`, { method: 'PUT', body: JSON.stringify(b) }),
    delete: (id: string) => request<{ ok: boolean }>(`/tag-rules/${id}`, { method: 'DELETE' }),
    evaluate: (id: string) => request<{ matched: number; total: number }>(`/tag-rules/${id}/evaluate`, { method: 'POST' }),
    evaluateAll: () => request<{ rulesEvaluated: number; totalMatches: number }>('/tag-rules/evaluate-all', { method: 'POST' }),
    evaluateHost: (hostId: string) => request<{ rulesMatched: number; tagsAssigned: string[] }>(`/tag-rules/evaluate-host/${hostId}`, { method: 'POST' }),
  },

  // === Capability 2: Policy Templates ===
  templates: {
    list: (category?: string) => {
      const q = category ? `?category=${encodeURIComponent(category)}` : '';
      return request<{ templates: any[] }>(`/policy-templates${q}`);
    },
    categories: () => request<{ categories: string[] }>('/policy-templates/categories'),
    get: (id: string) => request<{ template: any; rules: any[] }>(`/policy-templates/${id}`),
    create: (b: any) => request<{ template: any }>('/policy-templates', { method: 'POST', body: JSON.stringify(b) }),
    update: (id: string, b: any) => request<{ template: any }>(`/policy-templates/${id}`, { method: 'PUT', body: JSON.stringify(b) }),
    delete: (id: string) => request<{ ok: boolean }>(`/policy-templates/${id}`, { method: 'DELETE' }),
    getRules: (id: string) => request<{ rules: any[] }>(`/policy-templates/${id}/rules`),
    addRule: (id: string, b: any) => request<{ rule: any }>(`/policy-templates/${id}/rules`, { method: 'POST', body: JSON.stringify(b) }),
    updateRule: (ruleId: string, b: any) => request<{ rule: any }>(`/policy-templates/rules/${ruleId}`, { method: 'PUT', body: JSON.stringify(b) }),
    deleteRule: (ruleId: string) => request<{ ok: boolean }>(`/policy-templates/rules/${ruleId}`, { method: 'DELETE' }),
    instantiate: (id: string, b?: any) => request<{ policySet: any; version: any; rulesCreated: number }>(`/policy-templates/${id}/instantiate`, { method: 'POST', body: JSON.stringify(b ?? {}) }),
    preview: (id: string) => request<{ template: any; rules: any[]; targetHosts: any[] }>(`/policy-templates/${id}/preview`, { method: 'POST' }),
  },

  // === Capability 3: Visual Topology ===
  topology: {
    listViews: () => request<{ views: any[] }>('/topology/views'),
    getView: (id: string) => request<{ view: any; flows: any[] }>(`/topology/views/${id}`),
    createView: (b: any) => request<{ view: any }>('/topology/views', { method: 'POST', body: JSON.stringify(b) }),
    updateView: (id: string, b: any) => request<{ view: any }>(`/topology/views/${id}`, { method: 'PUT', body: JSON.stringify(b) }),
    deleteView: (id: string) => request<{ ok: boolean }>(`/topology/views/${id}`, { method: 'DELETE' }),
    addFlow: (viewId: string, b: any) => request<{ flow: any }>(`/topology/views/${viewId}/flows`, { method: 'POST', body: JSON.stringify(b) }),
    deleteFlow: (flowId: string) => request<{ ok: boolean }>(`/topology/flows/${flowId}`, { method: 'DELETE' }),
    generatePolicies: (viewId: string, name?: string) => request<{ policySetId: string; versionId: string; rulesCreated: number }>(`/topology/views/${viewId}/generate-policies`, { method: 'POST', body: JSON.stringify({ name }) }),
    autoDiscover: () => request<{ nodes: any[]; edges: any[] }>('/topology/auto-discover'),
  },

  // === Capability 4: Policy Recommendations ===
  recommendations: {
    list: (params?: { status?: string; hostId?: string }) => {
      const q = new URLSearchParams();
      if (params?.status) q.append('status', params.status);
      if (params?.hostId) q.append('hostId', params.hostId);
      const qs = q.toString();
      return request<{ recommendations: any[] }>(`/recommendations${qs ? `?${qs}` : ''}`);
    },
    get: (id: string) => request<{ recommendation: any }>(`/recommendations/${id}`),
    generate: (auditSessionId: string, hostId: string) =>
      request<{ recommendationId: string; ruleCount: number; avgConfidence: number }>('/recommendations/generate', {
        method: 'POST', body: JSON.stringify({ auditSessionId, hostId })
      }),
    accept: (id: string) => request<{ recommendation: any }>(`/recommendations/${id}/accept`, { method: 'POST' }),
    reject: (id: string) => request<{ recommendation: any }>(`/recommendations/${id}/reject`, { method: 'POST' }),
    apply: (id: string, policySetId?: string) =>
      request<{ versionId: string; rulesCreated: number }>(`/recommendations/${id}/apply`, {
        method: 'POST', body: JSON.stringify({ policySetId })
      }),
  },

  // === Capability 5: Integrations ===
  integrations: {
    list: () => request<{ integrations: any[] }>('/integrations'),
    get: (id: string) => request<{ integration: any; recentEvents: any[] }>(`/integrations/${id}`),
    create: (b: any) => request<{ integration: any }>('/integrations', { method: 'POST', body: JSON.stringify(b) }),
    update: (id: string, b: any) => request<{ integration: any }>(`/integrations/${id}`, { method: 'PUT', body: JSON.stringify(b) }),
    delete: (id: string) => request<{ ok: boolean }>(`/integrations/${id}`, { method: 'DELETE' }),
    test: (id: string) => request<{ success: boolean; message: string }>(`/integrations/${id}/test`, { method: 'POST' }),
    sync: (id: string) => request<{ success: boolean; message: string }>(`/integrations/${id}/sync`, { method: 'POST' }),
    events: (id: string, limit?: number) => request<{ events: any[] }>(`/integrations/${id}/events${limit ? `?limit=${limit}` : ''}`),
    hostVulnerabilities: (hostId: string) => request<{ vulnerabilities: any[] }>(`/integrations/vulnerabilities/by-host/${hostId}`),
    threatIntel: () => request<{ entries: any[] }>('/integrations/threat-intel'),
  },

  // === Capability 6: Policy Testing ===
  policyTest: {
    listSessions: (params?: { hostId?: string; status?: string }) => {
      const q = new URLSearchParams();
      if (params?.hostId) q.append('hostId', params.hostId);
      if (params?.status) q.append('status', params.status);
      const qs = q.toString();
      return request<{ sessions: any[] }>(`/policy-test/sessions${qs ? `?${qs}` : ''}`);
    },
    getSession: (id: string) => request<{ session: any }>(`/policy-test/sessions/${id}`),
    start: (b: { policyVersionId: string; hostId: string; durationMinutes?: number }) =>
      request<{ session: any; message: string; compiled?: any }>('/policy-test/start', { method: 'POST', body: JSON.stringify(b) }),
    stop: (id: string) => request<{ session: any; message: string; flowCount: number; entryCount: number }>(`/policy-test/sessions/${id}/stop`, { method: 'POST' }),
    collectLogs: (id: string) => request<{ message: string; flowCount: number; entryCount: number; flows: any[] }>(`/policy-test/sessions/${id}/collect-logs`, { method: 'POST' }),
    analyze: (id: string) => request<{ analysis: any; message: string }>(`/policy-test/sessions/${id}/analyze`, { method: 'POST' }),
  },

  // === Capability 7: Kubernetes ===
  k8s: {
    clusters: () => request<{ clusters: any[] }>('/k8s/clusters'),
    cluster: (id: string) => request<{ cluster: any; workloadSummary: any[]; namespaces: any[] }>(`/k8s/clusters/${id}`),
    createCluster: (b: any) => request<{ cluster: any }>('/k8s/clusters', { method: 'POST', body: JSON.stringify(b) }),
    updateCluster: (id: string, b: any) => request<{ cluster: any }>(`/k8s/clusters/${id}`, { method: 'PUT', body: JSON.stringify(b) }),
    deleteCluster: (id: string) => request<{ ok: boolean }>(`/k8s/clusters/${id}`, { method: 'DELETE' }),
    workloads: (clusterId: string, params?: { namespace?: string; kind?: string }) => {
      const q = new URLSearchParams();
      if (params?.namespace) q.append('namespace', params.namespace);
      if (params?.kind) q.append('kind', params.kind);
      const qs = q.toString();
      return request<{ workloads: any[] }>(`/k8s/clusters/${clusterId}/workloads${qs ? `?${qs}` : ''}`);
    },
    mapWorkloadTag: (workloadId: string, tagId: string) =>
      request<{ ok: boolean }>(`/k8s/workloads/${workloadId}/map-tag`, { method: 'POST', body: JSON.stringify({ tagId }) }),
    networkPolicies: (clusterId: string) => request<{ networkPolicies: any[] }>(`/k8s/clusters/${clusterId}/network-policies`),
    deployPolicy: (clusterId: string, b: any) =>
      request<{ networkPolicy: any }>(`/k8s/clusters/${clusterId}/deploy-policy`, { method: 'POST', body: JSON.stringify(b) }),
    testConnection: (clusterId: string) =>
      request<{ ok: boolean; serverVersion?: string; message?: string }>(`/k8s/clusters/${clusterId}/test-connection`, { method: 'POST', body: '{}' }),
    applyPolicy: (clusterId: string, npId: string, b: { dryRun?: boolean; overwrite?: boolean } = {}) =>
      request<{ ok: boolean; dryRun?: boolean; replaced?: boolean; replaces?: boolean; message?: string; networkPolicy?: any }>(`/k8s/clusters/${clusterId}/network-policies/${npId}/apply`, { method: 'POST', body: JSON.stringify(b) }),
    checkPolicy: (clusterId: string, npId: string) =>
      request<{ ok: boolean; state: 'IN_SYNC' | 'DRIFTED' | 'MISSING'; managedBySegmentra: boolean | null }>(`/k8s/clusters/${clusterId}/network-policies/${npId}/check`, { method: 'POST', body: '{}' }),
    removePolicy: (clusterId: string, npId: string) =>
      request<{ ok: boolean; alreadyAbsent: boolean }>(`/k8s/clusters/${clusterId}/network-policies/${npId}/remove`, { method: 'POST', body: '{}' }),
    createWorkload: (clusterId: string, b: { namespace: string; name: string; kind?: string; labels?: Record<string, string> }) =>
      request<{ workload: any }>(`/k8s/clusters/${clusterId}/workloads`, { method: 'POST', body: JSON.stringify(b) }),
    deleteWorkload: (workloadId: string) => request<{ ok: boolean }>(`/k8s/workloads/${workloadId}`, { method: 'DELETE' }),
    unmapWorkloadTag: (workloadId: string, tagId: string) => request<{ ok: boolean }>(`/k8s/workloads/${workloadId}/tags/${tagId}`, { method: 'DELETE' }),
  },

  // === Capability 8: OT/IoT ===
  iot: {
    assets: (params?: { assetType?: string; zone?: string; vlanId?: string; gatewayId?: string }) => {
      const q = new URLSearchParams();
      if (params?.assetType) q.append('assetType', params.assetType);
      if (params?.zone) q.append('zone', params.zone);
      if (params?.vlanId) q.append('vlanId', params.vlanId);
      if (params?.gatewayId) q.append('gatewayId', params.gatewayId);
      const qs = q.toString();
      return request<{ assets: any[] }>(`/iot-assets${qs ? `?${qs}` : ''}`);
    },
    asset: (id: string) => request<{ asset: any; gateways: any[]; observedFlows: any[]; tags: any[] }>(`/iot-assets/${id}`),
    createAsset: (b: any) => request<{ asset: any }>('/iot-assets', { method: 'POST', body: JSON.stringify(b) }),
    updateAsset: (id: string, b: any) => request<{ asset: any }>(`/iot-assets/${id}`, { method: 'PUT', body: JSON.stringify(b) }),
    deleteAsset: (id: string) => request<{ ok: boolean }>(`/iot-assets/${id}`, { method: 'DELETE' }),
    bulkImport: (assets: any[]) => request<{ imported: number; total: number }>('/iot-assets/bulk-import', { method: 'POST', body: JSON.stringify({ assets }) }),
    addTag: (assetId: string, tagId: string) => request<{ ok: boolean }>(`/iot-assets/${assetId}/tags`, { method: 'POST', body: JSON.stringify({ tagId }) }),
    removeTag: (assetId: string, tagId: string) => request<{ ok: boolean }>(`/iot-assets/${assetId}/tags/${tagId}`, { method: 'DELETE' }),
    flows: (assetId: string) => request<{ flows: any[] }>(`/iot-assets/${assetId}/flows`),
    baseline: (assetId: string) => request<{ ok: boolean; baselineFlows: number }>(`/iot-assets/${assetId}/baseline`, { method: 'POST' }),
    assignGateways: (assetId: string, gatewayIds: string[]) => request<{ ok: boolean }>(`/iot-assets/${assetId}/gateways`, { method: 'POST', body: JSON.stringify({ gatewayIds }) }),
    removeGateway: (assetId: string, hostId: string) => request<{ ok: boolean }>(`/iot-assets/${assetId}/gateways/${hostId}`, { method: 'DELETE' }),
    // Gateway views
    gateways: () => request<{ gateways: any[] }>('/iot-assets/gateways/list'),
    gateway: (hostId: string) => request<{ gateway: any; protectedAssets: any[]; recentDeployments: any[] }>(`/iot-assets/gateways/${hostId}`),
    // Protocol catalog, protection coverage, passive discovery from a gateway, vendor list
    protocols: () => request<{ protocols: any[] }>('/iot-assets/protocols'),
    coverage: () => request<{ assets: any[]; summary: Record<string, number>; zones: any[] }>('/iot-assets/coverage'),
    discover: (gatewayId: string, probe?: { sweepCidr: string }) =>
      request<any>('/iot-assets/discover', { method: 'POST', body: JSON.stringify(probe ? { gatewayId, sweepCidr: probe.sweepCidr, confirmActiveProbe: true } : { gatewayId }) }),
    discoverImport: (body: any) => request<{ created: any[]; skipped: any[]; note: string }>('/iot-assets/discover/import', { method: 'POST', body: JSON.stringify(body) }),
    ouiStatus: () => request<{ entries: number }>('/iot-assets/oui/status'),
    importOui: async (text: string, replace: boolean) => {
      const token = getToken();
      const resp = await fetch(`${API_BASE}/iot-assets/oui?replace=${replace}`, { method: 'POST', headers: { 'content-type': 'text/csv', ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: text });
      const body = await resp.json().catch(() => ({}));
      if (!resp.ok) throw new ApiError(body.message || body.error || `${resp.status} ${resp.statusText}`, resp.status, body);
      return body as { imported: number; entries: number };
    },
  },

  // === Notifications ===
  notifications: {
    channels: () => request<{ channels: any[] }>('/notifications/channels'),
    channel: (id: string) => request<{ channel: any; rules: any[]; recentLog: any[] }>(`/notifications/channels/${id}`),
    createChannel: (b: any) => request<{ channel: any }>('/notifications/channels', { method: 'POST', body: JSON.stringify(b) }),
    updateChannel: (id: string, b: any) => request<{ channel: any }>(`/notifications/channels/${id}`, { method: 'PUT', body: JSON.stringify(b) }),
    deleteChannel: (id: string) => request<{ ok: boolean }>(`/notifications/channels/${id}`, { method: 'DELETE' }),
    testChannel: (id: string) => request<{ success: boolean; message: string }>(`/notifications/channels/${id}/test`, { method: 'POST' }),
    addRule: (channelId: string, b: any) => request<{ rule: any }>(`/notifications/channels/${channelId}/rules`, { method: 'POST', body: JSON.stringify(b) }),
    deleteRule: (ruleId: string) => request<{ ok: boolean }>(`/notifications/rules/${ruleId}`, { method: 'DELETE' }),
    log: (params?: { limit?: number; status?: string }) => {
      const q = new URLSearchParams();
      if (params?.limit) q.append('limit', String(params.limit));
      if (params?.status) q.append('status', params.status);
      const qs = q.toString();
      return request<{ log: any[] }>(`/notifications/log${qs ? `?${qs}` : ''}`);
    },
  },

  // === User Management ===
  users: {
    list: () => request<{ users: any[] }>('/admin/users'),
    get: (id: string) => request<{ user: any }>(`/admin/users/${id}`),
    create: (b: any) => request<{ user: any }>('/admin/users', { method: 'POST', body: JSON.stringify(b) }),
    update: (id: string, b: any) => request<{ user: any }>(`/admin/users/${id}`, { method: 'PUT', body: JSON.stringify(b) }),
    resetPassword: (id: string, newPassword: string) =>
      request<{ ok: boolean }>(`/admin/users/${id}/reset-password`, { method: 'POST', body: JSON.stringify({ newPassword }) }),
    delete: (id: string) => request<{ ok: boolean }>(`/admin/users/${id}`, { method: 'DELETE' }),
  },

  // === Security Audit ===
  securityAudit: {
    scan: () => request<{ findings: any[]; summary: any; scanId: string; scannedAt: string }>('/security-audit/scan'),
    latest: () => request<{ findings: any[]; summary: any; scanId?: string; scannedAt?: string; triggeredBy?: string }>('/security-audit/latest'),
    history: () => request<{ history: any[] }>('/security-audit/history'),
    summary: () => request<{ summary: any }>('/security-audit/summary'),
  },
};

export const previewTagRule = (b: any) => api.tagRules.preview(b);
export const deletePolicySet = (id: string) => api.deletePolicySet(id);
