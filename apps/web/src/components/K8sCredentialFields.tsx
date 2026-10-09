import { useEffect, useState } from 'react';

export const K8S_AUTH_TYPES: Array<{ value: string; label: string }> = [
  { value: 'kubeconfig', label: 'Kubeconfig' },
  { value: 'service_account', label: 'Service Account token' },
  { value: 'token', label: 'Bearer token' },
  { value: 'eks', label: 'Amazon EKS (AWS access key)' },
  { value: 'gke', label: 'Google GKE (service account key)' },
  { value: 'aks', label: 'Azure AKS (service principal)' },
];

export const isCloudAuth = (authType: string) => ['eks', 'gke', 'aks'].includes(authType);

type Props = {
  authType: string;
  /** Receives the credential text to store (raw kubeconfig/token, or JSON for the cloud logins). */
  onChange: (credentials: string) => void;
  /** Changes when the surrounding form is reset or another cluster is edited. */
  resetKey?: string;
};

const mono = { fontFamily: 'monospace', fontSize: '12px' } as const;

/** Credential inputs for a Kubernetes cluster, depending on its auth type. Write-only. */
export function K8sCredentialFields({ authType, onChange, resetKey }: Props) {
  const [text, setText] = useState('');
  const [eks, setEks] = useState({ clusterName: '', region: '', accessKeyId: '', secretAccessKey: '', sessionToken: '' });
  const [aks, setAks] = useState({ tenantId: '', clientId: '', clientSecret: '' });

  useEffect(() => { setText(''); setEks({ clusterName: '', region: '', accessKeyId: '', secretAccessKey: '', sessionToken: '' }); setAks({ tenantId: '', clientId: '', clientSecret: '' }); }, [resetKey, authType]);

  useEffect(() => {
    if (authType === 'eks') {
      const filled = eks.clusterName && eks.region && eks.accessKeyId && eks.secretAccessKey;
      onChange(filled ? JSON.stringify({ ...eks, sessionToken: eks.sessionToken || undefined }) : '');
    } else if (authType === 'aks') {
      onChange(aks.tenantId && aks.clientId && aks.clientSecret ? JSON.stringify(aks) : '');
    } else {
      onChange(text);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authType, text, eks, aks]);

  if (authType === 'eks') {
    return (
      <div>
        <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
          <div className="form-group"><label>EKS cluster name *</label><input value={eks.clusterName} onChange={(e) => setEks((f) => ({ ...f, clusterName: e.target.value }))} placeholder="the name in AWS, signed into the token" /></div>
          <div className="form-group"><label>AWS region *</label><input value={eks.region} onChange={(e) => setEks((f) => ({ ...f, region: e.target.value }))} placeholder="e.g., eu-west-1" /></div>
          <div className="form-group"><label>Access key ID *</label><input value={eks.accessKeyId} onChange={(e) => setEks((f) => ({ ...f, accessKeyId: e.target.value }))} autoComplete="off" /></div>
          <div className="form-group"><label>Secret access key *</label><input type="password" value={eks.secretAccessKey} onChange={(e) => setEks((f) => ({ ...f, secretAccessKey: e.target.value }))} autoComplete="new-password" /></div>
        </div>
        <div className="form-group"><label>Session token (optional, for temporary credentials)</label><input type="password" value={eks.sessionToken} onChange={(e) => setEks((f) => ({ ...f, sessionToken: e.target.value }))} autoComplete="new-password" /></div>
        <div style={{ fontSize: '11.5px', color: '#97846c' }}>The IAM identity must be mapped to a Kubernetes user with access to NetworkPolicies (EKS access entry or aws-auth). Segmentra mints the same short-lived token as <code>aws eks get-token</code>; no AWS CLI is needed. Provide the cluster's API endpoint and CA certificate too.</div>
      </div>
    );
  }
  if (authType === 'aks') {
    return (
      <div>
        <div className="form-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
          <div className="form-group"><label>Tenant ID *</label><input value={aks.tenantId} onChange={(e) => setAks((f) => ({ ...f, tenantId: e.target.value }))} autoComplete="off" /></div>
          <div className="form-group"><label>Client (application) ID *</label><input value={aks.clientId} onChange={(e) => setAks((f) => ({ ...f, clientId: e.target.value }))} autoComplete="off" /></div>
        </div>
        <div className="form-group"><label>Client secret *</label><input type="password" value={aks.clientSecret} onChange={(e) => setAks((f) => ({ ...f, clientSecret: e.target.value }))} autoComplete="new-password" /></div>
        <div style={{ fontSize: '11.5px', color: '#97846c' }}>For an AKS cluster with Microsoft Entra ID integration. The service principal needs an Azure Kubernetes Service RBAC role (or Kubernetes RBAC) that allows NetworkPolicies. Provide the cluster's API endpoint and CA certificate too.</div>
      </div>
    );
  }
  if (authType === 'gke') {
    return (
      <div className="form-group">
        <label>Service account key (JSON) *</label>
        <textarea rows={7} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} autoComplete="off" style={mono} placeholder='{"type": "service_account", "client_email": "...", "private_key": "-----BEGIN PRIVATE KEY-----..."}' />
        <div style={{ fontSize: '11.5px', color: '#97846c', marginTop: 2 }}>Paste the key file contents. The service account needs a role such as Kubernetes Engine Developer. Segmentra signs a JWT and exchanges it for an access token; no gcloud or gke-gcloud-auth-plugin is needed. Provide the cluster's API endpoint and CA certificate too.</div>
      </div>
    );
  }
  return (
    <div className="form-group">
      <label>{authType === 'kubeconfig' ? 'Kubeconfig' : 'Bearer token'}</label>
      <textarea rows={authType === 'kubeconfig' ? 6 : 2} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} autoComplete="off" style={mono}
        placeholder={authType === 'kubeconfig' ? 'Paste a kubeconfig with an inline token or client certificate (certificate-authority-data, client-certificate-data, client-key-data).' : 'Service account token'} />
    </div>
  );
}
