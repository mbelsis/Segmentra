import './App.css'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'

import { AppShell } from './components/AppShell'
import { RequireAuth } from './components/RequireAuth'
import { LoginPage } from './pages/LoginPage'
import { DashboardPage } from './pages/DashboardPage'
import { InventoryPage } from './pages/InventoryPage'
import { PolicySetsPage } from './pages/PolicySetsPage'
import { PolicySetDetailPage } from './pages/PolicySetDetailPage'
import { PolicyVersionPage } from './pages/PolicyVersionPage'
import { ApprovalsPage } from './pages/ApprovalsPage'
import { DeploymentsPage } from './pages/DeploymentsPage'
import { DeploymentDetailPage } from './pages/DeploymentDetailPage'
import { AuditPage } from './pages/AuditPage'
import { AdminPage } from './pages/AdminPage'
import { TroubleshootPage } from './pages/TroubleshootPage'
import { PolicyTemplatesPage } from './pages/PolicyTemplatesPage'
import { TopologyPage } from './pages/TopologyPage'
import { IntegrationsPage } from './pages/IntegrationsPage'
import { PolicyTestPage } from './pages/PolicyTestPage'
import { KubernetesPage } from './pages/KubernetesPage'
import { IoTPage } from './pages/IoTPage'
import { SecurityAuditPage } from './pages/SecurityAuditPage'
import { NotificationsPage } from './pages/NotificationsPage'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/"
          element={
            <RequireAuth>
              <AppShell />
            </RequireAuth>
          }
        >
          <Route index element={<DashboardPage />} />
          <Route path="inventory" element={<InventoryPage />} />
          <Route path="policies" element={<PolicySetsPage />} />
          <Route path="policy-set/:policySetId" element={<PolicySetDetailPage />} />
          <Route path="policy-version/:versionId" element={<PolicyVersionPage />} />
          <Route path="policy-templates" element={<PolicyTemplatesPage />} />
          <Route path="topology" element={<TopologyPage />} />
          <Route path="approvals" element={<ApprovalsPage />} />
          <Route path="deployments" element={<DeploymentsPage />} />
          <Route path="deployment/:deploymentId" element={<DeploymentDetailPage />} />
          <Route path="policy-testing" element={<PolicyTestPage />} />
          <Route path="troubleshoot" element={<TroubleshootPage />} />
          <Route path="integrations" element={<IntegrationsPage />} />
          <Route path="kubernetes" element={<KubernetesPage />} />
          <Route path="iot" element={<IoTPage />} />
          <Route path="security-audit" element={<SecurityAuditPage />} />
          <Route path="notifications" element={<NotificationsPage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="admin" element={<AdminPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
