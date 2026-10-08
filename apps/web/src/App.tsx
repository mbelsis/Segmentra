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
import { AuthProvider } from './lib/auth-context'
import { RequireRole } from './components/RequireRole'

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
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
          {/* All roles can view */}
          <Route index element={<DashboardPage />} />
          <Route path="inventory" element={<InventoryPage />} />
          <Route path="policies" element={<PolicySetsPage />} />
          <Route path="policy-set/:policySetId" element={<PolicySetDetailPage />} />
          <Route path="policy-version/:versionId" element={<PolicyVersionPage />} />
          <Route path="deployments" element={<DeploymentsPage />} />
          <Route path="deployment/:deploymentId" element={<DeploymentDetailPage />} />
          <Route path="troubleshoot" element={<TroubleshootPage />} />
          <Route path="kubernetes" element={<KubernetesPage />} />
          <Route path="iot" element={<IoTPage />} />
          <Route path="security-audit" element={<SecurityAuditPage />} />
          {/* Audit log: API allows every authenticated role to read */}
          <Route path="audit" element={<AuditPage />} />
          {/* Templates: readable by every role; create/edit gated inside the page */}
          <Route path="policy-templates" element={<PolicyTemplatesPage />} />

          {/* Operator + Admin only */}
          <Route path="topology" element={<RequireRole roles={['operator', 'admin']}><TopologyPage /></RequireRole>} />
          <Route path="policy-testing" element={<RequireRole roles={['operator', 'approver', 'admin']}><PolicyTestPage /></RequireRole>} />

          {/* Approver + Admin only */}
          <Route path="approvals" element={<RequireRole roles={['approver', 'admin']}><ApprovalsPage /></RequireRole>} />

          {/* Admin only */}
          <Route path="integrations" element={<RequireRole roles={['admin']}><IntegrationsPage /></RequireRole>} />
          <Route path="notifications" element={<RequireRole roles={['admin']}><NotificationsPage /></RequireRole>} />
          <Route path="admin" element={<RequireRole roles={['admin']}><AdminPage /></RequireRole>} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}

export default App
