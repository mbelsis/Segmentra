import './App.css'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'

import { AppShell } from './components/AppShell'
import { RequireAuth } from './components/RequireAuth'
import { LoginPage } from './pages/LoginPage'
import { DashboardPage } from './pages/DashboardPage'
import { InventoryPage } from './pages/InventoryPage'
import { PolicySetsPage } from './pages/PolicySetsPage'
import { PolicyVersionPage } from './pages/PolicyVersionPage'
import { ApprovalsPage } from './pages/ApprovalsPage'
import { DeploymentsPage } from './pages/DeploymentsPage'
import { AuditPage } from './pages/AuditPage'
import { AdminPage } from './pages/AdminPage'

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
          <Route path="policy-version/:versionId" element={<PolicyVersionPage />} />
          <Route path="approvals" element={<ApprovalsPage />} />
          <Route path="deployments" element={<DeploymentsPage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="admin" element={<AdminPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
