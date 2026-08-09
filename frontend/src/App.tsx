import { Navigate, Route, Routes } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';

import AppShell from './components/layout/AppShell';
import { PhantomDataProvider } from './hooks/usePhantomData';
import { AuthProvider } from './context/AuthContext';
import { ProtectedRoute } from './components/auth/ProtectedRoute';
import DashboardPage from './features/dashboard/DashboardPage';
import LiveScanPage from './features/scans/LiveScanPage';
import FindingsPage from './features/findings/FindingsPage';
import AssetsPage from './features/assets/AssetsPage';
import CvePage from './features/cve/CvePage';
import RemediationPage from './features/remediation/RemediationPage';
import AgentsPage from './features/operations/AgentsPage';
import ScanHistoryPage from './features/operations/ScanHistoryPage';
import AuditLogsPage from './features/operations/AuditLogsPage';
import SelfAuditPage from './features/system/SelfAuditPage';
import NotificationsPage from './features/system/NotificationsPage';
import SystemHealthPage from './features/system/SystemHealthPage';
import SettingsPage from './features/system/SettingsPage';
import AttackIntelligence from './features/private/AttackIntelligence';
import AuthorizedTestingPage from './features/authorized-testing/AuthorizedTestingPage';
import ScanQualityPage from './features/learning/ScanQualityPage';
import DoSPanel from './features/private/DoSPanel';
import ReportPage from './features/reports/ReportPage';
import GitHubConnectPage from './features/github/GitHubConnectPage';
import MultiSourceScanPage from './features/multi-source/MultiSourceScanPage';
import MultiSourceDetailPage from './features/multi-source/MultiSourceDetailPage';
import CIIntegrationPage from './features/ci/CIIntegrationPage';
import AuthCallbackPage from './features/auth/AuthCallbackPage';
import ProfilePage from './features/auth/ProfilePage';
import LoginPage from './features/auth/LoginPage';
import RegisterPage from './features/auth/RegisterPage';

export default function App() {
  const isAuthCallback = window.location.pathname === '/auth/callback';

  if (isAuthCallback) {
    return (
      <AuthProvider>
        <AuthCallbackPage />
      </AuthProvider>
    );
  }

  return (
    <AuthProvider>
      <PhantomDataProvider>
        <AppShell>
          <Routes>
            {/* Public routes */}
            <Route path="/" element={<DashboardPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            
            {/* Protected routes - FREE tier */}
            <Route path="/scan" element={<ProtectedRoute><LiveScanPage /></ProtectedRoute>} />
            <Route path="/findings" element={<ProtectedRoute><FindingsPage /></ProtectedRoute>} />
            <Route path="/assets" element={<ProtectedRoute><AssetsPage /></ProtectedRoute>} />
            <Route path="/cve" element={<ProtectedRoute><CvePage /></ProtectedRoute>} />
            <Route path="/remediation" element={<ProtectedRoute><RemediationPage /></ProtectedRoute>} />
            <Route path="/agents" element={<ProtectedRoute><AgentsPage /></ProtectedRoute>} />
            <Route path="/history" element={<ProtectedRoute><ScanHistoryPage /></ProtectedRoute>} />
            <Route path="/audit-logs" element={<ProtectedRoute><AuditLogsPage /></ProtectedRoute>} />
            <Route path="/self-audit" element={<ProtectedRoute><SelfAuditPage /></ProtectedRoute>} />
            <Route path="/notifications" element={<ProtectedRoute><NotificationsPage /></ProtectedRoute>} />
            <Route path="/system-health" element={<ProtectedRoute><SystemHealthPage /></ProtectedRoute>} />
            <Route path="/settings" element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />
            <Route path="/intelligence" element={<ProtectedRoute><AttackIntelligence /></ProtectedRoute>} />
            <Route path="/quality" element={<ProtectedRoute><ScanQualityPage /></ProtectedRoute>} />
            <Route path="/github" element={<ProtectedRoute><GitHubConnectPage /></ProtectedRoute>} />
            <Route path="/github/callback" element={<ProtectedRoute><GitHubConnectPage /></ProtectedRoute>} />
            <Route path="/profile" element={<ProtectedRoute><ProfilePage /></ProtectedRoute>} />
            <Route path="/multi-source" element={<ProtectedRoute><MultiSourceScanPage /></ProtectedRoute>} />
            <Route path="/multi-source/:scan_id" element={<ProtectedRoute><MultiSourceDetailPage /></ProtectedRoute>} />
            <Route path="/ci-cd" element={<ProtectedRoute><CIIntegrationPage /></ProtectedRoute>} />
            <Route path="/report/:scan_id" element={<ProtectedRoute><ReportPage /></ProtectedRoute>} />
            
            {/* Protected routes - PRO tier only */}
            <Route path="/authorized-testing" element={<ProtectedRoute requiredTier="PRO"><AuthorizedTestingPage /></ProtectedRoute>} />
            <Route path="/private/dos" element={<ProtectedRoute requiredTier="PRO"><DoSPanel /></ProtectedRoute>} />
            
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </AppShell>
        <Toaster
          position="bottom-right"
          toastOptions={{
            duration: 3500,
            style: {
              background: 'var(--surface-primary)',
              color: 'var(--text-strong)',
              border: '1px solid var(--border-default)',
              borderRadius: 'var(--radius-control)',
              fontFamily: 'Inter, sans-serif',
              fontSize: '13px',
              boxShadow: 'var(--shadow-float)',
            },
          }}
        />
      </PhantomDataProvider>
    </AuthProvider>
  );
}