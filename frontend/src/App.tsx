import { Navigate, Route, Routes } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';

import AppShell from './components/layout/AppShell';
import { PhantomDataProvider } from './hooks/usePhantomData';
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
import AuthorizedTestingPage from './features/authorized-testing/AuthorizedTestingPage';
import ReportPage from './features/reports/ReportPage';

export default function App() {
  return (
    <PhantomDataProvider>
      <AppShell>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/scan" element={<LiveScanPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/assets" element={<AssetsPage />} />
          <Route path="/cve" element={<CvePage />} />
          <Route path="/remediation" element={<RemediationPage />} />
          <Route path="/agents" element={<AgentsPage />} />
          <Route path="/history" element={<ScanHistoryPage />} />
          <Route path="/audit-logs" element={<AuditLogsPage />} />
          <Route path="/self-audit" element={<SelfAuditPage />} />
          <Route path="/notifications" element={<NotificationsPage />} />
          <Route path="/system-health" element={<SystemHealthPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/authorized-testing" element={<AuthorizedTestingPage />} />
          <Route path="/report/:scan_id" element={<ReportPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppShell>
      <Toaster
        position="bottom-right"
        toastOptions={{
          duration: 3500,
          style: {
            background: 'rgba(11, 16, 32, 0.96)',
            color: '#F8FAFC',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: '16px',
            fontFamily: 'Inter, sans-serif',
            fontSize: '14px',
            boxShadow: '0 22px 60px rgba(0, 0, 0, 0.45)',
            backdropFilter: 'blur(18px)'
          }
        }}
      />
    </PhantomDataProvider>
  );
}
