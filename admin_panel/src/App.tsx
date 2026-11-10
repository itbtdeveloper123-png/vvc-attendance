import React, { Suspense } from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { AuthProvider } from './context/AuthContext';
import { AdminLayout } from './components/layout/AdminLayout';

// Dynamic code splitting with React.lazy to reduce initial bundle size and speed up page load
const LoginPage = React.lazy(() => import('./pages/LoginPage').then(m => ({ default: m.LoginPage })));
const DashboardPage = React.lazy(() => import('./pages/DashboardPage').then(m => ({ default: m.DashboardPage })));
const UsersPage = React.lazy(() => import('./pages/UsersPage').then(m => ({ default: m.UsersPage })));
const AttendanceReportsPage = React.lazy(() => import('./pages/AttendanceReportsPage').then(m => ({ default: m.AttendanceReportsPage })));
const RequestsPage = React.lazy(() => import('./pages/RequestsPage').then(m => ({ default: m.RequestsPage })));
const StockPage = React.lazy(() => import('./pages/StockPage').then(m => ({ default: m.StockPage })));
const GpsTrackingPage = React.lazy(() => import('./pages/GpsTrackingPage').then(m => ({ default: m.GpsTrackingPage })));
const PayrollPage = React.lazy(() => import('./pages/PayrollPage').then(m => ({ default: m.PayrollPage })));
const MeetingsPage = React.lazy(() => import('./pages/MeetingsPage').then(m => ({ default: m.MeetingsPage })));
const NotificationsPage = React.lazy(() => import('./pages/NotificationsPage').then(m => ({ default: m.NotificationsPage })));
const PollsPage = React.lazy(() => import('./pages/PollsPage').then(m => ({ default: m.PollsPage })));
const LocationsPage = React.lazy(() => import('./pages/LocationsPage').then(m => ({ default: m.LocationsPage })));
const CategoriesPage = React.lazy(() => import('./pages/CategoriesPage').then(m => ({ default: m.CategoriesPage })));
const TokensPage = React.lazy(() => import('./pages/TokensPage').then(m => ({ default: m.TokensPage })));
const AuditLogsPage = React.lazy(() => import('./pages/AuditLogsPage').then(m => ({ default: m.AuditLogsPage })));
const TrainingQuizPage = React.lazy(() => import('./pages/TrainingQuizPage').then(m => ({ default: m.TrainingQuizPage })));
const SettingsPage = React.lazy(() => import('./pages/SettingsPage').then(m => ({ default: m.SettingsPage })));

const PageFallback: React.FC = () => (
  <div className="flex h-[60vh] w-full items-center justify-center">
    <div className="flex flex-col items-center space-y-3">
      <div className="h-9 w-9 animate-spin rounded-full border-3 border-indigo-600 border-t-transparent dark:border-indigo-400"></div>
      <p className="text-sm font-medium text-gray-500 dark:text-gray-400">កំពុងផ្ទុកទំព័រ...</p>
    </div>
  </div>
);

export const App: React.FC = () => {
  return (
    <ThemeProvider>
      <AuthProvider>
        <HashRouter>
          <Suspense fallback={<PageFallback />}>
            <Routes>
              {/* Public Auth Route */}
              <Route path="/login" element={<LoginPage />} />

              {/* Protected Admin Routes */}
              <Route element={<AdminLayout />}>
                <Route path="/" element={<DashboardPage />} />
                <Route path="/dashboard" element={<DashboardPage />} />
                <Route path="/users" element={<UsersPage />} />
                <Route path="/attendance" element={<AttendanceReportsPage />} />
                <Route path="/reports" element={<AttendanceReportsPage />} />
                <Route path="/requests" element={<RequestsPage />} />
                <Route path="/stock" element={<StockPage />} />
                <Route path="/gps" element={<GpsTrackingPage />} />
                <Route path="/gps-tracking" element={<GpsTrackingPage />} />
                <Route path="/payroll" element={<PayrollPage />} />
                <Route path="/meetings" element={<MeetingsPage />} />
                <Route path="/notifications" element={<NotificationsPage />} />
                <Route path="/polls" element={<PollsPage />} />
                <Route path="/locations" element={<LocationsPage />} />
                <Route path="/categories" element={<CategoriesPage />} />
                <Route path="/tokens" element={<TokensPage />} />
                <Route path="/audit-logs" element={<AuditLogsPage />} />
                <Route path="/logs" element={<AuditLogsPage />} />
                <Route path="/training" element={<TrainingQuizPage />} />
                <Route path="/settings" element={<SettingsPage />} />
              </Route>

              {/* Fallback */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
        </HashRouter>
      </AuthProvider>
    </ThemeProvider>
  );
};
