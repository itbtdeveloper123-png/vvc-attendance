import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { AuthProvider } from './context/AuthContext';
import { AdminLayout } from './components/layout/AdminLayout';

import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { UsersPage } from './pages/UsersPage';
import { AttendanceReportsPage } from './pages/AttendanceReportsPage';
import { RequestsPage } from './pages/RequestsPage';
import { StockPage } from './pages/StockPage';
import { GpsTrackingPage } from './pages/GpsTrackingPage';
import { PayrollPage } from './pages/PayrollPage';
import { MeetingsPage } from './pages/MeetingsPage';
import { NotificationsPage } from './pages/NotificationsPage';
import { PollsPage } from './pages/PollsPage';
import { LocationsPage } from './pages/LocationsPage';
import { CategoriesPage } from './pages/CategoriesPage';
import { TokensPage } from './pages/TokensPage';
import { TrainingQuizPage } from './pages/TrainingQuizPage';
import { SettingsPage } from './pages/SettingsPage';

export const App: React.FC = () => {
  return (
    <ThemeProvider>
      <AuthProvider>
        <BrowserRouter>
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
              <Route path="/training" element={<TrainingQuizPage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Route>

            {/* Fallback */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  );
};
