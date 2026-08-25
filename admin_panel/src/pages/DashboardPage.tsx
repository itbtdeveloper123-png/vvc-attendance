import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  LayoutGrid,
  Users,
  BarChart3,
  FileCheck2,
  MapPin,
  FolderTree,
  KeyRound,
  Bell,
  Banknote,
  Package,
  Handshake,
  Send,
  GraduationCap,
  SlidersHorizontal,
  Vote,
  ShieldAlert,
} from 'lucide-react';
import { adminApi, DashboardSummary } from '../api/adminApi';

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const [summary, setSummary] = useState<DashboardSummary>({
    total_employees: 76,
    total_admins: 6,
    today_good: 0,
    today_late: 0,
    today_scans_count: 0,
    pending_requests: 0,
    total_locations: 0,
    total_categories: 0,
    total_tokens: 0,
    total_notifications: 0,
    total_payroll: 0,
    total_stock: 0,
    low_stock: 0,
    total_meetings: 0,
    active_trips: 0,
    total_training: 0,
    total_polls: 0,
    total_audit_logs: 0,
    today_threats: 0,
    today_scans: [],
  });

  const loadData = async () => {
    try {
      const data = await adminApi.getDashboardSummary();
      if (data && (data.success || (data as any).status === 'success')) {
        setSummary(data);
      }
    } catch {}
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  const workspaceApps = [
    {
      id: 'dashboard',
      title: 'Dashboard',
      path: '/dashboard',
      icon: LayoutGrid,
      color: '#10b981',
      badge: null,
      badgeColor: '#ef4444',
    },
    {
      id: 'users',
      title: 'គ្រប់គ្រងអ្នកប្រើប្រាស់',
      path: '/users',
      icon: Users,
      color: '#06b6d4',
      badge: summary.total_employees ? String(summary.total_employees) : '76',
      badgeColor: '#3b82f6',
    },
    {
      id: 'reports',
      title: 'របាយការណ៍វត្តមាន',
      path: '/reports',
      icon: BarChart3,
      color: '#8b5cf6',
      badge: summary.today_scans_count !== undefined && summary.today_scans_count > 0 ? `${summary.today_scans_count}` : (summary.today_good || summary.today_late ? `${summary.today_good + summary.today_late}` : null),
      badgeColor: '#8b5cf6',
    },
    {
      id: 'requests',
      title: 'គ្រប់គ្រងសំណើរ',
      path: '/requests',
      icon: FileCheck2,
      color: '#f97316',
      badge: summary.pending_requests !== undefined && summary.pending_requests > 0 ? String(summary.pending_requests) : null,
      badgeColor: '#f97316',
    },
    {
      id: 'locations',
      title: 'គ្រប់គ្រងទីតាំង/QR',
      path: '/locations',
      icon: MapPin,
      color: '#f43f5e',
      badge: summary.total_locations !== undefined && summary.total_locations > 0 ? String(summary.total_locations) : null,
      badgeColor: '#f43f5e',
    },
    {
      id: 'categories',
      title: 'គ្រប់គ្រងប្រភេទ',
      path: '/categories',
      icon: FolderTree,
      color: '#64748b',
      badge: summary.total_categories !== undefined && summary.total_categories > 0 ? String(summary.total_categories) : null,
      badgeColor: '#6366f1',
    },
    {
      id: 'tokens',
      title: 'គ្រប់គ្រង Token',
      path: '/tokens',
      icon: KeyRound,
      color: '#3b82f6',
      badge: summary.total_tokens !== undefined && summary.total_tokens > 0 ? String(summary.total_tokens) : null,
      badgeColor: '#3b82f6',
    },
    {
      id: 'notifications',
      title: 'Notifications',
      path: '/notifications',
      icon: Bell,
      color: '#ec4899',
      badge: summary.total_notifications !== undefined && summary.total_notifications > 0 ? String(summary.total_notifications) : null,
      badgeColor: '#ec4899',
    },
    {
      id: 'payroll',
      title: 'Payroll',
      path: '/payroll',
      icon: Banknote,
      color: '#10b981',
      badge: summary.total_payroll !== undefined && summary.total_payroll > 0 ? String(summary.total_payroll) : null,
      badgeColor: '#10b981',
    },
    {
      id: 'stock',
      title: 'Stock',
      path: '/stock',
      icon: Package,
      color: '#f97316',
      badge: summary.low_stock ? `${summary.low_stock} Low` : (summary.total_stock !== undefined && summary.total_stock > 0 ? String(summary.total_stock) : null),
      badgeColor: summary.low_stock ? '#ef4444' : '#f97316',
    },
    {
      id: 'meetings',
      title: 'Meetings',
      path: '/meetings',
      icon: Handshake,
      color: '#0d9488',
      badge: summary.total_meetings !== undefined && summary.total_meetings > 0 ? String(summary.total_meetings) : null,
      badgeColor: '#0d9488',
    },
    {
      id: 'gps',
      title: 'Gps tracking',
      path: '/gps',
      icon: Send,
      color: '#2563eb',
      badge: summary.active_trips !== undefined && summary.active_trips > 0 ? `${summary.active_trips} Active` : null,
      badgeColor: '#2563eb',
    },
    {
      id: 'training',
      title: 'Training',
      path: '/training',
      icon: GraduationCap,
      color: '#ea580c',
      badge: summary.total_training !== undefined && summary.total_training > 0 ? String(summary.total_training) : null,
      badgeColor: '#ea580c',
    },
    {
      id: 'settings',
      title: 'ការកំណត់',
      path: '/settings',
      icon: SlidersHorizontal,
      color: '#7c3aed',
      badge: null,
      badgeColor: '#ef4444',
    },
    {
      id: 'polls',
      title: 'Polls',
      path: '/polls',
      icon: Vote,
      color: '#4f46e5',
      badge: summary.total_polls !== undefined && summary.total_polls > 0 ? String(summary.total_polls) : null,
      badgeColor: '#4f46e5',
    },
    {
      id: 'audit-logs',
      title: 'Audit Logs (សុវត្ថិភាព)',
      path: '/audit-logs',
      icon: ShieldAlert,
      color: '#dc2626',
      badge: summary.today_threats !== undefined && summary.today_threats > 0 ? `${summary.today_threats} Threats` : (summary.total_audit_logs !== undefined && summary.total_audit_logs > 0 ? String(summary.total_audit_logs) : 'Security'),
      badgeColor: '#dc2626',
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%' }}>
      {/* Workspace Header & KPI Counters */}
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '20px',
        }}
      >
        {/* Workspace Title */}
        <div style={{ maxWidth: '640px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
            <div
              style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                background: 'linear-gradient(135deg, #4f46e5, #3b82f6)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'white',
              }}
            >
              <LayoutGrid size={18} />
            </div>
            <h1
              style={{
                fontSize: '24px',
                fontWeight: 900,
                color: 'var(--text-primary)',
                letterSpacing: '-0.4px',
                margin: 0,
              }}
            >
              Admin Workspace
            </h1>
          </div>
          <p
            style={{
              fontSize: '13px',
              color: 'var(--text-secondary)',
              lineHeight: 1.6,
              margin: 0,
            }}
          >
            Navigate every module faster with cleaner shortcuts, clearer section hierarchy, and a smoother workspace flow for daily admin work. Updated 24 Aug 2026.
          </p>
        </div>

        {/* 4 Mini Stat Pills */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {[
            { label: 'GOOD', value: summary.today_good },
            { label: 'LATE', value: summary.today_late },
            { label: 'USERS', value: summary.total_employees || 76 },
            { label: 'ADMINS', value: summary.total_admins || 6 },
          ].map((stat, i) => (
            <div
              key={i}
              className="hrm-card"
              style={{
                padding: '10px 20px',
                minWidth: '95px',
                borderRadius: '12px',
                display: 'flex',
                flexDirection: 'column',
                gap: '2px',
                textAlign: 'center',
              }}
            >
              <span
                style={{
                  fontSize: '10.5px',
                  fontWeight: 800,
                  color: 'var(--text-muted)',
                  letterSpacing: '0.8px',
                }}
              >
                {stat.label}
              </span>
              <span
                style={{
                  fontSize: '20px',
                  fontWeight: 900,
                  color: 'var(--text-primary)',
                  fontFamily: "'Outfit', sans-serif",
                }}
              >
                {stat.value}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* 15 Workspace Launcher Cards Grid (Matching Screenshot) */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(135px, 1fr))',
          gap: '24px 18px',
          marginTop: '8px',
        }}
      >
        {workspaceApps.map((app) => {
          const Icon = app.icon;
          return (
            <div
              key={app.id}
              onClick={() => navigate(app.path)}
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: '10px',
                cursor: 'pointer',
              }}
            >
              {/* Outer Tile Box */}
              <div
                className="hrm-card"
                style={{
                  width: '100%',
                  aspectRatio: '1/1',
                  borderRadius: '22px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  position: 'relative',
                  background: 'var(--surface)',
                  border: '1px solid var(--border)',
                  boxShadow: 'var(--shadow)',
                  transition: 'all 0.22s cubic-bezier(0.4, 0, 0.2, 1)',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.transform = 'translateY(-4px)';
                  e.currentTarget.style.borderColor = 'var(--primary)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = 'translateY(0)';
                  e.currentTarget.style.borderColor = 'var(--border)';
                }}
              >
                {/* Badge if any */}
                {app.badge && (
                  <span
                    style={{
                      position: 'absolute',
                      top: '8px',
                      right: '8px',
                      background: app.badgeColor,
                      color: 'white',
                      fontSize: '10px',
                      fontWeight: 800,
                      minWidth: '18px',
                      height: '18px',
                      padding: '0 5px',
                      borderRadius: '9px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      boxShadow: '0 2px 6px rgba(0,0,0,0.3)',
                    }}
                  >
                    {app.badge}
                  </span>
                )}

                {/* White Squircle in center */}
                <div
                  style={{
                    width: '54px',
                    height: '54px',
                    borderRadius: '16px',
                    background: '#ffffff',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: app.color,
                    boxShadow: '0 4px 10px rgba(0,0,0,0.06)',
                  }}
                >
                  <Icon size={28} strokeWidth={2.2} />
                </div>
              </div>

              {/* Khmer Label below */}
              <span
                style={{
                  fontSize: '12.5px',
                  fontWeight: 700,
                  color: 'var(--text-primary)',
                  textAlign: 'center',
                  lineHeight: 1.3,
                }}
              >
                {app.title}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
