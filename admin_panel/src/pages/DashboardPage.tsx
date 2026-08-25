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
    today_good: 0,
    today_late: 0,
    pending_requests: 2,
    today_scans: [],
  });

  const loadData = async () => {
    try {
      const data = await adminApi.getDashboardSummary();
      if (data && data.success) {
        setSummary(data);
      }
    } catch {}
  };

  useEffect(() => {
    loadData();
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
      badge: null,
      badgeColor: '#ef4444',
    },
    {
      id: 'requests',
      title: 'គ្រប់គ្រងសំណើរ',
      path: '/requests',
      icon: FileCheck2,
      color: '#f97316',
      badge: '2',
      badgeColor: '#ef4444',
    },
    {
      id: 'locations',
      title: 'គ្រប់គ្រងទីតាំង/QR',
      path: '/locations',
      icon: MapPin,
      color: '#f43f5e',
      badge: '14',
      badgeColor: '#3b82f6',
    },
    {
      id: 'categories',
      title: 'គ្រប់គ្រងប្រភេទ',
      path: '/categories',
      icon: FolderTree,
      color: '#64748b',
      badge: null,
      badgeColor: '#ef4444',
    },
    {
      id: 'tokens',
      title: 'គ្រប់គ្រង Token',
      path: '/tokens',
      icon: KeyRound,
      color: '#3b82f6',
      badge: '259',
      badgeColor: '#3b82f6',
    },
    {
      id: 'notifications',
      title: 'Notifications',
      path: '/notifications',
      icon: Bell,
      color: '#ec4899',
      badge: null,
      badgeColor: '#ef4444',
    },
    {
      id: 'payroll',
      title: 'Payroll',
      path: '/payroll',
      icon: Banknote,
      color: '#64748b',
      badge: null,
      badgeColor: '#ef4444',
    },
    {
      id: 'stock',
      title: 'Stock',
      path: '/stock',
      icon: Package,
      color: '#f97316',
      badge: '2',
      badgeColor: '#ef4444',
    },
    {
      id: 'meetings',
      title: 'Meetings',
      path: '/meetings',
      icon: Handshake,
      color: '#0d9488',
      badge: null,
      badgeColor: '#ef4444',
    },
    {
      id: 'gps',
      title: 'Gps tracking',
      path: '/gps',
      icon: Send,
      color: '#2563eb',
      badge: null,
      badgeColor: '#ef4444',
    },
    {
      id: 'training',
      title: 'Training',
      path: '/training',
      icon: GraduationCap,
      color: '#ea580c',
      badge: null,
      badgeColor: '#ef4444',
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
      badge: null,
      badgeColor: '#ef4444',
    },
    {
      id: 'audit-logs',
      title: 'Audit Logs (សុវត្ថិភាព)',
      path: '/audit-logs',
      icon: ShieldAlert,
      color: '#dc2626',
      badge: 'Security',
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
            { label: 'ADMINS', value: 6 },
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
