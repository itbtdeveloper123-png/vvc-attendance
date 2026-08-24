import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutGrid,
  Users,
  CalendarCheck,
  FileText,
  Package,
  Send,
  DollarSign,
  Video,
  Bell,
  Vote,
  MapPin,
  KeyRound,
  ShieldAlert,
  GraduationCap,
  Settings,
  ChevronLeft,
  Building2,
  LogOut,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

interface SidebarProps {
  collapsed?: boolean;
  onToggle?: () => void;
  onToggleCollapse?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ collapsed = false, onToggle, onToggleCollapse }) => {
  const toggleHandler = onToggle || onToggleCollapse;
  const { admin, logout } = useAuth();

  const menuItems = [
    { key: 'dashboard', label: 'ផ្ទាំងសង្ខេប', path: '/dashboard', icon: LayoutGrid, badge: null },
    { key: 'users', label: 'គ្រប់គ្រងបុគ្គលិក', path: '/users', icon: Users, badge: null },
    { key: 'reports', label: 'របាយការណ៍វត្តមាន', path: '/reports', icon: CalendarCheck, badge: null },
    { key: 'requests', label: 'គ្រប់គ្រងសំណើរ', path: '/requests', icon: FileText, badge: '3' },
    { key: 'stock', label: 'គ្រប់គ្រងស្តុក & សម្ភារៈ', path: '/stock', icon: Package, badge: null },
    { key: 'gps', label: 'តាមដានការធ្វើដំណើរ & GPS', path: '/gps', icon: Send, badge: null },
    { key: 'payroll', label: 'ប្រាក់បៀវត្ស', path: '/payroll', icon: DollarSign, badge: null },
    { key: 'meetings', label: 'កិច្ចប្រជុំ & AI', path: '/meetings', icon: Video, badge: null },
    { key: 'notifications', label: 'ការជូនដំណឹង', path: '/notifications', icon: Bell, badge: null },
    { key: 'polls', label: 'ការបោះឆ្នោត', path: '/polls', icon: Vote, badge: null },
    { key: 'locations', label: 'ទីតាំង & QR Code', path: '/locations', icon: MapPin, badge: null },
    { key: 'tokens', label: 'Session & សុវត្ថិភាព', path: '/tokens', icon: KeyRound, badge: null },
    { key: 'audit-logs', label: 'កំណត់ត្រាសកម្មភាព & Audit', path: '/audit-logs', icon: ShieldAlert, badge: null },
    { key: 'training', label: 'Quiz & បណ្តុះបណ្តាល', path: '/training', icon: GraduationCap, badge: null },
    { key: 'settings', label: 'ការកំណត់ Panel', path: '/settings', icon: Settings, badge: null },
  ];

  const adminName = admin?.name || 'Super Administrator';
  const adminId = admin?.employee_id || 'ADMIN01';

  return (
    <aside
      style={{
        width: collapsed ? '80px' : '260px',
        minWidth: collapsed ? '80px' : '260px',
        height: '100vh',
        background: '#0c101c',
        borderRight: '1px solid rgba(255, 255, 255, 0.06)',
        display: 'flex',
        flexDirection: 'column',
        position: 'fixed',
        left: 0,
        top: 0,
        zIndex: 100,
        transition: 'width 0.25s ease',
        userSelect: 'none',
      }}
    >
      {/* Brand Header */}
      <div
        style={{
          padding: '20px 18px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', minWidth: 0 }}>
          {/* Gold Logo Icon */}
          <div
            style={{
              width: '38px',
              height: '38px',
              borderRadius: '10px',
              background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#ffffff',
              boxShadow: '0 4px 12px rgba(245, 158, 11, 0.35)',
              flexShrink: 0,
            }}
          >
            <Building2 size={20} />
          </div>

          {!collapsed && (
            <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
              <span
                style={{
                  fontSize: '14px',
                  fontWeight: 800,
                  color: '#ffffff',
                  letterSpacing: '0.5px',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                VVC ATTENDANCE
              </span>
              <span
                style={{
                  fontSize: '11px',
                  color: 'rgba(255, 255, 255, 0.45)',
                  fontWeight: 500,
                }}
              >
                Admin Portal v2.0
              </span>
            </div>
          )}
        </div>

        {toggleHandler && !collapsed && (
          <button
            onClick={toggleHandler}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'rgba(255, 255, 255, 0.4)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '4px',
              borderRadius: '6px',
            }}
          >
            <ChevronLeft size={16} />
          </button>
        )}
      </div>

      {/* Navigation List */}
      <nav
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: '12px 8px',
          display: 'flex',
          flexDirection: 'column',
          gap: '3px',
        }}
      >
        {menuItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.key}
              to={item.path}
              className={({ isActive }) => (isActive ? 'sidebar-link active' : 'sidebar-link')}
              style={({ isActive }) => ({
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                padding: '10px 14px',
                borderRadius: '10px',
                textDecoration: 'none',
                fontSize: '13px',
                fontWeight: isActive ? 700 : 500,
                color: isActive ? '#818cf8' : 'rgba(255, 255, 255, 0.7)',
                background: isActive ? 'rgba(99, 102, 241, 0.15)' : 'transparent',
                transition: 'all 0.18s ease',
                position: 'relative',
              })}
            >
              <Icon size={18} style={{ flexShrink: 0 }} />

              {!collapsed && (
                <span
                  style={{
                    flex: 1,
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {item.label}
                </span>
              )}

              {!collapsed && item.badge && (
                <span
                  style={{
                    background: '#ef4444',
                    color: '#ffffff',
                    fontSize: '10px',
                    fontWeight: 800,
                    minWidth: '18px',
                    height: '18px',
                    padding: '0 5px',
                    borderRadius: '9px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    boxShadow: '0 2px 6px rgba(239, 68, 68, 0.5)',
                  }}
                >
                  {item.badge}
                </span>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* Bottom Profile Info Card */}
      <div
        style={{
          padding: '14px 16px',
          borderTop: '1px solid rgba(255, 255, 255, 0.06)',
          background: 'rgba(0, 0, 0, 0.2)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '10px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0 }}>
          <div
            style={{
              width: '34px',
              height: '34px',
              borderRadius: '50%',
              background: 'linear-gradient(135deg, #6366f1, #4f46e5)',
              color: '#ffffff',
              fontWeight: 800,
              fontSize: '14px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            {adminName.charAt(0).toUpperCase()}
          </div>

          {!collapsed && (
            <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
              <span
                style={{
                  fontSize: '12.5px',
                  fontWeight: 700,
                  color: '#ffffff',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {adminName}
              </span>
              <span
                style={{
                  fontSize: '10.5px',
                  color: 'rgba(255, 255, 255, 0.4)',
                  fontFamily: "'Outfit', monospace",
                }}
              >
                {adminId}
              </span>
            </div>
          )}
        </div>

        {!collapsed && (
          <button
            onClick={logout}
            title="ចាកចេញ (Logout)"
            style={{
              background: 'transparent',
              border: 'none',
              color: '#ef4444',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '6px',
              borderRadius: '8px',
              transition: 'background 0.2s',
            }}
          >
            <LogOut size={16} />
          </button>
        )}
      </div>
    </aside>
  );
};
