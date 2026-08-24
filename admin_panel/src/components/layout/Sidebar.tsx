import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Users,
  CalendarCheck,
  FileText,
  DollarSign,
  Video,
  Bell,
  MapPin,
  Settings,
  ChevronLeft,
  ChevronRight,
  LogOut,
  Building2,
  LucideIcon,
  Package,
  Navigation,
  Vote,
  KeyRound,
  GraduationCap,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

interface MenuItem {
  path: string;
  name: string;
  nameEn: string;
  icon: LucideIcon;
  badge?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ collapsed, onToggle }) => {
  const { logout, admin } = useAuth();

  const menuItems: MenuItem[] = [
    {
      path: '/dashboard',
      name: 'ផ្ទាំងសង្ខេប',
      nameEn: 'Dashboard',
      icon: LayoutDashboard,
    },
    {
      path: '/users',
      name: 'គ្រប់គ្រងបុគ្គលិក',
      nameEn: 'Employees',
      icon: Users,
    },
    {
      path: '/attendance',
      name: 'របាយការណ៍វត្តមាន',
      nameEn: 'Attendance',
      icon: CalendarCheck,
    },
    {
      path: '/requests',
      name: 'គ្រប់គ្រងសំណើរ',
      nameEn: 'Requests',
      icon: FileText,
      badge: 3,
    },
    {
      path: '/stock',
      name: 'គ្រប់គ្រងស្តុក & សម្ភារៈ',
      nameEn: 'Stock Control',
      icon: Package,
    },
    {
      path: '/gps-tracking',
      name: 'តាមដានការធ្វើដំណើរ & GPS',
      nameEn: 'GPS Tracking',
      icon: Navigation,
    },
    {
      path: '/payroll',
      name: 'ប្រាក់បៀវត្ស',
      nameEn: 'Payroll',
      icon: DollarSign,
    },
    {
      path: '/meetings',
      name: 'កិច្ចប្រជុំ & AI',
      nameEn: 'Meetings',
      icon: Video,
    },
    {
      path: '/notifications',
      name: 'ការជូនដំណឹង',
      nameEn: 'Notifications',
      icon: Bell,
    },
    {
      path: '/polls',
      name: 'ការបោះឆ្នោត',
      nameEn: 'Polls',
      icon: Vote,
    },
    {
      path: '/locations',
      name: 'ទីតាំង & QR Code',
      nameEn: 'Locations & QR',
      icon: MapPin,
    },
    {
      path: '/tokens',
      name: 'Session & សុវត្ថិភាព',
      nameEn: 'Security & Sessions',
      icon: KeyRound,
    },
    {
      path: '/training',
      name: 'Quiz & បណ្តុះបណ្តាល',
      nameEn: 'Training & Quiz',
      icon: GraduationCap,
    },
    {
      path: '/settings',
      name: 'ការកំណត់ Panel',
      nameEn: 'Settings',
      icon: Settings,
    },
  ];

  return (
    <aside className={`admin-sidebar ${collapsed ? 'collapsed' : ''}`}>
      {/* Brand Header */}
      <div
        style={{
          height: '70px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: collapsed ? 'center' : 'space-between',
          padding: '0 20px',
          borderBottom: '1px solid var(--sidebar-border)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', overflow: 'hidden' }}>
          <div
            style={{
              width: '40px',
              height: '40px',
              borderRadius: '10px',
              background: 'linear-gradient(135deg, #d4af37 0%, #b8860b 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
              boxShadow: '0 2px 10px rgba(212, 175, 55, 0.3)',
            }}
          >
            <Building2 size={22} color="#1a1500" />
          </div>
          {!collapsed && (
            <div style={{ whiteSpace: 'nowrap' }}>
              <div style={{ fontWeight: 800, fontSize: '15px', color: '#ffffff', letterSpacing: '0.5px' }}>
                VVC ATTENDANCE
              </div>
              <div style={{ fontSize: '11px', color: '#94a3b8' }}>Admin Portal v2.0</div>
            </div>
          )}
        </div>

        {!collapsed && (
          <button
            onClick={onToggle}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#94a3b8',
              cursor: 'pointer',
              padding: '6px',
              borderRadius: '6px',
            }}
            title="បង្រួម Sidebar"
          >
            <ChevronLeft size={18} />
          </button>
        )}
      </div>

      {/* Navigation List */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 12px' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          {menuItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                style={({ isActive }) => ({
                  display: 'flex',
                  alignItems: 'center',
                  gap: '14px',
                  padding: collapsed ? '12px 0' : '12px 16px',
                  justifyContent: collapsed ? 'center' : 'flex-start',
                  borderRadius: '10px',
                  textDecoration: 'none',
                  fontSize: '13.5px',
                  fontWeight: isActive ? 600 : 500,
                  color: isActive ? '#ffffff' : '#94a3b8',
                  background: isActive
                    ? 'linear-gradient(90deg, rgba(79, 70, 229, 0.25) 0%, rgba(79, 70, 229, 0.1) 100%)'
                    : 'transparent',
                  borderLeft: isActive ? '3px solid #4f46e5' : '3px solid transparent',
                  transition: 'all 0.2s ease',
                })}
              >
                <Icon size={20} />
                {!collapsed && (
                  <span style={{ flex: 1, whiteSpace: 'nowrap' }}>{item.name}</span>
                )}
                {!collapsed && item.badge && (
                  <span
                    style={{
                      background: '#ef4444',
                      color: '#ffffff',
                      fontSize: '11px',
                      fontWeight: 700,
                      padding: '2px 7px',
                      borderRadius: '10px',
                    }}
                  >
                    {item.badge}
                  </span>
                )}
              </NavLink>
            );
          })}
        </div>
      </div>

      {/* Footer / User & Logout */}
      <div
        style={{
          padding: '16px 12px',
          borderTop: '1px solid var(--sidebar-border)',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
        }}
      >
        {collapsed ? (
          <button
            onClick={onToggle}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#94a3b8',
              cursor: 'pointer',
              padding: '10px 0',
              display: 'flex',
              justifyContent: 'center',
            }}
            title="ពង្រីក Sidebar"
          >
            <ChevronRight size={20} />
          </button>
        ) : (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '8px 12px',
              borderRadius: '10px',
              background: 'rgba(255, 255, 255, 0.04)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', overflow: 'hidden' }}>
              <div
                style={{
                  width: '34px',
                  height: '34px',
                  borderRadius: '50%',
                  background: '#4f46e5',
                  color: '#ffffff',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontWeight: 700,
                  fontSize: '13px',
                }}
              >
                {admin?.name?.substring(0, 1) || 'A'}
              </div>
              <div style={{ whiteSpace: 'nowrap', overflow: 'hidden' }}>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#ffffff' }}>
                  {admin?.name || 'Administrator'}
                </div>
                <div style={{ fontSize: '11px', color: '#94a3b8' }}>
                  {admin?.employee_id || 'Super Admin'}
                </div>
              </div>
            </div>
            <button
              onClick={logout}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#ef4444',
                cursor: 'pointer',
                padding: '6px',
                borderRadius: '6px',
              }}
              title="ចាកចេញ (Logout)"
            >
              <LogOut size={18} />
            </button>
          </div>
        )}
      </div>
    </aside>
  );
};
