import React, { useState } from 'react';
import {
  Sun,
  Moon,
  Search,
  Bell,
  User,
  LogOut,
  Settings,
  ShieldCheck,
} from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';
import { useAuth } from '../../context/AuthContext';

interface TopHeaderProps {
  title?: string;
  onSearch?: (query: string) => void;
}

export const TopHeader: React.FC<TopHeaderProps> = ({ title, onSearch }) => {
  const { theme, toggleTheme } = useTheme();
  const { admin, logout } = useAuth();
  const [profileOpen, setProfileOpen] = useState(false);
  const [searchVal, setSearchVal] = useState('');

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchVal(e.target.value);
    if (onSearch) onSearch(e.target.value);
  };

  return (
    <header className="admin-top-header">
      {/* Page Title / Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <h1
          style={{
            fontSize: '18px',
            fontWeight: 700,
            color: 'var(--text-primary)',
            letterSpacing: '-0.2px',
          }}
        >
          {title || 'ផ្ទាំងគ្រប់គ្រង (Admin Dashboard)'}
        </h1>
        <span
          className="badge badge-primary"
          style={{ display: 'flex', alignItems: 'center', gap: '4px' }}
        >
          <ShieldCheck size={13} />
          <span>VVC Live</span>
        </span>
      </div>

      {/* Right Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        {/* Search Bar */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            background: 'var(--surface-alt)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            padding: '6px 12px',
            width: '260px',
            gap: '8px',
          }}
        >
          <Search size={16} color="var(--text-muted)" />
          <input
            type="text"
            placeholder="ស្វែងរកបុគ្គលិក, សំណើរ..."
            value={searchVal}
            onChange={handleSearchChange}
            style={{
              background: 'transparent',
              border: 'none',
              outline: 'none',
              fontSize: '13px',
              color: 'var(--text-primary)',
              fontFamily: 'inherit',
              width: '100%',
            }}
          />
        </div>

        {/* Dark/Light Mode Toggle */}
        <button
          onClick={toggleTheme}
          style={{
            width: '38px',
            height: '38px',
            borderRadius: 'var(--radius)',
            background: 'var(--surface-alt)',
            border: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            cursor: 'pointer',
            color: 'var(--text-secondary)',
            transition: 'all 0.2s ease',
          }}
          title={theme === 'dark' ? 'ប្តូរទៅ Light Mode' : 'ប្តូរទៅ Dark Mode'}
        >
          {theme === 'dark' ? <Sun size={18} color="#f59e0b" /> : <Moon size={18} color="#4f46e5" />}
        </button>

        {/* Notifications Icon */}
        <button
          style={{
            width: '38px',
            height: '38px',
            borderRadius: 'var(--radius)',
            background: 'var(--surface-alt)',
            border: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            cursor: 'pointer',
            color: 'var(--text-secondary)',
            position: 'relative',
          }}
          title="ការជូនដំណឹង"
        >
          <Bell size={18} />
          <span
            style={{
              position: 'absolute',
              top: '8px',
              right: '8px',
              width: '7px',
              height: '7px',
              borderRadius: '50%',
              background: '#ef4444',
            }}
          />
        </button>

        {/* Admin Profile Dropdown */}
        <div style={{ position: 'relative' }}>
          <button
            onClick={() => setProfileOpen(!profileOpen)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              background: 'var(--surface-alt)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              padding: '5px 12px 5px 6px',
              cursor: 'pointer',
            }}
          >
            <div
              style={{
                width: '30px',
                height: '30px',
                borderRadius: '8px',
                background: 'linear-gradient(135deg, #4f46e5 0%, #3b82f6 100%)',
                color: '#ffffff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 700,
                fontSize: '12px',
              }}
            >
              {admin?.name?.substring(0, 1) || 'A'}
            </div>
            <div style={{ textAlign: 'left' }}>
              <div style={{ fontSize: '12.5px', fontWeight: 600, color: 'var(--text-primary)' }}>
                {admin?.name || 'Administrator'}
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                {admin?.user_role || 'Super Admin'}
              </div>
            </div>
          </button>

          {profileOpen && (
            <div
              style={{
                position: 'absolute',
                top: '48px',
                right: 0,
                width: '200px',
                background: 'var(--surface)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                boxShadow: 'var(--shadow-lg)',
                padding: '6px',
                zIndex: 100,
                animation: 'scaleUp 0.15s ease',
              }}
            >
              <div style={{ padding: '8px 12px', borderBottom: '1px solid var(--border)' }}>
                <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {admin?.name}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  ID: {admin?.employee_id || 'ADMIN'}
                </div>
              </div>
              <button
                onClick={() => { setProfileOpen(false); window.location.href = '/settings'; }}
                style={{
                  width: '100%',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  padding: '9px 12px',
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-secondary)',
                  fontSize: '13px',
                  cursor: 'pointer',
                  borderRadius: 'var(--radius-sm)',
                  textAlign: 'left',
                }}
              >
                <Settings size={15} />
                <span>ការកំណត់ (Settings)</span>
              </button>
              <button
                onClick={logout}
                style={{
                  width: '100%',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  padding: '9px 12px',
                  background: 'transparent',
                  border: 'none',
                  color: '#ef4444',
                  fontSize: '13px',
                  cursor: 'pointer',
                  borderRadius: 'var(--radius-sm)',
                  textAlign: 'left',
                }}
              >
                <LogOut size={15} />
                <span>ចាកចេញ (Logout)</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
