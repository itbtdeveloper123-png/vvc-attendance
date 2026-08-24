import React from 'react';
import {
  Sun,
  Moon,
  LogOut,
} from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';
import { useAuth } from '../../context/AuthContext';

interface TopHeaderProps {
  title?: string;
}

export const TopHeader: React.FC<TopHeaderProps> = ({ title }) => {
  const { theme, toggleTheme } = useTheme();
  const { admin, logout } = useAuth();

  const formattedDate = new Intl.DateTimeFormat('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
  }).format(new Date());

  const adminName = admin?.name || 'Vvc';

  return (
    <header
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '12px 20px',
        background: 'var(--surface)',
        borderRadius: '16px',
        border: '1px solid var(--border)',
        boxShadow: '0 8px 24px -16px rgba(15, 23, 42, 0.1)',
        marginBottom: '16px',
      }}
    >
      {/* Title & Subtext */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
        <h1
          style={{
            fontSize: '18px',
            fontWeight: 800,
            color: 'var(--text-primary)',
            letterSpacing: '-0.3px',
            margin: 0,
          }}
        >
          {title || 'VVC Admin Dashboard'}
        </h1>
        <span
          style={{
            fontSize: '12px',
            fontWeight: 600,
            color: 'var(--text-muted)',
          }}
        >
          {formattedDate} | {adminName}
        </span>
      </div>

      {/* Right Actions: Theme Toggle & Logout */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <button
          onClick={toggleTheme}
          className="btn btn-secondary btn-sm"
          style={{
            width: '38px',
            height: '38px',
            padding: 0,
            borderRadius: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
          title={theme === 'dark' ? 'ប្តូរទៅ Light Mode' : 'ប្តូរទៅ Dark Mode'}
        >
          {theme === 'dark' ? <Sun size={17} color="#fbbf24" /> : <Moon size={17} />}
        </button>

        <button
          onClick={logout}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '8px 16px',
            borderRadius: '12px',
            background: 'var(--surface)',
            color: '#ef4444',
            border: '1px solid #fecaca',
            fontSize: '13px',
            fontWeight: 700,
            cursor: 'pointer',
            transition: 'all 0.2s ease',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = '#ef4444';
            e.currentTarget.style.color = '#ffffff';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = 'var(--surface)';
            e.currentTarget.style.color = '#ef4444';
          }}
        >
          <LogOut size={15} />
          <span>ចេញ ({adminName})</span>
        </button>
      </div>
    </header>
  );
};
