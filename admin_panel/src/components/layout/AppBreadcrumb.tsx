import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Home, ChevronRight, Compass, FolderOpen } from 'lucide-react';

const routeTitleMap: Record<string, { module: string; action?: string }> = {
  '/dashboard': { module: 'Dashboard' },
  '/': { module: 'Dashboard' },
  '/users': { module: 'គ្រប់គ្រងបុគ្គលិក', action: 'បញ្ជីអ្នកប្រើប្រាស់' },
  '/reports': { module: 'របាយការណ៍វត្តមាន', action: 'វត្តមានប្រចាំថ្ងៃ' },
  '/attendance': { module: 'របាយការណ៍វត្តមាន', action: 'វត្តមានប្រចាំថ្ងៃ' },
  '/requests': { module: 'គ្រប់គ្រងសំណើរ', action: 'សំណើរទាំងអស់' },
  '/stock': { module: 'គ្រប់គ្រងស្តុក & សម្ភារៈ', action: 'បញ្ជីស្តុកទំនិញ' },
  '/gps': { module: 'តាមដានការធ្វើដំណើរ & GPS', action: 'ផ្ទាំងគ្រប់គ្រងការធ្វើដំណើរ' },
  '/gps-tracking': { module: 'តាមដានការធ្វើដំណើរ & GPS', action: 'ផ្ទាំងគ្រប់គ្រងការធ្វើដំណើរ' },
  '/payroll': { module: 'ប្រាក់បៀវត្ស', action: 'គ្រប់គ្រងប្រាក់ខែបុគ្គលិក' },
  '/meetings': { module: 'កិច្ចប្រជុំ & AI', action: 'បញ្ជីកិច្ចប្រជុំ' },
  '/notifications': { module: 'ការជូនដំណឹង', action: 'ផ្ញើការជូនដំណឹង & Banners' },
  '/polls': { module: 'ការបោះឆ្នោត', action: 'គ្រប់គ្រងការបោះឆ្នោត' },
  '/locations': { module: 'ទីតាំង & QR Code', action: 'បញ្ជីទីតាំង & QR' },
  '/categories': { module: 'គ្រប់គ្រងប្រភេទ', action: 'បញ្ជីប្រភេទមុខទំនិញ' },
  '/tokens': { module: 'Session & សុវត្ថិភាព', action: 'Session សកម្ម' },
  '/training': { module: 'Quiz & បណ្តុះបណ្តាល', action: 'កម្រងសំណួរ Quiz' },
  '/settings': { module: 'ការកំណត់ Panel', action: 'ការកំណត់ទូទៅ' },
};

export const AppBreadcrumb: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();

  const currentPath = location.pathname;
  const isDashboard = currentPath === '/' || currentPath === '/dashboard';
  const info = routeTitleMap[currentPath] || { module: 'ទំព័រ', action: '' };

  const formattedDate = new Intl.DateTimeFormat('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
  }).format(new Date());

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '7px 14px',
        background: 'var(--surface)',
        borderRadius: '12px',
        border: '1px solid var(--border)',
        boxShadow: 'var(--shadow-sm)',
        marginBottom: '20px',
        flexWrap: 'wrap',
        gap: '10px',
      }}
    >
      {/* Left Breadcrumb Links */}
      <nav
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          flexWrap: 'wrap',
        }}
      >
        <button
          onClick={() => navigate('/dashboard')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            padding: '5px 11px',
            borderRadius: '8px',
            background: 'rgba(99, 102, 241, 0.1)',
            border: '1px solid rgba(99, 102, 241, 0.2)',
            color: 'var(--primary)',
            fontSize: '12.5px',
            fontWeight: 700,
            cursor: 'pointer',
            transition: 'all 0.18s ease',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = 'rgba(99, 102, 241, 0.18)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = 'rgba(99, 102, 241, 0.1)';
          }}
        >
          <Home size={13} />
          <span>Dashboard</span>
        </button>

        {!isDashboard && (
          <>
            <ChevronRight size={13} color="var(--text-muted)" />
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
                padding: '4px 8px',
                color: 'var(--text-secondary)',
                fontSize: '12.5px',
                fontWeight: 600,
              }}
            >
              <FolderOpen size={13} />
              <span>{info.module}</span>
            </div>

            {info.action && (
              <>
                <ChevronRight size={13} color="var(--text-muted)" />
                <div
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '5px',
                    padding: '4px 10px',
                    borderRadius: '8px',
                    background: 'rgba(99, 102, 241, 0.08)',
                    border: '1px solid rgba(99, 102, 241, 0.18)',
                    color: 'var(--primary)',
                    fontSize: '12.5px',
                    fontWeight: 700,
                  }}
                >
                  <span>{info.action}</span>
                </div>
              </>
            )}
          </>
        )}
      </nav>

      {/* Right Context Badge */}
      <div
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '4px 10px',
          borderRadius: '8px',
          background: 'var(--surface-alt)',
          color: 'var(--text-secondary)',
          fontSize: '11.5px',
          fontWeight: 600,
          border: '1px solid var(--border)',
        }}
      >
        <Compass size={12} />
        <span>{isDashboard ? 'Workspace Overview' : formattedDate}</span>
      </div>
    </div>
  );
};
