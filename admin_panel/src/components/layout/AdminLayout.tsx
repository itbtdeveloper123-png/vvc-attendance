import React from 'react';
import { Outlet, Navigate } from 'react-router-dom';
import { TopHeader } from './TopHeader';
import { AppBreadcrumb } from './AppBreadcrumb';
import { useAuth } from '../../context/AuthContext';

export const AdminLayout: React.FC = () => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div
        style={{
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: 'var(--background)',
          color: 'var(--primary)',
        }}
      >
        <div style={{ textAlign: 'center' }}>
          <div
            style={{
              width: '40px',
              height: '40px',
              border: '3px solid var(--border)',
              borderTopColor: 'var(--primary)',
              borderRadius: '50%',
              animation: 'spin 0.8s linear infinite',
              margin: '0 auto 16px',
            }}
          />
          <div style={{ fontSize: '14px', fontWeight: 600 }}>កំពុងដំណើរការ...</div>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        background: 'var(--background)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        padding: '16px 24px 48px',
        position: 'relative',
        overflowX: 'hidden',
      }}
    >
      {/* Background Ambient Glow Orbs */}
      <div
        style={{
          position: 'absolute',
          top: '-80px',
          left: '-100px',
          width: '500px',
          height: '500px',
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(99, 102, 241, 0.07) 0%, transparent 70%)',
          pointerEvents: 'none',
          zIndex: 0,
        }}
      />
      <div
        style={{
          position: 'absolute',
          top: '40px',
          right: '-100px',
          width: '550px',
          height: '550px',
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(236, 72, 153, 0.05) 0%, transparent 70%)',
          pointerEvents: 'none',
          zIndex: 0,
        }}
      />

      {/* Centered Main Container (Max Width 1240px) */}
      <div
        style={{
          width: '100%',
          maxWidth: '1240px',
          display: 'flex',
          flexDirection: 'column',
          position: 'relative',
          zIndex: 1,
        }}
      >
        {/* Top Header Bar */}
        <TopHeader />

        {/* Dynamic App Breadcrumb with Dashboard Return Link */}
        <AppBreadcrumb />

        {/* Main Content Body */}
        <main style={{ width: '100%' }}>
          <Outlet />
        </main>
      </div>
    </div>
  );
};
