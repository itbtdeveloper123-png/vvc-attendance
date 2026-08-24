import React from 'react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ReactNode;
  variant?: 'primary' | 'gold' | 'success' | 'warning' | 'danger';
  trend?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  variant = 'primary',
  trend,
}) => {
  const getGradient = () => {
    switch (variant) {
      case 'gold':
        return 'linear-gradient(135deg, rgba(212, 175, 55, 0.15) 0%, rgba(184, 134, 11, 0.05) 100%)';
      case 'success':
        return 'linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%, rgba(5, 150, 105, 0.05) 100%)';
      case 'warning':
        return 'linear-gradient(135deg, rgba(245, 158, 11, 0.15) 0%, rgba(217, 119, 6, 0.05) 100%)';
      case 'danger':
        return 'linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(220, 38, 38, 0.05) 100%)';
      case 'primary':
      default:
        return 'linear-gradient(135deg, rgba(79, 70, 229, 0.15) 0%, rgba(67, 56, 202, 0.05) 100%)';
    }
  };

  const getIconColor = () => {
    switch (variant) {
      case 'gold':
        return '#d4af37';
      case 'success':
        return '#10b981';
      case 'warning':
        return '#f59e0b';
      case 'danger':
        return '#ef4444';
      case 'primary':
      default:
        return '#4f46e5';
    }
  };

  return (
    <div
      className="hrm-card hover-lift"
      style={{
        background: 'var(--surface)',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Background soft glow accent */}
      <div
        style={{
          position: 'absolute',
          top: 0,
          right: 0,
          width: '120px',
          height: '120px',
          background: getGradient(),
          borderRadius: '50%',
          filter: 'blur(20px)',
          pointerEvents: 'none',
        }}
      />

      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)' }}>
            {title}
          </div>
          <div
            style={{
              fontSize: '28px',
              fontWeight: 800,
              color: 'var(--text-primary)',
              marginTop: '4px',
              fontFamily: "'Outfit', 'Kantumruy Pro', sans-serif",
            }}
          >
            {value}
          </div>
        </div>

        <div
          style={{
            width: '46px',
            height: '46px',
            borderRadius: '12px',
            background: getGradient(),
            color: getIconColor(),
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            border: `1px solid ${getIconColor()}33`,
          }}
        >
          {icon}
        </div>
      </div>

      {(subtitle || trend) && (
        <div
          style={{
            marginTop: '14px',
            fontSize: '12px',
            color: 'var(--text-muted)',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          {trend && (
            <span style={{ fontWeight: 700, color: variant === 'danger' ? '#ef4444' : '#10b981' }}>
              {trend}
            </span>
          )}
          {subtitle && <span>{subtitle}</span>}
        </div>
      )}
    </div>
  );
};
