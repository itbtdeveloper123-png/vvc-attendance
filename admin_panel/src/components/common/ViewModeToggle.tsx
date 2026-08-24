import React from 'react';
import { LayoutGrid, Table as TableIcon } from 'lucide-react';

export type ViewMode = 'grid' | 'table';

interface ViewModeToggleProps {
  mode: ViewMode;
  onChange: (mode: ViewMode) => void;
  gridLabel?: string;
  tableLabel?: string;
}

export const ViewModeToggle: React.FC<ViewModeToggleProps> = ({
  mode,
  onChange,
  gridLabel = 'ទម្រង់ក្រឡា (Grid View)',
  tableLabel = 'ទម្រង់តារាង (Table View)',
}) => {
  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        background: 'var(--surface-subtle, #f1f5f9)',
        padding: '3px',
        borderRadius: '12px',
        border: '1px solid var(--border, #e2e8f0)',
        gap: '2px',
      }}
    >
      <button
        type="button"
        onClick={() => onChange('grid')}
        title={gridLabel}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: '34px',
          height: '32px',
          borderRadius: '9px',
          border: 'none',
          cursor: 'pointer',
          transition: 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
          background: mode === 'grid' ? 'var(--surface, #ffffff)' : 'transparent',
          color: mode === 'grid' ? 'var(--primary, #6366f1)' : 'var(--text-muted, #94a3b8)',
          boxShadow: mode === 'grid' ? '0 2px 8px rgba(0, 0, 0, 0.08)' : 'none',
        }}
      >
        <LayoutGrid size={17} strokeWidth={mode === 'grid' ? 2.5 : 2} />
      </button>

      <button
        type="button"
        onClick={() => onChange('table')}
        title={tableLabel}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: '34px',
          height: '32px',
          borderRadius: '9px',
          border: 'none',
          cursor: 'pointer',
          transition: 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
          background: mode === 'table' ? 'var(--surface, #ffffff)' : 'transparent',
          color: mode === 'table' ? 'var(--primary, #6366f1)' : 'var(--text-muted, #94a3b8)',
          boxShadow: mode === 'table' ? '0 2px 8px rgba(0, 0, 0, 0.08)' : 'none',
        }}
      >
        <TableIcon size={17} strokeWidth={mode === 'table' ? 2.5 : 2} />
      </button>
    </div>
  );
};
