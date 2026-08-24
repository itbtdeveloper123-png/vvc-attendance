import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Search,
  RefreshCw,
  Trash2,
  Eye,
  Activity,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Calendar,
  ChevronLeft,
  ChevronRight,
  Database,
  FileSpreadsheet,
  Zap,
} from 'lucide-react';
import { adminApi, AuditLog, AuditLogStats } from '../api/adminApi';
import { useAuth } from '../context/AuthContext';

export const AuditLogsPage: React.FC = () => {
  const { admin } = useAuth();

  // Data States
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [stats, setStats] = useState<AuditLogStats>({
    total_logs: 0,
    today_count: 0,
    warning_count: 0,
    danger_count: 0,
    top_actors: [],
    module_breakdown: [],
  });
  const [loading, setLoading] = useState<boolean>(true);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(25);

  // Filters
  const [search, setSearch] = useState<string>('');
  const [selectedModule, setSelectedModule] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [startDate, setStartDate] = useState<string>('');
  const [endDate, setEndDate] = useState<string>('');
  const [viewMode, setViewMode] = useState<'table' | 'timeline'>('table');
  const [autoRefresh, setAutoRefresh] = useState<boolean>(false);

  // Modals
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);
  const [showClearModal, setShowClearModal] = useState<boolean>(false);
  const [clearDays, setClearDays] = useState<number>(90);
  const [isClearing, setIsClearing] = useState<boolean>(false);

  // Fetch Logs
  const loadLogs = useCallback(
    async (isSilent = false) => {
      if (!isSilent) setLoading(true);
      try {
        const res = await adminApi.fetchAuditLogs({
          search,
          module: selectedModule,
          severity: selectedSeverity,
          start_date: startDate,
          end_date: endDate,
          page,
          limit: pageSize,
        });

        if (res && res.success) {
          setLogs(res.logs || []);
          setTotalCount(res.total || 0);
          if (res.stats) {
            setStats(res.stats);
          }
        }
      } catch (err) {
        console.error('Error fetching audit logs:', err);
      } finally {
        if (!isSilent) setLoading(false);
      }
    },
    [search, selectedModule, selectedSeverity, startDate, endDate, page, pageSize]
  );

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  // Auto Refresh Interval
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      loadLogs(true);
    }, 15000);
    return () => clearInterval(interval);
  }, [autoRefresh, loadLogs]);

  // Date Presets
  const handleDatePreset = (preset: 'today' | '7days' | '30days' | 'all') => {
    const today = new Date();
    const pad = (n: number) => String(n).padStart(2, '0');
    const toYMD = (d: Date) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;

    if (preset === 'today') {
      const tStr = toYMD(today);
      setStartDate(tStr);
      setEndDate(tStr);
    } else if (preset === '7days') {
      const past = new Date();
      past.setDate(today.getDate() - 7);
      setStartDate(toYMD(past));
      setEndDate(toYMD(today));
    } else if (preset === '30days') {
      const past = new Date();
      past.setDate(today.getDate() - 30);
      setStartDate(toYMD(past));
      setEndDate(toYMD(today));
    } else {
      setStartDate('');
      setEndDate('');
    }
    setPage(1);
  };

  // Export to CSV
  const handleExportCSV = () => {
    if (!logs.length) return;
    const headers = ['ID', 'កាលបរិច្ឆេទ', 'អ្នកប្រើប្រាស់', 'តួនាទី', 'សកម្មភាព', 'ផ្នែក', 'គោលដៅ', 'ព័ត៌មានលម្អិត', 'កម្រិត', 'IP Address'];
    const rows = logs.map((l) => [
      l.id,
      `"${l.created_at}"`,
      `"${l.actor_name || ''}"`,
      `"${l.actor_role || ''}"`,
      `"${l.action || ''}"`,
      `"${l.module || ''}"`,
      `"${l.target_name || ''}"`,
      `"${(l.details || '').replace(/"/g, '""')}"`,
      `"${l.severity || 'info'}"`,
      `"${l.ip_address || ''}"`,
    ]);

    const csvContent = '\uFEFF' + [headers.join(','), ...rows.map((e) => e.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `Audit_Logs_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Handle Purge / Clear
  const handleClearLogs = async () => {
    setIsClearing(true);
    try {
      const adminName = admin?.name || 'Super Administrator';
      const res = await adminApi.clearAuditLogs(clearDays, adminName);
      if (res && res.success) {
        setShowClearModal(false);
        loadLogs();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsClearing(false);
    }
  };

  // Helpers
  const formatTimeAgo = (dateStr: string) => {
    try {
      const date = new Date(dateStr.replace(/-/g, '/'));
      const now = new Date();
      const diffMs = now.getTime() - date.getTime();
      const diffMins = Math.floor(diffMs / 60000);
      const diffHours = Math.floor(diffMins / 60);
      const diffDays = Math.floor(diffHours / 24);

      if (diffMins < 1) return 'ទើបតែឥឡូវ';
      if (diffMins < 60) return `${diffMins} នាទីមុន`;
      if (diffHours < 24) return `${diffHours} ម៉ោងមុន`;
      if (diffDays === 1) return 'ម្សិលមិញ';
      return `${diffDays} ថ្ងៃមុន`;
    } catch {
      return dateStr;
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'danger':
      case 'critical':
        return (
          <span
            style={{
              padding: '4px 10px',
              borderRadius: '20px',
              background: 'rgba(239, 68, 68, 0.12)',
              color: '#ef4444',
              border: '1px solid rgba(239, 68, 68, 0.25)',
              fontSize: '12px',
              fontWeight: 700,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px',
            }}
          >
            <XCircle size={13} /> ហានិភ័យ / Danger
          </span>
        );
      case 'warning':
        return (
          <span
            style={{
              padding: '4px 10px',
              borderRadius: '20px',
              background: 'rgba(245, 158, 11, 0.12)',
              color: '#f59e0b',
              border: '1px solid rgba(245, 158, 11, 0.25)',
              fontSize: '12px',
              fontWeight: 700,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px',
            }}
          >
            <AlertTriangle size={13} /> គួរកត់សម្គាល់ / Warning
          </span>
        );
      default:
        return (
          <span
            style={{
              padding: '4px 10px',
              borderRadius: '20px',
              background: 'rgba(16, 185, 129, 0.12)',
              color: '#10b981',
              border: '1px solid rgba(16, 185, 129, 0.25)',
              fontSize: '12px',
              fontWeight: 700,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px',
            }}
          >
            <CheckCircle2 size={13} /> ធម្មតា / Info
          </span>
        );
    }
  };

  const getModuleKhmer = (mod: string) => {
    switch (mod?.toLowerCase()) {
      case 'auth':
        return '🔐 ការចូលប្រើប្រាស់';
      case 'attendance':
        return '📅 វត្តមាន & របាយការណ៍';
      case 'users':
        return '👥 គ្រប់គ្រងបុគ្គលិក';
      case 'payroll':
        return '💰 ប្រាក់បៀវត្ស';
      case 'requests':
        return '📝 សំណើរ & ច្បាប់';
      case 'settings':
        return '⚙️ ការកំណត់ប្រព័ន្ធ';
      case 'locations':
        return '📍 ទីតាំង & QR';
      case 'stock':
        return '📦 ស្តុកសម្ភារៈ';
      case 'audit':
        return '🛡️ សុវត្ថិភាព Audit';
      default:
        return mod || 'ទូទៅ';
    }
  };

  const getActionColor = (action: string) => {
    const act = (action || '').toUpperCase();
    if (act.includes('DELETE') || act.includes('CLEAR') || act.includes('REJECT') || act.includes('REMOVE')) {
      return { bg: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', border: 'rgba(239, 68, 68, 0.2)' };
    }
    if (act.includes('CREATE') || act.includes('ADD') || act.includes('APPROVE') || act.includes('SUCCESS')) {
      return { bg: 'rgba(16, 185, 129, 0.1)', color: '#10b981', border: 'rgba(16, 185, 129, 0.2)' };
    }
    if (act.includes('UPDATE') || act.includes('EDIT') || act.includes('SAVE')) {
      return { bg: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6', border: 'rgba(59, 130, 246, 0.2)' };
    }
    return { bg: 'rgba(139, 92, 246, 0.1)', color: '#8b5cf6', border: 'rgba(139, 92, 246, 0.2)' };
  };

  const totalPages = Math.ceil(totalCount / pageSize) || 1;

  return (
    <div style={{ padding: '24px 28px', maxWidth: '1600px', margin: '0 auto' }}>
      {/* 1. Page Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '16px',
          marginBottom: '24px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div
            style={{
              width: '46px',
              height: '46px',
              borderRadius: '14px',
              background: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#ffffff',
              boxShadow: '0 6px 16px rgba(37, 99, 235, 0.3)',
            }}
          >
            <ShieldAlert size={24} />
          </div>
          <div>
            <h1 style={{ fontSize: '22px', fontWeight: 800, margin: 0, color: 'var(--text-primary)' }}>
              កំណត់ត្រាសកម្មភាព & សុវត្ថិភាព (Audit Logs History)
            </h1>
            <p style={{ margin: '3px 0 0 0', fontSize: '13.5px', color: 'var(--text-secondary)' }}>
              តាមដានរាល់សកម្មភាពកែសម្រួលទិន្នន័យ ការលុប ការបង្កើត និងការចូលប្រើប្រាស់របស់ Admin ទាំងអស់
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {/* Auto Refresh Toggle */}
          <button
            type="button"
            onClick={() => setAutoRefresh(!autoRefresh)}
            className="btn btn-secondary btn-sm"
            style={{
              height: '40px',
              borderRadius: '10px',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              borderColor: autoRefresh ? '#10b981' : undefined,
              color: autoRefresh ? '#10b981' : undefined,
            }}
            title="Auto-refresh រៀងរាល់ ១៥ វិនាទី"
          >
            <Zap size={16} className={autoRefresh ? 'text-emerald-500' : ''} />
            <span>{autoRefresh ? 'Live ON (15s)' : 'Live Auto-refresh'}</span>
          </button>

          {/* Refresh Button */}
          <button
            type="button"
            onClick={() => loadLogs()}
            disabled={loading}
            className="btn btn-secondary btn-sm"
            style={{ height: '40px', borderRadius: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
            <span>ផ្ទុកឡើងវិញ</span>
          </button>

          {/* Export CSV Button */}
          <button
            type="button"
            onClick={handleExportCSV}
            className="btn btn-secondary btn-sm"
            style={{ height: '40px', borderRadius: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <FileSpreadsheet size={16} />
            <span>Export CSV</span>
          </button>

          {/* Clear Logs Button (Admin) */}
          <button
            type="button"
            onClick={() => setShowClearModal(true)}
            className="btn btn-danger btn-sm"
            style={{ height: '40px', borderRadius: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <Trash2 size={16} />
            <span>សម្អាតកំណត់ត្រា</span>
          </button>
        </div>
      </div>

      {/* 2. Top Metric Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '16px',
          marginBottom: '24px',
        }}
      >
        {/* Total Logs */}
        <div className="hrm-card" style={{ padding: '18px 20px', borderRadius: '16px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(59, 130, 246, 0.12)',
              color: '#3b82f6',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Database size={24} />
          </div>
          <div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', fontWeight: 600 }}>កំណត់ត្រាសរុប</div>
            <div style={{ fontSize: '24px', fontWeight: 800, color: 'var(--text-primary)', marginTop: '2px' }}>
              {stats.total_logs?.toLocaleString() || totalCount.toLocaleString()}
            </div>
          </div>
        </div>

        {/* Today's Activity */}
        <div className="hrm-card" style={{ padding: '18px 20px', borderRadius: '16px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(16, 185, 129, 0.12)',
              color: '#10b981',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Activity size={24} />
          </div>
          <div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', fontWeight: 600 }}>សកម្មភាពថ្ងៃនេះ</div>
            <div style={{ fontSize: '24px', fontWeight: 800, color: '#10b981', marginTop: '2px' }}>
              {stats.today_count?.toLocaleString() || 0}
            </div>
          </div>
        </div>

        {/* Warnings */}
        <div className="hrm-card" style={{ padding: '18px 20px', borderRadius: '16px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(245, 158, 11, 0.12)',
              color: '#f59e0b',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <AlertTriangle size={24} />
          </div>
          <div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', fontWeight: 600 }}>ការកែប្រែ & ព្រមាន</div>
            <div style={{ fontSize: '24px', fontWeight: 800, color: '#f59e0b', marginTop: '2px' }}>
              {stats.warning_count?.toLocaleString() || 0}
            </div>
          </div>
        </div>

        {/* Danger / High Risk */}
        <div className="hrm-card" style={{ padding: '18px 20px', borderRadius: '16px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(239, 68, 68, 0.12)',
              color: '#ef4444',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <ShieldAlert size={24} />
          </div>
          <div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', fontWeight: 600 }}>សកម្មភាពលុប / ហានិភ័យ</div>
            <div style={{ fontSize: '24px', fontWeight: 800, color: '#ef4444', marginTop: '2px' }}>
              {stats.danger_count?.toLocaleString() || 0}
            </div>
          </div>
        </div>
      </div>

      {/* 3. Filters & Controls Bar */}
      <div
        className="hrm-card"
        style={{
          padding: '18px 20px',
          borderRadius: '16px',
          marginBottom: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '14px',
        }}
      >
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'center', justifyContent: 'space-between' }}>
          {/* Search Input */}
          <div style={{ position: 'relative', flex: '1 1 260px', minWidth: '240px' }}>
            <Search
              size={17}
              style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }}
            />
            <input
              type="text"
              className="form-control"
              placeholder="ស្វែងរកតាមឈ្មោះ, Action, ព័ត៌មានលម្អិត, IP..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              style={{ paddingLeft: '38px', height: '42px', borderRadius: '10px' }}
            />
          </div>

          {/* Module Filter */}
          <select
            className="form-select"
            value={selectedModule}
            onChange={(e) => {
              setSelectedModule(e.target.value);
              setPage(1);
            }}
            style={{ width: '190px', height: '42px', borderRadius: '10px' }}
          >
            <option value="all">📁 គ្រប់ផ្នែកទាំងអស់</option>
            <option value="attendance">📅 វត្តមាន & របាយការណ៍</option>
            <option value="users">👥 គ្រប់គ្រងបុគ្គលិក</option>
            <option value="payroll">💰 ប្រាក់បៀវត្ស</option>
            <option value="requests">📝 សំណើរ & ច្បាប់</option>
            <option value="settings">⚙️ ការកំណត់ប្រព័ន្ធ</option>
            <option value="locations">📍 ទីតាំង & QR</option>
            <option value="auth">🔐 Login & Auth</option>
            <option value="audit">🛡️ សុវត្ថិភាព Audit</option>
          </select>

          {/* Severity Filter */}
          <select
            className="form-select"
            value={selectedSeverity}
            onChange={(e) => {
              setSelectedSeverity(e.target.value);
              setPage(1);
            }}
            style={{ width: '170px', height: '42px', borderRadius: '10px' }}
          >
            <option value="all">⚡ គ្រប់កម្រិតទាំងអស់</option>
            <option value="info">🟢 ធម្មតា (Info)</option>
            <option value="warning">🟡 គួរកត់សម្គាល់ (Warning)</option>
            <option value="danger">🔴 ហានិភ័យ/លុប (Danger)</option>
          </select>

          {/* View Mode Toggle */}
          <div
            style={{
              display: 'flex',
              background: 'var(--bg-card-hover)',
              padding: '3px',
              borderRadius: '10px',
              border: '1px solid var(--border-color)',
            }}
          >
            <button
              type="button"
              onClick={() => setViewMode('table')}
              style={{
                padding: '6px 14px',
                borderRadius: '8px',
                border: 'none',
                background: viewMode === 'table' ? 'var(--primary-color)' : 'transparent',
                color: viewMode === 'table' ? '#ffffff' : 'var(--text-secondary)',
                fontWeight: 700,
                fontSize: '13px',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              📋 តារាង
            </button>
            <button
              type="button"
              onClick={() => setViewMode('timeline')}
              style={{
                padding: '6px 14px',
                borderRadius: '8px',
                border: 'none',
                background: viewMode === 'timeline' ? 'var(--primary-color)' : 'transparent',
                color: viewMode === 'timeline' ? '#ffffff' : 'var(--text-secondary)',
                fontWeight: 700,
                fontSize: '13px',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              ⏱️ Timeline
            </button>
          </div>
        </div>

        {/* Date Filter & Presets */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', color: 'var(--text-secondary)' }}>
            <Calendar size={15} />
            <span>កាលបរិច្ឆេទ៖</span>
          </div>

          <input
            type="date"
            className="form-control"
            value={startDate}
            onChange={(e) => {
              setStartDate(e.target.value);
              setPage(1);
            }}
            style={{ width: '150px', height: '36px', borderRadius: '8px', fontSize: '13px' }}
          />
          <span style={{ color: 'var(--text-muted)' }}>—</span>
          <input
            type="date"
            className="form-control"
            value={endDate}
            onChange={(e) => {
              setEndDate(e.target.value);
              setPage(1);
            }}
            style={{ width: '150px', height: '36px', borderRadius: '8px', fontSize: '13px' }}
          />

          {/* Quick Date Pills */}
          <div style={{ display: 'flex', gap: '6px', marginLeft: 'auto' }}>
            <button
              type="button"
              onClick={() => handleDatePreset('today')}
              className="btn btn-sm"
              style={{ height: '32px', fontSize: '12px', borderRadius: '6px', background: 'var(--bg-card-hover)', border: '1px solid var(--border-color)' }}
            >
              ថ្ងៃនេះ
            </button>
            <button
              type="button"
              onClick={() => handleDatePreset('7days')}
              className="btn btn-sm"
              style={{ height: '32px', fontSize: '12px', borderRadius: '6px', background: 'var(--bg-card-hover)', border: '1px solid var(--border-color)' }}
            >
              ៧ ថ្ងៃចុងក្រោយ
            </button>
            <button
              type="button"
              onClick={() => handleDatePreset('30days')}
              className="btn btn-sm"
              style={{ height: '32px', fontSize: '12px', borderRadius: '6px', background: 'var(--bg-card-hover)', border: '1px solid var(--border-color)' }}
            >
              ៣០ ថ្ងៃចុងក្រោយ
            </button>
            <button
              type="button"
              onClick={() => handleDatePreset('all')}
              className="btn btn-sm"
              style={{ height: '32px', fontSize: '12px', borderRadius: '6px', background: 'var(--bg-card-hover)', border: '1px solid var(--border-color)' }}
            >
              ទាំងអស់
            </button>
          </div>
        </div>
      </div>

      {/* 4. Content Area: Table View or Timeline View */}
      {viewMode === 'table' ? (
        <div className="hrm-card" style={{ borderRadius: '16px', overflow: 'hidden', padding: 0 }}>
          <div style={{ overflowX: 'auto' }}>
            <table className="table table-hover" style={{ margin: 0, width: '100%', fontSize: '13.5px' }}>
              <thead style={{ background: 'var(--bg-card-hover)', borderBottom: '1px solid var(--border-color)' }}>
                <tr>
                  <th style={{ padding: '14px 16px', width: '170px' }}>ពេលវេលា</th>
                  <th style={{ padding: '14px 16px', width: '180px' }}>អ្នកធ្វើសកម្មភាព</th>
                  <th style={{ padding: '14px 16px', width: '160px' }}>ប្រភេទ & ផ្នែក</th>
                  <th style={{ padding: '14px 16px', width: '140px' }}>គោលដៅ</th>
                  <th style={{ padding: '14px 16px' }}>ព័ត៌មានលម្អិតនៃសកម្មភាព</th>
                  <th style={{ padding: '14px 16px', width: '140px', textAlign: 'center' }}>កម្រិត</th>
                  <th style={{ padding: '14px 16px', width: '140px' }}>IP / ឧបករណ៍</th>
                  <th style={{ padding: '14px 16px', width: '80px', textAlign: 'center' }}>មើល</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan={8} style={{ textAlign: 'center', padding: '60px 20px', color: 'var(--text-muted)' }}>
                      <RefreshCw size={24} className="animate-spin" style={{ margin: '0 auto 10px auto' }} />
                      <div>កំពុងផ្ទុកទិន្នន័យ Audit Logs...</div>
                    </td>
                  </tr>
                ) : logs.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ textAlign: 'center', padding: '60px 20px', color: 'var(--text-muted)' }}>
                      <ShieldCheck size={36} style={{ margin: '0 auto 10px auto', opacity: 0.5 }} />
                      <div style={{ fontSize: '15px', fontWeight: 700 }}>មិនមានកំណត់ត្រាសកម្មភាពឡើយ</div>
                      <div style={{ fontSize: '13px', marginTop: '4px' }}>សូមជ្រើសរើសចន្លោះកាលបរិច្ឆេទ ឬស្វែងរកឡើងវិញ</div>
                    </td>
                  </tr>
                ) : (
                  logs.map((log) => {
                    const actColor = getActionColor(log.action);
                    return (
                      <tr key={log.id} style={{ borderBottom: '1px solid var(--border-color)', transition: 'background 0.15s ease' }}>
                        {/* Time */}
                        <td style={{ padding: '14px 16px', verticalAlign: 'middle' }}>
                          <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
                            {log.created_at?.slice(11, 19) || ''}
                          </div>
                          <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
                            {log.created_at?.slice(0, 10) || ''} ({formatTimeAgo(log.created_at)})
                          </div>
                        </td>

                        {/* Actor */}
                        <td style={{ padding: '14px 16px', verticalAlign: 'middle' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <div
                              style={{
                                width: '32px',
                                height: '32px',
                                borderRadius: '8px',
                                background: 'rgba(59, 130, 246, 0.12)',
                                color: '#3b82f6',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                fontWeight: 800,
                                fontSize: '13px',
                                flexShrink: 0,
                              }}
                            >
                              {(log.actor_name || 'A')[0].toUpperCase()}
                            </div>
                            <div style={{ minWidth: 0 }}>
                              <div style={{ fontWeight: 700, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                {log.actor_name || 'Administrator'}
                              </div>
                              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                                {log.actor_role || 'Admin'} {log.actor_id ? `(${log.actor_id})` : ''}
                              </div>
                            </div>
                          </div>
                        </td>

                        {/* Action & Module */}
                        <td style={{ padding: '14px 16px', verticalAlign: 'middle' }}>
                          <span
                            style={{
                              padding: '3px 8px',
                              borderRadius: '6px',
                              background: actColor.bg,
                              color: actColor.color,
                              border: `1px solid ${actColor.border}`,
                              fontSize: '11.5px',
                              fontWeight: 700,
                              display: 'inline-block',
                              marginBottom: '3px',
                            }}
                          >
                            {log.action}
                          </span>
                          <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                            {getModuleKhmer(log.module)}
                          </div>
                        </td>

                        {/* Target */}
                        <td style={{ padding: '14px 16px', verticalAlign: 'middle' }}>
                          <span
                            style={{
                              padding: '3px 8px',
                              borderRadius: '6px',
                              background: 'var(--bg-card-hover)',
                              color: 'var(--text-primary)',
                              border: '1px solid var(--border-color)',
                              fontSize: '12px',
                              fontWeight: 600,
                            }}
                          >
                            {log.target_name || '—'}
                          </span>
                        </td>

                        {/* Details */}
                        <td style={{ padding: '14px 16px', verticalAlign: 'middle', maxWidth: '340px' }}>
                          <div
                            style={{
                              color: 'var(--text-primary)',
                              whiteSpace: 'nowrap',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              fontWeight: 500,
                            }}
                            title={log.details}
                          >
                            {log.details || '—'}
                          </div>
                        </td>

                        {/* Severity */}
                        <td style={{ padding: '14px 16px', verticalAlign: 'middle', textAlign: 'center' }}>
                          {getSeverityBadge(log.severity)}
                        </td>

                        {/* IP & UA */}
                        <td style={{ padding: '14px 16px', verticalAlign: 'middle' }}>
                          <div style={{ fontSize: '12.5px', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'monospace' }}>
                            {log.ip_address || '127.0.0.1'}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '120px' }}>
                            {log.user_agent || 'Browser'}
                          </div>
                        </td>

                        {/* Action View */}
                        <td style={{ padding: '14px 16px', verticalAlign: 'middle', textAlign: 'center' }}>
                          <button
                            type="button"
                            onClick={() => setSelectedLog(log)}
                            className="btn btn-secondary btn-sm"
                            style={{ width: '32px', height: '32px', padding: 0, borderRadius: '8px' }}
                            title="មើលព័ត៌មានលម្អិត"
                          >
                            <Eye size={15} />
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div
            style={{
              padding: '14px 20px',
              borderTop: '1px solid var(--border-color)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '12px',
            }}
          >
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
              បង្ហាញ <span style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{logs.length}</span> នៃ <span style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{totalCount}</span> កំណត់ត្រាសរុប (ទំព័រ {page} នៃ {totalPages})
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <select
                className="form-select form-select-sm"
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(1);
                }}
                style={{ width: '100px', height: '34px', borderRadius: '8px' }}
              >
                <option value={25}>25 ជួរ</option>
                <option value={50}>50 ជួរ</option>
                <option value={100}>100 ជួរ</option>
              </select>

              <button
                type="button"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="btn btn-secondary btn-sm"
                style={{ width: '34px', height: '34px', padding: 0, borderRadius: '8px' }}
              >
                <ChevronLeft size={16} />
              </button>

              <span style={{ fontSize: '13px', fontWeight: 700, padding: '0 8px' }}>{page}</span>

              <button
                type="button"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="btn btn-secondary btn-sm"
                style={{ width: '34px', height: '34px', padding: 0, borderRadius: '8px' }}
              >
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        </div>
      ) : (
        /* Timeline View */
        <div className="hrm-card" style={{ borderRadius: '16px', padding: '28px 32px' }}>
          {loading ? (
            <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-muted)' }}>
              <RefreshCw size={24} className="animate-spin" style={{ margin: '0 auto 10px auto' }} />
              <div>កំពុងផ្ទុក Timeline...</div>
            </div>
          ) : logs.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-muted)' }}>
              មិនមានទិន្នន័យឡើយ
            </div>
          ) : (
            <div style={{ position: 'relative', paddingLeft: '30px' }}>
              {/* Vertical line */}
              <div
                style={{
                  position: 'absolute',
                  left: '11px',
                  top: '10px',
                  bottom: '10px',
                  width: '2px',
                  background: 'var(--border-color)',
                }}
              />

              {logs.map((log) => {
                const actColor = getActionColor(log.action);
                return (
                  <div key={log.id} style={{ position: 'relative', marginBottom: '28px' }}>
                    {/* Node Dot */}
                    <div
                      style={{
                        position: 'absolute',
                        left: '-30px',
                        top: '4px',
                        width: '24px',
                        height: '24px',
                        borderRadius: '50%',
                        background: actColor.color,
                        border: '3px solid var(--bg-card)',
                        boxShadow: `0 0 0 2px ${actColor.border}`,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: '#fff',
                      }}
                    />

                    {/* Timeline Content Card */}
                    <div
                      style={{
                        background: 'var(--bg-card-hover)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '12px',
                        padding: '16px 20px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px', marginBottom: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span
                            style={{
                              padding: '2px 8px',
                              borderRadius: '6px',
                              background: actColor.bg,
                              color: actColor.color,
                              border: `1px solid ${actColor.border}`,
                              fontSize: '12px',
                              fontWeight: 800,
                            }}
                          >
                            {log.action}
                          </span>
                          <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
                            {log.actor_name || 'Admin'}
                          </span>
                          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                            ({getModuleKhmer(log.module)})
                          </span>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          {getSeverityBadge(log.severity)}
                          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                            {log.created_at} ({formatTimeAgo(log.created_at)})
                          </span>
                        </div>
                      </div>

                      <div style={{ fontSize: '13.5px', color: 'var(--text-primary)', marginBottom: '8px' }}>
                        {log.details || 'មិនមានព័ត៌មានលម្អិត'}
                      </div>

                      <div style={{ display: 'flex', gap: '16px', fontSize: '12px', color: 'var(--text-muted)', borderTop: '1px dashed var(--border-color)', paddingTop: '8px' }}>
                        <span>📍 គោលដៅ: <strong>{log.target_name || '—'}</strong></span>
                        <span>🌐 IP: <strong style={{ fontFamily: 'monospace' }}>{log.ip_address || '127.0.0.1'}</strong></span>
                        <button
                          type="button"
                          onClick={() => setSelectedLog(log)}
                          style={{ marginLeft: 'auto', background: 'none', border: 'none', color: '#3b82f6', cursor: 'pointer', fontWeight: 600 }}
                        >
                          មើលលម្អិត &gt;
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* 5. Detail Modal */}
      {selectedLog && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.65)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 999,
            padding: '20px',
          }}
          onClick={() => setSelectedLog(null)}
        >
          <div
            className="hrm-card"
            style={{
              maxWidth: '680px',
              width: '100%',
              borderRadius: '20px',
              padding: '28px 32px',
              background: 'var(--bg-card)',
              boxShadow: '0 20px 40px rgba(0,0,0,0.3)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <ShieldAlert size={22} color="#3b82f6" />
                <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)' }}>
                  ព័ត៌មានលម្អិតនៃ Audit Log #{selectedLog.id}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedLog(null)}
                className="btn btn-secondary btn-sm"
                style={{ width: '32px', height: '32px', padding: 0, borderRadius: '8px' }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px', marginBottom: '18px' }}>
              <div style={{ background: 'var(--bg-card-hover)', padding: '12px 14px', borderRadius: '10px' }}>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>អ្នកធ្វើសកម្មភាព (Actor)</div>
                <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                  {selectedLog.actor_name} ({selectedLog.actor_role || 'Admin'})
                </div>
              </div>

              <div style={{ background: 'var(--bg-card-hover)', padding: '12px 14px', borderRadius: '10px' }}>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>កាលបរិច្ឆេទ & ម៉ោង</div>
                <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                  {selectedLog.created_at}
                </div>
              </div>

              <div style={{ background: 'var(--bg-card-hover)', padding: '12px 14px', borderRadius: '10px' }}>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Action & Module</div>
                <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                  {selectedLog.action} / {selectedLog.module}
                </div>
              </div>

              <div style={{ background: 'var(--bg-card-hover)', padding: '12px 14px', borderRadius: '10px' }}>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>គោលដៅ (Target)</div>
                <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                  {selectedLog.target_name || '—'}
                </div>
              </div>
            </div>

            {/* Details Box */}
            <div style={{ marginBottom: '18px' }}>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '6px' }}>
                ខ្លឹមសារព័ត៌មានលម្អិត (Details Payload)៖
              </div>
              <div
                style={{
                  background: '#090d16',
                  color: '#38bdf8',
                  padding: '14px 16px',
                  borderRadius: '10px',
                  fontSize: '13px',
                  fontFamily: 'monospace',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                  maxHeight: '180px',
                  overflowY: 'auto',
                }}
              >
                {selectedLog.details || 'មិនមានព័ត៌មានលម្អិត'}
              </div>
            </div>

            {/* IP & User Agent */}
            <div style={{ background: 'var(--bg-card-hover)', padding: '12px 14px', borderRadius: '10px', marginBottom: '22px' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>IP Address & Browser User-Agent</div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px', fontFamily: 'monospace' }}>
                {selectedLog.ip_address}
              </div>
              <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', marginTop: '2px', wordBreak: 'break-all' }}>
                {selectedLog.user_agent}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                type="button"
                onClick={() => setSelectedLog(null)}
                className="btn btn-primary"
                style={{ borderRadius: '10px', padding: '0 22px', height: '40px' }}
              >
                បិទផ្ទាំង
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 6. Clear Logs Confirmation Modal */}
      {showClearModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.65)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 999,
            padding: '20px',
          }}
          onClick={() => setShowClearModal(false)}
        >
          <div
            className="hrm-card"
            style={{
              maxWidth: '480px',
              width: '100%',
              borderRadius: '20px',
              padding: '28px 32px',
              background: 'var(--bg-card)',
              boxShadow: '0 20px 40px rgba(0,0,0,0.3)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ textAlign: 'center', marginBottom: '18px' }}>
              <div
                style={{
                  width: '56px',
                  height: '56px',
                  borderRadius: '50%',
                  background: 'rgba(239, 68, 68, 0.12)',
                  color: '#ef4444',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  margin: '0 auto 12px auto',
                }}
              >
                <Trash2 size={28} />
              </div>
              <h3 style={{ margin: '0 0 6px 0', fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)' }}>
                សម្អាតកំណត់ត្រា Audit Logs
              </h3>
              <p style={{ margin: 0, fontSize: '13.5px', color: 'var(--text-secondary)' }}>
                តើលោកអ្នកចង់សម្អាត ឬលុបកំណត់ត្រាចាស់ៗចោលមែនទេ?
              </p>
            </div>

            <div style={{ marginBottom: '22px' }}>
              <label style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', display: 'block', marginBottom: '6px' }}>
                ជម្រើសរយៈពេលសម្អាត៖
              </label>
              <select
                className="form-select"
                value={clearDays}
                onChange={(e) => setClearDays(Number(e.target.value))}
                style={{ height: '42px', borderRadius: '10px' }}
              >
                <option value={30}>លុបកំណត់ត្រាចាស់ជាង ៣០ ថ្ងៃ</option>
                <option value={90}>លុបកំណត់ត្រាចាស់ជាង ៩០ ថ្ងៃ (ណែនាំ)</option>
                <option value={180}>លុបកំណត់ត្រាចាស់ជាង ១៨០ ថ្ងៃ</option>
                <option value={365}>លុបកំណត់ត្រាចាស់ជាង ១ ឆ្នាំ</option>
                <option value={0}>⚠️ លុបកំណត់ត្រាទាំងអស់ (Clear All Logs)</option>
              </select>
            </div>

            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <button
                type="button"
                onClick={() => setShowClearModal(false)}
                className="btn btn-secondary"
                style={{ borderRadius: '10px', height: '40px', padding: '0 18px' }}
              >
                បោះបង់
              </button>
              <button
                type="button"
                onClick={handleClearLogs}
                disabled={isClearing}
                className="btn btn-danger"
                style={{ borderRadius: '10px', height: '40px', padding: '0 20px', display: 'flex', alignItems: 'center', gap: '6px' }}
              >
                <Trash2 size={16} />
                <span>{isClearing ? 'កំពុងសម្អាត...' : 'យល់ព្រមសម្អាត'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
