import React, { useState, useEffect } from 'react';
import {
  Calendar,
  Download,
  Search,
  Filter,
  CheckCircle2,
  Clock,
  XCircle,
  MapPin,
  RefreshCw,
  FileSpreadsheet,
  AlertTriangle,
  FileText,
  Users,
  Building2,
  Eye,
  Camera,
  Layers,
  ChevronRight,
  TrendingUp,
} from 'lucide-react';
import { StatusBadge } from '../components/common/StatusBadge';
import { ViewModeToggle, ViewMode } from '../components/common/ViewModeToggle';
import { Modal } from '../components/common/Modal';
import { adminApi, AttendanceRecord } from '../api/adminApi';

export const AttendanceReportsPage: React.FC = () => {
  const [activeReportTab, setActiveReportTab] = useState<'daily' | 'late' | 'forgotten' | 'leave_deo' | 'combined'>('daily');
  const [viewMode, setViewMode] = useState<ViewMode>('table');

  const [records, setRecords] = useState<AttendanceRecord[]>([]);
  const [availableDates, setAvailableDates] = useState<string[]>([]);
  const [dateFilter, setDateFilter] = useState(new Date().toISOString().split('T')[0]);
  const [deptFilter, setDeptFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState({ total: 0, good: 0, late: 0 });

  // Photo Preview Modal
  const [previewPhoto, setPreviewPhoto] = useState<string | null>(null);

  const loadAttendance = async () => {
    setLoading(true);
    try {
      const data = await adminApi.fetchAttendance(page, 100, {
        date: dateFilter === 'all' ? undefined : dateFilter,
        department: deptFilter !== 'all' ? deptFilter : undefined,
        status: statusFilter !== 'all' ? statusFilter : undefined,
        search: search || undefined,
      });

      if (data && data.success) {
        if (Array.isArray(data.records)) {
          setRecords(data.records);
        }
        if (Array.isArray(data.available_dates)) {
          setAvailableDates(data.available_dates);
        }
        if (data.summary) {
          setSummary(data.summary);
        }
      }
    } catch (err) {
      console.error('Failed to fetch attendance:', err);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadAttendance();
  }, [dateFilter, deptFilter, statusFilter, page, activeReportTab]);

  // Tab-based record filtering
  const filteredRecords = records.filter((r) => {
    if (activeReportTab === 'late') {
      return r.status === 'Late' || (r.late_reason && r.late_reason.trim().length > 0);
    }
    if (activeReportTab === 'forgotten') {
      return r.action === 'Check-In' && !records.some(other => other.employee_id === r.employee_id && other.action === 'Check-Out');
    }
    return true;
  });

  const handleExportCSV = () => {
    const csvContent =
      'data:text/csv;charset=utf-8,\uFEFF' +
      ['អត្តលេខ,ឈ្មោះបុគ្គលិក,សកម្មភាព,ស្ថានភាព,កាលបរិច្ឆេទ,ទីតាំង,មូលហេតុមកយឺត']
        .concat(
          filteredRecords.map(
            (r) =>
              `"${r.employee_id}","${r.name}","${r.action}","${r.status}","${r.log_time}","${r.workplace}","${r.late_reason || ''}"`
          )
        )
        .join('\n');

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `VVC_${activeReportTab}_Report_${dateFilter}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Branch statistics for 'combined' tab
  const branchStats = React.useMemo(() => {
    const map: Record<string, { total: number; good: number; late: number }> = {};
    records.forEach(r => {
      const b = r.workplace || 'Store 318';
      if (!map[b]) map[b] = { total: 0, good: 0, late: 0 };
      map[b].total++;
      if (r.status === 'Late') map[b].late++;
      else map[b].good++;
    });
    return map;
  }, [records]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
      {/* Page Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
        }}
      >
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
            របាយការណ៍វត្តមាន & វិភាគទិន្នន័យ (Attendance & Reports)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: '4px 0 0 0' }}>
            របាយការណ៍វត្តមានប្រចាំថ្ងៃ មកយឺតសរុប ភ្លេចស្កេន សុំច្បាប់ដេអូស និងរបាយការណ៍រួមសាខា
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <button
            onClick={loadAttendance}
            className="btn btn-secondary"
            style={{ borderRadius: '10px' }}
            title="Refresh"
          >
            <RefreshCw size={14} className={loading ? 'fa-spin' : ''} />
            <span>ផ្ទុកឡើងវិញ</span>
          </button>

          <button onClick={handleExportCSV} className="btn btn-success" style={{ borderRadius: '10px', fontWeight: 700 }}>
            <Download size={16} />
            <span>ទាញយក CSV ({activeReportTab.toUpperCase()})</span>
          </button>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '14px',
        }}
      >
        <div
          className="hrm-card"
          style={{
            padding: '16px 20px',
            borderRadius: '16px',
            background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.08) 0%, rgba(99, 102, 241, 0.02) 100%)',
            border: '1px solid rgba(99, 102, 241, 0.2)',
            display: 'flex',
            alignItems: 'center',
            gap: '14px',
          }}
        >
          <div style={{ width: '44px', height: '44px', borderRadius: '12px', background: 'var(--primary)', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Clock size={22} />
          </div>
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 700 }}>ស្កេនសរុប (Total Scans)</div>
            <div style={{ fontSize: '22px', fontWeight: 900, color: 'var(--text-primary)' }}>{records.length}</div>
          </div>
        </div>

        <div
          className="hrm-card"
          style={{
            padding: '16px 20px',
            borderRadius: '16px',
            background: 'linear-gradient(135deg, rgba(34, 197, 94, 0.08) 0%, rgba(34, 197, 94, 0.02) 100%)',
            border: '1px solid rgba(34, 197, 94, 0.2)',
            display: 'flex',
            alignItems: 'center',
            gap: '14px',
          }}
        >
          <div style={{ width: '44px', height: '44px', borderRadius: '12px', background: '#22c55e', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <CheckCircle2 size={22} />
          </div>
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 700 }}>ទាន់ពេល (Good)</div>
            <div style={{ fontSize: '22px', fontWeight: 900, color: '#16a34a' }}>
              {records.filter(r => r.status === 'Good').length}
            </div>
          </div>
        </div>

        <div
          className="hrm-card"
          style={{
            padding: '16px 20px',
            borderRadius: '16px',
            background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.08) 0%, rgba(239, 68, 68, 0.02) 100%)',
            border: '1px solid rgba(239, 68, 68, 0.2)',
            display: 'flex',
            alignItems: 'center',
            gap: '14px',
          }}
        >
          <div style={{ width: '44px', height: '44px', borderRadius: '12px', background: '#ef4444', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <AlertTriangle size={22} />
          </div>
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 700 }}>មកយឺត (Late)</div>
            <div style={{ fontSize: '22px', fontWeight: 900, color: '#dc2626' }}>
              {records.filter(r => r.status === 'Late').length}
            </div>
          </div>
        </div>

        <div
          className="hrm-card"
          style={{
            padding: '16px 20px',
            borderRadius: '16px',
            background: 'linear-gradient(135deg, rgba(245, 158, 11, 0.08) 0%, rgba(245, 158, 11, 0.02) 100%)',
            border: '1px solid rgba(245, 158, 11, 0.2)',
            display: 'flex',
            alignItems: 'center',
            gap: '14px',
          }}
        >
          <div style={{ width: '44px', height: '44px', borderRadius: '12px', background: '#f59e0b', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Building2 size={22} />
          </div>
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 700 }}>សាខាមានសកម្មភាព</div>
            <div style={{ fontSize: '22px', fontWeight: 900, color: '#d97706' }}>
              {Object.keys(branchStats).length || 1}
            </div>
          </div>
        </div>
      </div>

      {/* Sub-Tabs for Different Reports */}
      <div
        className="hrm-card"
        style={{
          padding: '10px 14px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          overflowX: 'auto',
          borderRadius: '14px',
        }}
      >
        {[
          { id: 'daily', label: '📅 វត្តមានប្រចាំថ្ងៃ (Daily Log)' },
          { id: 'late', label: '⚠️ មកយឺតសរុប (Late Summary)' },
          { id: 'forgotten', label: '❓ ភ្លេចស្កេន (Forgotten Scan)' },
          { id: 'leave_deo', label: '📝 សុំច្បាប់ & ដេអូស (Leave & Deo)' },
          { id: 'combined', label: '📊 របាយការណ៍រួម (318 / PSP / PRV)' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveReportTab(tab.id as any)}
            className={`btn btn-sm ${activeReportTab === tab.id ? 'btn-primary' : 'btn-secondary'}`}
            style={{ borderRadius: '10px', padding: '7px 16px', fontWeight: 700, fontSize: '12.5px', whiteSpace: 'nowrap' }}
          >
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Filter Toolbar */}
      <div
        className="hrm-card"
        style={{
          padding: '18px 20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
          borderRadius: '16px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flexWrap: 'wrap' }}>
          {/* Date Picker */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-secondary)' }}>
              កាលបរិច្ឆេទ:
            </span>
            <input
              type="date"
              className="form-input"
              value={dateFilter === 'all' ? '' : dateFilter}
              onChange={(e) => setDateFilter(e.target.value || 'all')}
              style={{ width: '160px', padding: '7px 12px', fontSize: '13px', borderRadius: '10px' }}
            />
            {dateFilter !== 'all' && (
              <button
                type="button"
                onClick={() => setDateFilter('all')}
                className="btn btn-secondary btn-sm"
                style={{ padding: '6px 10px', borderRadius: '8px', fontSize: '11.5px' }}
                title="មើលកាលបរិច្ឆេទទាំងអស់"
              >
                មើលទាំងអស់
              </button>
            )}
          </div>

          {/* Quick Date Selector from available dates in DB */}
          {availableDates.length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>កាលបរិច្ឆេទថ្មីៗ:</span>
              <select
                className="form-select"
                value={dateFilter}
                onChange={(e) => setDateFilter(e.target.value)}
                style={{ width: '140px', padding: '6px 10px', fontSize: '12.5px', borderRadius: '8px' }}
              >
                <option value="all">គ្រប់ថ្ងៃទាំងអស់</option>
                {availableDates.slice(0, 15).map(d => (
                  <option key={d} value={d}>{d}</option>
                ))}
              </select>
            </div>
          )}

          {/* Department Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-secondary)' }}>
              សាខា:
            </span>
            <select
              className="form-select"
              value={deptFilter}
              onChange={(e) => setDeptFilter(e.target.value)}
              style={{ width: '160px', padding: '7px 12px', fontSize: '13px', borderRadius: '10px' }}
            >
              <option value="all">ទាំងអស់</option>
              <option value="Store 318">Store 318</option>
              <option value="Store SKKS2">Store SKKS2</option>
              <option value="Warehouse PSP">Warehouse PSP</option>
              <option value="IT Department">IT Department</option>
            </select>
          </div>
        </div>

        {/* Search & ViewModeToggle */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <ViewModeToggle mode={viewMode} onChange={setViewMode} />

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              background: 'var(--surface-alt)',
              border: '1px solid var(--border)',
              borderRadius: '10px',
              padding: '7px 12px',
              width: '240px',
              gap: '8px',
            }}
          >
            <Search size={15} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="ស្វែងរកឈ្មោះ, ID, ទីតាំង..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
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
        </div>
      </div>

      {/* COMBINED BRANCH SUMMARY TAB */}
      {activeReportTab === 'combined' && (
        <div className="hrm-card" style={{ padding: '24px', borderRadius: '18px' }}>
          <h3 style={{ fontSize: '16px', fontWeight: 800, margin: '0 0 16px 0', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Building2 size={18} color="var(--primary)" />
            <span>សង្ខេបវត្តមានតាមសាខា (Branch Breakdown) - {dateFilter === 'all' ? 'គ្រប់កាលបរិច្ឆេទ' : dateFilter}</span>
          </h3>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: '16px' }}>
            {Object.entries(branchStats).map(([branch, stat]) => (
              <div
                key={branch}
                className="hrm-card"
                style={{
                  padding: '18px',
                  borderRadius: '14px',
                  background: 'var(--surface-alt)',
                  border: '1px solid var(--border)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '10px',
                }}
              >
                <div style={{ fontWeight: 800, fontSize: '15px', color: 'var(--text-primary)' }}>{branch}</div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                  <span style={{ color: 'var(--text-muted)' }}>វត្តមានសរុប:</span>
                  <span style={{ fontWeight: 700 }}>{stat.total} នាក់</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                  <span style={{ color: '#16a34a' }}>ទាន់ពេល (Good):</span>
                  <span style={{ fontWeight: 700, color: '#16a34a' }}>{stat.good} នាក់</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                  <span style={{ color: '#dc2626' }}>មកយឺត (Late):</span>
                  <span style={{ fontWeight: 700, color: '#dc2626' }}>{stat.late} នាក់</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* View Mode Switching: Grid Cards or Table */}
      {viewMode === 'grid' ? (
        filteredRecords.length === 0 ? (
          <div className="hrm-card" style={{ textAlign: 'center', padding: '60px 24px', borderRadius: '18px' }}>
            <Calendar size={48} style={{ margin: '0 auto 14px auto', opacity: 0.25, display: 'block' }} />
            <div style={{ fontSize: '16px', fontWeight: 800, color: 'var(--text-primary)' }}>
              មិនទាន់មានទិន្នន័យសម្រាប់របាយការណ៍នេះឡើយ
            </div>
            <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginTop: '6px', maxWidth: '460px', margin: '6px auto 16px auto' }}>
              មិនមានទិន្នន័យស្កេនវត្តមានសម្រាប់កាលបរិច្ឆេទ {dateFilter === 'all' ? 'ដែលបានជ្រើសរើស' : dateFilter} ទេ។
            </p>

            {availableDates.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontSize: '12.5px', color: 'var(--text-secondary)', fontWeight: 600 }}>
                  ចុចដើម្បីមើលទិន្នន័យថ្ងៃដែលមានវត្តមាន៖
                </span>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', justifyContent: 'center' }}>
                  {availableDates.slice(0, 5).map((d) => (
                    <button
                      key={d}
                      type="button"
                      onClick={() => setDateFilter(d)}
                      className="btn btn-secondary btn-sm"
                      style={{ borderRadius: '8px', fontWeight: 700 }}
                    >
                      📅 {d}
                    </button>
                  ))}
                  <button
                    type="button"
                    onClick={() => setDateFilter('all')}
                    className="btn btn-primary btn-sm"
                    style={{ borderRadius: '8px', fontWeight: 700 }}
                  >
                    បង្ហាញទាំងអស់ (All)
                  </button>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(290px, 1fr))', gap: '16px' }}>
            {filteredRecords.map((r) => (
              <div
                key={r.id}
                className="hrm-card"
                style={{
                  padding: '18px',
                  borderRadius: '16px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '12px',
                  border: '1px solid var(--border)',
                  boxShadow: 'var(--shadow-sm)',
                  background: 'var(--surface)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div>
                    <div style={{ fontWeight: 800, fontSize: '15px', color: 'var(--text-primary)' }}>{r.name}</div>
                    <span style={{ fontFamily: "'Outfit', monospace", fontSize: '12px', color: 'var(--primary)', fontWeight: 700 }}>
                      ID: {r.employee_id}
                    </span>
                  </div>
                  <StatusBadge status={r.status} />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12.5px', color: 'var(--text-secondary)', background: 'var(--surface-alt)', padding: '10px 12px', borderRadius: '10px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-muted)' }}>សកម្មភាព:</span>
                    <span style={{ fontWeight: 700, color: r.action === 'Check-In' ? 'var(--success)' : 'var(--danger)' }}>{r.action}</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-muted)' }}>ម៉ោងស្កេន:</span>
                    <span style={{ fontFamily: "'Outfit', monospace", fontWeight: 600 }}>{r.log_time}</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-muted)' }}>ទីតាំង:</span>
                    <span style={{ fontWeight: 600 }}>{r.workplace}</span>
                  </div>
                  {r.geo_address && (
                    <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      📍 {r.geo_address}
                    </div>
                  )}
                </div>

                {r.late_reason && (
                  <div style={{ fontSize: '12px', color: '#b45309', background: 'rgba(245, 158, 11, 0.1)', padding: '8px 10px', borderRadius: '8px', border: '1px solid rgba(245, 158, 11, 0.25)' }}>
                    ⚠️ មូលហេតុ: {r.late_reason}
                  </div>
                )}

                {r.photo_path && (
                  <button
                    type="button"
                    onClick={() => setPreviewPhoto(r.photo_path || null)}
                    className="btn btn-secondary btn-sm"
                    style={{ borderRadius: '8px', fontSize: '11.5px', marginTop: 'auto' }}
                  >
                    <Camera size={13} />
                    <span>មើលរូបថតស្កេនផ្ទៃមុខ</span>
                  </button>
                )}
              </div>
            ))}
          </div>
        )
      ) : (
        /* Attendance Table */
        <div className="table-container">
          <table className="hrm-table">
            <thead>
              <tr>
                <th>អត្តលេខ</th>
                <th>ឈ្មោះបុគ្គលិក</th>
                <th>សកម្មភាព</th>
                <th>កាលបរិច្ឆេទ & ម៉ោង</th>
                <th>ស្ថានភាព</th>
                <th>សាខា / ទីតាំង</th>
                <th>មូលហេតុ (ប្រសិនបើមាន)</th>
                <th style={{ textAlign: 'center' }}>រូបថត</th>
              </tr>
            </thead>
            <tbody>
              {filteredRecords.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: '48px 24px', color: 'var(--text-muted)' }}>
                    <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)', marginBottom: '6px' }}>
                      មិនទាន់មានទិន្នន័យសម្រាប់របាយការណ៍នេះឡើយ
                    </div>
                    <p style={{ fontSize: '12.5px', marginBottom: '14px' }}>
                      សូមជ្រើសរើសកាលបរិច្ឆេទផ្សេង ឬចុច "បង្ហាញទាំងអស់" ដើម្បីមើលទិន្នន័យ។
                    </p>
                    {availableDates.length > 0 && (
                      <div style={{ display: 'flex', gap: '8px', justifyContent: 'center', flexWrap: 'wrap' }}>
                        {availableDates.slice(0, 5).map(d => (
                          <button
                            key={d}
                            type="button"
                            onClick={() => setDateFilter(d)}
                            className="btn btn-secondary btn-sm"
                            style={{ borderRadius: '8px' }}
                          >
                            📅 {d}
                          </button>
                        ))}
                        <button
                          type="button"
                          onClick={() => setDateFilter('all')}
                          className="btn btn-primary btn-sm"
                          style={{ borderRadius: '8px' }}
                        >
                          បង្ហាញទាំងអស់ (All)
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ) : (
                filteredRecords.map((r) => (
                  <tr key={r.id}>
                    <td style={{ fontFamily: "'Outfit', monospace", fontWeight: 700, color: 'var(--primary)' }}>
                      {r.employee_id}
                    </td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{r.name}</div>
                      {r.department && (
                        <small style={{ color: 'var(--text-muted)', fontSize: '11px' }}>{r.department}</small>
                      )}
                    </td>
                    <td>
                      <span
                        style={{
                          fontWeight: 700,
                          fontSize: '12px',
                          color: r.action === 'Check-In' ? '#16a34a' : '#dc2626',
                          background: r.action === 'Check-In' ? '#dcfce7' : '#fee2e2',
                          padding: '3px 8px',
                          borderRadius: '6px',
                        }}
                      >
                        {r.action}
                      </span>
                    </td>
                    <td style={{ fontFamily: "'Outfit', sans-serif", fontSize: '13px' }}>
                      {r.log_time}
                    </td>
                    <td>
                      <StatusBadge status={r.status} />
                    </td>
                    <td style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <MapPin size={13} color="var(--text-muted)" />
                        <span>{r.workplace}</span>
                      </div>
                      {r.geo_address && (
                        <small style={{ color: 'var(--text-muted)', fontSize: '11px', display: 'block', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {r.geo_address}
                        </small>
                      )}
                    </td>
                    <td style={{ fontSize: '12.5px', color: r.late_reason ? '#f59e0b' : 'var(--text-muted)' }}>
                      {r.late_reason || '-'}
                    </td>
                    <td style={{ textAlign: 'center' }}>
                      {r.photo_path ? (
                        <button
                          type="button"
                          onClick={() => setPreviewPhoto(r.photo_path || null)}
                          className="btn btn-secondary btn-sm"
                          style={{ padding: '4px 8px', borderRadius: '6px' }}
                          title="មើលរូបថត"
                        >
                          <Camera size={13} />
                        </button>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>-</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Photo Preview Modal */}
      <Modal
        isOpen={!!previewPhoto}
        onClose={() => setPreviewPhoto(null)}
        title="រូបថតស្កេនវត្តមាន (Attendance Photo)"
      >
        <div style={{ textAlign: 'center', padding: '10px' }}>
          {previewPhoto && (
            <img
              src={previewPhoto.startsWith('http') ? previewPhoto : `https://app.vvc.asia/flutter/${previewPhoto}`}
              alt="Scan Verification"
              style={{ maxWidth: '100%', maxHeight: '420px', borderRadius: '12px', objectFit: 'contain' }}
              onError={(e) => {
                (e.target as HTMLElement).style.display = 'none';
              }}
            />
          )}
        </div>
      </Modal>
    </div>
  );
};
