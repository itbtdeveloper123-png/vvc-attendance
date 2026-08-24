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
} from 'lucide-react';
import { StatusBadge } from '../components/common/StatusBadge';
import { adminApi, AttendanceRecord } from '../api/adminApi';

export const AttendanceReportsPage: React.FC = () => {
  const [activeReportTab, setActiveReportTab] = useState<'daily' | 'late' | 'forgotten' | 'leave_deo' | 'combined'>('daily');

  const [records, setRecords] = useState<AttendanceRecord[]>([
    {
      id: 1,
      employee_id: 'VVC-101',
      name: 'សុខ គឹមហុង',
      action: 'Check-In',
      status: 'Good',
      log_time: '2026-08-24 07:55:12',
      workplace: 'Store 318',
    },
    {
      id: 2,
      employee_id: 'VVC-102',
      name: 'កែវ សុភា',
      action: 'Check-In',
      status: 'Good',
      log_time: '2026-08-24 07:58:30',
      workplace: 'Store 318',
    },
    {
      id: 3,
      employee_id: 'VVC-103',
      name: 'ជា វណ្ណៈ',
      action: 'Check-In',
      status: 'Late',
      log_time: '2026-08-24 08:16:04',
      workplace: 'Warehouse PSP',
      late_reason: 'ភ្លៀងខ្លាំងនៅតំបន់ព្រែកព្នៅ',
    },
    {
      id: 4,
      employee_id: 'VVC-104',
      name: 'លឹម គឹមសាន',
      action: 'Check-In',
      status: 'Good',
      log_time: '2026-08-24 07:49:10',
      workplace: 'IT Department',
    },
  ]);

  const [dateFilter, setDateFilter] = useState(new Date().toISOString().split('T')[0]);
  const [deptFilter, setDeptFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);

  const loadAttendance = async () => {
    setLoading(true);
    try {
      const data = await adminApi.fetchAttendance(page, 50, {
        date: dateFilter,
        department: deptFilter !== 'all' ? deptFilter : undefined,
        status: statusFilter !== 'all' ? statusFilter : undefined,
        search: search || undefined,
      });
      if (data && data.success && Array.isArray(data.records)) {
        setRecords(data.records);
      }
    } catch {}
    setLoading(false);
  };

  useEffect(() => {
    loadAttendance();
  }, [dateFilter, deptFilter, statusFilter, page, activeReportTab]);

  const filteredRecords = records.filter((r) => {
    if (activeReportTab === 'late') {
      return r.status === 'Late';
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
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
          <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-primary)' }}>
            របាយការណ៍វត្តមាន & វិភាគទិន្នន័យ (Attendance & Reports)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            របាយការណ៍វត្តមានប្រចាំថ្ងៃ មកយឺតសរុប ភ្លេចស្កេន សុំច្បាប់ដេអូស និងរបាយការណ៍រួមសាខា
          </p>
        </div>

        <button onClick={handleExportCSV} className="btn btn-success">
          <Download size={16} />
          <span>ទាញយក CSV ({activeReportTab.toUpperCase()})</span>
        </button>
      </div>

      {/* Sub-Tabs for Different Reports */}
      <div
        className="hrm-card"
        style={{
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          overflowX: 'auto',
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
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          {/* Date Picker */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)' }}>
              កាលបរិច្ឆេទ:
            </span>
            <input
              type="date"
              className="form-input"
              value={dateFilter}
              onChange={(e) => setDateFilter(e.target.value)}
              style={{ width: '160px', padding: '7px 12px', fontSize: '13px' }}
            />
          </div>

          {/* Department Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)' }}>
              សាខា:
            </span>
            <select
              className="form-select"
              value={deptFilter}
              onChange={(e) => setDeptFilter(e.target.value)}
              style={{ width: '160px', padding: '7px 12px', fontSize: '13px' }}
            >
              <option value="all">ទាំងអស់</option>
              <option value="Store 318">Store 318</option>
              <option value="Store SKKS2">Store SKKS2</option>
              <option value="Warehouse PSP">Warehouse PSP</option>
              <option value="IT Department">IT Department</option>
            </select>
          </div>
        </div>

        {/* Search */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            background: 'var(--surface-alt)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            padding: '7px 12px',
            width: '260px',
            gap: '8px',
          }}
        >
          <Search size={15} color="var(--text-muted)" />
          <input
            type="text"
            placeholder="ស្វែងរកឈ្មោះ, ID..."
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

      {/* Attendance Table */}
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
            </tr>
          </thead>
          <tbody>
            {filteredRecords.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                  គ្មានទិន្នន័យសម្រាប់របាយការណ៍នេះឡើយ
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
                  </td>
                  <td>
                    <span style={{ fontWeight: 600, fontSize: '12.5px' }}>{r.action}</span>
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
                  </td>
                  <td style={{ fontSize: '12.5px', color: r.late_reason ? '#f59e0b' : 'var(--text-muted)' }}>
                    {r.late_reason || '-'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
