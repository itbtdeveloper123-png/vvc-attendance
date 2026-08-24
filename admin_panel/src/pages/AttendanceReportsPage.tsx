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
  Briefcase,
  Star,
  HardHat,
  Building2,
  Eye,
  Camera,
  Layers,
  ChevronRight,
  TrendingUp,
  Columns,
  Trash2,
} from 'lucide-react';
import { StatusBadge } from '../components/common/StatusBadge';
import { ViewModeToggle, ViewMode } from '../components/common/ViewModeToggle';
import { Modal } from '../components/common/Modal';
import { adminApi, AttendanceRecord } from '../api/adminApi';

export const AttendanceReportsPage: React.FC = () => {
  // Main Department Tabs: Administrative/Skill vs SKKS2/SKNR3 vs Worker vs All
  const [deptCategoryTab, setDeptCategoryTab] = useState<'department' | 'sk' | 'worker' | 'all'>('department');
  const [viewMode, setViewMode] = useState<ViewMode>('table');

  const [records, setRecords] = useState<AttendanceRecord[]>([]);
  const [availableDates, setAvailableDates] = useState<string[]>([]);
  const [selectedDate, setSelectedDate] = useState<string>('');
  const [customDate, setCustomDate] = useState<string>('');
  const [isCustomDateMode, setIsCustomDateMode] = useState<boolean>(false);

  const [statusFilter, setStatusFilter] = useState('All');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState({ total: 0, good: 0, late: 0 });

  // Selected checkbox rows
  const [selectedRowIds, setSelectedRowIds] = useState<number[]>([]);

  // Photo Preview Modal
  const [previewPhoto, setPreviewPhoto] = useState<string | null>(null);

  const loadAttendance = async () => {
    setLoading(true);
    try {
      const activeDate = isCustomDateMode && customDate ? customDate : selectedDate;

      const data = await adminApi.fetchAttendance(page, 200, {
        date: activeDate && activeDate !== 'all' ? activeDate : undefined,
        dept_category: deptCategoryTab !== 'all' ? deptCategoryTab : undefined,
        status: statusFilter !== 'All' ? statusFilter : undefined,
        search: search || undefined,
      });

      if (data && data.success) {
        if (Array.isArray(data.records)) {
          setRecords(data.records);
        }
        if (Array.isArray(data.available_dates)) {
          setAvailableDates(data.available_dates);
          // If no date was selected yet, set selectedDate to the first available date
          if (!selectedDate && data.available_dates.length > 0) {
            setSelectedDate(data.available_dates[0]);
          }
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
  }, [deptCategoryTab, selectedDate, customDate, isCustomDateMode, statusFilter, page]);

  // Format date helper for dropdown display e.g. "14 Aug 2026 (Fri)"
  const formatDateDisplay = (dateStr: string) => {
    if (!dateStr) return '';
    try {
      const d = new Date(dateStr + 'T00:00:00');
      const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
      const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      const dayName = days[d.getDay()];
      const monthName = months[d.getMonth()];
      const dayNum = String(d.getDate()).padStart(2, '0');
      const year = d.getFullYear();
      return `${dayNum} ${monthName} ${year} (${dayName})`;
    } catch {
      return dateStr;
    }
  };

  // Format date only (e.g. 14/08/2026)
  const formatDateOnly = (dateTimeStr: string) => {
    if (!dateTimeStr) return '-';
    try {
      const d = new Date(dateTimeStr.replace(' ', 'T'));
      if (isNaN(d.getTime())) {
        const parts = dateTimeStr.split(' ')[0].split('-');
        if (parts.length === 3) return `${parts[2]}/${parts[1]}/${parts[0]}`;
        return dateTimeStr;
      }
      const day = String(d.getDate()).padStart(2, '0');
      const month = String(d.getMonth() + 1).padStart(2, '0');
      const year = d.getFullYear();
      return `${day}/${month}/${year}`;
    } catch {
      return dateTimeStr;
    }
  };

  // Format time only (e.g. 05:05:49 PM)
  const formatTimeOnly = (dateTimeStr: string) => {
    if (!dateTimeStr) return '-';
    try {
      const d = new Date(dateTimeStr.replace(' ', 'T'));
      if (isNaN(d.getTime())) {
        const timePart = dateTimeStr.split(' ')[1];
        return timePart || dateTimeStr;
      }
      return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
    } catch {
      return dateTimeStr;
    }
  };

  // Filter records by search
  const filteredRecords = records.filter((r) => {
    if (!search) return true;
    const s = search.toLowerCase();
    return (
      (r.name && r.name.toLowerCase().includes(s)) ||
      (r.employee_id && r.employee_id.toLowerCase().includes(s)) ||
      (r.workplace && r.workplace.toLowerCase().includes(s))
    );
  });

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedRowIds(filteredRecords.map((r) => r.id));
    } else {
      setSelectedRowIds([]);
    }
  };

  const toggleRowSelection = (id: number) => {
    setSelectedRowIds((prev) => (prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]));
  };

  const handleExportCSV = () => {
    const csvContent =
      'data:text/csv;charset=utf-8,\uFEFF' +
      ['អត្តលេខ,ឈ្មោះបុគ្គលិក,ទីតាំង,សកម្មភាព,ថ្ងៃខែឆ្នាំ,ពេលវេលា,ស្ថានភាព,មូលហេតុ,NOTED']
        .concat(
          filteredRecords.map(
            (r) =>
              `"${r.employee_id}","${r.name}","${r.workplace}","${r.action}","${formatDateOnly(r.log_time)}","${formatTimeOnly(r.log_time)}","${r.status}","${r.late_reason || ''}","${r.noted || ''}"`
          )
        )
        .join('\n');

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `VVC_Attendance_${deptCategoryTab}_${selectedDate || 'all'}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Page Header Bar matching admin_attendance.php */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '14px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ width: '38px', height: '38px', borderRadius: '10px', background: 'var(--primary)', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <FileSpreadsheet size={20} />
          </div>
          <div>
            <h2 style={{ fontSize: '19px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              បញ្ជីវត្តមានបុគ្គលិក (Attendance Reports)
            </h2>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              ទាញយក និងតាមដានវត្តមានស្កេនចូល/ចេញ របស់បុគ្គលិកតាមផ្នែក
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <button
            onClick={loadAttendance}
            className="btn btn-secondary btn-sm"
            style={{ borderRadius: '10px', padding: '8px 14px' }}
            title="Refresh"
          >
            <RefreshCw size={14} className={loading ? 'fa-spin' : ''} />
            <span>ផ្ទុកឡើងវិញ</span>
          </button>

          <button
            onClick={handleExportCSV}
            className="btn btn-success btn-sm"
            style={{ borderRadius: '10px', padding: '8px 16px', fontWeight: 700 }}
          >
            <FileSpreadsheet size={15} />
            <span>Excel / CSV</span>
          </button>

          {selectedRowIds.length > 0 && (
            <button
              onClick={() => alert(`បានជ្រើសរើស ${selectedRowIds.length} ជួរដើម្បីអនុវត្តសកម្មភាព`)}
              className="btn btn-danger btn-sm"
              style={{ borderRadius: '10px', padding: '8px 14px', fontWeight: 700 }}
            >
              <Trash2 size={14} />
              <span>លុប ({selectedRowIds.length})</span>
            </button>
          )}
        </div>
      </div>

      {/* Main Container Card */}
      <div className="hrm-card" style={{ padding: 0, borderRadius: '18px', overflow: 'hidden' }}>
        {/* Top Department Tabs matching admin_attendance.php */}
        <div
          style={{
            background: 'var(--surface-alt)',
            padding: '0 20px',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            overflowX: 'auto',
          }}
        >
          <button
            type="button"
            onClick={() => setDeptCategoryTab('department')}
            style={{
              padding: '14px 20px',
              border: 'none',
              background: 'transparent',
              fontWeight: 700,
              fontSize: '13.5px',
              cursor: 'pointer',
              color: deptCategoryTab === 'department' ? 'var(--primary)' : 'var(--text-secondary)',
              borderBottom: deptCategoryTab === 'department' ? '3px solid var(--primary)' : '3px solid transparent',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              transition: 'all 0.2s ease',
              whiteSpace: 'nowrap',
            }}
          >
            <Briefcase size={16} />
            <span>ផ្នែករដ្ឋបាល/ជំនាញ</span>
          </button>

          <button
            type="button"
            onClick={() => setDeptCategoryTab('sk')}
            style={{
              padding: '14px 20px',
              border: 'none',
              background: 'transparent',
              fontWeight: 700,
              fontSize: '13.5px',
              cursor: 'pointer',
              color: deptCategoryTab === 'sk' ? 'var(--primary)' : 'var(--text-secondary)',
              borderBottom: deptCategoryTab === 'sk' ? '3px solid var(--primary)' : '3px solid transparent',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              transition: 'all 0.2s ease',
              whiteSpace: 'nowrap',
            }}
          >
            <Star size={16} />
            <span>SKKS2/SKNR3</span>
          </button>

          <button
            type="button"
            onClick={() => setDeptCategoryTab('worker')}
            style={{
              padding: '14px 20px',
              border: 'none',
              background: 'transparent',
              fontWeight: 700,
              fontSize: '13.5px',
              cursor: 'pointer',
              color: deptCategoryTab === 'worker' ? 'var(--primary)' : 'var(--text-secondary)',
              borderBottom: deptCategoryTab === 'worker' ? '3px solid var(--primary)' : '3px solid transparent',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              transition: 'all 0.2s ease',
              whiteSpace: 'nowrap',
            }}
          >
            <HardHat size={16} />
            <span>ផ្នែកកម្មករ</span>
          </button>

          <button
            type="button"
            onClick={() => setDeptCategoryTab('all')}
            style={{
              padding: '14px 20px',
              border: 'none',
              background: 'transparent',
              fontWeight: 700,
              fontSize: '13.5px',
              cursor: 'pointer',
              color: deptCategoryTab === 'all' ? 'var(--primary)' : 'var(--text-secondary)',
              borderBottom: deptCategoryTab === 'all' ? '3px solid var(--primary)' : '3px solid transparent',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              transition: 'all 0.2s ease',
              whiteSpace: 'nowrap',
            }}
          >
            <Layers size={16} />
            <span>ទាំងអស់ (All Departments)</span>
          </button>
        </div>

        {/* Filter Toolbar Section */}
        <div
          style={{
            padding: '20px 24px',
            display: 'flex',
            alignItems: 'flex-end',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '16px',
            borderBottom: '1px solid var(--border)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: '16px', flexWrap: 'wrap', flex: 1 }}>
            {/* Date Selector Dropdown matching admin_attendance.php */}
            <div style={{ minWidth: '240px', flex: '1 1 240px' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '8px' }}>
                <Calendar size={15} />
                <span>ជ្រើសរើសកាលបរិច្ឆេទ</span>
              </label>

              {!isCustomDateMode ? (
                <div style={{ display: 'flex', gap: '6px' }}>
                  <select
                    className="form-select"
                    value={selectedDate}
                    onChange={(e) => {
                      if (e.target.value === 'custom') {
                        setIsCustomDateMode(true);
                      } else {
                        setSelectedDate(e.target.value);
                      }
                    }}
                    style={{ height: '42px', borderRadius: '10px', fontWeight: 600, fontSize: '13.5px', width: '100%' }}
                  >
                    {availableDates.length === 0 ? (
                      <option value={new Date().toISOString().split('T')[0]}>
                        {formatDateDisplay(new Date().toISOString().split('T')[0])}
                      </option>
                    ) : (
                      availableDates.map((dateStr) => (
                        <option key={dateStr} value={dateStr}>
                          {formatDateDisplay(dateStr)}
                        </option>
                      ))
                    )}
                    <option value="all">គ្រប់កាលបរិច្ឆេទទាំងអស់ (All Dates)</option>
                    <option value="custom">📅 ជ្រើសរើសថ្ងៃផ្សេងទៀត (Pick Date)...</option>
                  </select>
                </div>
              ) : (
                <div style={{ display: 'flex', gap: '6px' }}>
                  <input
                    type="date"
                    className="form-input"
                    value={customDate || selectedDate}
                    onChange={(e) => setCustomDate(e.target.value)}
                    style={{ height: '42px', borderRadius: '10px', fontSize: '13px', flex: 1 }}
                  />
                  <button
                    type="button"
                    onClick={() => setIsCustomDateMode(false)}
                    className="btn btn-secondary btn-sm"
                    style={{ borderRadius: '8px', padding: '0 12px' }}
                  >
                    បញ្ជី
                  </button>
                </div>
              )}
            </div>

            {/* Status Filter */}
            <div style={{ minWidth: '180px', flex: '1 1 180px' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '8px' }}>
                <Filter size={15} />
                <span>ស្ថានភាព</span>
              </label>
              <select
                className="form-select"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                style={{ height: '42px', borderRadius: '10px', fontWeight: 600, fontSize: '13.5px', width: '100%' }}
              >
                <option value="All">ទាំងអស់ (All Status)</option>
                <option value="Good">ទាន់ពេល (Good)</option>
                <option value="Late">យឺត (Late)</option>
              </select>
            </div>
          </div>

          {/* Right Toolbar: ViewModeToggle & Search */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <ViewModeToggle mode={viewMode} onChange={setViewMode} />

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                background: 'var(--surface-alt)',
                border: '1px solid var(--border)',
                borderRadius: '10px',
                padding: '8px 14px',
                width: '220px',
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
        </div>

        {/* View Mode Switching: Grid Cards or Table */}
        {viewMode === 'grid' ? (
          filteredRecords.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '60px 24px', color: 'var(--text-muted)' }}>
              <Calendar size={48} style={{ margin: '0 auto 12px auto', opacity: 0.2, display: 'block' }} />
              <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)' }}>
                មិនមានទិន្នន័យវត្តមានសម្រាប់ថ្ងៃដែលបានជ្រើសរើសទេ។
              </div>
              <p style={{ fontSize: '13px', marginTop: '6px' }}>
                សូមជ្រើសរើសកាលបរិច្ឆេទផ្សេង ឬជ្រើសរើស "គ្រប់កាលបរិច្ឆេទទាំងអស់"។
              </p>
            </div>
          ) : (
            <div style={{ padding: '20px', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(290px, 1fr))', gap: '16px' }}>
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
                      <div style={{ fontWeight: 800, fontSize: '16px', color: 'var(--primary)' }}>{r.name}</div>
                      <span style={{ fontFamily: "'Outfit', monospace", fontSize: '12px', color: 'var(--text-muted)', fontWeight: 700 }}>
                        ID: {r.employee_id}
                      </span>
                    </div>
                    <span
                      style={{
                        background: r.status === 'Late' ? '#fee2e2' : '#dcfce7',
                        color: r.status === 'Late' ? '#dc2626' : '#16a34a',
                        fontWeight: 800,
                        fontSize: '12px',
                        padding: '4px 10px',
                        borderRadius: '20px',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px',
                      }}
                    >
                      <CheckCircle2 size={13} />
                      <span>{r.status}</span>
                    </span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12.5px', color: 'var(--text-secondary)', background: 'var(--surface-alt)', padding: '12px', borderRadius: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--text-muted)' }}>ទីតាំង:</span>
                      <span style={{ fontWeight: 700 }}>{r.workplace}</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--text-muted)' }}>សកម្មភាព:</span>
                      <span style={{ fontWeight: 700, color: r.action === 'Check-In' ? '#16a34a' : '#dc2626' }}>{r.action}</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--text-muted)' }}>ថ្ងៃខែឆ្នាំ:</span>
                      <span style={{ fontFamily: "'Outfit', monospace", fontWeight: 600 }}>{formatDateOnly(r.log_time)}</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--text-muted)' }}>ពេលវេលា:</span>
                      <span style={{ fontFamily: "'Outfit', monospace", fontWeight: 700, color: 'var(--text-primary)' }}>{formatTimeOnly(r.log_time)}</span>
                    </div>
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
          /* Table View matching admin_attendance.php 100% */
          <div className="table-container" style={{ border: 'none', boxShadow: 'none' }}>
            <table className="hrm-table">
              <thead>
                <tr>
                  <th style={{ width: '48px', textAlign: 'center' }}>
                    <input
                      type="checkbox"
                      checked={filteredRecords.length > 0 && selectedRowIds.length === filteredRecords.length}
                      onChange={(e) => handleSelectAll(e.target.checked)}
                      title="ជ្រើសរើសទាំងអស់"
                    />
                  </th>
                  <th style={{ width: '100px' }}>អត្តលេខ</th>
                  <th>ឈ្មោះ</th>
                  <th>ទីតាំង</th>
                  <th style={{ width: '120px' }}>សកម្មភាព</th>
                  <th style={{ width: '120px' }}>ថ្ងៃខែឆ្នាំ</th>
                  <th style={{ width: '130px' }}>ពេលវេលា</th>
                  <th style={{ width: '110px' }}>ស្ថានភាព</th>
                  <th>មូលហេតុ</th>
                  <th>NOTED</th>
                  <th style={{ width: '90px', textAlign: 'center' }}>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {filteredRecords.length === 0 ? (
                  <tr>
                    <td colSpan={11} style={{ textAlign: 'center', padding: '48px 24px', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                      {loading ? 'កំពុងទាញយកទិន្នន័យវត្តមាន...' : 'មិនមានទិន្នន័យវត្តមានសម្រាប់ថ្ងៃដែលបានជ្រើសរើសទេ។'}
                    </td>
                  </tr>
                ) : (
                  filteredRecords.map((log) => {
                    const isSelected = selectedRowIds.includes(log.id);

                    return (
                      <tr key={log.id} style={{ background: isSelected ? 'rgba(99, 102, 241, 0.04)' : undefined }}>
                        <td style={{ textAlign: 'center' }}>
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => toggleRowSelection(log.id)}
                          />
                        </td>
                        <td style={{ fontFamily: "'Outfit', monospace", fontWeight: 700, color: 'var(--text-muted)' }}>
                          {log.employee_id}
                        </td>
                        <td>
                          <div style={{ fontWeight: 800, fontSize: '15px', color: 'var(--primary)' }}>
                            {log.name}
                          </div>
                        </td>
                        <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>
                          {log.workplace}
                        </td>
                        <td>
                          <span
                            style={{
                              fontWeight: 700,
                              fontSize: '12px',
                              color: log.action === 'Check-In' ? '#16a34a' : '#dc2626',
                            }}
                          >
                            {log.action}
                          </span>
                        </td>
                        <td style={{ fontFamily: "'Outfit', sans-serif", fontSize: '13px', fontWeight: 600 }}>
                          {formatDateOnly(log.log_time)}
                        </td>
                        <td style={{ fontFamily: "'Outfit', monospace", fontSize: '13px', fontWeight: 600 }}>
                          {formatTimeOnly(log.log_time)}
                        </td>
                        <td>
                          <span
                            style={{
                              background: log.status === 'Late' ? '#fee2e2' : '#dcfce7',
                              color: log.status === 'Late' ? '#dc2626' : '#16a34a',
                              fontWeight: 800,
                              fontSize: '12px',
                              padding: '3px 10px',
                              borderRadius: '20px',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px',
                            }}
                          >
                            <CheckCircle2 size={12} />
                            <span>{log.status}</span>
                          </span>
                        </td>
                        <td style={{ fontSize: '12.5px', color: log.late_reason ? '#f59e0b' : 'var(--text-muted)' }}>
                          {log.late_reason || ''}
                        </td>
                        <td style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
                          {log.noted || ''}
                        </td>
                        <td style={{ textAlign: 'center' }}>
                          {log.photo_path ? (
                            <button
                              type="button"
                              onClick={() => setPreviewPhoto(log.photo_path || null)}
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
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

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
