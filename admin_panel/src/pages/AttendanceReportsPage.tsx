import React, { useState, useEffect, useRef, useMemo } from 'react';
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
  Edit3,
  ExternalLink,
  Save,
  Check,
  Plus,
  Printer,
  Sparkles,
} from 'lucide-react';
import { StatusBadge } from '../components/common/StatusBadge';
import { ViewModeToggle, ViewMode } from '../components/common/ViewModeToggle';
import { Modal } from '../components/common/Modal';
import { adminApi, AttendanceRecord } from '../api/adminApi';

interface LeaveDeoRecord {
  id: number;
  number: string;
  name: string;
  role: string;
  note: string;
  reports_date: string;
}

interface LateSummaryRecord {
  employee_id: string;
  name: string;
  gender: string;
  role: string;
  department: string;
  under_15: number;
  from_15_to_60: number;
  over_60: number;
  total: number;
}

interface ForgottenScanRecord {
  employee_id: string;
  name: string;
  gender: string;
  role: string;
  department: string;
  forgot_in: number;
  forgot_out: number;
  total: number;
  late_over_15: number;
}

export const AttendanceReportsPage: React.FC = () => {
  // Main Report Type Tab (Daily, Late Summary, Forgotten, Leave & Deo, Combined)
  const [activeReportTab, setActiveReportTab] = useState<'daily' | 'late' | 'forgotten' | 'leave_deo' | 'combined'>('daily');

  // Department Category Filter Tab (for Daily / Late / Forgotten)
  const [deptCategoryTab, setDeptCategoryTab] = useState<'department' | 'sk' | 'worker' | 'all'>('department');
  const [viewMode, setViewMode] = useState<ViewMode>('table');

  // Store selection for Leave & Deo / Combined reports (318, ks2, nr3, all)
  const [selectedStore, setSelectedStore] = useState<string>('318');

  // Date range filters for Late Summary & Forgotten Scan
  const [reportStartDate, setReportStartDate] = useState<string>(
    new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString().split('T')[0]
  );
  const [reportEndDate, setReportEndDate] = useState<string>(
    new Date().toISOString().split('T')[0]
  );

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

  // Leave / Deo records state
  const [leaveDeoRecords, setLeaveDeoRecords] = useState<LeaveDeoRecord[]>([]);
  const [approvedLeaves, setApprovedLeaves] = useState<any[]>([]);
  const [loadingLeaveDeo, setLoadingLeaveDeo] = useState(false);

  // Consolidated staff matrix data
  const [consolidatedScans, setConsolidatedScans] = useState<any[]>([]);
  const [consolidatedData, setConsolidatedData] = useState<Record<string, any>>({});
  const [savingCellKey, setSavingCellKey] = useState<string | null>(null);

  // Late Summary Report data (A4)
  const [lateSummaryRecords, setLateSummaryRecords] = useState<LateSummaryRecord[]>([]);
  const [lateSummaryTotals, setLateSummaryTotals] = useState({
    under_15: 0,
    from_15_to_60: 0,
    over_60: 0,
    grand_total: 0,
  });
  const [loadingLateSummary, setLoadingLateSummary] = useState(false);

  // Forgotten Scan Report data (A4)
  const [forgottenScanRecords, setForgottenScanRecords] = useState<ForgottenScanRecord[]>([]);
  const [forgottenScanTotals, setForgottenScanTotals] = useState({
    forgot_in: 0,
    forgot_out: 0,
    grand_total: 0,
    late_over_15: 0,
  });
  const [loadingForgottenScan, setLoadingForgottenScan] = useState(false);

  // Selected checkbox rows
  const [selectedRowIds, setSelectedRowIds] = useState<(string | number)[]>([]);

  // Photo Preview Modal
  const [previewPhoto, setPreviewPhoto] = useState<string | null>(null);

  // Note Editing Modal State
  const [editingNoteRecord, setEditingNoteRecord] = useState<AttendanceRecord | null>(null);
  const [editingNoteValue, setEditingNoteValue] = useState<string>('');
  const [isSavingNote, setIsSavingNote] = useState<boolean>(false);
  const [saveSuccessMsg, setSaveSuccessMsg] = useState<string | null>(null);

  const printRef = useRef<HTMLDivElement>(null);

  // Active Date string helper
  const getActiveDate = () => (isCustomDateMode && customDate ? customDate : (selectedDate || new Date().toISOString().split('T')[0]));

  const loadAttendance = async () => {
    setLoading(true);
    try {
      const activeDate = isCustomDateMode && customDate ? customDate : selectedDate;

      const data = await adminApi.fetchAttendance(page, 200, {
        date: activeDate && activeDate !== 'all' ? activeDate : undefined,
        dept_category: deptCategoryTab !== 'all' ? deptCategoryTab : undefined,
        status: statusFilter !== 'All' ? statusFilter : undefined,
        search: search || undefined,
        tab: activeReportTab,
      });

      if (data && data.success) {
        if (Array.isArray(data.records)) {
          setRecords(data.records);
        }
        if (Array.isArray(data.available_dates)) {
          setAvailableDates(data.available_dates);
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

  // Load Leave & Deo / Combined report data
  const loadLeaveDeoAndCombined = async () => {
    if (activeReportTab !== 'leave_deo' && activeReportTab !== 'combined') return;
    setLoadingLeaveDeo(true);
    try {
      const d = getActiveDate();
      if (activeReportTab === 'leave_deo') {
        try {
          const res = await adminApi.fetchLeaveDeoReport(selectedStore, d);
          if (res && res.success) {
            setLeaveDeoRecords(res.records || []);
            setApprovedLeaves(res.approved_leaves || []);
          }
        } catch (e) {
          console.warn('Failed to fetch leave deo report:', e);
        }
      }

      if (activeReportTab === 'combined') {
        try {
          const cRes = await adminApi.fetchConsolidatedReport(selectedStore, d);
          if (cRes && cRes.success) {
            setConsolidatedScans(cRes.scans || []);
            setConsolidatedData(cRes.consolidated || {});
            if (cRes.staff && Array.isArray(cRes.staff) && cRes.staff.length > 0) {
              setLeaveDeoRecords(cRes.staff);
            }
          }
        } catch (e) {
          console.warn('Failed to fetch consolidated report:', e);
        }
      }
    } catch (e) {
      console.error(e);
    }
    setLoadingLeaveDeo(false);
  };

  // Load Late Summary Report data (A4)
  const loadLateSummary = async () => {
    if (activeReportTab !== 'late') return;
    setLoadingLateSummary(true);
    try {
      const res = await adminApi.fetchLateSummaryReport({
        start_date: reportStartDate,
        end_date: reportEndDate,
        dept_category: deptCategoryTab,
      });
      if (res && res.success) {
        setLateSummaryRecords(res.records || []);
        if (res.totals) {
          setLateSummaryTotals(res.totals);
        }
      }
    } catch (e) {
      console.error(e);
    }
    setLoadingLateSummary(false);
  };

  // Load Forgotten Scan Report data (A4)
  const loadForgottenScan = async () => {
    if (activeReportTab !== 'forgotten') return;
    setLoadingForgottenScan(true);
    try {
      const res = await adminApi.fetchForgottenScanReport({
        start_date: reportStartDate,
        end_date: reportEndDate,
        dept_category: deptCategoryTab,
      });
      if (res && res.success) {
        setForgottenScanRecords(res.records || []);
        if (res.totals) {
          setForgottenScanTotals(res.totals);
        }
      }
    } catch (e) {
      console.error(e);
    }
    setLoadingForgottenScan(false);
  };

  useEffect(() => {
    if (activeReportTab === 'leave_deo' || activeReportTab === 'combined') {
      loadLeaveDeoAndCombined();
    } else if (activeReportTab === 'late') {
      loadLateSummary();
    } else if (activeReportTab === 'forgotten') {
      loadForgottenScan();
    } else {
      loadAttendance();
    }
  }, [activeReportTab, deptCategoryTab, selectedStore, reportStartDate, reportEndDate, selectedDate, customDate, isCustomDateMode, statusFilter, page]);

  // Format Khmer date string helper (e.g. ថ្ងៃ អង្គារ ទី២៤ ខែសីហា ឆ្នាំ ២០២៦)
  const formatKhmerDateString = (dateStr: string) => {
    if (!dateStr) return '';
    try {
      const d = new Date(dateStr + 'T00:00:00');
      const khmerDays = ['អាទិត្យ', 'ច័ន្ទ', 'អង្គារ', 'ពុធ', 'ព្រហស្បតិ៍', 'សុក្រ', 'សៅរ៍'];
      const khmerMonths = ['មករា', 'កុម្ភៈ', 'មីនា', 'មេសា', 'ឧសភា', 'មិថុនា', 'កក្កដា', 'សីហា', 'កញ្ញា', 'តុលា', 'វិច្ឆិកា', 'ធ្នូ'];
      const khmerDigits = ['០', '១', '២', '៣', '៤', '៥', '៦', '៧', '៨', '៩'];
      const toKhNum = (n: number | string) => String(n).split('').map((c) => khmerDigits[parseInt(c)] ?? c).join('');
      
      const weekday = khmerDays[d.getDay()];
      const day = toKhNum(d.getDate());
      const month = khmerMonths[d.getMonth()];
      const year = toKhNum(d.getFullYear());
      return `ថ្ងៃ ${weekday} ទី${day} ខែ${month} ឆ្នាំ ${year}`;
    } catch {
      return dateStr;
    }
  };

  // Update consolidated cell inline
  const handleUpdateConsolidatedCell = async (column: string, value: number) => {
    const d = getActiveDate();
    setSavingCellKey(column);
    setConsolidatedData((prev) => ({ ...prev, [column]: value }));
    try {
      await adminApi.updateSingleAttendance(selectedStore, d, column, value);
    } catch (e) {
      console.error('Failed to update inline cell:', e);
    } finally {
      setTimeout(() => setSavingCellKey(null), 500);
    }
  };

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

  // Khmer Date text generator for A4 Document
  const getKhmerDateHeader = (dateStr: string) => {
    try {
      const d = new Date(dateStr + 'T00:00:00');
      const khmerMonths = ['មករា', 'កុម្ភៈ', 'មីនា', 'មេសា', 'ឧសភា', 'មិថុនា', 'កក្កដា', 'សីហា', 'កញ្ញា', 'តុលា', 'វិច្ឆិកា', 'ធ្នូ'];
      const mName = khmerMonths[d.getMonth()];
      const yearKhmer = '២០២៦';
      return `ខែ ${mName} ឆ្នាំ${yearKhmer}`;
    } catch {
      return 'ខែ សីហា ឆ្នាំ២០២៦';
    }
  };

  const getKhmerDateRange = () => {
    return `គិតចាប់ពីថ្ងៃទី ${formatDateOnly(reportStartDate).replace(/\//g, '-')} ដល់ថ្ងៃទី ${formatDateOnly(reportEndDate).replace(/\//g, '-')}`;
  };

  // Filter records by search
  const filteredRecords = records.filter((r) => {
    if (!search) return true;
    const s = search.toLowerCase();
    return (
      (r.name && r.name.toLowerCase().includes(s)) ||
      (r.employee_id && r.employee_id.toLowerCase().includes(s)) ||
      (r.workplace && r.workplace.toLowerCase().includes(s)) ||
      (r.noted && r.noted.toLowerCase().includes(s))
    );
  });

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedRowIds(filteredRecords.map((r) => r.id));
    } else {
      setSelectedRowIds([]);
    }
  };

  const toggleRowSelection = (id: string | number) => {
    setSelectedRowIds((prev) => (prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]));
  };

  // Open Noted Modal
  const handleOpenNoteEditor = (record: AttendanceRecord) => {
    setEditingNoteRecord(record);
    setEditingNoteValue(record.noted || '');
  };

  // Save Note to Database
  const handleSaveNote = async () => {
    if (!editingNoteRecord) return;
    setIsSavingNote(true);
    try {
      const res = await adminApi.updateAttendanceNoted(editingNoteRecord.id, editingNoteValue);
      if (res && (res.success || res.status === 'success')) {
        setRecords((prev) =>
          prev.map((r) => (r.id === editingNoteRecord.id ? { ...r, noted: editingNoteValue } : r))
        );
        setSaveSuccessMsg('រក្សាទុកចំណាំដោយជោគជ័យ!');
        setTimeout(() => setSaveSuccessMsg(null), 3000);
        setEditingNoteRecord(null);
      } else {
        alert('មិនអាចរក្សាទុកចំណាំបានទេ៖ ' + (res?.message || 'កំហុសបច្ចេកទេស'));
      }
    } catch (err) {
      console.error('Error saving note:', err);
      alert('កំហុសក្នុងការរក្សាទុកចំណាំ');
    }
    setIsSavingNote(false);
  };

  // Add new row in Leave & Deo
  const handleAddNewLeaveDeoRow = async () => {
    const d = getActiveDate();
    const tempId = Date.now();
    const newRecord = {
      id: tempId,
      number: String(leaveDeoRecords.length + 1),
      name: '',
      role: '',
      note: '',
      reports_date: d,
    };
    setLeaveDeoRecords((prev) => [...prev, newRecord]);
    setSaveSuccessMsg('បានបន្ថែមជួរថ្មី!');
    setTimeout(() => setSaveSuccessMsg(null), 2500);

    try {
      const res = await adminApi.createLeaveDeoRow(selectedStore, d);
      if (res && res.success && res.new_id) {
        setLeaveDeoRecords((prev) =>
          prev.map((r) => (r.id === tempId ? { ...r, id: res.new_id } : r))
        );
      }
    } catch (e) {
      console.error('Failed to create row on server:', e);
    }
  };

  // Update cell in Leave & Deo
  const handleUpdateLeaveDeoCell = async (id: number | string, column: string, value: string) => {
    setLeaveDeoRecords((prev) =>
      prev.map((r) => (r.id === id ? { ...r, [column]: value } : r))
    );
    try {
      await adminApi.updateLeaveDeoRow(selectedStore, id, column, value);
    } catch (e) {
      console.error('Failed to update leave deo cell:', e);
    }
  };

  // Delete row in Leave & Deo
  const handleDeleteLeaveDeoRow = async (id: number | string) => {
    if (!window.confirm('តើអ្នកពិតជាចង់លុបជួរដេកនេះមែនទេ?')) return;
    setLeaveDeoRecords((prev) => prev.filter((r) => r.id !== id));
    try {
      await adminApi.deleteLeaveDeoRow(selectedStore, id);
    } catch (e) {
      console.error('Failed to delete leave deo row:', e);
    }
  };

  // Trigger Print A4 Portrait
  const handlePrintA4 = () => {
    window.print();
  };

  const handleExportCSV = () => {
    let csvContent = 'data:text/csv;charset=utf-8,\uFEFF';

    if (activeReportTab === 'late') {
      csvContent += ['ល.រ,អត្តលេខ,ឈ្មោះ,ភេទ,តួនាទី,ក្រោម ១៥ នាទី,ចាប់ពី ១៥ នាទី,ចាប់ពី១ម៉ោង,សរុប']
        .concat(
          lateSummaryRecords.map(
            (r, i) =>
              `"${i + 1}","${r.employee_id}","${r.name}","${r.gender}","${r.role}","${r.under_15}","${r.from_15_to_60}","${r.over_60}","${r.total}"`
          )
        )
        .join('\n');
    } else if (activeReportTab === 'forgotten') {
      csvContent += ['ល.រ,អត្តលេខ,ឈ្មោះ,ភេទ,តួនាទី,ចូល,ចេញ,សរុប,ចំនួនយឺតលើស15នាទី']
        .concat(
          forgottenScanRecords.map(
            (r, i) =>
              `"${i + 1}","${r.employee_id}","${r.name}","${r.gender}","${r.role}","${r.forgot_in}","${r.forgot_out}","${r.total}","${r.late_over_15}"`
          )
        )
        .join('\n');
    } else if (activeReportTab === 'leave_deo') {
      csvContent += ['ល.រ,ឈ្មោះបុគ្គលិក,តួនាទី,អធិប្បាយ/មូលហេតុ,ថ្ងៃរាយការណ៍']
        .concat(
          leaveDeoRecords.map((r, idx) => `"${r.number || idx + 1}","${r.name}","${r.role}","${r.note}","${r.reports_date}"`)
        )
        .join('\n');
    } else {
      csvContent += ['អត្តលេខ,ឈ្មោះបុគ្គលិក,ទីតាំង,សកម្មភាព,ថ្ងៃខែឆ្នាំ,ពេលវេលា,ស្ថានភាព,មូលហេតុ,NOTED']
        .concat(
          filteredRecords.map(
            (r) =>
              `"${r.employee_id}","${r.name}","${r.workplace}","${r.action}","${formatDateOnly(r.log_time)}","${formatTimeOnly(r.log_time)}","${r.status}","${r.late_reason || ''}","${r.noted || ''}"`
          )
        )
        .join('\n');
    }

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `VVC_Attendance_${activeReportTab}_${selectedDate || 'all'}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Render clickable note content
  const renderNotedContent = (noteStr?: string) => {
    if (!noteStr) return <span style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>+ ចុចដើម្បីសរសេរ</span>;
    const isUrl = /^https?:\/\//i.test(noteStr) || /^(www\.)/i.test(noteStr);
    if (isUrl) {
      const url = noteStr.startsWith('http') ? noteStr : 'https://' + noteStr;
      return (
        <a
          href={url}
          target="_blank"
          rel="noopener noreferrer"
          onClick={(e) => e.stopPropagation()}
          style={{ color: 'var(--primary)', textDecoration: 'underline', display: 'inline-flex', alignItems: 'center', gap: '4px', wordBreak: 'break-all' }}
        >
          <span>{noteStr}</span>
          <ExternalLink size={11} />
        </a>
      );
    }
    return <span>{noteStr}</span>;
  };

  // Department definitions for Matrix Table
  const matrixDepartments = [
    { key: 'sales', label: 'ផ្នែកលក់ (Sales)' },
    { key: 'warehouse', label: 'ផ្នែកឃ្លាំង (Warehouse)' },
    { key: 'delivery', label: 'ផ្នែកដឹកជញ្ជូន (Delivery)' },
    { key: 'admin', label: 'ផ្នែករដ្ឋបាល (Admin)' },
    { key: 'accounting', label: 'ផ្នែកគណនេយ្យ (Accounting)' },
    { key: 'it', label: 'បច្ចេកវិទ្យា (IT)' },
  ];

// Default Roster for SKKS2/SKNR3 Late Summary
const DEFAULT_SK_LATE_RECORDS: LateSummaryRecord[] = [
  { employee_id: '0336', name: 'ប្រាក់ លីហេង', gender: 'ប្រុស', role: 'បុគ្គលិកស្តុកSK-KS2', department: 'SK-KS2', under_15: 5, from_15_to_60: 0, over_60: 0, total: 5 },
  { employee_id: '0341', name: 'ថេត ម៉ានិត', gender: 'ស្រី', role: 'អនុប្រធានហាង SK-KS2', department: 'SK-KS2', under_15: 3, from_15_to_60: 0, over_60: 0, total: 3 },
  { employee_id: '0337', name: 'សេង ចាន់ណា', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកគិតលុយSK-NR3', department: 'SK-NR3', under_15: 3, from_15_to_60: 0, over_60: 0, total: 3 },
  { employee_id: '0340', name: 'ស៊ុំ កុន', gender: 'ស្រី', role: 'ប្រធានហាងSK-KS2', department: 'SK-KS2', under_15: 2, from_15_to_60: 0, over_60: 0, total: 2 },
  { employee_id: '0349', name: 'ខ្លឹម ឃ្លាំងមឿង', gender: 'ប្រុស', role: 'បុគ្គលិកផ្នែកបើកកង់បី SK KS2', department: 'SK-KS2', under_15: 1, from_15_to_60: 1, over_60: 0, total: 2 },
  { employee_id: '0342', name: 'កាន់ ស្រីណាត', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកលក់SK-KS2', department: 'SK-KS2', under_15: 1, from_15_to_60: 0, over_60: 1, total: 2 },
  { employee_id: '0323', name: 'ជីន សុភាស់', gender: 'ស្រី', role: 'អនុប្រធានគ្រប់គ្រងហាង SK-NR3', department: 'SK-NR3', under_15: 1, from_15_to_60: 0, over_60: 0, total: 1 },
  { employee_id: '0315', name: 'ផាត ស្រីរដ្ឋ', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកគិតលុយSK-NR3', department: 'SK-NR3', under_15: 0, from_15_to_60: 1, over_60: 0, total: 1 },
  { employee_id: '0346', name: 'ឃុក ណេសា', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកលក់SK-NR3', department: 'SK-NR3', under_15: 1, from_15_to_60: 0, over_60: 0, total: 1 },
  { employee_id: '0320', name: 'អ៊ាង សេងហុង', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកលក់SK-KS2', department: 'SK-KS2', under_15: 1, from_15_to_60: 0, over_60: 0, total: 1 },
  { employee_id: '0326', name: 'ឌិន ស្រីកា', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកលក់SK-KS2', department: 'SK-KS2', under_15: 1, from_15_to_60: 0, over_60: 0, total: 1 },
  { employee_id: '0321', name: 'ហុង ទិត្យារ៉ាវីត', gender: 'ប្រុស', role: 'បុគ្គលិកស្តុកSK-KS2', department: 'SK-KS2', under_15: 1, from_15_to_60: 0, over_60: 0, total: 1 },
  { employee_id: '0303', name: 'ង៉ែត ពិសី', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកលក់ SK-NR3', department: 'SK-NR3', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
  { employee_id: '0301', name: 'បូរ ស្រីនិច', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកគិតលុយSK-KS2', department: 'SK-KS2', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
  { employee_id: '0312', name: 'សៅ សូលីនដា', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកគិតលុយSK-NR3', department: 'SK-NR3', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
  { employee_id: '0345', name: 'ប្រាក់ សុខក្រា', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកលក់SK-KS2', department: 'SK-KS2', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
  { employee_id: '0348', name: 'កែវ មួយចេង', gender: 'ស្រី', role: 'ប្រធានគ្រប់គ្រងហាង SK-NR3', department: 'SK-NR3', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
  { employee_id: '0350', name: 'ហេង ចរិយា', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកលក់SK-KS2', department: 'SK-KS2', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
  { employee_id: '0343', name: 'រ៉ុង ភីលីព', gender: 'ប្រុស', role: 'ប្រធានគ្រប់គ្រងទូទៅ', department: 'SK-General', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
  { employee_id: '0347', name: 'តាត ផានុត', gender: 'ប្រុស', role: 'បុគ្គលិកផ្នែកលក់SK-KS2', department: 'SK-KS2', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
  { employee_id: '0335', name: 'ម៉ុន មករា', gender: 'ប្រុស', role: 'បុគ្គលិកស្តុកSK-KS2', department: 'SK-KS2', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
];

// Default Roster for SKKS2/SKNR3 Forgotten Scan
const DEFAULT_SK_FORGOTTEN_RECORDS: ForgottenScanRecord[] = [
  { employee_id: '0336', name: 'ប្រាក់ លីហេង', gender: 'ប្រុស', role: 'បុគ្គលិកស្តុកSK-KS2', department: 'SK-KS2', forgot_in: 1, forgot_out: 1, total: 2, late_over_15: 0 },
  { employee_id: '0335', name: 'ម៉ុន មករា', gender: 'ប្រុស', role: 'បុគ្គលិកស្តុកSK-KS2', department: 'SK-KS2', forgot_in: 0, forgot_out: 2, total: 2, late_over_15: 0 },
  { employee_id: '0323', name: 'ជីន សុភាស់', gender: 'ស្រី', role: 'អនុប្រធានគ្រប់គ្រងហាង SK-NR3', department: 'SK-NR3', forgot_in: 0, forgot_out: 1, total: 1, late_over_15: 0 },
  { employee_id: '0321', name: 'ហុង ទិត្យារ៉ាវីត', gender: 'ប្រុស', role: 'បុគ្គលិកស្តុកSK-KS2', department: 'SK-KS2', forgot_in: 0, forgot_out: 1, total: 1, late_over_15: 0 },
  { employee_id: '0342', name: 'កាន់ ស្រីណាត', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកលក់SK-KS2', department: 'SK-KS2', forgot_in: 0, forgot_out: 1, total: 1, late_over_15: 0 },
  { employee_id: '0316', name: 'ខ្លឹម ឃ្លាំងមឿង', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកបើកកង់បី SK-KS2', department: 'SK-KS2', forgot_in: 0, forgot_out: 1, total: 1, late_over_15: 0 },
  { employee_id: '0337', name: 'សេង ចាន់ណា', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកគិតលុយSK-NR3', department: 'SK-NR3', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0303', name: 'ង៉ែត ពិសី', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកលក់ SK-NR3', department: 'SK-NR3', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0326', name: 'ឌិន ស្រីកា', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកលក់SK-KS2', department: 'SK-KS2', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0341', name: 'ថេត ម៉ានិត', gender: 'ស្រី', role: 'អនុប្រធានហាង SK-KS2', department: 'SK-KS2', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0340', name: 'ស៊ុំ កុន', gender: 'ស្រី', role: 'ប្រធានហាងSK-KS2', department: 'SK-KS2', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0346', name: 'ឃុក ណេសា', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកលក់SK-NR3', department: 'SK-NR3', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0345', name: 'ប្រាក់ សុខក្រា', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកលក់SK-KS2', department: 'SK-KS2', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0348', name: 'កែវ មួយចេង', gender: 'ស្រី', role: 'ប្រធានគ្រប់គ្រងហាង SK-NR3', department: 'SK-NR3', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0350', name: 'ហេង ចរិយា', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកលក់SK-KS2', department: 'SK-KS2', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0347', name: 'តាត ផានុត', gender: 'ប្រុស', role: 'បុគ្គលិកផ្នែកលក់SK-KS2', department: 'SK-KS2', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0312', name: 'អ៊ាង សេងហុង', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកលក់SK-KS2', department: 'SK-KS2', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0318', name: 'បូរ ស្រីនិច', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកគិតលុយ SK-KS2', department: 'SK-KS2', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0172', name: 'សៅ សូលីនដា', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកគិតលុយ SK-NR3', department: 'SK-NR3', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0315', name: 'ផាត ស្រីរដ្ឋ', gender: 'ស្រី', role: 'បុគ្គលិកផ្នែកគិតលុយSK-NR3', department: 'SK-NR3', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0343', name: 'រ៉ុង ភីលីព', gender: 'ប្រុស', role: 'ប្រធានគ្រប់គ្រងទូទៅ', department: 'SK-General', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
];

// Default Roster for Department Late Summary
const DEFAULT_DEPT_LATE_RECORDS: LateSummaryRecord[] = [
  { employee_id: '0331', name: 'ឯម ខេមរា', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', under_15: 5, from_15_to_60: 0, over_60: 0, total: 5 },
  { employee_id: '0296', name: 'ផង ស្រីនិច', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', under_15: 3, from_15_to_60: 0, over_60: 0, total: 3 },
  { employee_id: '0244', name: 'ម៉ុល ធីតា', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', under_15: 2, from_15_to_60: 1, over_60: 0, total: 3 },
  { employee_id: '0245', name: 'ផល សុភិន', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', under_15: 2, from_15_to_60: 0, over_60: 0, total: 2 },
  { employee_id: '0169', name: 'ឡេង ឡឿន', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', under_15: 2, from_15_to_60: 0, over_60: 0, total: 2 },
  { employee_id: '0334', name: 'មាស ពេជ្រតារា', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', under_15: 1, from_15_to_60: 1, over_60: 0, total: 2 },
  { employee_id: '0250', name: 'ស៊ីម សុខ', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', under_15: 2, from_15_to_60: 0, over_60: 0, total: 2 },
  { employee_id: '0295', name: 'សន លីណា', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', under_15: 1, from_15_to_60: 0, over_60: 0, total: 1 },
  { employee_id: '0127', name: 'យ៉ុក វ៉ាន់ដា', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', under_15: 1, from_15_to_60: 0, over_60: 0, total: 1 },
  { employee_id: '0158', name: 'ឌឹម សុជាតិ', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', under_15: 1, from_15_to_60: 0, over_60: 0, total: 1 },
  { employee_id: '0119', name: 'រឹម រស្មី', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', under_15: 1, from_15_to_60: 0, over_60: 0, total: 1 },
  { employee_id: '0308', name: 'វណ្ណ ស្រីនិច', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', under_15: 0, from_15_to_60: 1, over_60: 0, total: 1 },
  { employee_id: '0224', name: 'លី សាំងអី', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', under_15: 1, from_15_to_60: 0, over_60: 0, total: 1 },
  { employee_id: '0150', name: 'សៀង សារុន', gender: 'ប្រុស', role: 'IT Support', department: 'Store 318', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
  { employee_id: '0016', name: 'កឿន ដាលីន', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
  { employee_id: '0163', name: 'សៅ សម្បត្តិ', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
  { employee_id: '0021', name: 'យី វ៉ាន់ដេត', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
  { employee_id: '0226', name: 'រាម ចន្ទី', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
  { employee_id: '0190', name: 'សែម រស្មី', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
  { employee_id: '0062', name: 'វ៉ាន់ សាម៉ែត', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
  { employee_id: '0183', name: 'ភី គីកឡា', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
  { employee_id: '0066', name: 'ម៉ុង ដាលីន', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
  { employee_id: '0324', name: 'រិទ្ធ ពិសិដ្ឋ', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', under_15: 0, from_15_to_60: 0, over_60: 0, total: 0 },
];

// Default Roster for Department Forgotten Scan
const DEFAULT_DEPT_FORGOTTEN_RECORDS: ForgottenScanRecord[] = [
  { employee_id: '0331', name: 'ឯម ខេមរា', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0296', name: 'ផង ស្រីនិច', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0244', name: 'ម៉ុល ធីតា', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0245', name: 'ផល សុភិន', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0169', name: 'ឡេង ឡឿន', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0334', name: 'មាស ពេជ្រតារា', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0250', name: 'ស៊ីម សុខ', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0295', name: 'សន លីណា', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0127', name: 'យ៉ុក វ៉ាន់ដា', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0158', name: 'ឌឹម សុជាតិ', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0119', name: 'រឹម រស្មី', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0308', name: 'វណ្ណ ស្រីនិច', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0224', name: 'លី សាំងអី', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0150', name: 'សៀង សារុន', gender: 'ប្រុស', role: 'IT Support', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0016', name: 'កឿន ដាលីន', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0163', name: 'សៅ សម្បត្តិ', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0021', name: 'យី វ៉ាន់ដេត', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0226', name: 'រាម ចន្ទី', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0190', name: 'សែម រស្មី', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0062', name: 'វ៉ាន់ សាម៉ែត', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0183', name: 'ភី គីកឡា', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0066', name: 'ម៉ុង ដាលីន', gender: 'ស្រី', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
  { employee_id: '0324', name: 'រិទ្ធ ពិសិដ្ឋ', gender: 'ប្រុស', role: 'បុគ្គលិក', department: 'Store 318', forgot_in: 0, forgot_out: 0, total: 0, late_over_15: 0 },
];

  // Dynamic Theme Helpers for SK Cosmetic vs Van Van Cambodia
  const isSkMode = deptCategoryTab === 'sk';
  const activeLogoUrl = isSkMode
    ? 'https://i.ibb.co/1JXccBzm/Your-paragraph-text-2.png'
    : 'https://i.ibb.co/NdJMpN75/Logo-Van-Van-2.png';

  const bannerBg = isSkMode ? '#fef3c7' : '#1e3a8a';
  const bannerBorder = isSkMode ? '1px solid #fde68a' : 'none';
  const bannerShadow = isSkMode ? '0 4px 14px rgba(217, 119, 6, 0.12)' : '0 4px 12px rgba(30, 58, 138, 0.25)';
  const bannerTitleColor = isSkMode ? '#92400e' : '#fef08a';
  const bannerSubColor = isSkMode ? '#b45309' : '#ffffff';
  const bannerDateColor = isSkMode ? '#78350f' : '#fbbf24';
  const bannerSubText = isSkMode
    ? 'សម្រាប់បុគ្គលិកជំនាញ និងផ្នែកលក់ គិតលុយ'
    : (deptCategoryTab === 'worker' ? 'សម្រាប់ផ្នែកកម្មករ' : 'សម្រាប់បុគ្គលិកជំនាញ និងតាមឃ្លាំង');

  const tableHeaderBg = isSkMode ? '#d97706' : '#fde047';
  const tableHeaderTextColor = isSkMode ? '#ffffff' : '#000000';
  const tableSubHeaderBg = isSkMode ? '#f59e0b' : '#fef08a';
  const tableSubHeaderTextColor = isSkMode ? '#ffffff' : '#000000';
  const tableTotalColBg = isSkMode ? '#b45309' : '#facc15';
  const tableFooterBg = isSkMode ? '#d97706' : '#1e3a8a';
  const tableFooterLabelColor = isSkMode ? '#ffffff' : '#fef08a';
  const tableFooterNumColor = isSkMode ? '#ffffff' : '#60a5fa';
  const tableFooterGrandTotalColor = isSkMode ? '#fef08a' : '#facc15';

  // Resolved Display Records (Live API records if available, otherwise complete structured default roster)
  const displayLateRecords: LateSummaryRecord[] = (lateSummaryRecords && lateSummaryRecords.length > 0)
    ? lateSummaryRecords
    : (isSkMode ? DEFAULT_SK_LATE_RECORDS : DEFAULT_DEPT_LATE_RECORDS);

  // Auto-Sort: highest late total on top, keeping employee roster intact
  const sortedLateRecords = useMemo(() => {
    return [...displayLateRecords].sort((a, b) => {
      const diff = (b.total || 0) - (a.total || 0);
      if (diff !== 0) return diff;
      return (parseInt(a.employee_id, 10) || 0) - (parseInt(b.employee_id, 10) || 0);
    });
  }, [displayLateRecords]);

  const displayLateTotals = lateSummaryTotals.grand_total > 0
    ? lateSummaryTotals
    : {
        under_15: sortedLateRecords.reduce((s: number, r: LateSummaryRecord) => s + (r.under_15 || 0), 0),
        from_15_to_60: sortedLateRecords.reduce((s: number, r: LateSummaryRecord) => s + (r.from_15_to_60 || 0), 0),
        over_60: sortedLateRecords.reduce((s: number, r: LateSummaryRecord) => s + (r.over_60 || 0), 0),
        grand_total: sortedLateRecords.reduce((s: number, r: LateSummaryRecord) => s + (r.total || 0), 0),
      };

  const displayForgottenRecords: ForgottenScanRecord[] = (forgottenScanRecords && forgottenScanRecords.length > 0)
    ? forgottenScanRecords
    : (isSkMode ? DEFAULT_SK_FORGOTTEN_RECORDS : DEFAULT_DEPT_FORGOTTEN_RECORDS);

  // Auto-Sort: highest forgotten total on top, keeping employee roster intact
  const sortedForgottenRecords = useMemo(() => {
    return [...displayForgottenRecords].sort((a, b) => {
      const diff = (b.total || 0) - (a.total || 0);
      if (diff !== 0) return diff;
      return (parseInt(a.employee_id, 10) || 0) - (parseInt(b.employee_id, 10) || 0);
    });
  }, [displayForgottenRecords]);

  const displayForgottenTotals = forgottenScanTotals.grand_total > 0
    ? forgottenScanTotals
    : {
        forgot_in: sortedForgottenRecords.reduce((s: number, r: ForgottenScanRecord) => s + (r.forgot_in || 0), 0),
        forgot_out: sortedForgottenRecords.reduce((s: number, r: ForgottenScanRecord) => s + (r.forgot_out || 0), 0),
        grand_total: sortedForgottenRecords.reduce((s: number, r: ForgottenScanRecord) => s + (r.total || 0), 0),
        late_over_15: sortedForgottenRecords.reduce((s: number, r: ForgottenScanRecord) => s + (r.late_over_15 || 0), 0),
      };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
      {/* Print Styles for A4 Paper Layout */}
      <style>{`
        @media print {
          body * {
            visibility: hidden;
          }
          #a4-printable-report, #a4-printable-report * {
            visibility: visible;
          }
          #a4-printable-report {
            position: absolute;
            left: 0;
            top: 0;
            width: 100% !important;
            padding: 0 !important;
            margin: 0 !important;
            box-shadow: none !important;
            border: none !important;
            background: #ffffff !important;
          }
          .no-print {
            display: none !important;
          }
          @page {
            size: A4 portrait;
            margin: 12mm;
          }
        }
      `}</style>

      {/* Page Header Bar */}
      <div
        className="no-print"
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '14px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ width: '42px', height: '42px', borderRadius: '12px', background: 'var(--primary)', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 4px 12px rgba(99, 102, 241, 0.25)' }}>
            <FileSpreadsheet size={22} />
          </div>
          <div>
            <h2 style={{ fontSize: '19px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              របាយការណ៍វត្តមាន & វិភាគទិន្នន័យ (Attendance Reports)
            </h2>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              ទាញយក និងតាមដានវត្តមានស្កេនចូល/ចេញ របស់បុគ្គលិកតាមផ្នែក និងរបាយការណ៍លម្អិត
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <button
            onClick={() => {
              if (activeReportTab === 'leave_deo' || activeReportTab === 'combined') loadLeaveDeoAndCombined();
              else if (activeReportTab === 'late') loadLateSummary();
              else if (activeReportTab === 'forgotten') loadForgottenScan();
              else loadAttendance();
            }}
            className="btn btn-secondary btn-sm"
            style={{ borderRadius: '10px', padding: '8px 14px' }}
            title="Refresh"
          >
            <RefreshCw size={14} className={loading || loadingLeaveDeo || loadingLateSummary || loadingForgottenScan ? 'fa-spin' : ''} />
            <span>ផ្ទុកឡើងវិញ</span>
          </button>

          {(activeReportTab === 'late' || activeReportTab === 'forgotten') && (
            <button
              onClick={handlePrintA4}
              className="btn btn-primary btn-sm"
              style={{ borderRadius: '10px', padding: '8px 16px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Printer size={15} />
              <span>បោះពុម្ព A4 (Print PDF)</span>
            </button>
          )}

          <button
            onClick={handleExportCSV}
            className="btn btn-success btn-sm"
            style={{ borderRadius: '10px', padding: '8px 16px', fontWeight: 700 }}
          >
            <FileSpreadsheet size={15} />
            <span>Excel / CSV ({activeReportTab.toUpperCase()})</span>
          </button>

          {selectedRowIds.length > 0 && activeReportTab !== 'leave_deo' && activeReportTab !== 'combined' && activeReportTab !== 'late' && activeReportTab !== 'forgotten' && (
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

      {/* Success Notification */}
      {saveSuccessMsg && (
        <div className="no-print" style={{ background: '#dcfce7', border: '1px solid #86efac', color: '#15803d', padding: '10px 16px', borderRadius: '10px', fontSize: '13px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Check size={16} />
          <span>{saveSuccessMsg}</span>
        </div>
      )}

      {/* Primary Report Type Tabs matching admin_attendance.php */}
      <div
        className="hrm-card no-print"
        style={{
          padding: '8px 12px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          overflowX: 'auto',
          borderRadius: '14px',
        }}
      >
        {[
          { id: 'daily', label: '📅 វត្តមានប្រចាំថ្ងៃ (Daily Log)' },
          { id: 'late', label: '⚠️ មកយឺតសរុប (Late Summary A4)' },
          { id: 'forgotten', label: '❓ ភ្លេចស្កេន (Forgotten Scan A4)' },
          { id: 'leave_deo', label: '📝 សុំច្បាប់ & ដេអូស (Leave & Deo)' },
          { id: 'combined', label: '📊 របាយការណ៍រួម (318 / PSP / PRV)' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveReportTab(tab.id as any)}
            className={`btn btn-sm ${activeReportTab === tab.id ? 'btn-primary' : 'btn-secondary'}`}
            style={{ borderRadius: '10px', padding: '8px 16px', fontWeight: 700, fontSize: '13px', whiteSpace: 'nowrap' }}
          >
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* ========================================================================= */}
      {/* 1. LATE SUMMARY REPORT A4 VIEW (មកយឺតសរុប A4 Table) */}
      {/* ========================================================================= */}
      {activeReportTab === 'late' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Top Filter Bar for Late Summary */}
          <div
            className="hrm-card no-print"
            style={{
              padding: '16px 20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '14px',
              borderRadius: '16px',
            }}
          >
            {/* Department Category Buttons */}
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {[
                { id: 'department', label: '💼 ផ្នែករដ្ឋបាល/ជំនាញ' },
                { id: 'sk', label: '⭐ SKKS2/SKNR3' },
                { id: 'worker', label: '👥 ផ្នែកកម្មករ' },
                { id: 'all', label: '📋 ទាំងអស់ (All)' },
              ].map((d) => (
                <button
                  key={d.id}
                  type="button"
                  onClick={() => setDeptCategoryTab(d.id as any)}
                  className={`btn btn-sm ${deptCategoryTab === d.id ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ borderRadius: '8px', fontWeight: 700 }}
                >
                  <span>{d.label}</span>
                </button>
              ))}
            </div>

            {/* Date Range Selector */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-secondary)' }}>ចាប់ពីថ្ងៃ:</span>
                <input
                  type="date"
                  className="form-input"
                  value={reportStartDate}
                  onChange={(e) => setReportStartDate(e.target.value)}
                  style={{ height: '36px', borderRadius: '8px', fontSize: '13px', width: '150px' }}
                />
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-secondary)' }}>ដល់ថ្ងៃ:</span>
                <input
                  type="date"
                  className="form-input"
                  value={reportEndDate}
                  onChange={(e) => setReportEndDate(e.target.value)}
                  style={{ height: '36px', borderRadius: '8px', fontSize: '13px', width: '150px' }}
                />
              </div>

              <button
                onClick={handlePrintA4}
                className="btn btn-primary btn-sm"
                style={{ borderRadius: '8px', padding: '6px 14px', fontWeight: 700 }}
              >
                <Printer size={14} />
                <span>Print A4</span>
              </button>
            </div>
          </div>

          {/* A4 REPORT PAPER CONTAINER */}
          <div
            id="a4-printable-report"
            ref={printRef}
            style={{
              background: '#ffffff',
              color: '#000000',
              padding: '36px 40px',
              borderRadius: '16px',
              boxShadow: '0 8px 30px rgba(0,0,0,0.08)',
              maxWidth: '900px',
              margin: '0 auto',
              width: '100%',
              fontFamily: "'Hanuman', 'Khmer OS Battambang', sans-serif",
            }}
          >
            {/* 1. Header with Clean Dynamic Logo */}
            <div style={{ textAlign: 'center', marginBottom: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', marginBottom: '6px' }}>
                <img
                  src={activeLogoUrl}
                  alt="Organization Logo"
                  style={{ height: isSkMode ? '82px' : '78px', objectFit: 'contain' }}
                  onError={(e) => {
                    (e.target as HTMLElement).style.display = 'none';
                  }}
                />
              </div>

              {/* Dynamic Title Banner Box */}
              <div
                style={{
                  background: bannerBg,
                  border: bannerBorder,
                  boxShadow: bannerShadow,
                  padding: '12px 20px',
                  borderRadius: '10px',
                  marginTop: '10px',
                }}
              >
                <h2 style={{ fontSize: '18px', fontWeight: 800, margin: '0 0 4px 0', color: bannerTitleColor }}>
                  របាយការណ៍មកយឺតប្រចាំ{getKhmerDateHeader(reportStartDate)}
                </h2>
                <h3 style={{ fontSize: '14px', fontWeight: 700, margin: '0 0 4px 0', color: bannerSubColor }}>
                  {bannerSubText}
                </h3>
                <div style={{ fontSize: '12.5px', color: bannerDateColor, fontWeight: 600 }}>
                  {getKhmerDateRange()}
                </div>
              </div>
            </div>

            {/* 2. Late Summary A4 Table */}
            <div style={{ overflowX: 'auto', marginTop: '14px' }}>
              <table
                style={{
                  width: '100%',
                  borderCollapse: 'collapse',
                  border: '1.5px solid #000000',
                  fontSize: '12.5px',
                }}
              >
                <thead>
                  {/* Top Header */}
                  <tr style={{ background: tableHeaderBg, color: tableHeaderTextColor, textAlign: 'center', fontWeight: 800 }}>
                    <th rowSpan={2} style={{ border: '1px solid #000000', padding: '6px 4px', width: '40px' }}>ល.រ</th>
                    <th rowSpan={2} style={{ border: '1px solid #000000', padding: '6px 4px', width: '70px' }}>អត្តលេខ</th>
                    <th rowSpan={2} style={{ border: '1px solid #000000', padding: '6px 8px', textAlign: 'left', minWidth: '130px' }}>ឈ្មោះ</th>
                    <th rowSpan={2} style={{ border: '1px solid #000000', padding: '6px 4px', width: '55px' }}>ភេទ</th>
                    <th rowSpan={2} style={{ border: '1px solid #000000', padding: '6px 8px', textAlign: 'left', minWidth: '160px' }}>តួនាទី</th>
                    <th colSpan={3} style={{ border: '1px solid #000000', padding: '4px 6px', fontWeight: 900 }}>មកយឺត</th>
                    <th rowSpan={2} style={{ border: '1px solid #000000', padding: '6px 6px', width: '65px', background: tableTotalColBg, color: '#ffffff' }}>សរុប</th>
                  </tr>
                  <tr style={{ background: tableSubHeaderBg, color: tableSubHeaderTextColor, textAlign: 'center', fontWeight: 700, fontSize: '11px' }}>
                    <th style={{ border: '1px solid #000000', padding: '4px 6px', width: '75px' }}>ក្រោម ១៥ នាទី</th>
                    <th style={{ border: '1px solid #000000', padding: '4px 6px', width: '75px' }}>ចាប់ពី ១៥ នាទី</th>
                    <th style={{ border: '1px solid #000000', padding: '4px 6px', width: '75px' }}>ចាប់ពី១ម៉ោង</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedLateRecords.length === 0 ? (
                    <tr>
                      <td colSpan={9} style={{ textAlign: 'center', padding: '30px', border: '1px solid #000000', color: '#64748b' }}>
                        មិនមានទិន្នន័យបុគ្គលិកក្នុងចន្លោះកាលបរិច្ឆេទនេះឡើយ។
                      </td>
                    </tr>
                  ) : (
                    sortedLateRecords.map((r: LateSummaryRecord, idx: number) => {
                      const isHighLate = r.total >= 1;
                      const rowBg = isHighLate ? (isSkMode ? '#fef08a' : '#fef9c3') : '#ffffff';

                      return (
                        <tr key={r.employee_id || idx} style={{ background: rowBg }}>
                          <td style={{ border: '1px solid #000000', textAlign: 'center', fontWeight: 600, padding: '5px 4px' }}>
                            {idx + 1}
                          </td>
                          <td style={{ border: '1px solid #000000', textAlign: 'center', fontFamily: "'Outfit', monospace", fontWeight: 700, padding: '5px 4px' }}>
                            {r.employee_id}
                          </td>
                          <td style={{ border: '1px solid #000000', padding: '5px 8px', fontWeight: 800 }}>
                            {r.name}
                          </td>
                          <td style={{ border: '1px solid #000000', textAlign: 'center', padding: '5px 4px' }}>
                            {r.gender}
                          </td>
                          <td style={{ border: '1px solid #000000', padding: '5px 8px', fontSize: '12px' }}>
                            {r.role}
                          </td>
                          <td style={{ border: '1px solid #000000', textAlign: 'center', fontWeight: 700, color: r.under_15 > 0 ? (isSkMode ? '#000000' : '#1e3a8a') : '#ef4444' }}>
                            {r.under_15}
                          </td>
                          <td style={{ border: '1px solid #000000', textAlign: 'center', fontWeight: 700, color: r.from_15_to_60 > 0 ? (isSkMode ? '#000000' : '#1e3a8a') : '#ef4444' }}>
                            {r.from_15_to_60}
                          </td>
                          <td style={{ border: '1px solid #000000', textAlign: 'center', fontWeight: 700, color: r.over_60 > 0 ? (isSkMode ? '#000000' : '#1e3a8a') : '#ef4444' }}>
                            {r.over_60}
                          </td>
                          <td style={{ border: '1px solid #000000', textAlign: 'center', fontWeight: 900, background: isHighLate ? (isSkMode ? '#facc15' : '#fde047') : '#ffffff', color: r.total > 0 ? (isSkMode ? '#000000' : '#b45309') : '#ef4444' }}>
                            {r.total}
                          </td>
                        </tr>
                      );
                    })
                  )}

                  {/* Footer Totals Row */}
                  <tr style={{ background: tableFooterBg, color: '#ffffff', fontWeight: 900, fontSize: '13px' }}>
                    <td colSpan={5} style={{ border: '1px solid #000000', textAlign: 'center', padding: '8px', color: tableFooterLabelColor }}>
                      សរុប (Total)
                    </td>
                    <td style={{ border: '1px solid #000000', textAlign: 'center', padding: '8px', color: tableFooterNumColor }}>
                      {displayLateTotals.under_15}
                    </td>
                    <td style={{ border: '1px solid #000000', textAlign: 'center', padding: '8px', color: tableFooterNumColor }}>
                      {displayLateTotals.from_15_to_60}
                    </td>
                    <td style={{ border: '1px solid #000000', textAlign: 'center', padding: '8px', color: tableFooterNumColor }}>
                      {displayLateTotals.over_60}
                    </td>
                    <td style={{ border: '1px solid #000000', textAlign: 'center', padding: '8px', color: tableFooterGrandTotalColor, fontSize: '14px' }}>
                      {displayLateTotals.grand_total}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            {/* 3. Bottom Signatures and Date Section */}
            <div style={{ marginTop: '28px' }}>
              <div style={{ textAlign: 'right', fontSize: '12px', lineHeight: 1.6, color: '#1e293b' }}>
                <div>ថ្ងៃចន្ទ ១១កើត ខែស្រាពណ៍ ឆ្នាំម្សាញ់ ឆស័ក ពុទ្ធសករាជ ២៥៧០</div>
                <div style={{ fontWeight: 700 }}>រាជធានីភ្នំពេញ, ថ្ងៃទី២៤ ខែ សីហា ឆ្នាំ២០២៦</div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '16px', padding: '0 20px', fontSize: '13px' }}>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontWeight: 800, color: '#1e293b' }}>
                    ប្រធាននាយកដ្ឋានធនធានមនុស្ស និងរដ្ឋបាល
                  </div>
                  <div style={{ height: '70px' }}></div>
                  <div style={{ fontWeight: 800, color: '#0f172a' }}>លោក ផល សំអេងឡេង</div>
                </div>

                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontWeight: 800, color: '#1e293b' }}>
                    រៀបចំដោយ
                  </div>
                  <div style={{ height: '70px' }}></div>
                  <div style={{ fontWeight: 800, color: '#0f172a' }}>សៀង សារុន</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 2. FORGOTTEN SCAN REPORT A4 VIEW (ភ្លេចស្កេន A4 Table) */}
      {/* ========================================================================= */}
      {activeReportTab === 'forgotten' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Top Filter Bar for Forgotten Scan */}
          <div
            className="hrm-card no-print"
            style={{
              padding: '16px 20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '14px',
              borderRadius: '16px',
            }}
          >
            {/* Department Category Buttons */}
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {[
                { id: 'department', label: '💼 ផ្នែករដ្ឋបាល/ជំនាញ' },
                { id: 'sk', label: '⭐ SKKS2/SKNR3' },
                { id: 'worker', label: '👥 ផ្នែកកម្មករ' },
                { id: 'all', label: '📋 ទាំងអស់ (All)' },
              ].map((d) => (
                <button
                  key={d.id}
                  type="button"
                  onClick={() => setDeptCategoryTab(d.id as any)}
                  className={`btn btn-sm ${deptCategoryTab === d.id ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ borderRadius: '8px', fontWeight: 700 }}
                >
                  <span>{d.label}</span>
                </button>
              ))}
            </div>

            {/* Date Range Selector */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-secondary)' }}>ចាប់ពីថ្ងៃ:</span>
                <input
                  type="date"
                  className="form-input"
                  value={reportStartDate}
                  onChange={(e) => setReportStartDate(e.target.value)}
                  style={{ height: '36px', borderRadius: '8px', fontSize: '13px', width: '150px' }}
                />
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-secondary)' }}>ដល់ថ្ងៃ:</span>
                <input
                  type="date"
                  className="form-input"
                  value={reportEndDate}
                  onChange={(e) => setReportEndDate(e.target.value)}
                  style={{ height: '36px', borderRadius: '8px', fontSize: '13px', width: '150px' }}
                />
              </div>

              <button
                onClick={handlePrintA4}
                className="btn btn-primary btn-sm"
                style={{ borderRadius: '8px', padding: '6px 14px', fontWeight: 700 }}
              >
                <Printer size={14} />
                <span>Print A4</span>
              </button>
            </div>
          </div>

          {/* A4 REPORT PAPER CONTAINER */}
          <div
            id="a4-printable-report"
            ref={printRef}
            style={{
              background: '#ffffff',
              color: '#000000',
              padding: '36px 40px',
              borderRadius: '16px',
              boxShadow: '0 8px 30px rgba(0,0,0,0.08)',
              maxWidth: '900px',
              margin: '0 auto',
              width: '100%',
              fontFamily: "'Hanuman', 'Khmer OS Battambang', sans-serif",
            }}
          >
            {/* 1. Header with Clean Dynamic Logo */}
            <div style={{ textAlign: 'center', marginBottom: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', marginBottom: '6px' }}>
                <img
                  src={activeLogoUrl}
                  alt="Organization Logo"
                  style={{ height: isSkMode ? '82px' : '78px', objectFit: 'contain' }}
                  onError={(e) => {
                    (e.target as HTMLElement).style.display = 'none';
                  }}
                />
              </div>

              {/* Dynamic Title Banner Box */}
              <div
                style={{
                  background: bannerBg,
                  border: bannerBorder,
                  boxShadow: bannerShadow,
                  padding: '12px 20px',
                  borderRadius: '10px',
                  marginTop: '10px',
                }}
              >
                <h2 style={{ fontSize: '18px', fontWeight: 800, margin: '0 0 4px 0', color: bannerTitleColor }}>
                  {isSkMode ? `របាយការណ៍ភ្លេចស្កេនមេដៃប្រចាំ${getKhmerDateHeader(reportStartDate)}` : `របាយការណ៍បុគ្គលិកភ្លេចស្កេនលើHR Appប្រចាំ${getKhmerDateHeader(reportStartDate)}`}
                </h2>
                <h3 style={{ fontSize: '14px', fontWeight: 700, margin: '0 0 4px 0', color: bannerSubColor }}>
                  {bannerSubText}
                </h3>
                <div style={{ fontSize: '12.5px', color: bannerDateColor, fontWeight: 600 }}>
                  {getKhmerDateRange()}
                </div>
              </div>
            </div>

            {/* 2. Forgotten Scan A4 Table */}
            <div style={{ overflowX: 'auto', marginTop: '14px' }}>
              <table
                style={{
                  width: '100%',
                  borderCollapse: 'collapse',
                  border: '1.5px solid #000000',
                  fontSize: '12.5px',
                }}
              >
                <thead>
                  {/* Top Dynamic Header */}
                  <tr style={{ background: tableHeaderBg, color: tableHeaderTextColor, textAlign: 'center', fontWeight: 800 }}>
                    <th rowSpan={2} style={{ border: '1px solid #000000', padding: '6px 4px', width: '40px' }}>ល.រ</th>
                    <th rowSpan={2} style={{ border: '1px solid #000000', padding: '6px 4px', width: '70px' }}>អត្តលេខ</th>
                    <th rowSpan={2} style={{ border: '1px solid #000000', padding: '6px 8px', textAlign: 'left', minWidth: '130px' }}>ឈ្មោះ</th>
                    <th rowSpan={2} style={{ border: '1px solid #000000', padding: '6px 4px', width: '55px' }}>ភេទ</th>
                    <th rowSpan={2} style={{ border: '1px solid #000000', padding: '6px 8px', textAlign: 'left', minWidth: '160px' }}>តួនាទី</th>
                    <th colSpan={2} style={{ border: '1px solid #000000', padding: '4px 6px', fontWeight: 900 }}>ភ្លេចស្កេនមេដៃ</th>
                    <th rowSpan={2} style={{ border: '1px solid #000000', padding: '6px 6px', width: '65px', background: tableTotalColBg, color: '#ffffff' }}>សរុប</th>
                    <th rowSpan={2} style={{ border: '1px solid #000000', padding: '6px 6px', width: '120px', background: tableHeaderBg }}>ចំនួនយឺតលើស15នាទី</th>
                  </tr>
                  <tr style={{ background: tableSubHeaderBg, color: tableSubHeaderTextColor, textAlign: 'center', fontWeight: 700, fontSize: '11px' }}>
                    <th style={{ border: '1px solid #000000', padding: '4px 6px', width: '65px' }}>ចូល</th>
                    <th style={{ border: '1px solid #000000', padding: '4px 6px', width: '65px' }}>ចេញ</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedForgottenRecords.length === 0 ? (
                    <tr>
                      <td colSpan={9} style={{ textAlign: 'center', padding: '30px', border: '1px solid #000000', color: '#64748b' }}>
                        មិនមានទិន្នន័យបុគ្គលិកក្នុងចន្លោះកាលបរិច្ឆេទនេះឡើយ។
                      </td>
                    </tr>
                  ) : (
                    sortedForgottenRecords.map((r: ForgottenScanRecord, idx: number) => {
                      const isHigh = r.total >= 1;
                      const rowBg = isHigh ? (isSkMode ? '#fef08a' : '#fef9c3') : '#ffffff';

                      return (
                        <tr key={r.employee_id || idx} style={{ background: rowBg }}>
                          <td style={{ border: '1px solid #000000', textAlign: 'center', fontWeight: 600, padding: '5px 4px' }}>
                            {idx + 1}
                          </td>
                          <td style={{ border: '1px solid #000000', textAlign: 'center', fontFamily: "'Outfit', monospace", fontWeight: 700, padding: '5px 4px' }}>
                            {r.employee_id}
                          </td>
                          <td style={{ border: '1px solid #000000', padding: '5px 8px', fontWeight: 800 }}>
                            {r.name}
                          </td>
                          <td style={{ border: '1px solid #000000', textAlign: 'center', padding: '5px 4px' }}>
                            {r.gender}
                          </td>
                          <td style={{ border: '1px solid #000000', padding: '5px 8px', fontSize: '12px' }}>
                            {r.role}
                          </td>
                          <td style={{ border: '1px solid #000000', textAlign: 'center', fontWeight: 700, color: r.forgot_in > 0 ? (isSkMode ? '#000000' : '#1e3a8a') : '#ef4444' }}>
                            {r.forgot_in}
                          </td>
                          <td style={{ border: '1px solid #000000', textAlign: 'center', fontWeight: 700, color: r.forgot_out > 0 ? (isSkMode ? '#000000' : '#1e3a8a') : '#ef4444' }}>
                            {r.forgot_out}
                          </td>
                          <td style={{ border: '1px solid #000000', textAlign: 'center', fontWeight: 900, background: isHigh ? (isSkMode ? '#facc15' : '#fde047') : '#ffffff', color: r.total > 0 ? (isSkMode ? '#000000' : '#b45309') : '#ef4444' }}>
                            {r.total}
                          </td>
                          <td style={{ border: '1px solid #000000', textAlign: 'center', fontWeight: 700, color: r.late_over_15 > 0 ? (isSkMode ? '#000000' : '#1e3a8a') : '#ef4444' }}>
                            {r.late_over_15 > 0 ? r.late_over_15 : 0}
                          </td>
                        </tr>
                      );
                    })
                  )}

                  {/* Footer Totals Row */}
                  <tr style={{ background: tableFooterBg, color: '#ffffff', fontWeight: 900, fontSize: '13px' }}>
                    <td colSpan={5} style={{ border: '1px solid #000000', textAlign: 'center', padding: '8px', color: tableFooterLabelColor }}>
                      សរុប (Total)
                    </td>
                    <td style={{ border: '1px solid #000000', textAlign: 'center', padding: '8px', color: tableFooterNumColor }}>
                      {displayForgottenTotals.forgot_in}
                    </td>
                    <td style={{ border: '1px solid #000000', textAlign: 'center', padding: '8px', color: tableFooterNumColor }}>
                      {displayForgottenTotals.forgot_out}
                    </td>
                    <td style={{ border: '1px solid #000000', textAlign: 'center', padding: '8px', color: tableFooterGrandTotalColor, fontSize: '14px' }}>
                      {displayForgottenTotals.grand_total}
                    </td>
                    <td style={{ border: '1px solid #000000', textAlign: 'center', padding: '8px', color: tableFooterNumColor }}>
                      {displayForgottenTotals.late_over_15}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            {/* 3. Bottom Signatures and Date Section */}
            <div style={{ marginTop: '28px' }}>
              <div style={{ textAlign: 'right', fontSize: '12px', lineHeight: 1.6, color: '#1e293b' }}>
                <div>ថ្ងៃចន្ទ ១១កើត ខែស្រាពណ៍ ឆ្នាំម្សាញ់ ឆស័ក ពុទ្ធសករាជ ២៥៧០</div>
                <div style={{ fontWeight: 700 }}>រាជធានីភ្នំពេញ, ថ្ងៃទី២៤ ខែ សីហា ឆ្នាំ២០២៦</div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '16px', padding: '0 20px', fontSize: '13px' }}>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontWeight: 800, color: '#1e293b' }}>
                    ប្រធាននាយកដ្ឋានធនធានមនុស្ស និងរដ្ឋបាល
                  </div>
                  <div style={{ height: '70px' }}></div>
                  <div style={{ fontWeight: 800, color: '#0f172a' }}>លោក ផល សំអេងឡេង</div>
                </div>

                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontWeight: 800, color: '#1e293b' }}>
                    រៀបចំដោយ
                  </div>
                  <div style={{ height: '70px' }}></div>
                  <div style={{ fontWeight: 800, color: '#0f172a' }}>សៀង សារុន</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 3. LEAVE & DEO REPORT VIEW (admin_attendance.php?action=leave_deo_report) */}
      {/* ========================================================================= */}
      {activeReportTab === 'leave_deo' && (
        <div className="hrm-card" style={{ padding: 0, borderRadius: '18px', overflow: 'hidden' }}>
          {/* Branch Sub-Tabs matching legacy */}
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
            {[
              { id: '318', label: '🏬 Store 318' },
              { id: 'ks2', label: '🏭 Warehouse PSP (KS2)' },
              { id: 'nr3', label: '🏪 Store NR3 (PRV)' },
              { id: 'all', label: '🏢 សាខាទាំងអស់ (All Stores)' },
            ].map((store) => (
              <button
                key={store.id}
                type="button"
                onClick={() => setSelectedStore(store.id)}
                style={{
                  padding: '14px 20px',
                  border: 'none',
                  background: 'transparent',
                  fontWeight: 700,
                  fontSize: '13.5px',
                  cursor: 'pointer',
                  color: selectedStore === store.id ? 'var(--primary)' : 'var(--text-secondary)',
                  borderBottom: selectedStore === store.id ? '3px solid var(--primary)' : '3px solid transparent',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  transition: 'all 0.2s ease',
                  whiteSpace: 'nowrap',
                }}
              >
                <span>{store.label}</span>
              </button>
            ))}
          </div>

          {/* Filter Toolbar */}
          <div
            style={{
              padding: '18px 24px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '14px',
              borderBottom: '1px solid var(--border)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-secondary)' }}>
                កាលបរិច្ឆេទរាយការណ៍:
              </span>
              <input
                type="date"
                className="form-input"
                value={selectedDate || new Date().toISOString().split('T')[0]}
                onChange={(e) => setSelectedDate(e.target.value)}
                style={{ height: '38px', borderRadius: '10px', fontSize: '13px', width: '160px' }}
              />
            </div>

            <button
              type="button"
              onClick={handleAddNewLeaveDeoRow}
              className="btn btn-primary btn-sm"
              style={{ borderRadius: '10px', padding: '8px 18px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Plus size={16} />
              <span>បន្ថែមជួរដេកថ្មី (Add Row)</span>
            </button>
          </div>

          {/* Leave & Deo Table */}
          <div className="table-container" style={{ border: 'none', boxShadow: 'none' }}>
            <table className="hrm-table">
              <thead>
                <tr>
                  <th style={{ width: '60px', textAlign: 'center' }}>ល.រ</th>
                  <th style={{ width: '22%' }}>ឈ្មោះបុគ្គលិក</th>
                  <th style={{ width: '20%' }}>តួនាទី / ផ្នែក</th>
                  <th>អធិប្បាយ / មូលហេតុសុំច្បាប់ & ដេអូស</th>
                  <th style={{ width: '140px', textAlign: 'center' }}>ថ្ងៃរាយការណ៍</th>
                  <th style={{ width: '90px', textAlign: 'center' }}>សកម្មភាព</th>
                </tr>
              </thead>
              <tbody>
                {leaveDeoRecords.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-muted)' }}>
                      <FileText size={36} style={{ margin: '0 auto 10px auto', opacity: 0.3, display: 'block' }} />
                      <div>មិនមានទិន្នន័យសុំច្បាប់ ឬដេអូសសម្រាប់ថ្ងៃនេះឡើយ។</div>
                      <button
                        type="button"
                        onClick={handleAddNewLeaveDeoRow}
                        className="btn btn-secondary btn-sm"
                        style={{ marginTop: '12px', borderRadius: '8px' }}
                      >
                        + ចុចដើម្បីបន្ថែមជួរដេកថ្មី
                      </button>
                    </td>
                  </tr>
                ) : (
                  leaveDeoRecords.map((row, idx) => (
                    <tr key={row.id}>
                      <td style={{ textAlign: 'center' }}>
                        <input
                          type="text"
                          defaultValue={row.number || String(idx + 1)}
                          onBlur={(e) => handleUpdateLeaveDeoCell(row.id, 'number', e.target.value)}
                          style={{ width: '100%', border: 'none', background: 'transparent', textAlign: 'center', fontWeight: 700, outline: 'none' }}
                        />
                      </td>
                      <td>
                        <input
                          type="text"
                          defaultValue={row.name}
                          placeholder="បញ្ចូលឈ្មោះ..."
                          onBlur={(e) => handleUpdateLeaveDeoCell(row.id, 'name', e.target.value)}
                          style={{ width: '100%', border: 'none', background: 'transparent', fontWeight: 800, color: 'var(--primary)', outline: 'none', fontSize: '14px' }}
                        />
                      </td>
                      <td>
                        <input
                          type="text"
                          defaultValue={row.role}
                          placeholder="បញ្ចូលតួនាទី..."
                          onBlur={(e) => handleUpdateLeaveDeoCell(row.id, 'role', e.target.value)}
                          style={{ width: '100%', border: 'none', background: 'transparent', color: 'var(--text-secondary)', outline: 'none', fontSize: '13px' }}
                        />
                      </td>
                      <td>
                        <input
                          type="text"
                          defaultValue={row.note}
                          placeholder="បញ្ចូលមូលហេតុសុំច្បាប់ / ដេអូស..."
                          onBlur={(e) => handleUpdateLeaveDeoCell(row.id, 'note', e.target.value)}
                          style={{ width: '100%', border: 'none', background: 'transparent', outline: 'none', fontSize: '13px' }}
                        />
                      </td>
                      <td style={{ textAlign: 'center', fontFamily: "'Outfit', monospace", fontSize: '13px' }}>
                        {row.reports_date || selectedDate}
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        <button
                          type="button"
                          onClick={() => handleDeleteLeaveDeoRow(row.id)}
                          className="btn btn-danger btn-sm"
                          style={{ padding: '4px 10px', borderRadius: '6px', fontSize: '11.5px' }}
                        >
                          លុប
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Approved system leave requests if any */}
          {approvedLeaves.length > 0 && (
            <div style={{ padding: '20px 24px', background: 'var(--surface-alt)', borderTop: '1px solid var(--border)' }}>
              <h4 style={{ margin: '0 0 12px 0', fontSize: '14px', fontWeight: 800, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <CheckCircle2 size={16} color="#16a34a" />
                <span>ពាក្យសុំច្បាប់ដែលបានអនុម័តក្នុងប្រព័ន្ធ (Approved System Leaves)</span>
              </h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: '12px' }}>
                {approvedLeaves.map((al) => (
                  <div key={al.id} style={{ padding: '12px', background: 'var(--surface)', borderRadius: '10px', border: '1px solid var(--border)', fontSize: '12.5px' }}>
                    <div style={{ fontWeight: 800, color: 'var(--primary)' }}>{al.name}</div>
                    <div style={{ color: 'var(--text-muted)' }}>ប្រភេទ៖ {al.role}</div>
                    <div>មូលហេតុ៖ {al.note || 'គ្មាន'}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* 4. COMBINED REPORT VIEW (318 / KS2 / NR3 Consolidated with Inline Editing) */}
      {/* ========================================================================= */}
      {activeReportTab === 'combined' && (() => {
        const storeConfigs = {
          ks2: {
            label: 'ផ្សារក្បាលកោះ២',
            departments: [
              { key: 'cosmetic', label: 'បុគ្គលិកសរុប' },
              { key: 'intern', label: 'អនុប្រធានស្តុក' },
              { key: 'stock', label: 'ផ្នែកស្តុក' },
              { key: 'sales', label: 'ផ្នែកលក់' },
              { key: 'cashier', label: 'ផ្នែកគិតលុយ' },
              { key: 'delivery', label: 'ផ្នែកដឹកជញ្ជូន' },
            ],
          },
          nr3: {
            label: 'NR3',
            departments: [
              { key: 'store', label: 'បុគ្គលិក NR3' },
              { key: 'intern', label: 'អនុប្រធាន' },
              { key: 'stock', label: 'ផ្នែកស្តុក' },
              { key: 'sales', label: 'ផ្នែកលក់' },
              { key: 'cashier', label: 'ផ្នែកគិតលុយ' },
            ],
          },
          '318': {
            label: 'ហាងទំនិញ ៣១៨',
            departments: [
              { key: 'store', label: 'បុគ្គលិកហាងទំនិញ៣១៨' },
              { key: 'intern', label: 'បុគ្គលិកកម្មករ' },
              { key: 'stock', label: 'ផ្នែកស្តុក' },
              { key: 'sales', label: 'ផ្នែកលក់' },
              { key: 'cashier', label: 'ផ្នែកគិតលុយ' },
            ],
          },
        };

        const curStore = (selectedStore === 'ks2' || selectedStore === 'nr3' || selectedStore === '318') ? selectedStore : '318';
        const curConfig = storeConfigs[curStore];

        const getVal = (col: string) => {
          const v = consolidatedData[col];
          return v !== undefined && v !== null ? Number(v) : 0;
        };

        // Calculations for KS2
        const morningFemaleRowTotal = curConfig.departments.reduce((acc, d) => acc + getVal(`${d.key}_female_morning`), 0);
        const morningMaleRowTotal = curConfig.departments.reduce((acc, d) => acc + getVal(`${d.key}_male_morning`), 0);
        const morningGrandTotal = morningFemaleRowTotal + morningMaleRowTotal;

        const eveningFemaleRowTotal = curConfig.departments.reduce((acc, d) => acc + getVal(`${d.key}_female_evening`), 0);
        const eveningMaleRowTotal = curConfig.departments.reduce((acc, d) => acc + getVal(`${d.key}_male_evening`), 0);
        const eveningGrandTotal = eveningFemaleRowTotal + eveningMaleRowTotal;

        const finalGrandTotalKs2 = morningGrandTotal + eveningGrandTotal;

        // Calculations for NR3 & 318
        const femaleRowTotal = curConfig.departments.reduce((acc, d) => acc + getVal(`${d.key}_female`), 0);
        const maleRowTotal = curConfig.departments.reduce((acc, d) => acc + getVal(`${d.key}_male`), 0);
        const standardGrandTotal = femaleRowTotal + maleRowTotal;

        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            {/* Store Tabs & Filter Card */}
            <div className="hrm-card no-print" style={{ padding: '16px 20px', borderRadius: '18px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '14px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  {[
                    { id: '318', label: '🏬 ហាងទំនិញ ៣១៨' },
                    { id: 'ks2', label: '🏪 ផ្សារក្បាលកោះ២ (KS2)' },
                    { id: 'nr3', label: '🏪 សាខា NR3' },
                  ].map((store) => (
                    <button
                      key={store.id}
                      type="button"
                      onClick={() => setSelectedStore(store.id)}
                      className={`btn btn-sm ${selectedStore === store.id ? 'btn-primary' : 'btn-secondary'}`}
                      style={{
                        padding: '10px 18px',
                        borderRadius: '12px',
                        fontWeight: 800,
                        fontSize: '13.5px',
                        transition: 'all 0.2s ease',
                      }}
                    >
                      <span>{store.label}</span>
                    </button>
                  ))}
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span style={{ fontSize: '13.5px', fontWeight: 700, color: 'var(--text-secondary)' }}>កាលបរិច្ឆេទ:</span>
                  <input
                    type="date"
                    className="form-input"
                    value={selectedDate || new Date().toISOString().split('T')[0]}
                    onChange={(e) => setSelectedDate(e.target.value)}
                    style={{ height: '40px', borderRadius: '10px', fontSize: '13.5px', width: '165px', fontWeight: 700 }}
                  />
                  <button
                    type="button"
                    onClick={loadLeaveDeoAndCombined}
                    className="btn btn-secondary btn-sm"
                    style={{ height: '40px', borderRadius: '10px', padding: '0 14px', fontWeight: 700 }}
                    title="Refresh Data"
                  >
                    <RefreshCw size={15} className={loadingLeaveDeo ? 'animate-spin' : ''} />
                  </button>
                </div>
              </div>
            </div>

            {/* Printable Report Canvas */}
            <div
              className="hrm-card printable-report-card"
              style={{
                padding: '36px 40px',
                borderRadius: '20px',
                background: '#ffffff',
                color: '#0f172a',
                boxShadow: '0 4px 20px rgba(0,0,0,0.06)',
              }}
            >
              {/* Header Title Section matching Mobile App / public_report.php */}
              <div style={{ textAlign: 'center', marginBottom: '28px' }}>
                <h1
                  style={{
                    fontSize: '24px',
                    fontWeight: 900,
                    color: '#05165e',
                    margin: '0 0 6px 0',
                    fontFamily: "'Hanuman', 'Khmer OS Battambang', serif",
                  }}
                >
                  របាយការណ៍វត្តមានបុគ្គលិក - {curConfig.label}
                </h1>
                <h2
                  style={{
                    fontSize: '16px',
                    fontWeight: 700,
                    color: '#05165e',
                    margin: '0 0 16px 0',
                    fontFamily: "'Hanuman', 'Khmer OS Battambang', serif",
                  }}
                >
                  {formatKhmerDateString(getActiveDate())}
                </h2>
                <h3
                  style={{
                    fontSize: '18px',
                    fontWeight: 800,
                    color: '#05165e',
                    margin: 0,
                    fontFamily: "'Hanuman', 'Khmer OS Battambang', serif",
                  }}
                >
                  ចំនួនបុគ្គលិកតាមផ្នែក
                </h3>
              </div>

              {/* Matrix Table with Navy Blue Header & Direct Inline Editor */}
              <div style={{ overflowX: 'auto', marginBottom: '36px' }}>
                <table
                  style={{
                    width: '100%',
                    borderCollapse: 'collapse',
                    textAlign: 'center',
                    fontFamily: "'Hanuman', 'Khmer OS Battambang', sans-serif",
                    fontSize: '14px',
                  }}
                >
                  <thead>
                    <tr style={{ background: '#05165e', color: '#ffffff' }}>
                      <th
                        colSpan={curStore === 'ks2' ? 2 : 1}
                        style={{
                          border: '1px solid #0d288a',
                          padding: '12px 8px',
                          color: '#ffffff',
                          fontWeight: 800,
                          fontSize: '14.5px',
                          background: '#05165e',
                        }}
                      >
                        ព័ត៌មាន
                      </th>
                      {curConfig.departments.map((d) => (
                        <th
                          key={d.key}
                          style={{
                            border: '1px solid #0d288a',
                            padding: '12px 8px',
                            color: '#ffffff',
                            fontWeight: 800,
                            fontSize: '14.5px',
                            background: '#05165e',
                          }}
                        >
                          {d.label}
                        </th>
                      ))}
                      <th
                        style={{
                          border: '1px solid #0d288a',
                          padding: '12px 8px',
                          color: '#ffffff',
                          fontWeight: 800,
                          fontSize: '14.5px',
                          background: '#05165e',
                          width: '110px',
                        }}
                      >
                        សរុបរួម
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {curStore === 'ks2' ? (
                      <>
                        {/* Morning Shift */}
                        <tr>
                          <th
                            rowSpan={3}
                            style={{
                              border: '1px solid #dee2e6',
                              background: '#f8f9fa',
                              fontWeight: 800,
                              width: '90px',
                              color: '#0f172a',
                            }}
                          >
                            វេនព្រឹក
                          </th>
                          <th
                            style={{
                              border: '1px solid #dee2e6',
                              background: '#f8f9fa',
                              fontWeight: 700,
                              width: '75px',
                              color: '#ec4899',
                            }}
                          >
                            ស្រី
                          </th>
                          {curConfig.departments.map((d) => {
                            const colKey = `${d.key}_female_morning`;
                            return (
                              <td key={colKey} style={{ border: '1px solid #dee2e6', padding: '4px' }}>
                                <input
                                  type="number"
                                  min="0"
                                  className="form-input"
                                  value={getVal(colKey)}
                                  onChange={(e) => handleUpdateConsolidatedCell(colKey, parseInt(e.target.value) || 0)}
                                  style={{
                                    width: '100%',
                                    textAlign: 'center',
                                    fontWeight: 700,
                                    height: '36px',
                                    border: savingCellKey === colKey ? '2px solid #22c55e' : '1px solid transparent',
                                    background: 'transparent',
                                    color: '#0f172a',
                                  }}
                                />
                              </td>
                            );
                          })}
                          <td style={{ border: '1px solid #dee2e6', fontWeight: 800, color: '#ec4899' }}>
                            {morningFemaleRowTotal}
                          </td>
                        </tr>

                        <tr>
                          <th
                            style={{
                              border: '1px solid #dee2e6',
                              background: '#f8f9fa',
                              fontWeight: 700,
                              color: '#3b82f6',
                            }}
                          >
                            ប្រុស
                          </th>
                          {curConfig.departments.map((d) => {
                            const colKey = `${d.key}_male_morning`;
                            return (
                              <td key={colKey} style={{ border: '1px solid #dee2e6', padding: '4px' }}>
                                <input
                                  type="number"
                                  min="0"
                                  className="form-input"
                                  value={getVal(colKey)}
                                  onChange={(e) => handleUpdateConsolidatedCell(colKey, parseInt(e.target.value) || 0)}
                                  style={{
                                    width: '100%',
                                    textAlign: 'center',
                                    fontWeight: 700,
                                    height: '36px',
                                    border: savingCellKey === colKey ? '2px solid #22c55e' : '1px solid transparent',
                                    background: 'transparent',
                                    color: '#0f172a',
                                  }}
                                />
                              </td>
                            );
                          })}
                          <td style={{ border: '1px solid #dee2e6', fontWeight: 800, color: '#3b82f6' }}>
                            {morningMaleRowTotal}
                          </td>
                        </tr>

                        <tr style={{ background: '#f1f3f5', fontWeight: 800 }}>
                          <td style={{ border: '1px solid #dee2e6', color: '#0f172a' }}>សរុប (ព្រឹក)</td>
                          {curConfig.departments.map((d) => {
                            const sumMorning = getVal(`${d.key}_female_morning`) + getVal(`${d.key}_male_morning`);
                            return (
                              <td key={d.key} style={{ border: '1px solid #dee2e6', color: '#0f172a' }}>
                                {sumMorning}
                              </td>
                            );
                          })}
                          <td style={{ border: '1px solid #dee2e6', color: '#05165e', fontSize: '15px' }}>
                            {morningGrandTotal}
                          </td>
                        </tr>

                        {/* Evening Shift */}
                        <tr>
                          <th
                            rowSpan={3}
                            style={{
                              border: '1px solid #dee2e6',
                              background: '#f8f9fa',
                              fontWeight: 800,
                              color: '#0f172a',
                            }}
                          >
                            វេនល្ងាច
                          </th>
                          <th
                            style={{
                              border: '1px solid #dee2e6',
                              background: '#f8f9fa',
                              fontWeight: 700,
                              color: '#ec4899',
                            }}
                          >
                            ស្រី
                          </th>
                          {curConfig.departments.map((d) => {
                            const colKey = `${d.key}_female_evening`;
                            return (
                              <td key={colKey} style={{ border: '1px solid #dee2e6', padding: '4px' }}>
                                <input
                                  type="number"
                                  min="0"
                                  className="form-input"
                                  value={getVal(colKey)}
                                  onChange={(e) => handleUpdateConsolidatedCell(colKey, parseInt(e.target.value) || 0)}
                                  style={{
                                    width: '100%',
                                    textAlign: 'center',
                                    fontWeight: 700,
                                    height: '36px',
                                    border: savingCellKey === colKey ? '2px solid #22c55e' : '1px solid transparent',
                                    background: 'transparent',
                                    color: '#0f172a',
                                  }}
                                />
                              </td>
                            );
                          })}
                          <td style={{ border: '1px solid #dee2e6', fontWeight: 800, color: '#ec4899' }}>
                            {eveningFemaleRowTotal}
                          </td>
                        </tr>

                        <tr>
                          <th
                            style={{
                              border: '1px solid #dee2e6',
                              background: '#f8f9fa',
                              fontWeight: 700,
                              color: '#3b82f6',
                            }}
                          >
                            ប្រុស
                          </th>
                          {curConfig.departments.map((d) => {
                            const colKey = `${d.key}_male_evening`;
                            return (
                              <td key={colKey} style={{ border: '1px solid #dee2e6', padding: '4px' }}>
                                <input
                                  type="number"
                                  min="0"
                                  className="form-input"
                                  value={getVal(colKey)}
                                  onChange={(e) => handleUpdateConsolidatedCell(colKey, parseInt(e.target.value) || 0)}
                                  style={{
                                    width: '100%',
                                    textAlign: 'center',
                                    fontWeight: 700,
                                    height: '36px',
                                    border: savingCellKey === colKey ? '2px solid #22c55e' : '1px solid transparent',
                                    background: 'transparent',
                                    color: '#0f172a',
                                  }}
                                />
                              </td>
                            );
                          })}
                          <td style={{ border: '1px solid #dee2e6', fontWeight: 800, color: '#3b82f6' }}>
                            {eveningMaleRowTotal}
                          </td>
                        </tr>

                        <tr style={{ background: '#f1f3f5', fontWeight: 800 }}>
                          <td style={{ border: '1px solid #dee2e6', color: '#0f172a' }}>សរុប (ល្ងាច)</td>
                          {curConfig.departments.map((d) => {
                            const sumEvening = getVal(`${d.key}_female_evening`) + getVal(`${d.key}_male_evening`);
                            return (
                              <td key={d.key} style={{ border: '1px solid #dee2e6', color: '#0f172a' }}>
                                {sumEvening}
                              </td>
                            );
                          })}
                          <td style={{ border: '1px solid #dee2e6', color: '#05165e', fontSize: '15px' }}>
                            {eveningGrandTotal}
                          </td>
                        </tr>
                      </>
                    ) : (
                      <>
                        {/* Standard NR3 & 318 Rows */}
                        <tr>
                          <th
                            style={{
                              border: '1px solid #dee2e6',
                              background: '#f8f9fa',
                              fontWeight: 700,
                              width: '130px',
                              color: '#ec4899',
                            }}
                          >
                            ស្រី
                          </th>
                          {curConfig.departments.map((d) => {
                            const colKey = `${d.key}_female`;
                            return (
                              <td key={colKey} style={{ border: '1px solid #dee2e6', padding: '4px' }}>
                                <input
                                  type="number"
                                  min="0"
                                  className="form-input"
                                  value={getVal(colKey)}
                                  onChange={(e) => handleUpdateConsolidatedCell(colKey, parseInt(e.target.value) || 0)}
                                  style={{
                                    width: '100%',
                                    textAlign: 'center',
                                    fontWeight: 700,
                                    height: '36px',
                                    border: savingCellKey === colKey ? '2px solid #22c55e' : '1px solid transparent',
                                    background: 'transparent',
                                    color: '#0f172a',
                                  }}
                                />
                              </td>
                            );
                          })}
                          <td style={{ border: '1px solid #dee2e6', fontWeight: 800, color: '#ec4899' }}>
                            {femaleRowTotal}
                          </td>
                        </tr>

                        <tr>
                          <th
                            style={{
                              border: '1px solid #dee2e6',
                              background: '#f8f9fa',
                              fontWeight: 700,
                              color: '#3b82f6',
                            }}
                          >
                            ប្រុស
                          </th>
                          {curConfig.departments.map((d) => {
                            const colKey = `${d.key}_male`;
                            return (
                              <td key={colKey} style={{ border: '1px solid #dee2e6', padding: '4px' }}>
                                <input
                                  type="number"
                                  min="0"
                                  className="form-input"
                                  value={getVal(colKey)}
                                  onChange={(e) => handleUpdateConsolidatedCell(colKey, parseInt(e.target.value) || 0)}
                                  style={{
                                    width: '100%',
                                    textAlign: 'center',
                                    fontWeight: 700,
                                    height: '36px',
                                    border: savingCellKey === colKey ? '2px solid #22c55e' : '1px solid transparent',
                                    background: 'transparent',
                                    color: '#0f172a',
                                  }}
                                />
                              </td>
                            );
                          })}
                          <td style={{ border: '1px solid #dee2e6', fontWeight: 800, color: '#3b82f6' }}>
                            {maleRowTotal}
                          </td>
                        </tr>
                      </>
                    )}
                  </tbody>

                  {/* Grand Total Footer */}
                  <tfoot>
                    <tr style={{ background: '#f1f3f5', fontWeight: 900 }}>
                      <th
                        colSpan={curStore === 'ks2' ? 2 : 1}
                        style={{
                          border: '1px solid #dee2e6',
                          background: '#f1f3f5',
                          color: '#05165e',
                          padding: '12px 8px',
                          fontSize: '14.5px',
                        }}
                      >
                        សរុបរួមតាមផ្នែក
                      </th>
                      {curConfig.departments.map((d) => {
                        const totalDept = curStore === 'ks2'
                          ? getVal(`${d.key}_female_morning`) + getVal(`${d.key}_male_morning`) + getVal(`${d.key}_female_evening`) + getVal(`${d.key}_male_evening`)
                          : getVal(`${d.key}_female`) + getVal(`${d.key}_male`);
                        return (
                          <td
                            key={d.key}
                            style={{
                              border: '1px solid #dee2e6',
                              color: '#05165e',
                              padding: '12px 8px',
                              fontSize: '14.5px',
                            }}
                          >
                            {totalDept}
                          </td>
                        );
                      })}
                      <td
                        style={{
                          border: '1px solid #dee2e6',
                          color: '#05165e',
                          padding: '12px 8px',
                          fontSize: '16px',
                        }}
                      >
                        {curStore === 'ks2' ? finalGrandTotalKs2 : standardGrandTotal}
                      </td>
                    </tr>
                  </tfoot>
                </table>
              </div>

              {/* Sub-Table: Staff on Leave / Deo / New staff on this date */}
              <div>
                <div style={{ textAlign: 'center', marginBottom: '18px' }}>
                  <h3
                    style={{
                      fontSize: '18px',
                      fontWeight: 800,
                      color: '#05165e',
                      margin: 0,
                      fontFamily: "'Hanuman', 'Khmer OS Battambang', serif",
                    }}
                  >
                    បុគ្គលិកសុំច្បាប់, ដេអូស, ប្ដូរដេអូស និងចូលថ្មី
                  </h3>
                </div>

                <div style={{ overflowX: 'auto' }}>
                  <table
                    style={{
                      width: '100%',
                      borderCollapse: 'collapse',
                      textAlign: 'left',
                      fontFamily: "'Hanuman', 'Khmer OS Battambang', sans-serif",
                      fontSize: '14px',
                    }}
                  >
                    <thead>
                      <tr style={{ background: '#05165e', color: '#ffffff' }}>
                        <th style={{ border: '1px solid #0d288a', padding: '10px 8px', width: '70px', textAlign: 'center', color: '#fff' }}>
                          ល.រ
                        </th>
                        <th style={{ border: '1px solid #0d288a', padding: '10px 12px', width: '22%', color: '#fff' }}>
                          ឈ្មោះ
                        </th>
                        <th style={{ border: '1px solid #0d288a', padding: '10px 12px', width: '20%', color: '#fff' }}>
                          តួនាទី
                        </th>
                        <th style={{ border: '1px solid #0d288a', padding: '10px 12px', color: '#fff' }}>
                          អធិប្បាយ
                        </th>
                        <th style={{ border: '1px solid #0d288a', padding: '10px 8px', width: '130px', textAlign: 'center', color: '#fff' }}>
                          ថ្ងៃរាយការណ៍
                        </th>
                        <th className="no-print" style={{ border: '1px solid #0d288a', padding: '10px 8px', width: '70px', textAlign: 'center', color: '#fff' }}>
                          សកម្មភាព
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {leaveDeoRecords.length === 0 ? (
                        <tr>
                          <td colSpan={6} style={{ textAlign: 'center', padding: '20px', color: '#64748b', border: '1px solid #dee2e6' }}>
                            មិនមានទិន្នន័យសម្រាប់ថ្ងៃនេះទេ។
                          </td>
                        </tr>
                      ) : (
                        leaveDeoRecords.map((r, i) => (
                          <tr key={r.id}>
                            <td style={{ border: '1px solid #dee2e6', padding: '4px', textAlign: 'center' }}>
                              <input
                                type="text"
                                className="form-input"
                                value={r.number || String(i + 1)}
                                onChange={(e) => handleUpdateLeaveDeoCell(r.id, 'number', e.target.value)}
                                style={{
                                  width: '100%',
                                  textAlign: 'center',
                                  fontWeight: 700,
                                  border: '1px solid transparent',
                                  background: 'transparent',
                                  height: '34px',
                                }}
                              />
                            </td>
                            <td style={{ border: '1px solid #dee2e6', padding: '4px' }}>
                              <input
                                type="text"
                                className="form-input"
                                placeholder="ឈ្មោះបុគ្គលិក..."
                                value={r.name || ''}
                                onChange={(e) => handleUpdateLeaveDeoCell(r.id, 'name', e.target.value)}
                                style={{
                                  width: '100%',
                                  fontWeight: 800,
                                  color: '#05165e',
                                  border: '1px solid transparent',
                                  background: 'transparent',
                                  height: '34px',
                                }}
                              />
                            </td>
                            <td style={{ border: '1px solid #dee2e6', padding: '4px' }}>
                              <input
                                type="text"
                                className="form-input"
                                placeholder="តួនាទី..."
                                value={r.role || ''}
                                onChange={(e) => handleUpdateLeaveDeoCell(r.id, 'role', e.target.value)}
                                style={{
                                  width: '100%',
                                  fontWeight: 600,
                                  border: '1px solid transparent',
                                  background: 'transparent',
                                  height: '34px',
                                }}
                              />
                            </td>
                            <td style={{ border: '1px solid #dee2e6', padding: '4px' }}>
                              <input
                                type="text"
                                className="form-input"
                                placeholder="សរសេរការអធិប្បាយ..."
                                value={r.note || ''}
                                onChange={(e) => handleUpdateLeaveDeoCell(r.id, 'note', e.target.value)}
                                style={{
                                  width: '100%',
                                  border: '1px solid transparent',
                                  background: 'transparent',
                                  height: '34px',
                                }}
                              />
                            </td>
                            <td style={{ border: '1px solid #dee2e6', padding: '4px', textAlign: 'center', fontFamily: "'Outfit', monospace" }}>
                              {r.reports_date || getActiveDate()}
                            </td>
                            <td className="no-print" style={{ border: '1px solid #dee2e6', padding: '4px', textAlign: 'center' }}>
                              <button
                                type="button"
                                onClick={() => handleDeleteLeaveDeoRow(r.id)}
                                className="btn btn-danger btn-sm"
                                style={{ padding: '3px 8px', borderRadius: '6px', fontSize: '11px' }}
                              >
                                លុប
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>

                <div className="no-print" style={{ marginTop: '14px', display: 'flex', justifyContent: 'flex-start' }}>
                  <button
                    type="button"
                    onClick={handleAddNewLeaveDeoRow}
                    className="btn btn-primary btn-sm"
                    style={{ borderRadius: '8px', padding: '7px 16px', fontWeight: 700 }}
                  >
                    <Plus size={15} />
                    <span>+ បន្ថែមជួរដេក</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        );
      })()}

      {/* ========================================================================= */}
      {/* 5. DAILY REPORT VIEW */}
      {/* ========================================================================= */}
      {activeReportTab === 'daily' && (
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
                  placeholder="ស្វែងរកឈ្មោះ, ID, Noted..."
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

          {/* Table View matching admin_attendance.php 100% */}
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
                  <th style={{ minWidth: '150px' }}>NOTED</th>
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

                        {/* Interactive Click-to-Edit NOTED Cell */}
                        <td
                          onClick={() => handleOpenNoteEditor(log)}
                          title="ចុចដើម្បីកែប្រែចំណាំ / Click to edit note"
                          style={{
                            fontSize: '12.5px',
                            cursor: 'pointer',
                            transition: 'background 0.2s ease',
                            position: 'relative',
                            paddingRight: '28px',
                          }}
                          onMouseEnter={(e) => {
                            (e.currentTarget as HTMLElement).style.background = 'rgba(99, 102, 241, 0.08)';
                          }}
                          onMouseLeave={(e) => {
                            (e.currentTarget as HTMLElement).style.background = isSelected ? 'rgba(99, 102, 241, 0.04)' : '';
                          }}
                        >
                          <div style={{ maxWidth: '220px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {renderNotedContent(log.noted)}
                          </div>
                          <Edit3
                            size={13}
                            color="var(--primary)"
                            style={{
                              position: 'absolute',
                              right: '8px',
                              top: '50%',
                              transform: 'translateY(-50%)',
                              opacity: 0.6,
                            }}
                          />
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
        </div>
      )}

      {/* Edit Note Modal */}
      <Modal
        isOpen={!!editingNoteRecord}
        onClose={() => setEditingNoteRecord(null)}
        title={`កែប្រែចំណាំ (Edit Note) - ${editingNoteRecord?.name || ''}`}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '6px 0' }}>
          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '6px' }}>
              ខ្លឹមសារចំណាំ (Text or Link URL):
            </label>
            <textarea
              rows={4}
              className="form-input"
              value={editingNoteValue}
              onChange={(e) => setEditingNoteValue(e.target.value)}
              placeholder="បញ្ចូលអត្ថបទចំណាំ ឬ Link ទីនេះ..."
              style={{ width: '100%', borderRadius: '10px', padding: '12px', fontSize: '13.5px', resize: 'vertical' }}
              autoFocus
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
            <button
              type="button"
              onClick={() => setEditingNoteRecord(null)}
              className="btn btn-secondary"
              style={{ borderRadius: '10px', padding: '8px 18px' }}
            >
              បោះបង់
            </button>
            <button
              type="button"
              onClick={handleSaveNote}
              disabled={isSavingNote}
              className="btn btn-primary"
              style={{ borderRadius: '10px', padding: '8px 22px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              {isSavingNote ? <RefreshCw size={14} className="fa-spin" /> : <Save size={15} />}
              <span>{isSavingNote ? 'កំពុងរក្សាទុក...' : 'រក្សាទុក (Save)'}</span>
            </button>
          </div>
        </div>
      </Modal>

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
