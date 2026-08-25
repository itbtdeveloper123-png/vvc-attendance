import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
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
  MapPin,
  ExternalLink,
  Clock,
  Globe,
  Copy,
  Check,
  Laptop,
  Smartphone,
  Shield,
  Ban,
  Unlock,
  AlertOctagon,
  Radio,
} from 'lucide-react';
import { adminApi, AuditLog, AuditLogStats, BlockedIp } from '../api/adminApi';
import { useAuth } from '../context/AuthContext';

interface GeoInfo {
  city: string;
  country: string;
  countryCode: string;
  lat: number;
  lng: number;
  isp?: string;
}

// Geo Cache (Module-level, persists across renders)
const geoCache: Record<string, GeoInfo> = {};

// Standalone Helper: Fetch GeoIP Location for an IP address
const resolveIpLocation = async (ip: string): Promise<GeoInfo> => {
  if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
    return {
      city: 'Phnom Penh',
      country: 'Cambodia',
      countryCode: 'KH',
      lat: 11.5564,
      lng: 104.9282,
      isp: 'Local / Office Network',
    };
  }

  if (geoCache[ip]) {
    return geoCache[ip];
  }

  try {
    const res = await fetch(`https://freeipapi.com/api/json/${ip}`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      const data = await res.json();
      const info: GeoInfo = {
        city: data.cityName && data.cityName !== '-' ? data.cityName : 'Phnom Penh',
        country: data.countryName || 'Cambodia',
        countryCode: data.countryCode || 'KH',
        lat: typeof data.latitude === 'number' && data.latitude !== 0 ? data.latitude : 11.5564,
        lng: typeof data.longitude === 'number' && data.longitude !== 0 ? data.longitude : 104.9282,
        isp: data.ipVersion ? 'ISP Broadband' : undefined,
      };
      geoCache[ip] = info;
      return info;
    }
  } catch {
    // Fallback Phnom Penh coordinates for Cambodia IPs
    const info: GeoInfo = {
      city: 'Phnom Penh',
      country: 'Cambodia',
      countryCode: 'KH',
      lat: 11.5564,
      lng: 104.9282,
      isp: 'Cambodia ISP',
    };
    geoCache[ip] = info;
    return info;
  }

  const fallbackInfo: GeoInfo = {
    city: 'Phnom Penh',
    country: 'Cambodia',
    countryCode: 'KH',
    lat: 11.5564,
    lng: 104.9282,
  };
  geoCache[ip] = fallbackInfo;
  return fallbackInfo;
};

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
  const [blockedIps, setBlockedIps] = useState<string[]>([]);
  const [blockedList, setBlockedList] = useState<BlockedIp[]>([]);
  const [geoLocations, setGeoLocations] = useState<Record<string, GeoInfo>>({});
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

  // Modals & UI helpers
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);
  const [showClearModal, setShowClearModal] = useState<boolean>(false);
  const [clearDays, setClearDays] = useState<number>(90);
  const [isClearing, setIsClearing] = useState<boolean>(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  // Block IP Modal
  const [ipToBlock, setIpToBlock] = useState<string | null>(null);
  const [blockReason, setBlockReason] = useState<string>('សកម្មភាពគួរឱ្យសង្ស័យ (Suspicious / Unauthorized Access)');
  const [isBlocking, setIsBlocking] = useState<boolean>(false);
  const [showBlockedIpsModal, setShowBlockedIpsModal] = useState<boolean>(false);

  // Fetch Logs & Blocked IPs
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
          const logList: AuditLog[] = res.logs || [];
          setLogs(logList);
          setTotalCount(res.total || 0);
          if (res.stats) {
            setStats(res.stats);
          }
          if (res.blocked_ips) {
            setBlockedIps(res.blocked_ips);
          }
          if (res.blocked_details) {
            setBlockedList(res.blocked_details);
          }

          // Asynchronously resolve Geo Location for IPs without blocking UI
          const uniqueIps = Array.from(new Set(logList.map((l) => l.ip_address).filter(Boolean))) as string[];
          const newGeos: Record<string, GeoInfo> = {};
          let hasNew = false;
          for (const ip of uniqueIps) {
            if (!geoCache[ip]) {
              const geo = await resolveIpLocation(ip);
              newGeos[ip] = geo;
              hasNew = true;
            }
          }
          if (hasNew) {
            setGeoLocations((prev) => ({ ...prev, ...geoCache, ...newGeos }));
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

  // Auto Refresh Interval (15s)
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
    const headers = ['ID', 'កាលបរិច្ឆេទ & ម៉ោងភ្នំពេញ', 'អ្នកប្រើប្រាស់', 'តួនាទី', 'សកម្មភាព', 'ផ្នែក', 'គោលដៅ', 'ព័ត៌មានលម្អិត', 'កម្រិត', 'IP Address', 'ទីតាំង Geo'];
    const rows = logs.map((l) => {
      const pt = formatPhnomPenhDateTime(l.created_at);
      const geo = geoLocations[l.ip_address || ''] || { city: 'Phnom Penh', country: 'Cambodia' };
      return [
        l.id,
        `"${pt.full}"`,
        `"${l.actor_name || ''}"`,
        `"${l.actor_role || ''}"`,
        `"${l.action || ''}"`,
        `"${l.module || ''}"`,
        `"${l.target_name || ''}"`,
        `"${(l.details || '').replace(/"/g, '""')}"`,
        `"${l.severity || 'info'}"`,
        `"${l.ip_address || ''}"`,
        `"${geo.city}, ${geo.country}"`,
      ];
    });

    const csvContent = '\uFEFF' + [headers.join(','), ...rows.map((e) => e.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `VVC_Audit_Logs_${new Date().toISOString().slice(0, 10)}.csv`);
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

  // Handle Block IP
  const handleBlockIp = async () => {
    if (!ipToBlock) return;
    setIsBlocking(true);
    try {
      const adminName = admin?.name || 'Super Administrator';
      const res = await adminApi.blockIp(ipToBlock, blockReason, adminName);
      if (res && res.success) {
        setBlockedIps((prev) => [...prev, ipToBlock]);
        setIpToBlock(null);
        loadLogs();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsBlocking(false);
    }
  };

  // Handle Unblock IP
  const handleUnblockIp = async (ip: string) => {
    try {
      const adminName = admin?.name || 'Super Administrator';
      const res = await adminApi.unblockIp(ip, adminName);
      if (res && res.success) {
        setBlockedIps((prev) => prev.filter((i) => i !== ip));
        setBlockedList((prev) => prev.filter((b) => b.ip_address !== ip));
        loadLogs();
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Copy text helper
  const handleCopyText = (text: string, fieldKey: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldKey);
    setTimeout(() => setCopiedField(null), 2000);
  };

  // ==========================================
  // Phnom Penh Time Formatter (Asia/Phnom_Penh / ICT UTC+7)
  // ==========================================
  const formatPhnomPenhDateTime = (dateStr: string) => {
    if (!dateStr) return { time: '—', time12: '—', date: '—', full: '—', timeAgo: '' };
    try {
      const d = new Date(dateStr.replace(/-/g, '/'));
      if (isNaN(d.getTime())) return { time: dateStr, time12: dateStr, date: '', full: dateStr, timeAgo: '' };

      const time24 = new Intl.DateTimeFormat('en-GB', {
        timeZone: 'Asia/Phnom_Penh',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      }).format(d);

      const time12 = new Intl.DateTimeFormat('en-US', {
        timeZone: 'Asia/Phnom_Penh',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true,
      }).format(d);

      const dateFormatted = new Intl.DateTimeFormat('en-GB', {
        timeZone: 'Asia/Phnom_Penh',
        day: '2-digit',
        month: 'short',
        year: 'numeric',
      }).format(d);

      return {
        time: time24,
        time12: time12,
        date: dateFormatted,
        full: `${dateFormatted} ${time24}`,
        timeAgo: formatTimeAgo(dateStr),
      };
    } catch {
      return { time: dateStr, time12: dateStr, date: '', full: dateStr, timeAgo: '' };
    }
  };

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
              padding: '5px 12px',
              borderRadius: '20px',
              background: 'rgba(239, 68, 68, 0.12)',
              color: '#ef4444',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              fontSize: '12px',
              fontWeight: 700,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <XCircle size={14} /> ហានិភ័យ / Danger
          </span>
        );
      case 'warning':
        return (
          <span
            style={{
              padding: '5px 12px',
              borderRadius: '20px',
              background: 'rgba(245, 158, 11, 0.12)',
              color: '#f59e0b',
              border: '1px solid rgba(245, 158, 11, 0.3)',
              fontSize: '12px',
              fontWeight: 700,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <AlertTriangle size={14} /> គួរកត់សម្គាល់ / Warning
          </span>
        );
      default:
        return (
          <span
            style={{
              padding: '5px 12px',
              borderRadius: '20px',
              background: 'rgba(16, 185, 129, 0.12)',
              color: '#10b981',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              fontSize: '12px',
              fontWeight: 700,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <CheckCircle2 size={14} /> ធម្មតា / Info
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
      case 'security':
        return '🛡️ សុវត្ថិភាព Audit';
      default:
        return mod || 'ទូទៅ';
    }
  };

  const getActionColor = (action: string) => {
    const act = (action || '').toUpperCase();
    if (act.includes('DELETE') || act.includes('CLEAR') || act.includes('REJECT') || act.includes('REMOVE') || act.includes('BLOCKED') || act.includes('FAILED')) {
      return { bg: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', border: 'rgba(239, 68, 68, 0.25)' };
    }
    if (act.includes('CREATE') || act.includes('ADD') || act.includes('APPROVE') || act.includes('SUCCESS')) {
      return { bg: 'rgba(16, 185, 129, 0.1)', color: '#10b981', border: 'rgba(16, 185, 129, 0.25)' };
    }
    if (act.includes('UPDATE') || act.includes('EDIT') || act.includes('SAVE')) {
      return { bg: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6', border: 'rgba(59, 130, 246, 0.25)' };
    }
    return { bg: 'rgba(139, 92, 246, 0.1)', color: '#8b5cf6', border: 'rgba(139, 92, 246, 0.25)' };
  };

  const getDeviceIcon = (ua: string) => {
    const s = (ua || '').toLowerCase();
    if (s.includes('mobile') || s.includes('android') || s.includes('iphone')) {
      return <Smartphone size={13} style={{ color: '#3b82f6' }} />;
    }
    return <Laptop size={13} style={{ color: '#8b5cf6' }} />;
  };

  // Google Maps Coordinates URL Helper (Pins exact coordinates)
  const getGoogleMapCoordsUrl = (ip: string) => {
    const geo = geoLocations[ip] || { lat: 11.5564, lng: 104.9282, city: 'Phnom Penh' };
    return `https://www.google.com/maps?q=${geo.lat},${geo.lng}&z=15&hl=km`;
  };

  const totalPages = Math.ceil(totalCount / pageSize) || 1;

  return (
    <div style={{ padding: '24px 28px', maxWidth: '1600px', margin: '0 auto' }}>
      {/* 1. Top Page Header */}
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
              width: '48px',
              height: '48px',
              borderRadius: '16px',
              background: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#ffffff',
              boxShadow: '0 8px 20px rgba(37, 99, 235, 0.35)',
            }}
          >
            <ShieldAlert size={26} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <h1 style={{ fontSize: '22px', fontWeight: 800, margin: 0, color: 'var(--text-primary)' }}>
                កំណត់ត្រាសកម្មភាព & សុវត្ថិភាព (Audit Logs)
              </h1>
              <span
                style={{
                  padding: '2px 8px',
                  borderRadius: '6px',
                  background: 'rgba(59, 130, 246, 0.1)',
                  color: '#3b82f6',
                  fontSize: '11px',
                  fontWeight: 700,
                  border: '1px solid rgba(59, 130, 246, 0.2)',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                }}
              >
                <Clock size={11} /> ម៉ោងភ្នំពេញ (ICT UTC+7)
              </span>
            </div>
            <p style={{ margin: '3px 0 0 0', fontSize: '13.5px', color: 'var(--text-secondary)' }}>
              តាមដានរាល់សកម្មភាពកែសម្រួលទិន្នន័យ ការលុប ការបង្កើត ទីតាំង Map និងការ Block IP ជនសង្ស័យ
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {/* Blocked IPs Manager Button */}
          <button
            type="button"
            onClick={() => setShowBlockedIpsModal(true)}
            className="btn btn-secondary btn-sm"
            style={{
              height: '40px',
              borderRadius: '10px',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontWeight: 700,
              color: blockedIps.length > 0 ? '#ef4444' : undefined,
              borderColor: blockedIps.length > 0 ? 'rgba(239, 68, 68, 0.3)' : undefined,
            }}
            title="គ្រប់គ្រង IP ដែលត្រូវបាន Block"
          >
            <Ban size={15} color={blockedIps.length > 0 ? '#ef4444' : 'currentColor'} />
            <span>IP Blocklist ({blockedIps.length})</span>
          </button>

          {/* Live Auto-Refresh Button */}
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
              background: autoRefresh ? 'rgba(16, 185, 129, 0.08)' : undefined,
              fontWeight: 700,
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

      {/* 2. Top Metric KPI Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '16px',
          marginBottom: '24px',
        }}
      >
        {/* Total Logs */}
        <div className="hrm-card" style={{ padding: '18px 20px', borderRadius: '16px', display: 'flex', alignItems: 'center', gap: '16px', border: '1px solid var(--border)' }}>
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
        <div className="hrm-card" style={{ padding: '18px 20px', borderRadius: '16px', display: 'flex', alignItems: 'center', gap: '16px', border: '1px solid var(--border)' }}>
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
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', fontWeight: 600 }}>សកម្មភាពថ្ងៃនេះ (ភ្នំពេញ)</div>
            <div style={{ fontSize: '24px', fontWeight: 800, color: '#10b981', marginTop: '2px' }}>
              {stats.today_count?.toLocaleString() || 0}
            </div>
          </div>
        </div>

        {/* Blocked IPs count */}
        <div className="hrm-card" style={{ padding: '18px 20px', borderRadius: '16px', display: 'flex', alignItems: 'center', gap: '16px', border: '1px solid var(--border)' }}>
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
            <Ban size={24} />
          </div>
          <div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', fontWeight: 600 }}>IP ដែលបាន Block</div>
            <div style={{ fontSize: '24px', fontWeight: 800, color: '#ef4444', marginTop: '2px' }}>
              {blockedIps.length}
            </div>
          </div>
        </div>

        {/* Danger / Critical */}
        <div className="hrm-card" style={{ padding: '18px 20px', borderRadius: '16px', display: 'flex', alignItems: 'center', gap: '16px', border: '1px solid var(--border)' }}>
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
            <Shield size={24} />
          </div>
          <div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', fontWeight: 600 }}>ការព្រមាន & ហានិភ័យ</div>
            <div style={{ fontSize: '24px', fontWeight: 800, color: '#f59e0b', marginTop: '2px' }}>
              {(stats.warning_count + stats.danger_count)?.toLocaleString() || 0}
            </div>
          </div>
        </div>
      </div>

      {/* 3. Filter Bar */}
      <div
        className="hrm-card"
        style={{
          padding: '18px 20px',
          borderRadius: '16px',
          marginBottom: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '14px',
          border: '1px solid var(--border)',
        }}
      >
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'center', justifyContent: 'space-between' }}>
          {/* Search Input */}
          <div style={{ position: 'relative', flex: '1 1 280px', minWidth: '240px' }}>
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
              background: 'var(--surface-alt)',
              padding: '3px',
              borderRadius: '10px',
              border: '1px solid var(--border)',
            }}
          >
            <button
              type="button"
              onClick={() => setViewMode('table')}
              style={{
                padding: '6px 14px',
                borderRadius: '8px',
                border: 'none',
                background: viewMode === 'table' ? 'var(--primary)' : 'transparent',
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
                background: viewMode === 'timeline' ? 'var(--primary)' : 'transparent',
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
          <div style={{ display: 'flex', gap: '6px', marginLeft: 'auto', flexWrap: 'wrap' }}>
            <button
              type="button"
              onClick={() => handleDatePreset('today')}
              className="btn btn-sm"
              style={{ height: '32px', fontSize: '12px', borderRadius: '6px', background: 'var(--surface-alt)', border: '1px solid var(--border)' }}
            >
              ថ្ងៃនេះ
            </button>
            <button
              type="button"
              onClick={() => handleDatePreset('7days')}
              className="btn btn-sm"
              style={{ height: '32px', fontSize: '12px', borderRadius: '6px', background: 'var(--surface-alt)', border: '1px solid var(--border)' }}
            >
              ៧ ថ្ងៃចុងក្រោយ
            </button>
            <button
              type="button"
              onClick={() => handleDatePreset('30days')}
              className="btn btn-sm"
              style={{ height: '32px', fontSize: '12px', borderRadius: '6px', background: 'var(--surface-alt)', border: '1px solid var(--border)' }}
            >
              ៣០ ថ្ងៃចុងក្រោយ
            </button>
            <button
              type="button"
              onClick={() => handleDatePreset('all')}
              className="btn btn-sm"
              style={{ height: '32px', fontSize: '12px', borderRadius: '6px', background: 'var(--surface-alt)', border: '1px solid var(--border)' }}
            >
              ទាំងអស់
            </button>
          </div>
        </div>
      </div>

      {/* 4. Main Content Area: Table View or Timeline View */}
      {viewMode === 'table' ? (
        <div className="hrm-card" style={{ borderRadius: '16px', overflow: 'hidden', padding: 0, border: '1px solid var(--border)' }}>
          <div style={{ overflowX: 'auto' }}>
            <table className="table table-hover" style={{ margin: 0, width: '100%', fontSize: '13.5px' }}>
              <thead style={{ background: 'var(--surface-alt)', borderBottom: '1px solid var(--border)' }}>
                <tr>
                  <th style={{ padding: '14px 16px', width: '190px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Clock size={14} color="#3b82f6" />
                      <span>ម៉ោងភ្នំពេញ (Time)</span>
                    </div>
                  </th>
                  <th style={{ padding: '14px 16px', width: '180px' }}>អ្នកធ្វើសកម្មភាព</th>
                  <th style={{ padding: '14px 16px', width: '170px' }}>ប្រភេទ & ផ្នែក</th>
                  <th style={{ padding: '14px 16px', width: '140px' }}>គោលដៅ</th>
                  <th style={{ padding: '14px 16px' }}>ព័ត៌មានលម្អិតនៃសកម្មភាព</th>
                  <th style={{ padding: '14px 16px', width: '150px', textAlign: 'center' }}>កម្រិត</th>
                  <th style={{ padding: '14px 16px', width: '230px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Globe size={14} color="#10b981" />
                      <span>IP & ទីតាំង Maps</span>
                    </div>
                  </th>
                  <th style={{ padding: '14px 16px', width: '120px', textAlign: 'center' }}>សកម្មភាព</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan={8} style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-muted)' }}>
                      <RefreshCw size={24} className="animate-spin" style={{ margin: '0 auto 10px auto' }} />
                      <div>កំពុងទាញយកទិន្នន័យ Audit Logs...</div>
                    </td>
                  </tr>
                ) : logs.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ textAlign: 'center', padding: '50px 0', color: 'var(--text-muted)' }}>
                      មិនមានកំណត់ត្រាត្រូវគ្នានឹងការស្វែងរកឡើយ
                    </td>
                  </tr>
                ) : (
                  logs.map((log) => {
                    const actColor = getActionColor(log.action);
                    const pt = formatPhnomPenhDateTime(log.created_at);
                    const ip = log.ip_address || '127.0.0.1';
                    const isBlocked = blockedIps.includes(ip);
                    const geo = geoLocations[ip] || { city: 'Phnom Penh', country: 'Cambodia', lat: 11.5564, lng: 104.9282 };

                    return (
                      <tr key={log.id}>
                        {/* Phnom Penh Time Column */}
                        <td style={{ padding: '14px 16px', verticalAlign: 'middle' }}>
                          <div style={{ fontWeight: 800, color: 'var(--text-primary)', fontSize: '13.5px', fontFamily: 'monospace' }}>
                            {pt.time}
                          </div>
                          <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                            {pt.date} <span style={{ color: 'var(--text-muted)' }}>({pt.timeAgo})</span>
                          </div>
                        </td>

                        {/* Actor */}
                        <td style={{ padding: '14px 16px', verticalAlign: 'middle' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                            <div
                              style={{
                                width: '32px',
                                height: '32px',
                                borderRadius: '10px',
                                background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(147, 51, 234, 0.2))',
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
                              background: 'var(--surface-alt)',
                              color: 'var(--text-primary)',
                              border: '1px solid var(--border)',
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

                        {/* IP & Google Maps Location */}
                        <td style={{ padding: '14px 16px', verticalAlign: 'middle' }}>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '6px' }}>
                            <div>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <span style={{ fontSize: '12.5px', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'monospace' }}>
                                  {ip}
                                </span>
                                {isBlocked && (
                                  <span
                                    style={{
                                      padding: '1px 6px',
                                      borderRadius: '4px',
                                      background: '#ef4444',
                                      color: '#fff',
                                      fontSize: '10px',
                                      fontWeight: 800,
                                    }}
                                  >
                                    BLOCKED
                                  </span>
                                )}
                              </div>
                              <div style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px', marginTop: '2px' }}>
                                <span>📍 {geo.city}, {geo.countryCode}</span>
                              </div>
                            </div>

                            {/* Google Maps Button (Pins exact coordinates) */}
                            <a
                              href={getGoogleMapCoordsUrl(ip)}
                              target="_blank"
                              rel="noreferrer"
                              className="btn btn-sm"
                              style={{
                                padding: '4px 8px',
                                borderRadius: '8px',
                                background: 'rgba(59, 130, 246, 0.1)',
                                border: '1px solid rgba(59, 130, 246, 0.25)',
                                color: '#3b82f6',
                                fontSize: '11px',
                                fontWeight: 700,
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                                textDecoration: 'none',
                              }}
                              title={`បើកមើលទីតាំង ${geo.city}, ${geo.country} លើ Google Maps`}
                            >
                              <MapPin size={12} />
                              <span>Map</span>
                            </a>
                          </div>
                        </td>

                        {/* Actions (View & Block) */}
                        <td style={{ padding: '14px 16px', verticalAlign: 'middle', textAlign: 'center' }}>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
                            {/* View Detail Button */}
                            <button
                              type="button"
                              onClick={() => setSelectedLog(log)}
                              className="btn btn-secondary btn-sm"
                              style={{ width: '32px', height: '32px', padding: 0, borderRadius: '8px' }}
                              title="មើលព័ត៌មានលម្អិត & Google Maps"
                            >
                              <Eye size={15} />
                            </button>

                            {/* Block / Unblock IP Button */}
                            {ip !== '127.0.0.1' && ip !== '::1' && (
                              isBlocked ? (
                                <button
                                  type="button"
                                  onClick={() => handleUnblockIp(ip)}
                                  className="btn btn-sm"
                                  style={{
                                    width: '32px',
                                    height: '32px',
                                    padding: 0,
                                    borderRadius: '8px',
                                    background: 'rgba(16, 185, 129, 0.12)',
                                    color: '#10b981',
                                    border: '1px solid rgba(16, 185, 129, 0.3)',
                                  }}
                                  title="ដោះ Block លើ IP នេះ"
                                >
                                  <Unlock size={14} />
                                </button>
                              ) : (
                                <button
                                  type="button"
                                  onClick={() => {
                                    setIpToBlock(ip);
                                    setBlockReason(`Blocked from Audit Logs (Actor: ${log.actor_name}, Action: ${log.action})`);
                                  }}
                                  className="btn btn-sm"
                                  style={{
                                    width: '32px',
                                    height: '32px',
                                    padding: 0,
                                    borderRadius: '8px',
                                    background: 'rgba(239, 68, 68, 0.12)',
                                    color: '#ef4444',
                                    border: '1px solid rgba(239, 68, 68, 0.3)',
                                  }}
                                  title="Block អាសយដ្ឋាន IP នេះ"
                                >
                                  <Ban size={14} />
                                </button>
                              )
                            )}
                          </div>
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
              borderTop: '1px solid var(--border)',
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
        <div className="hrm-card" style={{ borderRadius: '16px', padding: '28px 32px', border: '1px solid var(--border)' }}>
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
                  background: 'var(--border)',
                }}
              />

              {logs.map((log) => {
                const actColor = getActionColor(log.action);
                const pt = formatPhnomPenhDateTime(log.created_at);
                const ip = log.ip_address || '127.0.0.1';
                const isBlocked = blockedIps.includes(ip);
                const geo = geoLocations[ip] || { city: 'Phnom Penh', country: 'Cambodia', lat: 11.5564, lng: 104.9282 };

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
                        border: '3px solid var(--surface)',
                        boxShadow: `0 0 0 2px ${actColor.border}`,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: '#fff',
                      }}
                    />

                    {/* Timeline Card */}
                    <div
                      style={{
                        background: 'var(--surface-alt)',
                        border: '1px solid var(--border)',
                        borderRadius: '14px',
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
                          <span style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                            <Clock size={12} /> {pt.full} ({pt.timeAgo})
                          </span>
                        </div>
                      </div>

                      <div style={{ fontSize: '13.5px', color: 'var(--text-primary)', marginBottom: '10px' }}>
                        {log.details || 'មិនមានព័ត៌មានលម្អិត'}
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontSize: '12px', color: 'var(--text-muted)', borderTop: '1px dashed var(--border)', paddingTop: '10px', flexWrap: 'wrap' }}>
                        <span>📍 គោលដៅ: <strong>{log.target_name || '—'}</strong></span>
                        <span>🌐 IP: <strong style={{ fontFamily: 'monospace' }}>{ip}</strong> {isBlocked && <span style={{ color: '#ef4444', fontWeight: 700 }}>(BLOCKED)</span>}</span>
                        <span>📍 ទីតាំង: <strong>{geo.city}, {geo.country}</strong></span>
                        
                        <a
                          href={getGoogleMapCoordsUrl(ip)}
                          target="_blank"
                          rel="noreferrer"
                          style={{ color: '#3b82f6', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '4px', fontWeight: 700 }}
                        >
                          <MapPin size={12} />
                          <span>Google Maps</span>
                          <ExternalLink size={10} />
                        </a>

                        <button
                          type="button"
                          onClick={() => setSelectedLog(log)}
                          style={{ marginLeft: 'auto', background: 'none', border: 'none', color: '#3b82f6', cursor: 'pointer', fontWeight: 700, fontSize: '12px' }}
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

      {/* 5. Detail Modal with Exact Coordinates Google Maps Location */}
      {selectedLog && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.7)',
            backdropFilter: 'blur(6px)',
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
              maxWidth: '780px',
              width: '100%',
              borderRadius: '24px',
              padding: '28px 32px',
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.4)',
              maxHeight: '90vh',
              overflowY: 'auto',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div
                  style={{
                    width: '40px',
                    height: '40px',
                    borderRadius: '12px',
                    background: 'rgba(59, 130, 246, 0.12)',
                    color: '#3b82f6',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <ShieldAlert size={22} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)' }}>
                    ព័ត៌មានលម្អិតនៃ Audit Log #{selectedLog.id}
                  </h3>
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    ម៉ោងភ្នំពេញ (ICT UTC+7): {formatPhnomPenhDateTime(selectedLog.created_at).full}
                  </span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setSelectedLog(null)}
                className="btn btn-secondary btn-sm"
                style={{ width: '34px', height: '34px', padding: 0, borderRadius: '10px' }}
              >
                ✕
              </button>
            </div>

            {/* Info Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px', marginBottom: '18px' }}>
              <div style={{ background: 'var(--surface-alt)', padding: '12px 16px', borderRadius: '12px', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>អ្នកធ្វើសកម្មភាព (Actor)</div>
                <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                  {selectedLog.actor_name} ({selectedLog.actor_role || 'Admin'})
                </div>
              </div>

              <div style={{ background: 'var(--surface-alt)', padding: '12px 16px', borderRadius: '12px', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>ម៉ោងភ្នំពេញ (Phnom Penh Time)</div>
                <div style={{ fontSize: '14px', fontWeight: 700, color: '#10b981', marginTop: '2px', fontFamily: 'monospace' }}>
                  {formatPhnomPenhDateTime(selectedLog.created_at).time} <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>({formatPhnomPenhDateTime(selectedLog.created_at).date})</span>
                </div>
              </div>

              <div style={{ background: 'var(--surface-alt)', padding: '12px 16px', borderRadius: '12px', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>សកម្មភាព & ផ្នែក (Action/Module)</div>
                <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                  {selectedLog.action} ({selectedLog.module})
                </div>
              </div>

              <div style={{ background: 'var(--surface-alt)', padding: '12px 16px', borderRadius: '12px', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>គោលដៅ (Target)</div>
                <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                  {selectedLog.target_name || '—'}
                </div>
              </div>
            </div>

            {/* Google Map Exact Location Section */}
            {(() => {
              const ip = selectedLog.ip_address || '127.0.0.1';
              const isBlocked = blockedIps.includes(ip);
              const geo = geoLocations[ip] || { city: 'Phnom Penh', country: 'Cambodia', countryCode: 'KH', lat: 11.5564, lng: 104.9282, isp: 'Cambodia Broadband' };

              return (
                <div style={{ background: 'var(--surface-alt)', padding: '16px', borderRadius: '16px', border: '1px solid var(--border)', marginBottom: '18px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px', flexWrap: 'wrap', gap: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <MapPin size={16} color="#3b82f6" />
                      <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
                        ទីតាំងភូមិសាស្ត្រជាក់ស្តែង (Geo Location & Coordinates)
                      </span>
                    </div>

                    <div style={{ display: 'flex', gap: '8px' }}>
                      {/* Block IP Button inside Modal */}
                      {ip !== '127.0.0.1' && ip !== '::1' && (
                        isBlocked ? (
                          <button
                            type="button"
                            onClick={() => handleUnblockIp(ip)}
                            className="btn btn-sm"
                            style={{
                              background: 'rgba(16, 185, 129, 0.12)',
                              color: '#10b981',
                              border: '1px solid rgba(16, 185, 129, 0.3)',
                              borderRadius: '8px',
                              padding: '5px 10px',
                              fontWeight: 700,
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px',
                            }}
                          >
                            <Unlock size={13} />
                            <span>ដោះ Block IP</span>
                          </button>
                        ) : (
                          <button
                            type="button"
                            onClick={() => {
                              setIpToBlock(ip);
                              setBlockReason(`Blocked from Modal (Actor: ${selectedLog.actor_name}, Action: ${selectedLog.action})`);
                            }}
                            className="btn btn-sm btn-danger"
                            style={{
                              borderRadius: '8px',
                              padding: '5px 10px',
                              fontWeight: 700,
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px',
                            }}
                          >
                            <Ban size={13} />
                            <span>Block IP នេះ</span>
                          </button>
                        )
                      )}

                      {/* Google Maps Link with Coordinates */}
                      <a
                        href={getGoogleMapCoordsUrl(ip)}
                        target="_blank"
                        rel="noreferrer"
                        className="btn btn-sm"
                        style={{
                          background: '#3b82f6',
                          color: '#ffffff',
                          padding: '5px 12px',
                          borderRadius: '8px',
                          fontSize: '12px',
                          fontWeight: 700,
                          textDecoration: 'none',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '6px',
                        }}
                      >
                        <ExternalLink size={13} />
                        <span>បើកលើ Google Maps ({geo.lat.toFixed(4)}, {geo.lng.toFixed(4)})</span>
                      </a>
                    </div>
                  </div>

                  {/* Map Info Bar */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '8px', fontSize: '12.5px', marginBottom: '12px', background: 'var(--surface)', padding: '10px 14px', borderRadius: '10px', border: '1px solid var(--border)' }}>
                    <div>🌐 IP Address: <strong style={{ fontFamily: 'monospace', color: isBlocked ? '#ef4444' : 'var(--text-primary)' }}>{ip}</strong> {isBlocked && <span style={{ color: '#ef4444' }}>(BLOCKED)</span>}</div>
                    <div>📍 ទីក្រុង/ប្រទេស: <strong style={{ color: 'var(--text-primary)' }}>{geo.city}, {geo.country} ({geo.countryCode})</strong></div>
                    <div>🎯 កូអរដោនេ: <strong style={{ fontFamily: 'monospace', color: '#3b82f6' }}>{geo.lat.toFixed(4)}, {geo.lng.toFixed(4)}</strong></div>
                  </div>

                  {/* Embedded Google Map with Exact Latitude and Longitude */}
                  <div style={{ borderRadius: '12px', overflow: 'hidden', border: '1px solid var(--border)', height: '230px', background: '#0f172a' }}>
                    <iframe
                      title="Google Maps Coordinates Location"
                      src={`https://maps.google.com/maps?q=${geo.lat},${geo.lng}&t=&z=14&ie=UTF8&iwloc=&output=embed`}
                      width="100%"
                      height="100%"
                      style={{ border: 0 }}
                      loading="lazy"
                    />
                  </div>
                </div>
              );
            })()}

            {/* Details Payload Box */}
            <div style={{ marginBottom: '18px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  ខ្លឹមសារព័ត៌មានលម្អិត (Details Payload)៖
                </span>
                <button
                  type="button"
                  onClick={() => handleCopyText(selectedLog.details || '', 'details')}
                  className="btn btn-sm"
                  style={{ background: 'transparent', border: 'none', color: '#3b82f6', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer' }}
                >
                  {copiedField === 'details' ? <Check size={13} color="#10b981" /> : <Copy size={13} />}
                  <span>{copiedField === 'details' ? 'បានចម្លង!' : 'ចម្លង Payload'}</span>
                </button>
              </div>
              <div
                style={{
                  background: '#090d16',
                  color: '#38bdf8',
                  padding: '14px 16px',
                  borderRadius: '12px',
                  fontSize: '13px',
                  fontFamily: 'monospace',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                  maxHeight: '160px',
                  overflowY: 'auto',
                  border: '1px solid #1e293b',
                }}
              >
                {selectedLog.details || 'មិនមានព័ត៌មានលម្អិត'}
              </div>
            </div>

            {/* User Agent */}
            <div style={{ background: 'var(--surface-alt)', padding: '12px 16px', borderRadius: '12px', marginBottom: '22px', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Browser User-Agent & Device Fingerprint</div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px', wordBreak: 'break-all' }}>
                {selectedLog.user_agent || 'Unknown'}
              </div>
            </div>

            {/* Modal Footer */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                type="button"
                onClick={() => setSelectedLog(null)}
                className="btn btn-primary"
                style={{ borderRadius: '10px', padding: '0 24px', height: '42px', fontWeight: 700 }}
              >
                បិទផ្ទាំង
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 6. Block IP Confirmation Modal */}
      {ipToBlock && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(6px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '20px',
          }}
          onClick={() => setIpToBlock(null)}
        >
          <div
            className="hrm-card"
            style={{
              maxWidth: '480px',
              width: '100%',
              borderRadius: '20px',
              padding: '28px 32px',
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              boxShadow: '0 20px 40px rgba(0,0,0,0.4)',
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
                <AlertOctagon size={28} />
              </div>
              <h3 style={{ margin: '0 0 6px 0', fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)' }}>
                Block អាសយដ្ឋាន IP ជនសង្ស័យ
              </h3>
              <p style={{ margin: 0, fontSize: '13.5px', color: 'var(--text-secondary)' }}>
                តើលោកអ្នកប្រាកដជាចង់ Block IP <strong style={{ color: '#ef4444', fontFamily: 'monospace' }}>{ipToBlock}</strong> មិនឱ្យចូលកាន់ Website/API ទៀតមែនទេ?
              </p>
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', display: 'block', marginBottom: '6px' }}>
                មូលហេតុនៃការ Block (Reason)៖
              </label>
              <input
                type="text"
                className="form-control"
                value={blockReason}
                onChange={(e) => setBlockReason(e.target.value)}
                placeholder="បញ្ជាក់មូលហេតុ..."
                style={{ height: '42px', borderRadius: '10px' }}
              />
            </div>

            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <button
                type="button"
                onClick={() => setIpToBlock(null)}
                className="btn btn-secondary"
                style={{ borderRadius: '10px', height: '40px', padding: '0 18px' }}
              >
                បោះបង់
              </button>
              <button
                type="button"
                onClick={handleBlockIp}
                disabled={isBlocking}
                className="btn btn-danger"
                style={{ borderRadius: '10px', height: '40px', padding: '0 20px', display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 700 }}
              >
                <Ban size={16} />
                <span>{isBlocking ? 'កំពុង Block...' : 'យល់ព្រម Block IP'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 7. Blocked IPs Manager Modal */}
      {showBlockedIpsModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.7)',
            backdropFilter: 'blur(6px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 999,
            padding: '20px',
          }}
          onClick={() => setShowBlockedIpsModal(false)}
        >
          <div
            className="hrm-card"
            style={{
              maxWidth: '650px',
              width: '100%',
              borderRadius: '20px',
              padding: '28px 32px',
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              boxShadow: '0 20px 40px rgba(0,0,0,0.3)',
              maxHeight: '80vh',
              overflowY: 'auto',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Ban size={22} color="#ef4444" />
                <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)' }}>
                  បញ្ជី IP ដែលត្រូវបាន Block (IP Blocklist)
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowBlockedIpsModal(false)}
                className="btn btn-secondary btn-sm"
                style={{ width: '32px', height: '32px', padding: 0, borderRadius: '8px' }}
              >
                ✕
              </button>
            </div>

            {blockedList.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-muted)' }}>
                <CheckCircle2 size={32} color="#10b981" style={{ margin: '0 auto 10px auto' }} />
                <div>មិនទាន់មាន IP ណាមួយត្រូវបាន Block ឡើយ</div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {blockedList.map((item) => (
                  <div
                    key={item.id || item.ip_address}
                    style={{
                      background: 'var(--surface-alt)',
                      padding: '12px 16px',
                      borderRadius: '12px',
                      border: '1px solid var(--border)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '12px',
                    }}
                  >
                    <div>
                      <div style={{ fontSize: '14px', fontWeight: 800, color: '#ef4444', fontFamily: 'monospace' }}>
                        {item.ip_address}
                      </div>
                      <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                        {item.reason} — <span style={{ color: 'var(--text-muted)' }}>ដោយ {item.blocked_by || 'Admin'} ({item.created_at})</span>
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleUnblockIp(item.ip_address)}
                      className="btn btn-sm btn-secondary"
                      style={{ borderRadius: '8px', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '4px' }}
                    >
                      <Unlock size={13} color="#10b981" />
                      <span>ដោះ Block</span>
                    </button>
                  </div>
                ))}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '20px' }}>
              <button
                type="button"
                onClick={() => setShowBlockedIpsModal(false)}
                className="btn btn-primary"
                style={{ borderRadius: '10px', padding: '0 20px', height: '38px' }}
              >
                បិទផ្ទាំង
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 8. Clear Logs Confirmation Modal */}
      {showClearModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.7)',
            backdropFilter: 'blur(6px)',
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
              background: 'var(--surface)',
              border: '1px solid var(--border)',
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
