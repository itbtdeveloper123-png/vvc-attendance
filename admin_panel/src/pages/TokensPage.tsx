import React, { useState, useEffect } from 'react';
import {
  KeyRound,
  Shield,
  Trash2,
  Check,
  RotateCw,
  Search,
  Sliders,
  Save,
  Lock,
  AlertCircle,
  CheckCircle2,
  Users,
  Copy,
  Power,
  Layers,
  Laptop,
  MoreVertical,
} from 'lucide-react';
import { StatCard } from '../components/common/StatCard';
import { ViewModeToggle, ViewMode } from '../components/common/ViewModeToggle';
import { adminApi, SessionItem, SessionGroup } from '../api/adminApi';

const formatSessionDate = (dateStr?: string) => {
  if (!dateStr) return { date: '-', time: '' };
  try {
    const parts = dateStr.trim().split(' ');
    const datePart = parts[0];
    const timePart = parts[1] || '';

    const d = new Date(dateStr.replace(' ', 'T'));
    if (isNaN(d.getTime())) {
      return { date: datePart || '-', time: timePart };
    }
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const formattedDate = `${d.getDate()} ${months[d.getMonth()]}, ${d.getFullYear()}`;
    const formattedTime = timePart || `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
    return { date: formattedDate, time: formattedTime };
  } catch (e) {
    return { date: dateStr.split(' ')[0] || '-', time: dateStr.split(' ')[1] || '' };
  }
};

export const TokensPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'active_sessions' | 'global_settings'>('active_sessions');
  const [viewMode, setViewMode] = useState<ViewMode>('table');
  const [sessions, setSessions] = useState<SessionItem[]>([]);
  const [groups, setGroups] = useState<SessionGroup[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [selectedGroup, setSelectedGroup] = useState('');
  const [selectedTokens, setSelectedTokens] = useState<string[]>([]);
  const [globalMaxTokens, setGlobalMaxTokens] = useState(1);
  const [savingSettings, setSavingSettings] = useState(false);
  const [copiedToken, setCopiedToken] = useState<string | null>(null);

  // Banner
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const showBanner = (type: 'success' | 'error', text: string) => {
    setBanner({ type, text });
    setTimeout(() => setBanner(null), 3500);
  };

  const loadSessions = async () => {
    setLoading(true);
    try {
      const res = await adminApi.fetchActiveSessions();
      if (res) {
        const rawSessions = Array.isArray(res)
          ? res
          : (Array.isArray(res.sessions) ? res.sessions : (Array.isArray(res.tokens) ? res.tokens : (Array.isArray(res.data) ? res.data : [])));
        setSessions(rawSessions);

        const rawGroups = Array.isArray(res.groups) ? res.groups : (Array.isArray(res.data?.groups) ? res.data.groups : []);
        setGroups(rawGroups);

        const maxTok = res.global_max_tokens || res.max_tokens || res.data?.global_max_tokens;
        if (maxTok) setGlobalMaxTokens(Number(maxTok) || 1);
      }
    } catch (err) {
      console.error('Error fetching sessions:', err);
    }
    setLoading(false);
  };

  const loadGlobalSettings = async () => {
    try {
      const res = await adminApi.fetchGlobalTokenSettings();
      if (res) {
        const maxTok = res.global_max_tokens || res.max_tokens || res.data?.global_max_tokens || res.data?.max_tokens;
        if (maxTok) setGlobalMaxTokens(Number(maxTok) || 1);
      }
    } catch (err) {
      console.error('Error fetching global token settings:', err);
    }
  };

  useEffect(() => {
    loadSessions();
    loadGlobalSettings();
  }, []);

  const handleToggleSelectAll = () => {
    if (selectedTokens.length === filteredSessions.length && filteredSessions.length > 0) {
      setSelectedTokens([]);
    } else {
      setSelectedTokens(filteredSessions.map((s) => s.auth_token || String(s.id)));
    }
  };

  const handleToggleToken = (token: string) => {
    if (selectedTokens.includes(token)) {
      setSelectedTokens(selectedTokens.filter((t) => t !== token));
    } else {
      setSelectedTokens([...selectedTokens, token]);
    }
  };

  const handleRevokeSingle = async (session: SessionItem) => {
    if (!window.confirm(`តើអ្នកពិតជាចង់លុប Session នេះមែនទេ?`)) return;
    try {
      const tokenOrId = session.auth_token || session.id;
      const res = await adminApi.revokeSession(tokenOrId);
      if (res && res.success) {
        showBanner('success', res.message || 'បានផ្តាច់ Token ជោគជ័យ!');
        setSelectedTokens(selectedTokens.filter((t) => t !== session.auth_token && t !== String(session.id)));
        loadSessions();
      } else {
        showBanner('error', res?.message || 'Error revoking session');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការផ្តាច់ Session');
    }
  };

  const handleBulkRevoke = async () => {
    if (selectedTokens.length === 0) return;
    if (!window.confirm(`តើអ្នកពិតជាចង់លុប Token ចំនួន ${selectedTokens.length} ដែលបានជ្រើសរើសមែនទេ?`)) return;
    try {
      const res = await adminApi.revokeBulkTokens(selectedTokens);
      if (res && res.success) {
        showBanner('success', res.message || `បានផ្តាច់ ${selectedTokens.length} Session ជោគជ័យ!`);
        setSelectedTokens([]);
        loadSessions();
      } else {
        showBanner('error', res?.message || 'Error bulk revoking sessions');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការផ្តាច់ Session');
    }
  };

  const handleRevokeAll = async () => {
    if (!window.confirm('តើអ្នកពិតជាចង់ផ្តាច់ Session ទាំងអស់ (Revoke All Sessions) ក្នុងប្រព័ន្ធមែនទេ?')) return;
    try {
      const res = await adminApi.revokeAllSessions();
      if (res && res.success) {
        showBanner('success', res.message || 'All sessions have been revoked.');
        setSelectedTokens([]);
        loadSessions();
      } else {
        showBanner('error', res?.message || 'Error revoking all sessions');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការផ្តាច់គ្រប់ Session');
    }
  };

  const handleSaveGlobalSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingSettings(true);
    try {
      const res = await adminApi.saveGlobalTokenSettings(globalMaxTokens);
      if (res && res.success) {
        showBanner('success', res.message || 'ការកំណត់ចំនួន Token ត្រូវបានរក្សាទុកដោយជោគជ័យ!');
      } else {
        showBanner('error', res?.message || 'Error saving settings');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការរក្សាទុកការកំណត់');
    }
    setSavingSettings(false);
  };

  const handleCopyToken = (token: string) => {
    navigator.clipboard.writeText(token);
    setCopiedToken(token);
    setTimeout(() => setCopiedToken(null), 2000);
  };

  const filteredSessions = sessions.filter((s) => {
    const q = (search || '').toLowerCase();
    const name = (s.user_name || s.name || '').toLowerCase();
    const eid = (s.employee_id || '').toLowerCase();
    const token = (s.auth_token || '').toLowerCase();

    const matchesQuery = name.includes(q) || eid.includes(q) || token.includes(q);

    if (!selectedGroup) return matchesQuery;

    let userGroupId = '';
    if (s.custom_data) {
      try {
        const parsed = typeof s.custom_data === 'string' ? JSON.parse(s.custom_data) : s.custom_data;
        userGroupId = String(parsed?.group_id || '');
      } catch (e) {
        // ignore
      }
    }
    return matchesQuery && userGroupId === String(selectedGroup);
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '22px', maxWidth: '1200px', margin: '0 auto', width: '100%' }}>
      {/* Header Banner with Clean Sub-Tabs */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
          background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.08), rgba(79, 70, 229, 0.03))',
          padding: '24px',
          borderRadius: '18px',
          border: '1px solid rgba(99, 102, 241, 0.15)',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
            <span
              style={{
                background: 'var(--primary)',
                color: '#fff',
                width: '36px',
                height: '36px',
                borderRadius: '10px',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: '0 4px 10px rgba(99, 102, 241, 0.3)',
              }}
            >
              <KeyRound size={20} />
            </span>
            <h2 style={{ fontSize: '22px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              គ្រប់គ្រង Token & Sessions (Token & Session Control)
            </h2>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0 }}>
            តាមដាន Active Tokens បុគ្គលិកលើទូរស័ព្ទ App ផ្តាច់ Session (Revoke) និងកំណត់ចំនួន Login អតិបរមា (Max Tokens)
          </p>
        </div>

        {/* Clean Segmented Sub-Tabs */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'var(--surface-subtle, #f1f5f9)', padding: '6px', borderRadius: '14px' }}>
          <button
            onClick={() => setActiveTab('active_sessions')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '9px 16px',
              borderRadius: '10px',
              fontWeight: 700,
              fontSize: '13px',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              background: activeTab === 'active_sessions' ? '#fff' : 'transparent',
              color: activeTab === 'active_sessions' ? 'var(--primary)' : 'var(--text-secondary)',
              boxShadow: activeTab === 'active_sessions' ? '0 4px 12px rgba(0,0,0,0.06)' : 'none',
            }}
          >
            <KeyRound size={15} />
            <span>Active Sessions ({sessions.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('global_settings')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '9px 16px',
              borderRadius: '10px',
              fontWeight: 700,
              fontSize: '13px',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              background: activeTab === 'global_settings' ? '#fff' : 'transparent',
              color: activeTab === 'global_settings' ? 'var(--primary)' : 'var(--text-secondary)',
              boxShadow: activeTab === 'global_settings' ? '0 4px 12px rgba(0,0,0,0.06)' : 'none',
            }}
          >
            <Sliders size={15} />
            <span>កំណត់ Token Limits</span>
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 1. ACTIVE SESSIONS TAB */}
      {/* ========================================================================= */}
      {activeTab === 'active_sessions' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Action Header & Bulk Controls */}
          <div
            className="hrm-card"
            style={{
              padding: '18px 24px',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '14px',
              borderRadius: '16px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '16px', fontWeight: 800, color: 'var(--text-primary)' }}>
              <Users size={18} color="var(--primary)" />
              <span>បញ្ជី Session សកម្ម (Active Sessions: {sessions.length})</span>
              {selectedTokens.length > 0 && (
                <span className="badge badge-primary" style={{ marginLeft: '6px' }}>
                  បានជ្រើសរើស {selectedTokens.length}
                </span>
              )}
            </div>

            <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
              {selectedTokens.length > 0 && (
                <button
                  type="button"
                  onClick={handleBulkRevoke}
                  className="btn btn-warning"
                  style={{ padding: '8px 18px', fontWeight: 700, borderRadius: '10px' }}
                >
                  <Trash2 size={14} />
                  <span>លុប Token ដែលបានជ្រើសរើស ({selectedTokens.length})</span>
                </button>
              )}
              <button
                type="button"
                onClick={handleRevokeAll}
                className="btn btn-danger"
                style={{ padding: '8px 20px', fontWeight: 700, borderRadius: '10px' }}
              >
                <Power size={14} />
                <span>Revoke All Sessions</span>
              </button>
            </div>
          </div>

          {/* Search & Filter Toolbar */}
          <div
            className="hrm-card"
            style={{
              padding: '16px 20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '12px',
              flexWrap: 'wrap',
              borderRadius: '16px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, flexWrap: 'wrap' }}>
              {/* Group Filter */}
              <div style={{ minWidth: '220px' }}>
                <select
                  className="form-input"
                  value={selectedGroup}
                  onChange={(e) => setSelectedGroup(e.target.value)}
                  style={{ height: '44px', fontWeight: 700, borderRadius: '12px' }}
                >
                  <option value="">— គ្រប់ក្រុមទាំងអស់ (All Groups) —</option>
                  {groups.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.group_name}
                    </option>
                  ))}
                </select>
              </div>

              {/* Search Box */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  background: 'var(--surface-alt)',
                  border: '1px solid var(--border)',
                  borderRadius: '12px',
                  padding: '8px 14px',
                  minWidth: '280px',
                  flex: 1,
                  gap: '8px',
                }}
              >
                <Search size={16} color="var(--text-muted)" />
                <input
                  type="text"
                  placeholder="ស្វែងរកតាមឈ្មោះ ឬ ID..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    outline: 'none',
                    fontSize: '13.5px',
                    color: 'var(--text-primary)',
                    fontFamily: 'inherit',
                    width: '100%',
                  }}
                />
              </div>

              <ViewModeToggle mode={viewMode} onChange={setViewMode} />

              <button
                type="button"
                onClick={loadSessions}
                className="btn btn-primary"
                style={{ height: '44px', width: '44px', borderRadius: '12px', padding: 0, justifyContent: 'center' }}
                title="ស្វែងរក / Refresh"
              >
                <Search size={16} />
              </button>
            </div>
          </div>

          {/* View Mode Switching: Grid Cards or Table */}
          {viewMode === 'grid' ? (
            filteredSessions.length === 0 ? (
              <div className="hrm-card" style={{ textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}>
                {loading ? 'កំពុងទាញយកបញ្ជី Session...' : 'មិនមាន Session សកម្មនៅក្នុងប្រព័ន្ធឡើយ'}
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '16px' }}>
                {filteredSessions.map((s) => {
                  const tokenKey = s.auth_token || String(s.id);
                  const isChecked = selectedTokens.includes(tokenKey);
                  const created = formatSessionDate(s.created_at);
                  const lastUsed = formatSessionDate(s.last_used);

                  return (
                    <div
                      key={s.id || s.auth_token}
                      className="hrm-card"
                      style={{
                        padding: '18px',
                        borderRadius: '16px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '14px',
                        border: isChecked ? '2px solid var(--primary)' : '1px solid var(--border)',
                        boxShadow: 'var(--shadow-sm)',
                        background: 'var(--surface)',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '10px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <input
                            type="checkbox"
                            checked={isChecked}
                            onChange={() => handleToggleToken(tokenKey)}
                            style={{ width: '18px', height: '18px', cursor: 'pointer', accentColor: 'var(--primary)' }}
                          />
                          <div>
                            <div style={{ fontWeight: 800, fontSize: '15px', color: 'var(--text-primary)' }}>
                              {s.user_name || s.name || 'User'}
                            </div>
                            <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: "'Outfit', monospace", fontWeight: 600 }}>
                              ID: {s.employee_id}
                            </div>
                          </div>
                        </div>

                        <span
                          style={{
                            background: '#f1f5f9',
                            color: '#475569',
                            border: '1px solid var(--border)',
                            fontSize: '11px',
                            padding: '3px 8px',
                            borderRadius: '8px',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                            fontWeight: 600,
                          }}
                        >
                          <Laptop size={12} />
                          <span>{(s as any).scan_user_type || 'Device'}</span>
                        </span>
                      </div>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', background: 'var(--surface-alt)', padding: '12px', borderRadius: '12px', fontSize: '12px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                          <span style={{ color: 'var(--text-muted)' }}>Token:</span>
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                            <code style={{ fontSize: '11px', background: 'var(--surface)', padding: '2px 6px', borderRadius: '4px', border: '1px solid var(--border)' }}>
                              {s.auth_token ? `${s.auth_token.substring(0, 12)}...` : 'N/A'}
                            </code>
                            {s.auth_token && (
                              <button
                                type="button"
                                onClick={() => handleCopyToken(s.auth_token)}
                                title="Copy Token"
                                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '2px', color: copiedToken === s.auth_token ? '#10b981' : 'var(--text-muted)' }}
                              >
                                {copiedToken === s.auth_token ? <Check size={12} /> : <Copy size={12} />}
                              </button>
                            )}
                          </div>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                          <span style={{ color: 'var(--text-muted)' }}>បានបង្កើត:</span>
                          <span style={{ fontWeight: 600 }}>{created.date} {created.time}</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                          <span style={{ color: 'var(--text-muted)' }}>សកម្មភាពចុងក្រោយ:</span>
                          <span style={{ fontWeight: 600 }}>{lastUsed.date} {lastUsed.time}</span>
                        </div>
                      </div>

                      <div style={{ display: 'flex', justifyContent: 'flex-end', borderTop: '1px solid var(--border)', paddingTop: '10px', marginTop: 'auto' }}>
                        <button
                          type="button"
                          onClick={() => handleRevokeSingle(s)}
                          className="btn btn-danger btn-sm"
                          style={{ padding: '6px 14px', borderRadius: '8px', fontSize: '12px' }}
                        >
                          <Trash2 size={13} />
                          <span>ផ្តាច់ Session (Revoke)</span>
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )
          ) : (
            /* Sessions Table */
            <div className="table-container" style={{ borderRadius: '16px' }}>
              <table className="hrm-table">
                <thead>
                  <tr>
                    <th style={{ width: '44px', textAlign: 'center' }}>
                      <input
                        type="checkbox"
                        checked={selectedTokens.length > 0 && selectedTokens.length === filteredSessions.length}
                        onChange={handleToggleSelectAll}
                        style={{ width: '18px', height: '18px', cursor: 'pointer' }}
                      />
                    </th>
                    <th>ព័ត៌មានអ្នកប្រើប្រាស់ (USER)</th>
                    <th>ប្រភេទ</th>
                    <th>TOKEN (សង្ខេប)</th>
                    <th>បង្កើតនៅ (CREATED AT)</th>
                    <th>សកម្មភាពចុងក្រោយ (LAST ACTIVITY)</th>
                    <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredSessions.length === 0 ? (
                    <tr>
                      <td colSpan={7} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                        {loading ? 'កំពុងទាញយកបញ្ជី Session...' : 'មិនមាន Session សកម្មនៅក្នុងប្រព័ន្ធឡើយ'}
                      </td>
                    </tr>
                  ) : (
                    filteredSessions.map((s) => {
                      const tokenKey = s.auth_token || String(s.id);
                      const isChecked = selectedTokens.includes(tokenKey);
                      const created = formatSessionDate(s.created_at);
                      const lastUsed = formatSessionDate(s.last_used);

                      return (
                        <tr key={s.id || s.auth_token}>
                          <td style={{ textAlign: 'center' }}>
                            <input
                              type="checkbox"
                              checked={isChecked}
                              onChange={() => handleToggleToken(tokenKey)}
                              style={{ width: '18px', height: '18px', cursor: 'pointer' }}
                            />
                          </td>
                          <td>
                            <div style={{ fontWeight: 800, color: 'var(--text-primary)', fontSize: '14px' }}>
                              {s.user_name || s.name || 'User'}
                            </div>
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                              ID: {s.employee_id}
                            </div>
                          </td>
                          <td>
                            <span
                              style={{
                                background: '#f1f5f9',
                                color: '#475569',
                                border: '1px solid var(--border)',
                                fontSize: '11px',
                                padding: '4px 10px',
                                borderRadius: '8px',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '5px',
                                fontWeight: 600,
                              }}
                            >
                              <Laptop size={12} />
                              <span>{(s as any).scan_user_type || 'N/A'}</span>
                            </span>
                          </td>
                          <td>
                            <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                              <code
                                style={{
                                  background: 'var(--surface-alt)',
                                  padding: '4px 8px',
                                  borderRadius: '6px',
                                  fontSize: '11.5px',
                                  border: '1px solid var(--border)',
                                  color: 'var(--text-secondary)',
                                }}
                              >
                                {s.auth_token ? `${s.auth_token.substring(0, 15)}...` : 'N/A'}
                              </code>
                              {s.auth_token && (
                                <button
                                  type="button"
                                  onClick={() => handleCopyToken(s.auth_token)}
                                  title="Copy Token"
                                  style={{
                                    background: 'none',
                                    border: 'none',
                                    cursor: 'pointer',
                                    padding: '2px',
                                    color: copiedToken === s.auth_token ? '#10b981' : 'var(--text-muted)',
                                  }}
                                >
                                  {copiedToken === s.auth_token ? <Check size={13} /> : <Copy size={13} />}
                                </button>
                              )}
                            </div>
                          </td>
                          <td style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                            <div>{created.date}</div>
                            <div style={{ color: 'var(--text-muted)', fontSize: '11px' }}>{created.time}</div>
                          </td>
                          <td style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                            <div>{lastUsed.date}</div>
                            <div style={{ color: 'var(--text-muted)', fontSize: '11px' }}>{lastUsed.time}</div>
                          </td>
                          <td style={{ textAlign: 'right' }}>
                            <button
                              type="button"
                              onClick={() => handleRevokeSingle(s)}
                              className="btn btn-danger btn-sm"
                              title="ផ្តាច់ Session"
                              style={{ padding: '5px 12px', borderRadius: '8px' }}
                            >
                              <Trash2 size={13} />
                              <span>Revoke</span>
                            </button>
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
      )}

      {/* ========================================================================= */}
      {/* 2. GLOBAL TOKEN LIMITS TAB */}
      {/* ========================================================================= */}
      {activeTab === 'global_settings' && (
        <div className="hrm-card" style={{ maxWidth: '600px', padding: '28px', borderRadius: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
            <Lock size={20} color="var(--primary)" />
            <h3 style={{ fontSize: '17px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              កំណត់ចំនួន Token អតិបរមា (Global Token Limits)
            </h3>
          </div>

          <form onSubmit={handleSaveGlobalSettings}>
            <div className="form-group">
              <label className="form-label" style={{ fontWeight: 700, color: 'var(--text-secondary)' }}>
                ចំនួន Token អតិបរមា (Max Tokens per User):
              </label>
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginTop: '8px' }}>
                <input
                  type="number"
                  min="1"
                  max="10"
                  className="form-input"
                  value={globalMaxTokens}
                  onChange={(e) => setGlobalMaxTokens(parseInt(e.target.value) || 1)}
                  style={{
                    maxWidth: '140px',
                    fontSize: '1.2rem',
                    fontWeight: 700,
                    textAlign: 'center',
                    height: '48px',
                    borderRadius: '12px',
                  }}
                  required
                />
                <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                  (អនុញ្ញាតចាប់ពី 1 ដល់ 10)
                </span>
              </div>
            </div>

            <div
              style={{
                marginTop: '20px',
                padding: '14px 18px',
                borderRadius: '12px',
                background: 'var(--surface-alt)',
                border: '1px solid var(--border)',
                display: 'flex',
                gap: '10px',
                alignItems: 'flex-start',
              }}
            >
              <AlertCircle size={18} color="var(--primary)" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
                <strong>បញ្ជាក់:</strong> ការកំណត់នេះនឹងកំណត់ចំនួនឧបករណ៍ (Devices) ដែល User នីមួយៗអាចប្រើប្រាស់ក្នុងពេលតែមួយ។
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '28px' }}>
              <button type="submit" disabled={savingSettings} className="btn btn-primary" style={{ padding: '10px 28px', borderRadius: '12px' }}>
                <Save size={16} />
                <span>{savingSettings ? 'កំពុងរក្សាទុក...' : 'រក្សាទុកការកំណត់'}</span>
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
