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
  Plus,
  Wand2,
  RefreshCcw,
  Sparkles,
  ExternalLink,
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
  const [activeTab, setActiveTab] = useState<'active_sessions' | 'global_settings' | 'remove_bg_keys'>('active_sessions');
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

  // Remove.bg API Keys Management State
  const [apiKeys, setApiKeys] = useState<any[]>([]);
  const [apiKeyStats, setApiKeyStats] = useState({
    total_keys: 0,
    active_keys: 0,
    total_free_calls: 0,
    total_credits: 0,
    pool_status: 'Active & Ready',
  });
  const [loadingKeys, setLoadingKeys] = useState(false);
  const [isKeyModalOpen, setIsKeyModalOpen] = useState(false);
  const [newKeyString, setNewKeyString] = useState('');
  const [newKeyLabel, setNewKeyLabel] = useState('');
  const [isTestingNewKey, setIsTestingNewKey] = useState(false);
  const [isAddingKey, setIsAddingKey] = useState(false);
  const [syncingAllKeys, setSyncingAllKeys] = useState(false);
  const [testingKeyId, setTestingKeyId] = useState<number | null>(null);
  const [keySearch, setKeySearch] = useState('');

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

  const loadApiKeys = async () => {
    setLoadingKeys(true);
    try {
      const res = await adminApi.getApiKeys('remove_bg');
      if (res && res.success) {
        setApiKeys(res.keys || []);
        if (res.stats) {
          setApiKeyStats(res.stats);
        }
      }
    } catch (err) {
      console.error('Error loading API keys:', err);
    }
    setLoadingKeys(false);
  };

  const handleAddNewApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyString.trim()) {
      showBanner('error', 'សូមបញ្ចូល API Key!');
      return;
    }
    setIsAddingKey(true);
    try {
      const res = await adminApi.addApiKey(newKeyString.trim(), newKeyLabel.trim(), 'remove_bg');
      if (res && res.success) {
        showBanner('success', res.message || 'បានបន្ថែម API Key ជោគជ័យ!');
        setIsKeyModalOpen(false);
        setNewKeyString('');
        setNewKeyLabel('');
        loadApiKeys();
      } else {
        showBanner('error', res.message || 'បរាជ័យក្នុងការបន្ថែម API Key');
      }
    } catch (err: any) {
      showBanner('error', 'កំហុស៖ ' + (err?.response?.data?.message || err.message));
    }
    setIsAddingKey(false);
  };

  const handleTestSingleKey = async (id: number) => {
    setTestingKeyId(id);
    try {
      const res = await adminApi.testApiKey(id);
      if (res && res.success) {
        showBanner('success', res.message || 'Key ដំណើរការល្អ!');
        loadApiKeys();
      } else {
        showBanner('error', res.message || 'Key មិនដំណើរការ ឬអស់ Credit');
        loadApiKeys();
      }
    } catch (err: any) {
      showBanner('error', 'កំហុសពេល Test៖ ' + err.message);
    }
    setTestingKeyId(null);
  };

  const handleToggleKeyActive = async (id: number) => {
    try {
      const res = await adminApi.toggleApiKey(id);
      if (res && res.success) {
        showBanner('success', res.message);
        loadApiKeys();
      }
    } catch (err: any) {
      showBanner('error', 'កំហុស៖ ' + err.message);
    }
  };

  const handleDeleteApiKey = async (id: number, label: string) => {
    if (!window.confirm(`តើអ្នកពិតជាចង់លុប ${label} ចេញពី Pool មែនទេ?`)) return;
    try {
      const res = await adminApi.deleteApiKey(id);
      if (res && res.success) {
        showBanner('success', res.message);
        loadApiKeys();
      }
    } catch (err: any) {
      showBanner('error', 'កំហុសពេលលុប៖ ' + err.message);
    }
  };

  const handleSyncAllKeys = async () => {
    setSyncingAllKeys(true);
    try {
      const res = await adminApi.syncAllApiKeys('remove_bg');
      if (res && res.success) {
        showBanner('success', res.message);
        loadApiKeys();
      }
    } catch (err: any) {
      showBanner('error', 'កំហុសពេល Sync៖ ' + err.message);
    }
    setSyncingAllKeys(false);
  };

  useEffect(() => {
    loadSessions();
    loadGlobalSettings();
    loadApiKeys();
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

          <button
            onClick={() => {
              setActiveTab('remove_bg_keys');
              loadApiKeys();
            }}
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
              background: activeTab === 'remove_bg_keys' ? '#fff' : 'transparent',
              color: activeTab === 'remove_bg_keys' ? 'var(--primary)' : 'var(--text-secondary)',
              boxShadow: activeTab === 'remove_bg_keys' ? '0 4px 12px rgba(0,0,0,0.06)' : 'none',
            }}
          >
            <Sparkles size={15} />
            <span>Remove.bg Keys Pool ({apiKeys.length || 6})</span>
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

      {/* ========================================================================= */}
      {/* 3. REMOVE.BG API KEYS POOL MANAGEMENT TAB */}
      {/* ========================================================================= */}
      {activeTab === 'remove_bg_keys' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* STAT CARDS */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
            <StatCard
              title="សរុប Keys ក្នុង Pool"
              value={`${apiKeyStats.active_keys} / ${apiKeyStats.total_keys}`}
              subtitle="Keys កំពុងដំណើរការ"
              icon={<Layers size={22} color="var(--primary)" />}
            />
            <StatCard
              title="Free Calls នៅសល់ / ខែ"
              value={`${apiKeyStats.total_free_calls}`}
              subtitle="Reset ជារៀងរាល់ខែ"
              icon={<Wand2 size={22} color="#10B981" />}
            />
            <StatCard
              title="Full-Res Credits"
              value={`${apiKeyStats.total_credits}`}
              subtitle="កាត់រូបច្បាស់ High-Res"
              icon={<Sparkles size={22} color="#F59E0B" />}
            />
            <StatCard
              title="ស្ថានភាពប្រព័ន្ធ Failover"
              value={apiKeyStats.pool_status}
              subtitle="Auto Rotate ពេលអស់ Credit"
              icon={<Shield size={22} color="#0284C7" />}
            />
          </div>

          {/* ACTION TOOLBAR */}
          <div
            className="card"
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
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, minWidth: '260px' }}>
              <div style={{ position: 'relative', width: '100%', maxWidth: '320px' }}>
                <Search size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input
                  type="text"
                  placeholder="ស្វែងរកតាមឈ្មោះ ឬ Key..."
                  className="form-input"
                  value={keySearch}
                  onChange={(e) => setKeySearch(e.target.value)}
                  style={{ paddingLeft: '36px', height: '40px', borderRadius: '10px' }}
                />
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <button
                type="button"
                onClick={handleSyncAllKeys}
                disabled={syncingAllKeys}
                className="btn btn-secondary"
                style={{ padding: '8px 16px', borderRadius: '10px', display: 'inline-flex', alignItems: 'center', gap: '8px' }}
                title="ពិនិត្យ និងធ្វើបច្ចុប្បន្នភាព Credit នៃ Keys ទាំងអស់"
              >
                <RefreshCcw size={15} className={syncingAllKeys ? 'animate-spin' : ''} />
                <span>{syncingAllKeys ? 'កំពុង Sync...' : 'Sync តុល្យភាពទាំងអស់'}</span>
              </button>

              <button
                type="button"
                onClick={() => setIsKeyModalOpen(true)}
                className="btn btn-primary"
                style={{
                  padding: '8px 18px',
                  borderRadius: '10px',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  background: 'linear-gradient(135deg, #6366F1, #8B5CF6)',
                }}
              >
                <Plus size={16} />
                <span>+ បន្ថែម API Key ថ្មី</span>
              </button>
            </div>
          </div>

          {/* KEYS TABLE */}
          <div className="card" style={{ padding: '0', borderRadius: '16px', overflow: 'hidden' }}>
            <div className="table-container" style={{ margin: 0 }}>
              <table className="hrm-table">
                <thead>
                  <tr>
                    <th style={{ width: '60px', textAlign: 'center' }}>ល.រ</th>
                    <th>ឈ្មោះសម្គាល់ (Label)</th>
                    <th>API Key (Secret)</th>
                    <th style={{ textAlign: 'center' }}>Free Calls / ខែ</th>
                    <th style={{ textAlign: 'center' }}>Full-Res Credits</th>
                    <th style={{ textAlign: 'center' }}>ស្ថានភាព (Status)</th>
                    <th style={{ width: '180px', textAlign: 'center' }}>សកម្មភាព (Actions)</th>
                  </tr>
                </thead>
                <tbody>
                  {loadingKeys ? (
                    <tr>
                      <td colSpan={7} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                        <RotateCw size={24} className="animate-spin" style={{ margin: '0 auto 10px auto', display: 'block' }} />
                        <span>កំពុងទាញយកបញ្ជី API Keys...</span>
                      </td>
                    </tr>
                  ) : apiKeys.filter((k) => (k.key_label || '').toLowerCase().includes(keySearch.toLowerCase()) || (k.api_key || '').toLowerCase().includes(keySearch.toLowerCase())).length === 0 ? (
                    <tr>
                      <td colSpan={7} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                        មិនមាន API Key ណាត្រូវនឹងការស្វែងរកឡើយ
                      </td>
                    </tr>
                  ) : (
                    apiKeys
                      .filter((k) => (k.key_label || '').toLowerCase().includes(keySearch.toLowerCase()) || (k.api_key || '').toLowerCase().includes(keySearch.toLowerCase()))
                      .map((k, idx) => {
                        const isTesting = testingKeyId === k.id;
                        return (
                          <tr key={k.id}>
                            <td style={{ textAlign: 'center', fontWeight: 700, color: 'var(--text-muted)' }}>
                              #{idx + 1}
                            </td>
                            <td>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <span
                                  style={{
                                    width: '28px',
                                    height: '28px',
                                    borderRadius: '8px',
                                    background: k.is_active ? 'rgba(99, 102, 241, 0.15)' : 'rgba(148, 163, 184, 0.15)',
                                    color: k.is_active ? 'var(--primary)' : 'var(--text-muted)',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    justifyContent: 'center',
                                    fontSize: '11px',
                                    fontWeight: 800,
                                  }}
                                >
                                  {idx + 1}
                                </span>
                                <div>
                                  <div style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '13.5px' }}>
                                    {k.key_label}
                                  </div>
                                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                                    Priority #{k.priority || idx + 1} • បង្កើត៖ {k.created_at ? k.created_at.split(' ')[0] : 'ថ្មី'}
                                  </div>
                                </div>
                              </div>
                            </td>
                            <td>
                              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', background: 'var(--surface-alt)', padding: '4px 10px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                                <code style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                                  {k.masked_key}
                                </code>
                                <button
                                  type="button"
                                  onClick={() => {
                                    navigator.clipboard.writeText(k.api_key);
                                    showBanner('success', `បានចម្លង ${k.key_label}`);
                                  }}
                                  title="Copy Key"
                                  style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: '2px', color: 'var(--text-muted)' }}
                                >
                                  <Copy size={13} />
                                </button>
                              </div>
                            </td>
                            <td style={{ textAlign: 'center' }}>
                              <span
                                style={{
                                  display: 'inline-block',
                                  padding: '3px 10px',
                                  borderRadius: '20px',
                                  fontSize: '12px',
                                  fontWeight: 700,
                                  background: k.free_calls > 10 ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
                                  color: k.free_calls > 10 ? '#10B981' : '#EF4444',
                                }}
                              >
                                {k.free_calls} / 50
                              </span>
                            </td>
                            <td style={{ textAlign: 'center' }}>
                              <span style={{ fontWeight: 700, fontSize: '13px', color: k.credits > 0 ? '#F59E0B' : 'var(--text-muted)' }}>
                                {k.credits}
                              </span>
                            </td>
                            <td style={{ textAlign: 'center' }}>
                              {k.is_active ? (
                                k.last_status === 'exhausted' ? (
                                  <span className="badge badge-warning" style={{ fontSize: '11.5px' }}>
                                    ⚠️ អស់ Credit
                                  </span>
                                ) : (
                                  <span className="badge badge-success" style={{ fontSize: '11.5px' }}>
                                    ✅ សកម្ម (Active)
                                  </span>
                                )
                              ) : (
                                <span className="badge badge-secondary" style={{ fontSize: '11.5px' }}>
                                  ⏸️ ផ្អាក (Disabled)
                                </span>
                              )}
                            </td>
                            <td style={{ textAlign: 'center' }}>
                              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                                <button
                                  type="button"
                                  onClick={() => handleTestSingleKey(k.id)}
                                  disabled={isTesting}
                                  className="btn btn-secondary btn-sm"
                                  style={{ padding: '5px 8px', borderRadius: '8px' }}
                                  title="តេស្តផ្ទៀងផ្ទាត់ Key នេះ"
                                >
                                  <RotateCw size={13} className={isTesting ? 'animate-spin' : ''} />
                                </button>

                                <button
                                  type="button"
                                  onClick={() => handleToggleKeyActive(k.id)}
                                  className="btn btn-secondary btn-sm"
                                  style={{
                                    padding: '5px 8px',
                                    borderRadius: '8px',
                                    color: k.is_active ? '#10B981' : 'var(--text-muted)',
                                  }}
                                  title={k.is_active ? 'ផ្អាកដំណើរការ' : 'បើកដំណើរការ'}
                                >
                                  <Power size={13} />
                                </button>

                                <button
                                  type="button"
                                  onClick={() => handleDeleteApiKey(k.id, k.key_label)}
                                  className="btn btn-danger btn-sm"
                                  style={{ padding: '5px 8px', borderRadius: '8px' }}
                                  title="លុប Key"
                                >
                                  <Trash2 size={13} />
                                </button>
                              </div>
                            </td>
                          </tr>
                        );
                      })
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* ADD KEY MODAL */}
          {isKeyModalOpen && (
            <div
              style={{
                position: 'fixed',
                inset: 0,
                backgroundColor: 'rgba(0, 0, 0, 0.65)',
                backdropFilter: 'blur(6px)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                zIndex: 9999,
                padding: '20px',
              }}
            >
              <div
                className="card"
                style={{
                  width: '100%',
                  maxWidth: '500px',
                  padding: '24px',
                  borderRadius: '20px',
                  boxShadow: '0 20px 40px rgba(0,0,0,0.4)',
                  animation: 'fadeIn 0.2s ease',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span
                      style={{
                        background: 'linear-gradient(135deg, #6366F1, #8B5CF6)',
                        color: '#fff',
                        width: '34px',
                        height: '34px',
                        borderRadius: '10px',
                        display: 'inline-flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      <Plus size={18} />
                    </span>
                    <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 800, color: 'var(--text-primary)' }}>
                      បន្ថែម Remove.bg API Key ថ្មី
                    </h3>
                  </div>
                  <button
                    type="button"
                    onClick={() => setIsKeyModalOpen(false)}
                    style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: '20px' }}
                  >
                    ✕
                  </button>
                </div>

                <form onSubmit={handleAddNewApiKey}>
                  <div className="form-group" style={{ marginBottom: '16px' }}>
                    <label className="form-label">ឈ្មោះសម្គាល់ (Key Label)</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="ឧ. Account 07 - HR Admin"
                      value={newKeyLabel}
                      onChange={(e) => setNewKeyLabel(e.target.value)}
                    />
                  </div>

                  <div className="form-group" style={{ marginBottom: '20px' }}>
                    <label className="form-label">API Key String *</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="ឧ. LM9UPg8HqRKeZ89FeM2hhaCR"
                      value={newKeyString}
                      onChange={(e) => setNewKeyString(e.target.value)}
                      required
                      style={{ fontFamily: 'monospace' }}
                    />
                    <span style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '4px', display: 'block' }}>
                      ប្រព័ន្ធនឹងធ្វើការ Test ផ្ទៀងផ្ទាត់ជាមួយ Server របស់ Remove.bg ដោយស្វ័យប្រវត្តមុនពេល Save។
                    </span>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', borderTop: '1px solid var(--border)', paddingTop: '16px' }}>
                    <button type="button" onClick={() => setIsKeyModalOpen(false)} className="btn btn-secondary">
                      បោះបង់
                    </button>
                    <button
                      type="submit"
                      disabled={isAddingKey}
                      className="btn btn-primary"
                      style={{
                        background: 'linear-gradient(135deg, #6366F1, #8B5CF6)',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                      }}
                    >
                      {isAddingKey ? (
                        <>
                          <RotateCw size={15} className="animate-spin" />
                          <span>កំពុងផ្ទៀងផ្ទាត់ & រក្សាទុក...</span>
                        </>
                      ) : (
                        <>
                          <Check size={15} />
                          <span>ផ្ទៀងផ្ទាត់ & រក្សាទុក</span>
                        </>
                      )}
                    </button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
