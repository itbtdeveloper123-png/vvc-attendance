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
} from 'lucide-react';
import { StatCard } from '../components/common/StatCard';
import { adminApi, SessionItem, SessionGroup } from '../api/adminApi';

export const TokensPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'active_sessions' | 'global_settings'>('active_sessions');
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
      if (res && res.success) {
        if (Array.isArray(res.sessions)) setSessions(res.sessions);
        if (Array.isArray(res.groups)) setGroups(res.groups);
        if (res.global_max_tokens) setGlobalMaxTokens(Number(res.global_max_tokens) || 1);
      }
    } catch (err) {
      console.error('Error fetching sessions:', err);
    }
    setLoading(false);
  };

  const loadGlobalSettings = async () => {
    try {
      const res = await adminApi.fetchGlobalTokenSettings();
      if (res && res.success) {
        setGlobalMaxTokens(res.global_max_tokens || res.max_tokens || 1);
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
    if (!window.confirm(`តើអ្នកពិតជាចង់ផ្តាច់ Session របស់ "${session.user_name || session.name || session.employee_id}" មែនទេ?`)) return;
    try {
      const tokenOrId = session.auth_token || session.id;
      const res = await adminApi.revokeSession(tokenOrId);
      if (res && res.success) {
        showBanner('success', res.message || 'បានផ្តាច់ Session ជោគជ័យ!');
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
    if (!window.confirm(`តើអ្នកពិតជាចង់ផ្តាច់ Session ចំនួន ${selectedTokens.length} ដែលបានជ្រើសរើសមែនទេ?`)) return;
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
    if (!window.confirm('⚠️ ការព្រមាន: តើអ្នកពិតជាចង់ផ្តាច់ Session ទាំងអស់ (Revoke All Sessions) ក្នុងប្រព័ន្ធមែនទេ? បុគ្គលិកទាំងអស់នឹងត្រូវ Login ឡើងវិញ។')) return;
    try {
      const res = await adminApi.revokeAllSessions();
      if (res && res.success) {
        showBanner('success', res.message || 'បានផ្តាច់គ្រប់ Session ទាំងអស់ដោយជោគជ័យ!');
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
    const dept = (s.department || '').toLowerCase();

    const matchesQuery = name.includes(q) || eid.includes(q) || token.includes(q) || dept.includes(q);

    if (!selectedGroup) return matchesQuery;

    let userGroupId = '';
    if (s.custom_data) {
      try {
        const parsed = JSON.parse(s.custom_data);
        userGroupId = String(parsed.group_id || '');
      } catch (e) {
        // ignore
      }
    }
    return matchesQuery && userGroupId === String(selectedGroup);
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '1200px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h2 style={{ fontSize: '22px', fontWeight: 800, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
            <KeyRound size={24} color="#6366f1" />
            គ្រប់គ្រង Session & Token សុវត្ថិភាព (Token & Session Control)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: '4px 0 0' }}>
            តាមដាន Active Tokens បុគ្គលិកលើទូរស័ព្ទ App ផ្តាច់ Session (Revoke) និងកំណត់ចំនួន Login អតិបរមា (Max Tokens)
          </p>
        </div>
      </div>

      {banner && (
        <div
          style={{
            padding: '12px 18px',
            borderRadius: '12px',
            background: banner.type === 'success' ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
            border: `1px solid ${banner.type === 'success' ? '#10b981' : '#ef4444'}`,
            color: banner.type === 'success' ? '#10b981' : '#ef4444',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '13.5px',
            fontWeight: 600,
          }}
        >
          <CheckCircle2 size={16} />
          <span>{banner.text}</span>
        </div>
      )}

      {/* Tabs Switcher */}
      <div
        className="hrm-card"
        style={{
          padding: '10px 14px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          overflowX: 'auto',
          borderRadius: '16px',
        }}
      >
        <button
          onClick={() => setActiveTab('active_sessions')}
          className={`btn btn-sm ${activeTab === 'active_sessions' ? 'btn-primary' : 'btn-secondary'}`}
          style={{ borderRadius: '12px', padding: '8px 18px', fontWeight: activeTab === 'active_sessions' ? 800 : 500 }}
        >
          <KeyRound size={15} />
          <span>បញ្ជី Session សកម្ម (Active Sessions: {sessions.length})</span>
        </button>
        <button
          onClick={() => setActiveTab('global_settings')}
          className={`btn btn-sm ${activeTab === 'global_settings' ? 'btn-primary' : 'btn-secondary'}`}
          style={{ borderRadius: '12px', padding: '8px 18px', fontWeight: activeTab === 'global_settings' ? 800 : 500 }}
        >
          <Sliders size={15} />
          <span>ការកំណត់ Token អតិបរមា (Global Token Limits)</span>
        </button>
      </div>

      {/* ========================================================================= */}
      {/* 1. ACTIVE SESSIONS TAB */}
      {/* ========================================================================= */}
      {activeTab === 'active_sessions' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* KPI Stat Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
            <StatCard
              title="Session កំពុងសកម្ម (Active Tokens)"
              value={`${sessions.length} ឧបករណ៍`}
              subtitle="បាន Login លើ App / Web"
              icon={<KeyRound size={22} />}
              variant="primary"
            />
            <StatCard
              title="កម្រិតកំណត់ Session (Max Tokens)"
              value={`${globalMaxTokens} ឧបករណ៍ / នាក់`}
              subtitle="កំណត់ការ Login ស្របគ្នា"
              icon={<Shield size={22} />}
              variant="gold"
            />
          </div>

          {/* Action Header & Bulk Controls */}
          <div className="hrm-card" style={{ padding: '16px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)' }}>
              <Users size={18} color="var(--primary)" />
              <span>បញ្ជី Session សកម្ម ({filteredSessions.length})</span>
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
                  className="btn btn-warning btn-sm"
                  style={{ padding: '8px 16px', fontWeight: 700 }}
                >
                  <Trash2 size={14} />
                  <span>លុប Token ដែលបានជ្រើសរើស ({selectedTokens.length})</span>
                </button>
              )}
              <button
                type="button"
                onClick={handleRevokeAll}
                className="btn btn-danger btn-sm"
                style={{ padding: '8px 16px', fontWeight: 700 }}
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
              padding: '14px 20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '12px',
              flexWrap: 'wrap',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, flexWrap: 'wrap' }}>
              {/* Group Filter */}
              {groups.length > 0 && (
                <div style={{ minWidth: '200px' }}>
                  <select
                    className="form-input"
                    value={selectedGroup}
                    onChange={(e) => setSelectedGroup(e.target.value)}
                    style={{ height: '40px', fontWeight: 600 }}
                  >
                    <option value="">— គ្រប់ក្រុមទាំងអស់ (All Groups) —</option>
                    {groups.map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.group_name}
                      </option>
                    ))}
                  </select>
                </div>
              )}

              {/* Search Box */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  background: 'var(--surface-alt)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius)',
                  padding: '7px 12px',
                  minWidth: '280px',
                  flex: 1,
                  gap: '8px',
                }}
              >
                <Search size={15} color="var(--text-muted)" />
                <input
                  type="text"
                  placeholder="ស្វែងរកតាមឈ្មោះ, ID, Token..."
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

            <button type="button" onClick={loadSessions} className="btn btn-secondary btn-sm" style={{ height: '40px' }}>
              <RotateCw size={14} className={loading ? 'animate-spin' : ''} />
              <span>ធ្វើបច្ចុប្បន្នភាព</span>
            </button>
          </div>

          {/* Sessions Table */}
          <div className="table-container">
            <table className="hrm-table">
              <thead>
                <tr>
                  <th style={{ width: '40px', textAlign: 'center' }}>
                    <input
                      type="checkbox"
                      checked={selectedTokens.length > 0 && selectedTokens.length === filteredSessions.length}
                      onChange={handleToggleSelectAll}
                      style={{ width: '16px', height: '16px', cursor: 'pointer' }}
                    />
                  </th>
                  <th>ព័ត៌មានអ្នកប្រើប្រាស់ (User)</th>
                  <th>តួនាទី / ផ្នែក</th>
                  <th>Token (សង្ខេប)</th>
                  <th>បង្កើតនៅ (Created At)</th>
                  <th>សកម្មភាពចុងក្រោយ (Last Activity)</th>
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
                    return (
                      <tr key={s.id || s.auth_token}>
                        <td style={{ textAlign: 'center' }}>
                          <input
                            type="checkbox"
                            checked={isChecked}
                            onChange={() => handleToggleToken(tokenKey)}
                            style={{ width: '16px', height: '16px', cursor: 'pointer' }}
                          />
                        </td>
                        <td>
                          <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
                            {s.user_name || s.name || 'បុគ្គលិក'}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>ID: {s.employee_id}</div>
                        </td>
                        <td>
                          <span className="badge badge-primary" style={{ fontSize: '11px' }}>
                            {s.user_role || s.position || s.department || 'Staff'}
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
                              }}
                            >
                              {s.auth_token ? `${s.auth_token.substring(0, 16)}...` : 'N/A'}
                            </code>
                            {s.auth_token && (
                              <button
                                type="button"
                                onClick={() => handleCopyToken(s.auth_token)}
                                title="Copy Full Token"
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
                        <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                          <div>{s.created_at ? s.created_at.split(' ')[0] : '-'}</div>
                          <small style={{ color: 'var(--text-muted)' }}>{s.created_at ? s.created_at.split(' ')[1] : ''}</small>
                        </td>
                        <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                          <div>{s.last_used ? s.last_used.split(' ')[0] : '-'}</div>
                          <small style={{ color: 'var(--text-muted)' }}>{s.last_used ? s.last_used.split(' ')[1] : ''}</small>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            type="button"
                            onClick={() => handleRevokeSingle(s)}
                            className="btn btn-danger btn-sm"
                            title="ផ្តាច់ Session នេះ"
                            style={{ padding: '4px 10px' }}
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
        </div>
      )}

      {/* ========================================================================= */}
      {/* 2. GLOBAL TOKEN LIMITS TAB */}
      {/* ========================================================================= */}
      {activeTab === 'global_settings' && (
        <div className="hrm-card" style={{ maxWidth: '650px', padding: '28px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
            <Lock size={20} color="var(--primary)" />
            <h3 style={{ fontSize: '17px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              កំណត់ចំនួន Token អតិបរមា (Global Token Limits)
            </h3>
          </div>

          <form onSubmit={handleSaveGlobalSettings}>
            <div className="form-group">
              <label className="form-label" style={{ fontWeight: 700 }}>
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
                    maxWidth: '120px',
                    fontSize: '1.2rem',
                    fontWeight: 700,
                    textAlign: 'center',
                    height: '46px',
                  }}
                  required
                />
                <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                  (អនុញ្ញាតចាប់ពី 1 ដល់ 10 ឧបករណ៍ក្នុងពេលតែមួយ)
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
                <strong>បញ្ជាក់:</strong> ការកំណត់នេះនឹងកំណត់ចំនួនឧបករណ៍ (Devices) ដែល User នីមួយៗអាច Login ប្រើប្រាស់ក្នុងពេលតែមួយ។ ប្រសិនបើ Login លើសពីចំនួនកំណត់នេះ ប្រព័ន្ធនឹងស្វ័យប្រវត្តផ្តាច់ Token ចាស់។
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '28px' }}>
              <button type="submit" disabled={savingSettings} className="btn btn-primary" style={{ padding: '10px 24px' }}>
                <Save size={16} />
                <span>{savingSettings ? 'កំពុងរក្សាទុក...' : 'រក្សាទុកការកំណត់ (Save)'}</span>
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
