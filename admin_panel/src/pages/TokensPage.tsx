import React, { useState, useEffect } from 'react';
import {
  KeyRound,
  Shield,
  Smartphone,
  Monitor,
  Trash2,
  Check,
  RotateCw,
  Search,
  Sliders,
  Save,
  Lock,
  AlertCircle,
} from 'lucide-react';
import { StatCard } from '../components/common/StatCard';
import { adminApi, SessionItem } from '../api/adminApi';

export const TokensPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'active_sessions' | 'global_settings'>('active_sessions');
  const [sessions, setSessions] = useState<SessionItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [globalMaxTokens, setGlobalMaxTokens] = useState(1);
  const [savingSettings, setSavingSettings] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const loadSessions = async () => {
    setLoading(true);
    try {
      const res = await adminApi.fetchActiveSessions();
      if (res && res.success && Array.isArray(res.sessions)) {
        setSessions(res.sessions);
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

  const handleRevoke = async (id: number) => {
    if (!window.confirm('តើអ្នកពិតជាចង់ផ្តាច់ Session ឧបករណ៍នេះមែនទេ?')) return;
    try {
      await adminApi.revokeSession(id);
      loadSessions();
    } catch (err) {
      alert('កំហុសក្នុងការផ្តាច់ Session');
    }
  };

  const handleSaveGlobalSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingSettings(true);
    setSaveSuccess(false);
    try {
      await adminApi.saveGlobalTokenSettings(globalMaxTokens);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err) {
      alert('កំហុសក្នុងការរក្សាទុកការកំណត់');
    }
    setSavingSettings(false);
  };

  const filteredSessions = sessions.filter((s) => {
    const q = search.toLowerCase();
    return (
      (s.name || '').toLowerCase().includes(q) ||
      (s.employee_id || '').toLowerCase().includes(q) ||
      (s.device || '').toLowerCase().includes(q) ||
      (s.ip_address || '').toLowerCase().includes(q)
    );
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-primary)' }}>
          គ្រប់គ្រង Session & Token សុវត្ថិភាព (Token & Session Control)
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
          តាមដានឧបករណ៍ទូរស័ព្ទ កុំព្យូទ័រ និងកំណត់ចំនួន Login អតិបរមាសម្រាប់បុគ្គលិកម្នាក់ៗ
        </p>
      </div>

      {/* Tabs */}
      <div
        className="hrm-card"
        style={{
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
        }}
      >
        <button
          onClick={() => setActiveTab('active_sessions')}
          className={`btn btn-sm ${activeTab === 'active_sessions' ? 'btn-primary' : 'btn-secondary'}`}
        >
          <KeyRound size={15} />
          <span>បញ្ជី Session សកម្ម (Active Sessions: {sessions.length})</span>
        </button>
        <button
          onClick={() => setActiveTab('global_settings')}
          className={`btn btn-sm ${activeTab === 'global_settings' ? 'btn-primary' : 'btn-secondary'}`}
        >
          <Sliders size={15} />
          <span>ការកំណត់ Token អតិបរមា (Global Token Limits)</span>
        </button>
      </div>

      {activeTab === 'active_sessions' && (
        <>
          {/* KPI Stats */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
              gap: '20px',
            }}
          >
            <StatCard
              title="Session កំពុងសកម្ម (Active)"
              value={`${sessions.length} ឧបករណ៍`}
              subtitle="ទូរស័ព្ទ & កុំព្យូទ័រ"
              icon={<KeyRound size={22} />}
              variant="primary"
            />
            <StatCard
              title="កម្រិតកំណត់ Session (Max Tokens)"
              value={`${globalMaxTokens} ឧបករណ៍ / នាក់`}
              subtitle="ការពារការ Login ច្រើនទូរស័ព្ទ"
              icon={<Shield size={22} />}
              variant="gold"
            />
          </div>

          {/* Search Toolbar */}
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
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                background: 'var(--surface-alt)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                padding: '7px 12px',
                width: '300px',
                gap: '8px',
              }}
            >
              <Search size={15} color="var(--text-muted)" />
              <input
                type="text"
                placeholder="ស្វែងរកឈ្មោះ, ID, ឧបករណ៍, IP..."
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

            <button onClick={loadSessions} className="btn btn-secondary btn-sm">
              <RotateCw size={14} className={loading ? 'fa-spin' : ''} />
              <span>ធ្វើបច្ចុប្បន្នភាព</span>
            </button>
          </div>

          {/* Sessions Table */}
          <div className="table-container">
            <table className="hrm-table">
              <thead>
                <tr>
                  <th>បុគ្គលិក</th>
                  <th>ឧបករណ៍ (Device)</th>
                  <th>IP Address</th>
                  <th>សកម្មភាពចុងក្រោយ (Last Used)</th>
                  <th>ស្ថានភាព</th>
                  <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
                </tr>
              </thead>
              <tbody>
                {filteredSessions.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                      {loading ? 'កំពុងទាញយកបញ្ជី Session...' : 'មិនមាន Session សកម្មឡើយ'}
                    </td>
                  </tr>
                ) : (
                  filteredSessions.map((s) => (
                    <tr key={s.id}>
                      <td>
                        <div style={{ fontWeight: 600 }}>{s.name || 'បុគ្គលិក'}</div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          {s.employee_id}
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <Smartphone size={15} color="var(--primary)" />
                          <span>{s.device}</span>
                        </div>
                      </td>
                      <td>
                        <code>{s.ip_address}</code>
                      </td>
                      <td style={{ fontFamily: "'Outfit', sans-serif" }}>{s.last_used}</td>
                      <td>
                        <span className="badge badge-good">សកម្ម (Active)</span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          onClick={() => handleRevoke(s.id)}
                          className="btn btn-danger btn-sm"
                          title="ផ្តាច់ Session"
                        >
                          <Trash2 size={13} />
                          <span>ផ្តាច់ Session</span>
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {activeTab === 'global_settings' && (
        <div className="hrm-card" style={{ maxWidth: '650px', padding: '28px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
            <Lock size={20} color="var(--primary)" />
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
              កំណត់ចំនួន Token អតិបរមា (Global Token Limits)
            </h3>
          </div>

          {saveSuccess && (
            <div
              style={{
                padding: '12px 18px',
                borderRadius: '10px',
                background: 'var(--success-light)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                color: 'var(--success)',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                fontSize: '13.5px',
                fontWeight: 600,
                marginBottom: '20px',
              }}
            >
              <Check size={16} />
              <span>ការកំណត់ចំនួន Token ត្រូវបានរក្សាទុកដោយជោគជ័យ!</span>
            </div>
          )}

          <form onSubmit={handleSaveGlobalSettings}>
            <div className="form-group">
              <label className="form-label">
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


