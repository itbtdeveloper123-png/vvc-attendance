import React, { useState, useEffect } from 'react';
import { KeyRound, Shield, Smartphone, Monitor, Trash2, Check, RotateCw } from 'lucide-react';
import { StatCard } from '../components/common/StatCard';
import { adminApi, SessionItem } from '../api/adminApi';

export const TokensPage: React.FC = () => {
  const [sessions, setSessions] = useState<SessionItem[]>([]);
  const [loading, setLoading] = useState(false);

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

  useEffect(() => {
    loadSessions();
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-primary)' }}>
          គ្រប់គ្រង Session & Token សកម្ម (Active Sessions & Security)
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
          តាមដានឧបករណ៍ទូរស័ព្ទ និងកុំព្យូទ័រដែលកំពុង Login ចូលប្រើប្រាស់ និងផ្តាច់ Session បុគ្គលិក
        </p>
      </div>

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
          value="1 ឧបករណ៍ / នាក់"
          subtitle="ការពារការ Login ច្រើនទូរស័ព្ទ"
          icon={<Shield size={22} />}
          variant="gold"
        />
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
            {sessions.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                  {loading ? 'កំពុងទាញយកបញ្ជី Session...' : 'មិនមាន Session សកម្មឡើយ'}
                </td>
              </tr>
            ) : (
              sessions.map((s) => (
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
    </div>
  );
};

