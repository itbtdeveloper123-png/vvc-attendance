import React, { useState } from 'react';
import { KeyRound, Shield, Smartphone, Monitor, Trash2, Check } from 'lucide-react';
import { StatCard } from '../components/common/StatCard';

export const TokensPage: React.FC = () => {
  const [sessions, setSessions] = useState([
    {
      id: 1,
      employee_id: 'VVC-101',
      name: 'សុខ គឹមហុង',
      device: 'iPhone 15 Pro (iOS 18.2)',
      ip_address: '103.216.48.12',
      last_used: '2026-08-24 08:35:10',
      status: 'Active',
    },
    {
      id: 2,
      employee_id: 'VVC-102',
      name: 'កែវ សុភា',
      device: 'Samsung Galaxy S24 (Android 14)',
      ip_address: '175.100.12.90',
      last_used: '2026-08-24 08:38:00',
      status: 'Active',
    },
    {
      id: 3,
      employee_id: 'VVC-103',
      name: 'ជា វណ្ណៈ',
      device: 'Xiaomi 13T (Android 14)',
      ip_address: '103.216.48.15',
      last_used: '2026-08-24 07:45:22',
      status: 'Active',
    },
  ]);

  const handleRevoke = (id: number) => {
    if (!window.confirm('តើអ្នកពិតជាចង់ផ្តាច់ Session ឧបករណ៍នេះមែនទេ?')) return;
    setSessions((prev) => prev.filter((s) => s.id !== id));
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
            {sessions.map((s) => (
              <tr key={s.id}>
                <td>
                  <div style={{ fontWeight: 600 }}>{s.name}</div>
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
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
