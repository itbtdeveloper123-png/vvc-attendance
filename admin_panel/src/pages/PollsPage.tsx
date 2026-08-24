import React, { useState } from 'react';
import { Vote, Plus, BarChart3, CheckCircle2, Clock } from 'lucide-react';
import { Modal } from '../components/common/Modal';

export const PollsPage: React.FC = () => {
  const [polls] = useState([
    {
      id: 1,
      title: 'ជ្រើសរើសទីតាំងដំណើរកម្សាន្តប្រចាំឆ្នាំ (Annual Company Trip 2026)',
      creator: 'Super Admin',
      status: 'Active',
      total_votes: 38,
      ends_at: '2026-08-31',
      options: [
        { text: 'ខេត្តមណ្ឌលគិរី (Mondulkiri)', votes: 22, percentage: 58 },
        { text: 'កោះរ៉ុងសន្លឹម (Koh Rong Sanloem)', votes: 12, percentage: 32 },
        { text: 'ខេត្តសៀមរាប (Siem Reap)', votes: 4, percentage: 10 },
      ],
    },
    {
      id: 2,
      title: 'ជ្រើសរើសម៉ឺនុយអាហារថ្ងៃត្រង់សម្រាប់ការប្រជុំធំ',
      creator: 'HR Manager',
      status: 'Closed',
      total_votes: 42,
      ends_at: '2026-08-15',
      options: [
        { text: 'ម្ហូបបែបខ្មែរ (Khmer Set Menu)', votes: 28, percentage: 67 },
        { text: 'អាហារប៊ូហ្វេ (Buffet)', votes: 14, percentage: 33 },
      ],
    },
  ]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
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
            គ្រប់គ្រងការបោះឆ្នោត (Polls & Voting Management)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            បង្កើតការបោះឆ្នោតស្ទង់មតិផ្ទៃក្នុងក្រុមហ៊ុន និងតាមដានលទ្ធផលបោះឆ្នោតផ្ទាល់
          </p>
        </div>

        <button className="btn btn-primary">
          <Plus size={16} />
          <span>បង្កើតការបោះឆ្នោតថ្មី</span>
        </button>
      </div>

      {/* Polls List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {polls.map((p) => (
          <div key={p.id} className="hrm-card" style={{ padding: '24px' }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '12px',
                marginBottom: '18px',
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                  <span
                    className={`badge ${p.status === 'Active' ? 'badge-good' : 'badge-primary'}`}
                  >
                    {p.status === 'Active' ? '🟢 កំពុងដំណើរការ' : '🔒 បានបិទ'}
                  </span>
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    បញ្ចប់ត្រឹម: {p.ends_at} • សំឡេងសរុប: {p.total_votes} នាក់
                  </span>
                </div>
                <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {p.title}
                </h3>
              </div>
            </div>

            {/* Poll Options Bar Chart */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {p.options.map((opt, idx) => (
                <div key={idx} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      fontSize: '13px',
                      fontWeight: 600,
                      color: 'var(--text-secondary)',
                    }}
                  >
                    <span>{opt.text}</span>
                    <span>
                      {opt.votes} សំឡេង ({opt.percentage}%)
                    </span>
                  </div>
                  <div
                    style={{
                      width: '100%',
                      height: '10px',
                      borderRadius: '5px',
                      background: 'var(--border)',
                      overflow: 'hidden',
                    }}
                  >
                    <div
                      style={{
                        width: `${opt.percentage}%`,
                        height: '100%',
                        borderRadius: '5px',
                        background:
                          idx === 0
                            ? 'linear-gradient(90deg, #4f46e5 0%, #3b82f6 100%)'
                            : idx === 1
                            ? 'linear-gradient(90deg, #d4af37 0%, #b8860b 100%)'
                            : 'linear-gradient(90deg, #10b981 0%, #059669 100%)',
                        transition: 'width 0.8s ease',
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
