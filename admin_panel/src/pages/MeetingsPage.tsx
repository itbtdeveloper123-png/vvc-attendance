import React, { useState } from 'react';
import { Video, Play, FileText, Calendar, Plus, Sparkles } from 'lucide-react';
import { Modal } from '../components/common/Modal';

export const MeetingsPage: React.FC = () => {
  const [meetings] = useState([
    {
      id: 1,
      topic: 'កិច្ចប្រជុំប្រចាំសប្តាហ៍ - វឌ្ឍនភាពការងារ & ផែនការលក់',
      department: 'Store 318 & SKKS2',
      date: '2026-08-20',
      duration: '45 នាទី',
      summary: 'ពិភាក្សាអំពីយុទ្ធសាស្រ្តបង្កើនការលក់ប្រចាំត្រីមាសទី ៣ និងការគ្រប់គ្រងស្តុកទំនិញថ្មី។',
      hasAudio: true,
    },
    {
      id: 2,
      topic: 'កិច្ចប្រជុំបច្ចេកទេស - ដំឡើងប្រព័ន្ធស្កេនមុខ (Face Net AI)',
      department: 'IT & HRM',
      date: '2026-08-18',
      duration: '30 នាទី',
      summary: 'រៀបចំដាក់ឱ្យដំណើរការមុខងារ AI Face Recognition លើ App ទូរស័ព្ទសម្រាប់បុគ្គលិកទាំងអស់។',
      hasAudio: true,
    },
  ]);

  const [selectedMeeting, setSelectedMeeting] = useState<any | null>(null);

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
            កិច្ចប្រជុំ & AI Summaries (Meetings Management)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            ស្តាប់សំឡេងកិច្ចប្រជុំ មើលប្រតិចារឹក (Transcripts) និងសេចក្តីសង្ខេប AI
          </p>
        </div>

        <button className="btn btn-primary">
          <Plus size={16} />
          <span>បង្ហោះកិច្ចប្រជុំថ្មី</span>
        </button>
      </div>

      {/* Meeting Cards List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {meetings.map((m) => (
          <div
            key={m.id}
            className="hrm-card hover-lift"
            style={{
              padding: '20px 24px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '16px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '16px' }}>
              <div
                style={{
                  width: '48px',
                  height: '48px',
                  borderRadius: '12px',
                  background: 'var(--primary-light)',
                  color: 'var(--primary)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                }}
              >
                <Video size={24} />
              </div>
              <div>
                <h3 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {m.topic}
                </h3>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '14px',
                    fontSize: '12px',
                    color: 'var(--text-muted)',
                    marginTop: '4px',
                  }}
                >
                  <span>📅 {m.date}</span>
                  <span>🏢 {m.department}</span>
                  <span>⏱️ {m.duration}</span>
                </div>
                <p
                  style={{
                    fontSize: '13px',
                    color: 'var(--text-secondary)',
                    marginTop: '8px',
                    maxWidth: '650px',
                  }}
                >
                  {m.summary}
                </p>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <button
                onClick={() => setSelectedMeeting(m)}
                className="btn btn-gold btn-sm"
              >
                <Sparkles size={14} />
                <span>មើល AI Summary & សំឡេង</span>
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Meeting Details Modal */}
      {selectedMeeting && (
        <Modal
          isOpen={!!selectedMeeting}
          onClose={() => setSelectedMeeting(null)}
          title="ព័ត៌មានលម្អិតនៃកិច្ចប្រជុំ & សំឡេង"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
            <div>
              <h4 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
                {selectedMeeting.topic}
              </h4>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
                {selectedMeeting.department} • {selectedMeeting.date}
              </div>
            </div>

            <div
              style={{
                padding: '16px',
                borderRadius: '12px',
                background: 'var(--surface-alt)',
                border: '1px solid var(--border)',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  fontWeight: 700,
                  fontSize: '13px',
                  color: 'var(--accent-gold)',
                  marginBottom: '6px',
                }}
              >
                <Sparkles size={16} />
                <span>សេចក្តីសង្ខេបស្វ័យប្រវត្ត (AI Summary):</span>
              </div>
              <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                {selectedMeeting.summary}
              </p>
            </div>

            <div
              style={{
                padding: '14px',
                borderRadius: '12px',
                background: 'rgba(79, 70, 229, 0.1)',
                border: '1px solid rgba(79, 70, 229, 0.2)',
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
              }}
            >
              <button
                style={{
                  width: '38px',
                  height: '38px',
                  borderRadius: '50%',
                  background: 'var(--primary)',
                  color: '#ffffff',
                  border: 'none',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  cursor: 'pointer',
                }}
              >
                <Play size={18} />
              </button>
              <div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  ឯកសារសំឡេងកិច្ចប្រជុំ (Meeting Audio)
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  ប្រវែង {selectedMeeting.duration} • គុណភាព HD Audio
                </div>
              </div>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
