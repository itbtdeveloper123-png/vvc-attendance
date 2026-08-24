import React, { useState, useEffect } from 'react';
import { Video, Play, FileText, Calendar, Plus, Sparkles, Trash2, Check, RotateCw } from 'lucide-react';
import { Modal } from '../components/common/Modal';
import { adminApi, MeetingItem } from '../api/adminApi';

export const MeetingsPage: React.FC = () => {
  const [meetings, setMeetings] = useState<MeetingItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedMeeting, setSelectedMeeting] = useState<MeetingItem | null>(null);
  const [createModal, setCreateModal] = useState(false);
  const [formData, setFormData] = useState({
    topic: '',
    department: 'Store 318 & SKKS2',
    date: new Date().toISOString().split('T')[0],
    duration: '30 នាទី',
    summary: '',
    audio_url: '',
  });

  const loadMeetings = async () => {
    setLoading(true);
    try {
      const res = await adminApi.fetchMeetings();
      if (res && res.success && Array.isArray(res.meetings)) {
        setMeetings(res.meetings);
      }
    } catch (err) {
      console.error('Error fetching meetings:', err);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadMeetings();
  }, []);

  const handleOpenCreate = () => {
    setFormData({
      topic: '',
      department: 'Store 318 & SKKS2',
      date: new Date().toISOString().split('T')[0],
      duration: '30 នាទី',
      summary: '',
      audio_url: '',
    });
    setCreateModal(true);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.topic) return;
    try {
      await adminApi.saveMeeting(formData);
      setCreateModal(false);
      loadMeetings();
    } catch (err) {
      alert('កំហុសក្នុងការរក្សាទុកកិច្ចប្រជុំ');
    }
  };

  const handleDelete = async (id: number) => {
    if (window.confirm('តើអ្នកពិតជាចង់លុបកិច្ចប្រជុំនេះមែនទេ?')) {
      try {
        await adminApi.deleteMeeting(id);
        loadMeetings();
      } catch (err) {
        alert('កំហុសក្នុងការលុប');
      }
    }
  };

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

        <button onClick={handleOpenCreate} className="btn btn-primary">
          <Plus size={16} />
          <span>បង្ហោះកិច្ចប្រជុំថ្មី (New Meeting)</span>
        </button>
      </div>

      {/* Meeting Cards List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {meetings.length === 0 ? (
          <div className="hrm-card" style={{ padding: '36px', textAlign: 'center', color: 'var(--text-muted)' }}>
            {loading ? 'កំពុងទាញយកទិន្នន័យកិច្ចប្រជុំ...' : 'មិនទាន់មានកិច្ចប្រជុំដែលបានកត់ត្រានៅឡើយទេ'}
          </div>
        ) : (
          meetings.map((m) => (
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
                <button
                  onClick={() => handleDelete(m.id)}
                  className="btn btn-danger btn-sm"
                  title="លុប"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Create Meeting Modal */}
      {createModal && (
        <Modal
          isOpen={createModal}
          onClose={() => setCreateModal(false)}
          title="បង្ហោះកិច្ចប្រជុំថ្មី"
          maxWidth="560px"
        >
          <form onSubmit={handleSave}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div className="form-group">
                <label className="form-label">ប្រធានបទកិច្ចប្រជុំ (Meeting Topic) *</label>
                <input
                  type="text"
                  className="form-input"
                  value={formData.topic}
                  onChange={(e) => setFormData({ ...formData, topic: e.target.value })}
                  placeholder="ឧ. កិច្ចប្រជុំប្រចាំសប្តាហ៍"
                  required
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">ផ្នែក / សាខា</label>
                  <input
                    type="text"
                    className="form-input"
                    value={formData.department}
                    onChange={(e) => setFormData({ ...formData, department: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">កាលបរិច្ឆេទ</label>
                  <input
                    type="date"
                    className="form-input"
                    value={formData.date}
                    onChange={(e) => setFormData({ ...formData, date: e.target.value })}
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">រយៈពេល (Duration)</label>
                <input
                  type="text"
                  className="form-input"
                  value={formData.duration}
                  onChange={(e) => setFormData({ ...formData, duration: e.target.value })}
                  placeholder="ឧ. 45 នាទី"
                />
              </div>

              <div className="form-group">
                <label className="form-label">សេចក្តីសង្ខេប / កំណត់ត្រា (Summary)</label>
                <textarea
                  className="form-input"
                  rows={4}
                  value={formData.summary}
                  onChange={(e) => setFormData({ ...formData, summary: e.target.value })}
                  placeholder="បញ្ចូលសេចក្តីសង្ខេបកិច្ចប្រជុំ..."
                />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px', borderTop: '1px solid var(--border)', paddingTop: '14px' }}>
              <button type="button" onClick={() => setCreateModal(false)} className="btn btn-secondary">
                បោះបង់
              </button>
              <button type="submit" className="btn btn-primary">
                <Check size={16} />
                <span>បង្ហោះកិច្ចប្រជុំ</span>
              </button>
            </div>
          </form>
        </Modal>
      )}

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

