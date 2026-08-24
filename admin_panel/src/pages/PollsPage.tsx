import React, { useState, useEffect } from 'react';
import { Vote, Plus, BarChart3, CheckCircle2, Clock, Trash2, Check, RotateCw } from 'lucide-react';
import { Modal } from '../components/common/Modal';
import { adminApi, PollItem } from '../api/adminApi';

export const PollsPage: React.FC = () => {
  const [polls, setPolls] = useState<PollItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [createModal, setCreateModal] = useState(false);
  const [title, setTitle] = useState('');
  const [endsAt, setEndsAt] = useState(
    new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
  );
  const [option1, setOption1] = useState('');
  const [option2, setOption2] = useState('');
  const [option3, setOption3] = useState('');

  const loadPolls = async () => {
    setLoading(true);
    try {
      const res = await adminApi.fetchPolls();
      if (res && res.success && Array.isArray(res.polls)) {
        setPolls(res.polls);
      }
    } catch (err) {
      console.error('Error fetching polls:', err);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadPolls();
  }, []);

  const handleOpenCreate = () => {
    setTitle('');
    setOption1('');
    setOption2('');
    setOption3('');
    setCreateModal(true);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title || !option1 || !option2) {
      alert('សូមបញ្ចូលចំណងជើង និងជម្រើសយ៉ាងតិច ២!');
      return;
    }

    const options = [
      { text: option1, votes: 0, percentage: 0 },
      { text: option2, votes: 0, percentage: 0 },
    ];
    if (option3.trim()) {
      options.push({ text: option3.trim(), votes: 0, percentage: 0 });
    }

    try {
      await adminApi.savePoll({
        title,
        ends_at: endsAt,
        status: 'Active',
        options,
      });
      setCreateModal(false);
      loadPolls();
    } catch (err) {
      alert('កំហុសក្នុងការបង្កើតការបោះឆ្នោត');
    }
  };

  const handleDelete = async (id: number) => {
    if (window.confirm('តើអ្នកពិតជាចង់លុបការបោះឆ្នោតនេះមែនទេ?')) {
      try {
        await adminApi.deletePoll(id);
        loadPolls();
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
            គ្រប់គ្រងការបោះឆ្នោត (Polls & Voting Management)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            បង្កើតការបោះឆ្នោតស្ទង់មតិផ្ទៃក្នុងក្រុមហ៊ុន និងតាមដានលទ្ធផលបោះឆ្នោតផ្ទាល់
          </p>
        </div>

        <button onClick={handleOpenCreate} className="btn btn-primary">
          <Plus size={16} />
          <span>បង្កើតការបោះឆ្នោតថ្មី (Create Poll)</span>
        </button>
      </div>

      {/* Polls List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {polls.length === 0 ? (
          <div className="hrm-card" style={{ padding: '36px', textAlign: 'center', color: 'var(--text-muted)' }}>
            {loading ? 'កំពុងទាញយកទិន្នន័យបោះឆ្នោត...' : 'មិនមានការបោះឆ្នោតនៅឡើយទេ'}
          </div>
        ) : (
          polls.map((p) => (
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

                <button
                  onClick={() => handleDelete(p.id)}
                  className="btn btn-danger btn-sm"
                  title="លុបការបោះឆ្នោត"
                >
                  <Trash2 size={14} />
                </button>
              </div>

              {/* Poll Options Bar Chart */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {Array.isArray(p.options) &&
                  p.options.map((opt, idx) => (
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
                          {opt.votes} សំឡេង ({opt.percentage || 0}%)
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
                            width: `${opt.percentage || 0}%`,
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
          ))
        )}
      </div>

      {/* Create Poll Modal */}
      {createModal && (
        <Modal
          isOpen={createModal}
          onClose={() => setCreateModal(false)}
          title="បង្កើតការបោះឆ្នោតស្ទង់មតិថ្មី"
          maxWidth="520px"
        >
          <form onSubmit={handleSave}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div className="form-group">
                <label className="form-label">ប្រធានបទ / ចំណងជើងបោះឆ្នោត *</label>
                <input
                  type="text"
                  className="form-input"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="ឧ. ជ្រើសរើសទីតាំងដំណើរកម្សាន្តប្រចាំឆ្នាំ..."
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">ថ្ងៃផុតកំណត់ (Ends At)</label>
                <input
                  type="date"
                  className="form-input"
                  value={endsAt}
                  onChange={(e) => setEndsAt(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">ជម្រើសទី ១ (Option 1) *</label>
                <input
                  type="text"
                  className="form-input"
                  value={option1}
                  onChange={(e) => setOption1(e.target.value)}
                  placeholder="ជម្រើសទី ១..."
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">ជម្រើសទី ២ (Option 2) *</label>
                <input
                  type="text"
                  className="form-input"
                  value={option2}
                  onChange={(e) => setOption2(e.target.value)}
                  placeholder="ជម្រើសទី ២..."
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">ជម្រើសទី ៣ (Option 3 - Optional)</label>
                <input
                  type="text"
                  className="form-input"
                  value={option3}
                  onChange={(e) => setOption3(e.target.value)}
                  placeholder="ជម្រើសទី ៣..."
                />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px', borderTop: '1px solid var(--border)', paddingTop: '14px' }}>
              <button type="button" onClick={() => setCreateModal(false)} className="btn btn-secondary">
                បោះបង់
              </button>
              <button type="submit" className="btn btn-primary">
                <Check size={16} />
                <span>បង្កើតការបោះឆ្នោត</span>
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
};

