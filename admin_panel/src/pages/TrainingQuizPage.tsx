import React, { useState, useEffect } from 'react';
import { HelpCircle, Plus, Edit2, Trash2, Award, CheckCircle2, Check, RotateCw } from 'lucide-react';
import { Modal } from '../components/common/Modal';
import { adminApi, QuizItem } from '../api/adminApi';

export const TrainingQuizPage: React.FC = () => {
  const [quizzes, setQuizzes] = useState<QuizItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [createModal, setCreateModal] = useState(false);
  const [formData, setFormData] = useState({
    question: '',
    department: 'All Departments',
    correct_answer: '',
    option_a: '',
    option_b: '',
    option_c: '',
    option_d: '',
    points: 10,
  });

  const loadQuizzes = async () => {
    setLoading(true);
    try {
      const res = await adminApi.fetchQuizzes();
      if (res && res.success && Array.isArray(res.quizzes)) {
        setQuizzes(res.quizzes);
      }
    } catch (err) {
      console.error('Error fetching quizzes:', err);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadQuizzes();
  }, []);

  const handleOpenCreate = () => {
    setFormData({
      question: '',
      department: 'All Departments',
      correct_answer: '',
      option_a: '',
      option_b: '',
      option_c: '',
      option_d: '',
      points: 10,
    });
    setCreateModal(true);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.question || !formData.correct_answer) {
      alert('សូមបញ្ចូលសំណួរ និងចម្លើយត្រឹមត្រូវ!');
      return;
    }

    const options = [formData.option_a, formData.option_b];
    if (formData.option_c.trim()) options.push(formData.option_c.trim());
    if (formData.option_d.trim()) options.push(formData.option_d.trim());

    try {
      await adminApi.saveQuiz({
        question: formData.question,
        department: formData.department,
        correct_answer: formData.correct_answer,
        options,
        points: formData.points,
      });
      setCreateModal(false);
      loadQuizzes();
    } catch (err) {
      alert('កំហុសក្នុងការរក្សាទុកសំណួរ');
    }
  };

  const handleDelete = async (id: number) => {
    if (window.confirm('តើអ្នកពិតជាចង់លុបសំណួរនេះមែនទេ?')) {
      try {
        await adminApi.deleteQuiz(id);
        loadQuizzes();
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
            គ្រប់គ្រងសំណួរ Quiz & បណ្តុះបណ្តាល (Training & Quiz)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            បង្កើតសំណួរប្រឡងវាស់ស្ទង់ចំណេះដឹង និងបណ្តុះបណ្តាលបុគ្គលិកថ្មីលើ App
          </p>
        </div>

        <button onClick={handleOpenCreate} className="btn btn-primary">
          <Plus size={16} />
          <span>បង្កើតសំណួរថ្មី (Add Quiz)</span>
        </button>
      </div>

      {/* Quiz Cards */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {quizzes.length === 0 ? (
          <div className="hrm-card" style={{ padding: '36px', textAlign: 'center', color: 'var(--text-muted)' }}>
            {loading ? 'កំពុងទាញយកបញ្ជីសំណួរ...' : 'មិនទាន់មានសំណួរ Quiz នៅឡើយទេ'}
          </div>
        ) : (
          quizzes.map((q, qIndex) => (
            <div key={q.id} className="hrm-card" style={{ padding: '20px 24px' }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span className="badge badge-primary">សំណួរទី {qIndex + 1}</span>
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{q.department} • ពិន្ទុ: {q.points}</span>
                </div>
                <button
                  onClick={() => handleDelete(q.id)}
                  className="btn btn-danger btn-sm"
                  title="លុបសំណួរ"
                >
                  <Trash2 size={13} />
                </button>
              </div>

              <h3 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '14px' }}>
                {q.question}
              </h3>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px' }}>
                {Array.isArray(q.options) &&
                  q.options.map((opt, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '10px 14px',
                        borderRadius: '8px',
                        background: opt === q.correct_answer ? 'rgba(16, 185, 129, 0.12)' : 'var(--surface-alt)',
                        border: `1px solid ${opt === q.correct_answer ? '#10b981' : 'var(--border)'}`,
                        color: opt === q.correct_answer ? '#10b981' : 'var(--text-secondary)',
                        fontWeight: opt === q.correct_answer ? 700 : 500,
                        fontSize: '13px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                      }}
                    >
                      {opt === q.correct_answer ? <CheckCircle2 size={15} /> : <span>•</span>}
                      <span>{opt}</span>
                    </div>
                  ))}
              </div>
            </div>
          ))
        )}
      </div>

      {/* Create Quiz Modal */}
      {createModal && (
        <Modal
          isOpen={createModal}
          onClose={() => setCreateModal(false)}
          title="បង្កើតសំណួរ Quiz ថ្មី"
          maxWidth="560px"
        >
          <form onSubmit={handleSave}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div className="form-group">
                <label className="form-label">សំណួរ (Question) *</label>
                <textarea
                  className="form-input"
                  rows={3}
                  value={formData.question}
                  onChange={(e) => setFormData({ ...formData, question: e.target.value })}
                  placeholder="បញ្ចូលសំណួរ..."
                  required
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">ផ្នែក (Department)</label>
                  <input
                    type="text"
                    className="form-input"
                    value={formData.department}
                    onChange={(e) => setFormData({ ...formData, department: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">ពិន្ទុ (Points)</label>
                  <input
                    type="number"
                    className="form-input"
                    value={formData.points}
                    onChange={(e) => setFormData({ ...formData, points: Number(e.target.value) })}
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">ជម្រើស A *</label>
                  <input
                    type="text"
                    className="form-input"
                    value={formData.option_a}
                    onChange={(e) => setFormData({ ...formData, option_a: e.target.value })}
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">ជម្រើស B *</label>
                  <input
                    type="text"
                    className="form-input"
                    value={formData.option_b}
                    onChange={(e) => setFormData({ ...formData, option_b: e.target.value })}
                    required
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">ជម្រើស C</label>
                  <input
                    type="text"
                    className="form-input"
                    value={formData.option_c}
                    onChange={(e) => setFormData({ ...formData, option_c: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">ជម្រើស D</label>
                  <input
                    type="text"
                    className="form-input"
                    value={formData.option_d}
                    onChange={(e) => setFormData({ ...formData, option_d: e.target.value })}
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">ចម្លើយត្រឹមត្រូវ (Correct Answer) *</label>
                <input
                  type="text"
                  className="form-input"
                  value={formData.correct_answer}
                  onChange={(e) => setFormData({ ...formData, correct_answer: e.target.value })}
                  placeholder="ត្រូវដូចគ្នានឹងជម្រើសណាមួយខាងលើ"
                  required
                />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px', borderTop: '1px solid var(--border)', paddingTop: '14px' }}>
              <button type="button" onClick={() => setCreateModal(false)} className="btn btn-secondary">
                បោះបង់
              </button>
              <button type="submit" className="btn btn-primary">
                <Check size={16} />
                <span>បង្កើតសំណួរ</span>
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
};

