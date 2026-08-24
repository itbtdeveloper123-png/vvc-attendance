import React, { useState } from 'react';
import { HelpCircle, Plus, Edit2, Trash2, Award, CheckCircle2 } from 'lucide-react';
import { Modal } from '../components/common/Modal';

export const TrainingQuizPage: React.FC = () => {
  const [quizzes] = useState([
    {
      id: 1,
      question: 'តើម៉ោងធ្វើការស្តង់ដារពេលព្រឹករបស់ VVC ចាប់ផ្តើមពីម៉ោងប៉ុន្មាន?',
      department: 'All Departments',
      correct_answer: '08:00 AM',
      options: ['07:30 AM', '08:00 AM', '08:30 AM', '09:00 AM'],
      points: 10,
    },
    {
      id: 2,
      question: 'តើការស្នើសុំច្បាប់ឈប់សម្រាកប្រចាំឆ្នាំ ត្រូវស្នើសុំមុនយ៉ាងតិចប៉ុន្មានថ្ងៃ?',
      department: 'HRM',
      correct_answer: '៣ ថ្ងៃមុន',
      options: ['១ ថ្ងៃមុន', '២ ថ្ងៃមុន', '៣ ថ្ងៃមុន', '៥ ថ្ងៃមុន'],
      points: 10,
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
            គ្រប់គ្រងសំណួរ Quiz & បណ្តុះបណ្តាល (Training & Quiz)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            បង្កើតសំណួរប្រឡងវាស់ស្ទង់ចំណេះដឹង និងបណ្តុះបណ្តាលបុគ្គលិកថ្មីលើ App
          </p>
        </div>

        <button className="btn btn-primary">
          <Plus size={16} />
          <span>បង្កើតសំណួរថ្មី</span>
        </button>
      </div>

      {/* Quiz Cards */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {quizzes.map((q) => (
          <div key={q.id} className="hrm-card" style={{ padding: '20px 24px' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span className="badge badge-primary">សំណួរទី {q.id}</span>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{q.department} • ពិន្ទុ: {q.points}</span>
              </div>
            </div>

            <h3 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '14px' }}>
              {q.question}
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px' }}>
              {q.options.map((opt, idx) => (
                <div
                  key={idx}
                  style={{
                    padding: '10px 14px',
                    borderRadius: '8px',
                    background: opt === q.correct_answer ? 'var(--success-light)' : 'var(--surface-alt)',
                    border: `1px solid ${opt === q.correct_answer ? 'var(--success)' : 'var(--border)'}`,
                    color: opt === q.correct_answer ? 'var(--success)' : 'var(--text-secondary)',
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
        ))}
      </div>
    </div>
  );
};
