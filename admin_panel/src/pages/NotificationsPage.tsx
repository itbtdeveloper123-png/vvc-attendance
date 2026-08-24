import React, { useState } from 'react';
import { Bell, Send, Image, Users, Sparkles, Check } from 'lucide-react';
import { adminApi } from '../api/adminApi';

export const NotificationsPage: React.FC = () => {
  const [title, setTitle] = useState('');
  const [message, setMessage] = useState('');
  const [targetType, setTargetType] = useState('all');
  const [imageUrl, setImageUrl] = useState('');
  const [sending, setSending] = useState(false);
  const [sentSuccess, setSentSuccess] = useState(false);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !message.trim()) {
      alert('សូមបញ្ចូលចំណងជើង និងខ្លឹមសារសារ!');
      return;
    }
    setSending(true);
    setSentSuccess(false);
    try {
      await adminApi.sendNotification(title, message, targetType, undefined, imageUrl);
      setSentSuccess(true);
      setTitle('');
      setMessage('');
      setImageUrl('');
      setTimeout(() => setSentSuccess(false), 4000);
    } catch {}
    setSending(false);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '800px' }}>
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-primary)' }}>
          ផ្ញើការជូនដំណឹង & Banners (Push Notifications)
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
          ផ្ញើ Push Notification ទៅកាន់ App ទូរស័ព្ទរបស់បុគ្គលិកទាំងអស់ ឬតាមផ្នែកជាក់លាក់
        </p>
      </div>

      {sentSuccess && (
        <div
          style={{
            padding: '14px 20px',
            borderRadius: '12px',
            background: 'var(--success-light)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            color: 'var(--success)',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            fontSize: '14px',
            fontWeight: 600,
          }}
        >
          <Check size={18} />
          <span>ការជូនដំណឹងត្រូវបានផ្ញើទៅកាន់បុគ្គលិកដោយជោគជ័យ!</span>
        </div>
      )}

      {/* Form Card */}
      <div className="hrm-card" style={{ padding: '28px' }}>
        <form onSubmit={handleSend}>
          <div className="form-group">
            <label className="form-label">អ្នកទទួល (Target Audience)</label>
            <select
              className="form-select"
              value={targetType}
              onChange={(e) => setTargetType(e.target.value)}
            >
              <option value="all">បុគ្គលិកទាំងអស់ (All Employees)</option>
              <option value="Store 318">បុគ្គលិក Store 318</option>
              <option value="Store SKKS2">បុគ្គលិក Store SKKS2</option>
              <option value="Warehouse PSP">បុគ្គលិក Warehouse PSP</option>
              <option value="IT Department">បុគ្គលិក IT</option>
            </select>
          </div>

          <div className="form-group">
            <label className="form-label">ចំណងជើងសារ (Notification Title)</label>
            <input
              type="text"
              className="form-input"
              placeholder="ឧ. សេចក្តីជូនដំណឹងស្តីពីការឈប់សម្រាកបុណ្យភ្ជុំបិណ្ឌ"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">ខ្លឹមសារសារ (Notification Body)</label>
            <textarea
              className="form-textarea"
              rows={4}
              placeholder="បញ្ចូលខ្លឹមសារលម្អិត..."
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">តំណភ្ជាប់រូបភាព (Image URL - ស្រេចចិត្ត)</label>
            <input
              type="url"
              className="form-input"
              placeholder="https://example.com/banner.jpg"
              value={imageUrl}
              onChange={(e) => setImageUrl(e.target.value)}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '24px' }}>
            <button
              type="submit"
              disabled={sending}
              className="btn btn-primary"
              style={{ padding: '12px 24px' }}
            >
              <Send size={16} />
              <span>{sending ? 'កំពុងផ្ញើ...' : 'ផ្ញើការជូនដំណឹង (Send Now)'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
