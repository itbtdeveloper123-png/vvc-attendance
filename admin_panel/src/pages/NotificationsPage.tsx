import React, { useState, useEffect } from 'react';
import { Bell, Send, Image, Users, Sparkles, Check, Trash2, RotateCw } from 'lucide-react';
import { adminApi } from '../api/adminApi';

export const NotificationsPage: React.FC = () => {
  const [title, setTitle] = useState('');
  const [message, setMessage] = useState('');
  const [targetType, setTargetType] = useState('all');
  const [imageUrl, setImageUrl] = useState('');
  const [sending, setSending] = useState(false);
  const [sentSuccess, setSentSuccess] = useState(false);
  const [notifications, setNotifications] = useState<any[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  const loadNotifications = async () => {
    setLoadingHistory(true);
    try {
      const res = await adminApi.fetchNotifications();
      if (res && res.success && Array.isArray(res.notifications)) {
        setNotifications(res.notifications);
      }
    } catch (err) {
      console.error('Error fetching notifications:', err);
    }
    setLoadingHistory(false);
  };

  useEffect(() => {
    loadNotifications();
  }, []);

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
      loadNotifications();
      setTimeout(() => setSentSuccess(false), 4000);
    } catch (err) {
      alert('កំហុសក្នុងការផ្ញើការជូនដំណឹង');
    }
    setSending(false);
  };

  const handleDelete = async (id: number) => {
    if (window.confirm('តើអ្នកពិតជាចង់លុបការជូនដំណឹងនេះមែនទេ?')) {
      try {
        await adminApi.deleteNotification(id);
        loadNotifications();
      } catch (err) {
        alert('កំហុសក្នុងការលុប');
      }
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
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

      {/* Grid: Form on Left, History on Right */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 500px) 1fr', gap: '24px', alignItems: 'start' }}>
        {/* Form Card */}
        <div className="hrm-card" style={{ padding: '24px' }}>
          <h3 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '16px', color: 'var(--text-primary)' }}>
            បង្កើតការជូនដំណឹងថ្មី (New Notification)
          </h3>
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
              <label className="form-label">ចំណងជើងសារ (Notification Title) *</label>
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
              <label className="form-label">ខ្លឹមសារសារ (Notification Body) *</label>
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

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '20px' }}>
              <button
                type="submit"
                disabled={sending}
                className="btn btn-primary"
                style={{ padding: '10px 20px', width: '100%', justifyContent: 'center' }}
              >
                <Send size={16} />
                <span>{sending ? 'កំពុងផ្ញើ...' : 'ផ្ញើការជូនដំណឹង (Send Now)'}</span>
              </button>
            </div>
          </form>
        </div>

        {/* History Table Card */}
        <div className="hrm-card" style={{ padding: '24px' }}>
          <h3 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '16px', color: 'var(--text-primary)' }}>
            ប្រវត្តិការជូនដំណឹង (Sent History)
          </h3>
          <div className="table-container">
            <table className="hrm-table">
              <thead>
                <tr>
                  <th>ចំណងជើង & ខ្លឹមសារ</th>
                  <th>អ្នកទទួល</th>
                  <th>កាលបរិច្ឆេទ</th>
                  <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
                </tr>
              </thead>
              <tbody>
                {notifications.length === 0 ? (
                  <tr>
                    <td colSpan={4} style={{ textAlign: 'center', padding: '28px', color: 'var(--text-muted)' }}>
                      {loadingHistory ? 'កំពុងទាញយក...' : 'មិនទាន់មានប្រវត្តិការជូនដំណឹងឡើយ'}
                    </td>
                  </tr>
                ) : (
                  notifications.map((n) => (
                    <tr key={n.id}>
                      <td>
                        <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{n.title}</div>
                        <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {n.message}
                        </div>
                      </td>
                      <td>
                        <span className="badge badge-primary">{n.recipient_type || 'all'}</span>
                      </td>
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        {n.created_at || '-'}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          onClick={() => handleDelete(n.id)}
                          className="btn btn-danger btn-sm"
                          title="លុប"
                        >
                          <Trash2 size={13} />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

