import React, { useState, useEffect } from 'react';
import {
  Bell,
  Send,
  Image as ImageIcon,
  Users,
  Sparkles,
  Check,
  Trash2,
  RotateCw,
  Search,
  Filter,
  Calendar,
  Clock,
  Layers,
  FileText,
  Plus,
  Edit3,
  Play,
  Pause,
  X,
  Smartphone,
  ExternalLink,
  ChevronRight,
  UserCheck,
  Tag,
  AlertCircle
} from 'lucide-react';
import {
  adminApi,
  NotificationItem,
  NotificationTemplate,
  NotificationSchedule,
  NotificationRecipientUser
} from '../api/adminApi';

export const NotificationsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'broadcast' | 'templates' | 'schedules' | 'history'>('broadcast');

  // Metadata
  const [usersList, setUsersList] = useState<NotificationRecipientUser[]>([]);
  const [rolesList, setRolesList] = useState<string[]>([]);

  // 1. Broadcast State
  const [sendTitle, setSendTitle] = useState('');
  const [sendMessage, setSendMessage] = useState('');
  const [targetType, setTargetType] = useState<'all' | 'role' | 'user'>('all');
  const [selectedRoles, setSelectedRoles] = useState<string[]>([]);
  const [selectedUsers, setSelectedUsers] = useState<string[]>([]);
  const [userSearchTerm, setUserSearchTerm] = useState('');
  const [expiryDate, setExpiryDate] = useState('');
  const [imageUrl, setImageUrl] = useState('');
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imageFilePreview, setImageFilePreview] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [sentSuccess, setSentSuccess] = useState(false);
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>('');

  // 2. Templates State
  const [templates, setTemplates] = useState<NotificationTemplate[]>([]);
  const [loadingTemplates, setLoadingTemplates] = useState(false);
  const [templateForm, setTemplateForm] = useState({
    id: 0,
    template_name: '',
    template_key: '',
    title_template: '',
    message_template: '',
    target_type: 'all',
    target_roles_text: '',
    target_users_text: '',
    image_url: '',
    is_active: 1
  });
  const [savingTemplate, setSavingTemplate] = useState(false);

  // 3. Schedules State
  const [schedules, setSchedules] = useState<NotificationSchedule[]>([]);
  const [loadingSchedules, setLoadingSchedules] = useState(false);
  const [scheduleForm, setScheduleForm] = useState({
    id: 0,
    schedule_name: '',
    template_id: 0,
    frequency: 'once',
    scheduled_at: '',
    time_of_day: '09:00',
    day_of_week: 1,
    day_of_month: 1,
    title_override: '',
    message_override: '',
    target_type: '',
    target_roles_text: '',
    target_users_text: '',
    image_url: '',
    is_active: 1
  });
  const [savingSchedule, setSavingSchedule] = useState(false);

  // 4. History State
  const [history, setHistory] = useState<NotificationItem[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [historySearch, setHistorySearch] = useState('');
  const [selectedHistoryIds, setSelectedHistoryIds] = useState<number[]>([]);
  const [lightboxImage, setLightboxImage] = useState<string | null>(null);

  // Load Recipients Metadata
  const loadRecipients = async () => {
    try {
      const res = await adminApi.fetchNotificationRecipients();
      if (res && res.success) {
        if (Array.isArray(res.users)) setUsersList(res.users);
        if (Array.isArray(res.roles)) setRolesList(res.roles);
      }
    } catch (err) {
      console.error('Error fetching recipients:', err);
    }
  };

  // Load Templates
  const loadTemplates = async () => {
    setLoadingTemplates(true);
    try {
      const res = await adminApi.fetchNotificationTemplates();
      if (res && res.success && Array.isArray(res.templates || res.data)) {
        setTemplates(res.templates || res.data);
      }
    } catch (err) {
      console.error('Error fetching templates:', err);
    }
    setLoadingTemplates(false);
  };

  // Load Schedules
  const loadSchedules = async () => {
    setLoadingSchedules(true);
    try {
      const res = await adminApi.fetchNotificationSchedules();
      if (res && res.success && Array.isArray(res.schedules || res.data)) {
        setSchedules(res.schedules || res.data);
      }
    } catch (err) {
      console.error('Error fetching schedules:', err);
    }
    setLoadingSchedules(false);
  };

  // Load History
  const loadHistory = async () => {
    setLoadingHistory(true);
    try {
      const res = await adminApi.fetchNotifications();
      if (res && res.success && Array.isArray(res.notifications || res.data)) {
        setHistory(res.notifications || res.data);
      }
    } catch (err) {
      console.error('Error fetching history:', err);
    }
    setLoadingHistory(false);
  };

  useEffect(() => {
    loadRecipients();
    loadTemplates();
    loadSchedules();
    loadHistory();
  }, []);

  // Handle Apply Template to Broadcast Form
  const handleApplyTemplate = (templateIdStr: string) => {
    setSelectedTemplateId(templateIdStr);
    if (!templateIdStr) return;
    const tpl = templates.find(t => String(t.id) === templateIdStr);
    if (tpl) {
      setSendTitle(tpl.title_template || '');
      setSendMessage(tpl.message_template || '');
      if (tpl.target_type === 'all' || tpl.target_type === 'role' || tpl.target_type === 'user') {
        setTargetType(tpl.target_type);
      }
      if (tpl.image_url) {
        setImageUrl(tpl.image_url);
      }
    }
  };

  // Insert placeholder helper into message
  const handleInsertPlaceholder = (placeholder: string) => {
    setSendMessage(prev => prev + ' ' + placeholder + ' ');
  };

  // Handle Image File Selection
  const handleImageFileChange = (file: File | null) => {
    setImageFile(file);
    if (file) {
      const url = URL.createObjectURL(file);
      setImageFilePreview(url);
    } else {
      setImageFilePreview(null);
    }
  };

  // Toggle Role selection
  const handleToggleRole = (role: string) => {
    setSelectedRoles(prev =>
      prev.includes(role) ? prev.filter(r => r !== role) : [...prev, role]
    );
  };

  // Toggle User selection
  const handleToggleUser = (empId: string) => {
    setSelectedUsers(prev =>
      prev.includes(empId) ? prev.filter(u => u !== empId) : [...prev, empId]
    );
  };

  // 1. Submit Broadcast Notification
  const handleSendBroadcast = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sendTitle.trim() || !sendMessage.trim()) {
      alert('សូមបញ្ចូលចំណងជើង និងខ្លឹមសារសារជូនដំណឹង!');
      return;
    }
    if (targetType === 'role' && selectedRoles.length === 0) {
      alert('សូមជ្រើសរើសតួនាទីយ៉ាងហោចណាស់មួយ!');
      return;
    }
    if (targetType === 'user' && selectedUsers.length === 0) {
      alert('សូមជ្រើសរើសបុគ្គលិកយ៉ាងហោចណាស់ម្នាក់!');
      return;
    }

    setSending(true);
    setSentSuccess(false);

    try {
      const formData = new FormData();
      formData.append('title', sendTitle);
      formData.append('message', sendMessage);
      formData.append('target_type', targetType);
      if (expiryDate) formData.append('expiry_date', expiryDate);
      if (imageUrl) formData.append('image_url', imageUrl);
      if (imageFile) formData.append('notification_image', imageFile);

      if (targetType === 'role') {
        selectedRoles.forEach(r => formData.append('target_roles[]', r));
      }
      if (targetType === 'user') {
        selectedUsers.forEach(u => formData.append('target_users[]', u));
      }

      const res = await adminApi.sendNotification(formData);
      if (res && (res.success || res.status === 'success')) {
        setSentSuccess(true);
        // Reset form
        setSendTitle('');
        setSendMessage('');
        setImageUrl('');
        setImageFile(null);
        setImageFilePreview(null);
        setSelectedRoles([]);
        setSelectedUsers([]);
        setSelectedTemplateId('');
        loadHistory();

        setTimeout(() => setSentSuccess(false), 4000);
      } else {
        alert(res.message || 'កំហុសក្នុងការផ្ញើការជូនដំណឹង');
      }
    } catch (err: any) {
      alert(err?.message || 'កំហុសក្នុងការតភ្ជាប់ទៅកាន់ Server');
    }
    setSending(false);
  };

  // 2. Template CRUD Handlers
  const handleSaveTemplate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!templateForm.template_name || !templateForm.title_template || !templateForm.message_template) {
      alert('សូមបំពេញឈ្មោះ Template, Title និង Message!');
      return;
    }
    setSavingTemplate(true);
    try {
      const res = await adminApi.saveNotificationTemplate(templateForm);
      if (res && (res.success || res.status === 'success')) {
        setTemplateForm({
          id: 0,
          template_name: '',
          template_key: '',
          title_template: '',
          message_template: '',
          target_type: 'all',
          target_roles_text: '',
          target_users_text: '',
          image_url: '',
          is_active: 1
        });
        loadTemplates();
      } else {
        alert(res.message || 'កំហុសក្នុងការរក្សាទុក Template');
      }
    } catch (err: any) {
      alert(err?.message || 'កំហុសក្នុងការតភ្ជាប់ទៅកាន់ Server');
    }
    setSavingTemplate(false);
  };

  const handleEditTemplate = (tpl: NotificationTemplate) => {
    setTemplateForm({
      id: tpl.id,
      template_name: tpl.template_name,
      template_key: tpl.template_key || '',
      title_template: tpl.title_template,
      message_template: tpl.message_template,
      target_type: tpl.target_type || 'all',
      target_roles_text: tpl.target_roles_json || '',
      target_users_text: tpl.target_users_json || '',
      image_url: tpl.image_url || '',
      is_active: tpl.is_active ? 1 : 0
    });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleDeleteTemplate = async (id: number) => {
    if (window.confirm('តើអ្នកពិតជាចង់លុប Template នេះមែនទេ?')) {
      try {
        await adminApi.deleteNotificationTemplate(id);
        loadTemplates();
      } catch (err) {
        alert('កំហុសក្នុងការលុប Template');
      }
    }
  };

  // 3. Schedule CRUD Handlers
  const handleSaveSchedule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scheduleForm.schedule_name) {
      alert('សូមបញ្ចូលឈ្មោះកាលវិភាគ (Schedule Name)!');
      return;
    }
    setSavingSchedule(true);
    try {
      const res = await adminApi.saveNotificationSchedule(scheduleForm);
      if (res && (res.success || res.status === 'success')) {
        setScheduleForm({
          id: 0,
          schedule_name: '',
          template_id: 0,
          frequency: 'once',
          scheduled_at: '',
          time_of_day: '09:00',
          day_of_week: 1,
          day_of_month: 1,
          title_override: '',
          message_override: '',
          target_type: '',
          target_roles_text: '',
          target_users_text: '',
          image_url: '',
          is_active: 1
        });
        loadSchedules();
      } else {
        alert(res.message || 'កំហុសក្នុងការរក្សាទុកកាលវិភាគ');
      }
    } catch (err: any) {
      alert(err?.message || 'កំហុសក្នុងការតភ្ជាប់ទៅកាន់ Server');
    }
    setSavingSchedule(false);
  };

  const handleEditSchedule = (sch: NotificationSchedule) => {
    setScheduleForm({
      id: sch.id,
      schedule_name: sch.schedule_name,
      template_id: sch.template_id || 0,
      frequency: sch.frequency || 'once',
      scheduled_at: sch.scheduled_at || '',
      time_of_day: sch.time_of_day || '09:00',
      day_of_week: sch.day_of_week !== undefined && sch.day_of_week !== null ? Number(sch.day_of_week) : 1,
      day_of_month: sch.day_of_month !== undefined && sch.day_of_month !== null ? Number(sch.day_of_month) : 1,
      title_override: sch.title_override || '',
      message_override: sch.message_override || '',
      target_type: sch.target_type || '',
      target_roles_text: sch.target_roles_json || '',
      target_users_text: sch.target_users_json || '',
      image_url: sch.image_url || '',
      is_active: sch.is_active ? 1 : 0
    });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleToggleSchedule = async (id: number) => {
    try {
      await adminApi.toggleNotificationSchedule(id);
      loadSchedules();
    } catch (err) {
      alert('កំហុសក្នុងការផ្លាស់ប្តូរស្ថានភាពកាលវិភាគ');
    }
  };

  const handleDeleteSchedule = async (id: number) => {
    if (window.confirm('តើអ្នកពិតជាចង់លុបកាលវិភាគនេះមែនទេ?')) {
      try {
        await adminApi.deleteNotificationSchedule(id);
        loadSchedules();
      } catch (err) {
        alert('កំហុសក្នុងការលុបកាលវិភាគ');
      }
    }
  };

  // 4. History Delete Handlers
  const handleDeleteHistory = async (id: number) => {
    if (window.confirm('តើអ្នកពិតជាចង់លុបសារជូនដំណឹងនេះមែនទេ?')) {
      try {
        await adminApi.deleteNotification(id);
        loadHistory();
      } catch (err) {
        alert('កំហុសក្នុងការលុប');
      }
    }
  };

  const handleBulkDeleteHistory = async () => {
    if (selectedHistoryIds.length === 0) return;
    if (window.confirm(`តើអ្នកពិតជាចង់លុបសារដែលបានជ្រើសរើសទាំង ${selectedHistoryIds.length} នេះមែនទេ?`)) {
      try {
        await adminApi.bulkDeleteNotifications(selectedHistoryIds);
        setSelectedHistoryIds([]);
        loadHistory();
      } catch (err) {
        alert('កំហុសក្នុងការលុបច្រើនសារ');
      }
    }
  };

  const handleToggleSelectAllHistory = () => {
    if (selectedHistoryIds.length === filteredHistory.length) {
      setSelectedHistoryIds([]);
    } else {
      setSelectedHistoryIds(filteredHistory.map(h => h.id));
    }
  };

  const handleToggleHistoryItem = (id: number) => {
    setSelectedHistoryIds(prev =>
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  const filteredHistory = history.filter(h => {
    const s = historySearch.toLowerCase();
    const title = (h.title || '').toLowerCase();
    const msg = (h.message || '').toLowerCase();
    return !historySearch || title.includes(s) || msg.includes(s);
  });

  const filteredUsersList = usersList.filter(u => {
    const s = userSearchTerm.toLowerCase();
    return !userSearchTerm || u.name.toLowerCase().includes(s) || u.employee_id.toLowerCase().includes(s) || (u.department || '').toLowerCase().includes(s);
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
      {/* Header Banner */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
          background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.08), rgba(79, 70, 229, 0.03))',
          padding: '24px',
          borderRadius: '18px',
          border: '1px solid rgba(99, 102, 241, 0.15)'
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
            <span
              style={{
                background: 'var(--primary)',
                color: '#fff',
                width: '36px',
                height: '36px',
                borderRadius: '10px',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: '0 4px 10px rgba(99, 102, 241, 0.3)'
              }}
            >
              <Bell size={20} />
            </span>
            <h2 style={{ fontSize: '22px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              ផ្ញើការជូនដំណឹង & កាលវិភាគ (Notifications & Schedules)
            </h2>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0 }}>
            ផ្ញើ Push Notification ភ្លាមៗ គ្រប់គ្រងគំរូសារ (Templates) កាលវិភាគ (Schedules) និងប្រវត្តិផ្ញើ
          </p>
        </div>

        {/* 4 Navigation Tabs */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'var(--surface-subtle, #f1f5f9)', padding: '6px', borderRadius: '14px', flexWrap: 'wrap' }}>
          <button
            type="button"
            onClick={() => setActiveTab('broadcast')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '9px 15px',
              borderRadius: '10px',
              fontWeight: 700,
              fontSize: '13px',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              background: activeTab === 'broadcast' ? 'var(--primary)' : 'transparent',
              color: activeTab === 'broadcast' ? '#fff' : 'var(--text-secondary)',
              boxShadow: activeTab === 'broadcast' ? '0 4px 12px rgba(99, 102, 241, 0.28)' : 'none'
            }}
          >
            <Send size={15} />
            <span>ផ្ញើភ្លាមៗ (Broadcast)</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('templates')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '9px 15px',
              borderRadius: '10px',
              fontWeight: 700,
              fontSize: '13px',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              background: activeTab === 'templates' ? '#fff' : 'transparent',
              color: activeTab === 'templates' ? 'var(--primary)' : 'var(--text-secondary)',
              boxShadow: activeTab === 'templates' ? '0 4px 12px rgba(0,0,0,0.06)' : 'none'
            }}
          >
            <FileText size={15} />
            <span>គំរូសារ Templates ({templates.length})</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('schedules')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '9px 15px',
              borderRadius: '10px',
              fontWeight: 700,
              fontSize: '13px',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              background: activeTab === 'schedules' ? '#fff' : 'transparent',
              color: activeTab === 'schedules' ? 'var(--primary)' : 'var(--text-secondary)',
              boxShadow: activeTab === 'schedules' ? '0 4px 12px rgba(0,0,0,0.06)' : 'none'
            }}
          >
            <Calendar size={15} />
            <span>កាលវិភាគ Schedules ({schedules.length})</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('history')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '9px 15px',
              borderRadius: '10px',
              fontWeight: 700,
              fontSize: '13px',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              background: activeTab === 'history' ? '#fff' : 'transparent',
              color: activeTab === 'history' ? 'var(--primary)' : 'var(--text-secondary)',
              boxShadow: activeTab === 'history' ? '0 4px 12px rgba(0,0,0,0.06)' : 'none'
            }}
          >
            <Clock size={15} />
            <span>ប្រវត្តិផ្ញើ History ({history.length})</span>
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: INSTANT BROADCAST                                                  */}
      {/* ========================================================================= */}
      {activeTab === 'broadcast' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(340px, 1fr) 340px', gap: '22px', alignItems: 'start' }}>
          {/* Left: Broadcast Form */}
          <div className="hrm-card" style={{ padding: '26px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', borderBottom: '1px solid #f1f5f9', paddingBottom: '14px' }}>
              <h3 style={{ fontSize: '17px', fontWeight: 800, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Send size={18} style={{ color: 'var(--primary)' }} />
                ផ្ញើសារជូនដំណឹងភ្លាមៗ (Instant Broadcast)
              </h3>
              <span className="badge badge-primary" style={{ fontSize: '11px', padding: '4px 10px' }}>
                <Sparkles size={11} style={{ marginRight: '4px' }} /> Mobile Push & In-App
              </span>
            </div>

            {sentSuccess && (
              <div
                style={{
                  padding: '14px 18px',
                  borderRadius: '12px',
                  background: 'var(--success-light, #dcfce7)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  color: 'var(--success, #166534)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  fontSize: '14px',
                  fontWeight: 700,
                  marginBottom: '20px'
                }}
              >
                <Check size={18} />
                <span>សារជូនដំណឹងត្រូវបានផ្ញើទៅកាន់បុគ្គលិកដោយជោគជ័យ!</span>
              </div>
            )}

            <form onSubmit={handleSendBroadcast}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {/* Apply Template & Expiry Date */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                  <div className="form-group">
                    <label className="form-label" style={{ fontWeight: 700 }}>
                      ជ្រើសរើសគំរូសារ (Apply Template)
                    </label>
                    <select
                      className="form-select"
                      value={selectedTemplateId}
                      onChange={(e) => handleApplyTemplate(e.target.value)}
                    >
                      <option value="">-- បញ្ចូលសារផ្ទាល់ខ្លួន (Custom) --</option>
                      {templates.map(t => (
                        <option key={t.id} value={t.id}>{t.template_name}</option>
                      ))}
                    </select>
                  </div>

                  <div className="form-group">
                    <label className="form-label" style={{ fontWeight: 700 }}>
                      ថ្ងៃផុតកំណត់ (Expiry Date - ស្រេចចិត្ត)
                    </label>
                    <input
                      type="date"
                      className="form-input"
                      value={expiryDate}
                      onChange={(e) => setExpiryDate(e.target.value)}
                    />
                  </div>
                </div>

                {/* Notification Title */}
                <div className="form-group">
                  <label className="form-label" style={{ fontWeight: 700 }}>
                    ចំណងជើងសារ (Notification Title) *
                  </label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="ឧ. សេចក្តីជូនដំណឹងស្តីពីការឈប់សម្រាកបុណ្យភ្ជុំបិណ្ឌ"
                    value={sendTitle}
                    onChange={(e) => setSendTitle(e.target.value)}
                    required
                    style={{ fontSize: '15px' }}
                  />
                </div>

                {/* Target Audience Selector */}
                <div className="form-group">
                  <label className="form-label" style={{ fontWeight: 700 }}>
                    អ្នកទទួលសារ (Target Audience) *
                  </label>
                  <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                    <button
                      type="button"
                      onClick={() => setTargetType('all')}
                      style={{
                        flex: 1,
                        minWidth: '130px',
                        padding: '10px 14px',
                        borderRadius: '10px',
                        fontWeight: 700,
                        fontSize: '13px',
                        border: targetType === 'all' ? '2px solid var(--primary)' : '1px solid #cbd5e1',
                        background: targetType === 'all' ? '#eef2ff' : '#fff',
                        color: targetType === 'all' ? 'var(--primary)' : '#475569',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '6px'
                      }}
                    >
                      <Users size={16} />
                      <span>បុគ្គលិកទាំងអស់ (All)</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setTargetType('role')}
                      style={{
                        flex: 1,
                        minWidth: '130px',
                        padding: '10px 14px',
                        borderRadius: '10px',
                        fontWeight: 700,
                        fontSize: '13px',
                        border: targetType === 'role' ? '2px solid var(--primary)' : '1px solid #cbd5e1',
                        background: targetType === 'role' ? '#eef2ff' : '#fff',
                        color: targetType === 'role' ? 'var(--primary)' : '#475569',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '6px'
                      }}
                    >
                      <Tag size={16} />
                      <span>តាមតួនាទី (By Role)</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setTargetType('user')}
                      style={{
                        flex: 1,
                        minWidth: '130px',
                        padding: '10px 14px',
                        borderRadius: '10px',
                        fontWeight: 700,
                        fontSize: '13px',
                        border: targetType === 'user' ? '2px solid var(--primary)' : '1px solid #cbd5e1',
                        background: targetType === 'user' ? '#eef2ff' : '#fff',
                        color: targetType === 'user' ? 'var(--primary)' : '#475569',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '6px'
                      }}
                    >
                      <UserCheck size={16} />
                      <span>បុគ្គលិកជាក់លាក់ (Users)</span>
                    </button>
                  </div>
                </div>

                {/* By Role Picker */}
                {targetType === 'role' && (
                  <div style={{ background: '#f8fafc', padding: '14px', borderRadius: '12px', border: '1px solid #e2e8f0' }}>
                    <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '8px' }}>
                      ជ្រើសរើសតួនាទីគោលដៅ ({selectedRoles.length} បានជ្រើសរើស):
                    </div>
                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      {rolesList.map(role => {
                        const isSelected = selectedRoles.includes(role);
                        return (
                          <button
                            key={role}
                            type="button"
                            onClick={() => handleToggleRole(role)}
                            style={{
                              padding: '6px 14px',
                              borderRadius: '999px',
                              fontSize: '12px',
                              fontWeight: 700,
                              border: isSelected ? '1px solid var(--primary)' : '1px solid #cbd5e1',
                              background: isSelected ? 'var(--primary)' : '#fff',
                              color: isSelected ? '#fff' : '#475569',
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '6px'
                            }}
                          >
                            {isSelected && <Check size={12} />}
                            <span>{role}</span>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Specific Users Picker */}
                {targetType === 'user' && (
                  <div style={{ background: '#f8fafc', padding: '14px', borderRadius: '12px', border: '1px solid #e2e8f0' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                      <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)' }}>
                        ជ្រើសរើសបុគ្គលិក ({selectedUsers.length} នាក់):
                      </div>
                      {selectedUsers.length > 0 && (
                        <button
                          type="button"
                          onClick={() => setSelectedUsers([])}
                          style={{ border: 'none', background: 'transparent', color: '#ef4444', fontSize: '11px', cursor: 'pointer', fontWeight: 700 }}
                        >
                          លុបជម្រើសទាំងអស់
                        </button>
                      )}
                    </div>

                    <div style={{ position: 'relative', marginBottom: '10px' }}>
                      <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: '#94a3b8' }} />
                      <input
                        type="text"
                        className="form-input"
                        placeholder="ស្វែងរកតាមឈ្មោះ ឬអត្តលេខបុគ្គលិក..."
                        value={userSearchTerm}
                        onChange={(e) => setUserSearchTerm(e.target.value)}
                        style={{ paddingLeft: '32px', fontSize: '12px', padding: '8px 12px 8px 32px' }}
                      />
                    </div>

                    <div style={{ maxHeight: '180px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      {filteredUsersList.map(u => {
                        const isSelected = selectedUsers.includes(u.employee_id);
                        return (
                          <div
                            key={u.employee_id}
                            onClick={() => handleToggleUser(u.employee_id)}
                            style={{
                              padding: '8px 12px',
                              borderRadius: '8px',
                              background: isSelected ? '#eef2ff' : '#fff',
                              border: isSelected ? '1px solid #818cf8' : '1px solid #e2e8f0',
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'space-between',
                              fontSize: '13px'
                            }}
                          >
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <div style={{ width: '26px', height: '26px', borderRadius: '50%', background: '#e2e8f0', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '11px', color: '#475569' }}>
                                {u.name ? u.name.charAt(0) : 'U'}
                              </div>
                              <div>
                                <span style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{u.name}</span>
                                <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginLeft: '6px' }}>({u.employee_id})</span>
                              </div>
                            </div>
                            <input
                              type="checkbox"
                              checked={isSelected}
                              onChange={() => {}}
                              style={{ accentColor: 'var(--primary)', cursor: 'pointer' }}
                            />
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Message Body */}
                <div className="form-group">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <label className="form-label" style={{ fontWeight: 700, margin: 0 }}>
                      ខ្លឹមសារសារ (Message Body) *
                    </label>
                    <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                      {['{{today}}', '{{time}}', '{{schedule_name}}'].map(ph => (
                        <button
                          key={ph}
                          type="button"
                          onClick={() => handleInsertPlaceholder(ph)}
                          style={{
                            border: '1px solid #cbd5e1',
                            background: '#f8fafc',
                            color: '#4338ca',
                            fontSize: '11px',
                            fontWeight: 700,
                            padding: '2px 6px',
                            borderRadius: '6px',
                            cursor: 'pointer'
                          }}
                          title={`ចុចដើម្បីបញ្ចូល ${ph}`}
                        >
                          + {ph}
                        </button>
                      ))}
                    </div>
                  </div>
                  <textarea
                    className="form-textarea"
                    rows={4}
                    placeholder="បញ្ចូលខ្លឹមសារលម្អិតនៃការជូនដំណឹង..."
                    value={sendMessage}
                    onChange={(e) => setSendMessage(e.target.value)}
                    required
                    style={{ lineHeight: 1.6 }}
                  />
                </div>

                {/* Image Upload & URL */}
                <div style={{ background: '#f8fafc', padding: '16px', borderRadius: '12px', border: '1px solid #e2e8f0' }}>
                  <label className="form-label" style={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                    <ImageIcon size={16} style={{ color: 'var(--primary)' }} />
                    <span>រូបភាពភ្ជាប់ Banner (Image Upload / URL - ស្រេចចិត្ត)</span>
                  </label>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', alignItems: 'center' }}>
                    <input
                      type="file"
                      accept="image/*"
                      className="form-input"
                      onChange={(e) => handleImageFileChange(e.target.files ? e.target.files[0] : null)}
                    />
                    <input
                      type="url"
                      className="form-input"
                      placeholder="ឬបញ្ចូល URL រូបភាពផ្ទាល់ (https://...)"
                      value={imageUrl}
                      onChange={(e) => setImageUrl(e.target.value)}
                    />
                  </div>
                  {(imageFilePreview || imageUrl) && (
                    <div style={{ marginTop: '10px', position: 'relative', width: '140px', height: '80px', borderRadius: '8px', overflow: 'hidden', border: '1px solid #cbd5e1' }}>
                      <img src={imageFilePreview || imageUrl} alt="Preview" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                      <button
                        type="button"
                        onClick={() => { setImageFile(null); setImageFilePreview(null); setImageUrl(''); }}
                        style={{ position: 'absolute', top: '3px', right: '3px', background: 'rgba(0,0,0,0.65)', color: '#fff', border: 'none', borderRadius: '50%', width: '18px', height: '18px', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}
                      >
                        <X size={10} />
                      </button>
                    </div>
                  )}
                </div>

                {/* Submit Button */}
                <div style={{ marginTop: '8px' }}>
                  <button
                    type="submit"
                    disabled={sending}
                    className="btn btn-primary"
                    style={{ width: '100%', justifyContent: 'center', padding: '12px', fontSize: '15px' }}
                  >
                    {sending ? (
                      <>
                        <RotateCw size={16} className="fa-spin" />
                        <span>កំពុងផ្ញើការជូនដំណឹង...</span>
                      </>
                    ) : (
                      <>
                        <Send size={16} />
                        <span>ផ្ញើការជូនដំណឹងឥឡូវនេះ (Send Notification)</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </form>
          </div>

          {/* Right: Live Mobile Mockup Preview */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div className="hrm-card" style={{ padding: '20px', borderRadius: '22px', border: '2px solid #e2e8f0', background: '#0f172a', color: '#fff' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', opacity: 0.8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}>
                  <Smartphone size={15} />
                  <span>Mobile Push Preview</span>
                </div>
                <span style={{ fontSize: '11px', background: 'rgba(255,255,255,0.1)', padding: '2px 8px', borderRadius: '6px' }}>
                  Lock Screen
                </span>
              </div>

              {/* Push Notification Card inside Mobile Frame */}
              <div
                style={{
                  background: 'rgba(255, 255, 255, 0.95)',
                  backdropFilter: 'blur(10px)',
                  color: '#0f172a',
                  borderRadius: '16px',
                  padding: '14px',
                  boxShadow: '0 10px 25px rgba(0,0,0,0.3)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <div style={{ width: '18px', height: '18px', borderRadius: '4px', background: '#4f46e5', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontSize: '9px', fontWeight: 900 }}>
                      V
                    </div>
                    <span style={{ fontSize: '11px', fontWeight: 700, color: '#475569' }}>VVC ATTENDANCE</span>
                  </div>
                  <span style={{ fontSize: '10px', color: '#94a3b8' }}>ឥឡូវនេះ</span>
                </div>

                <div style={{ fontSize: '13px', fontWeight: 800, color: '#0f172a' }}>
                  {sendTitle || 'ចំណងជើងការជូនដំណឹង (Title)'}
                </div>

                <div style={{ fontSize: '12px', color: '#334155', lineHeight: 1.5, maxHeight: '60px', overflow: 'hidden' }}>
                  {sendMessage || 'ខ្លឹមសារលម្អិតនៃសារជូនដំណឹងនឹងបង្ហាញនៅទីនេះលើទូរស័ព្ទដៃរបស់បុគ្គលិក...'}
                </div>

                {(imageFilePreview || imageUrl) && (
                  <div style={{ width: '100%', height: '110px', borderRadius: '10px', overflow: 'hidden', marginTop: '4px' }}>
                    <img src={imageFilePreview || imageUrl} alt="" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                  </div>
                )}
              </div>

              {/* Target info preview */}
              <div style={{ marginTop: '16px', fontSize: '11px', color: 'rgba(255,255,255,0.6)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div>👥 អ្នកទទួល: <strong style={{ color: '#fff' }}>{targetType === 'all' ? 'បុគ្គលិកទាំងអស់' : (targetType === 'role' ? `${selectedRoles.length} តួនាទី` : `${selectedUsers.length} នាក់`)}</strong></div>
                {expiryDate && <div>⏳ ផុតកំណត់: <strong style={{ color: '#fff' }}>{expiryDate}</strong></div>}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: NOTIFICATION TEMPLATES                                             */}
      {/* ========================================================================= */}
      {activeTab === 'templates' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
          {/* Create/Edit Template Form */}
          <div className="hrm-card" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px', borderBottom: '1px solid #f1f5f9', paddingBottom: '12px' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <FileText size={18} style={{ color: 'var(--primary)' }} />
                <span>{templateForm.id > 0 ? 'កែប្រែគំរូសារ (Edit Template)' : 'បង្កើតគំរូសារថ្មី (New Notification Template)'}</span>
              </h3>
              {templateForm.id > 0 && (
                <button
                  type="button"
                  onClick={() => setTemplateForm({
                    id: 0,
                    template_name: '',
                    template_key: '',
                    title_template: '',
                    message_template: '',
                    target_type: 'all',
                    target_roles_text: '',
                    target_users_text: '',
                    image_url: '',
                    is_active: 1
                  })}
                  className="btn btn-secondary btn-sm"
                >
                  <RotateCw size={12} /> បោះបង់ការកែប្រែ
                </button>
              )}
            </div>

            <form onSubmit={handleSaveTemplate}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                  <div className="form-group">
                    <label className="form-label" style={{ fontWeight: 700 }}>ឈ្មោះ Template *</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="ឧ. សាររំលឹកស្កេនវត្តមានព្រឹក"
                      value={templateForm.template_name}
                      onChange={(e) => setTemplateForm({ ...templateForm, template_name: e.target.value })}
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label" style={{ fontWeight: 700 }}>Template Key (សម្រាប់កូដ)</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="ឧ. morning_checkin_reminder"
                      value={templateForm.template_key}
                      onChange={(e) => setTemplateForm({ ...templateForm, template_key: e.target.value })}
                    />
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                  <div className="form-group">
                    <label className="form-label" style={{ fontWeight: 700 }}>ចំណងជើងគំរូ (Title Template) *</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="ឧ. រំលឹកស្កេនវត្តមានថ្ងៃ {{today}}"
                      value={templateForm.title_template}
                      onChange={(e) => setTemplateForm({ ...templateForm, title_template: e.target.value })}
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label" style={{ fontWeight: 700 }}>រូបភាព URL (ស្រេចចិត្ត)</label>
                    <input
                      type="url"
                      className="form-input"
                      placeholder="https://..."
                      value={templateForm.image_url}
                      onChange={(e) => setTemplateForm({ ...templateForm, image_url: e.target.value })}
                    />
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label" style={{ fontWeight: 700 }}>ខ្លឹមសារគំរូ (Message Template) *</label>
                  <textarea
                    className="form-textarea"
                    rows={3}
                    placeholder="ឧ. សូមជម្រាបជូនបុគ្គលិកទាំងអស់កុំភ្លេចស្កេនវត្តមានចូលធ្វើការមុនម៉ោង 08:30..."
                    value={templateForm.message_template}
                    onChange={(e) => setTemplateForm({ ...templateForm, message_template: e.target.value })}
                    required
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <label style={{ fontSize: '13px', fontWeight: 700 }}>Target Type:</label>
                      <select
                        className="form-select"
                        value={templateForm.target_type}
                        onChange={(e) => setTemplateForm({ ...templateForm, target_type: e.target.value })}
                        style={{ padding: '6px 10px', fontSize: '13px' }}
                      >
                        <option value="all">បុគ្គលិកទាំងអស់ (All)</option>
                        <option value="role">តាមតួនាទី (Role)</option>
                        <option value="user">បុគ្គលិកជាក់លាក់ (User)</option>
                      </select>
                    </div>

                    <label style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', cursor: 'pointer', fontSize: '13px', fontWeight: 600 }}>
                      <input
                        type="checkbox"
                        checked={Boolean(templateForm.is_active)}
                        onChange={(e) => setTemplateForm({ ...templateForm, is_active: e.target.checked ? 1 : 0 })}
                        style={{ accentColor: 'var(--primary)' }}
                      />
                      <span>Active</span>
                    </label>
                  </div>

                  <button
                    type="submit"
                    disabled={savingTemplate}
                    className="btn btn-primary"
                    style={{ minWidth: '150px' }}
                  >
                    {savingTemplate ? 'កំពុងរក្សាទុក...' : (templateForm.id > 0 ? 'កែប្រែ Template' : 'រក្សាទុក Template')}
                  </button>
                </div>
              </div>
            </form>
          </div>

          {/* Templates Table */}
          <div className="hrm-card" style={{ padding: '0', overflow: 'hidden' }}>
            <div className="table-container">
              <table className="hrm-table">
                <thead>
                  <tr>
                    <th>ឈ្មោះ Template</th>
                    <th>Target</th>
                    <th>ចំណងជើង & ខ្លឹមសារ</th>
                    <th>ស្ថានភាព</th>
                    <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
                  </tr>
                </thead>
                <tbody>
                  {loadingTemplates ? (
                    <tr><td colSpan={5} style={{ textAlign: 'center', padding: '30px' }}>កំពុងទាញយក Templates...</td></tr>
                  ) : templates.length === 0 ? (
                    <tr><td colSpan={5} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>មិនទាន់មាន Template ឡើយ</td></tr>
                  ) : (
                    templates.map(t => (
                      <tr key={t.id}>
                        <td>
                          <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{t.template_name}</div>
                          {t.template_key && <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>key: {t.template_key}</div>}
                        </td>
                        <td>
                          <span className="badge badge-primary">{t.target_type || 'all'}</span>
                        </td>
                        <td>
                          <div style={{ fontWeight: 600 }}>{t.title_template}</div>
                          <div style={{ fontSize: '12px', color: 'var(--text-muted)', maxWidth: '320px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {t.message_template}
                          </div>
                        </td>
                        <td>
                          <span className={`badge ${t.is_active ? 'badge-success' : 'badge-secondary'}`}>
                            {t.is_active ? 'Active' : 'Inactive'}
                          </span>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                            <button
                              type="button"
                              onClick={() => handleEditTemplate(t)}
                              className="btn btn-secondary btn-sm"
                              title="កែប្រែ"
                            >
                              <Edit3 size={14} />
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDeleteTemplate(t.id)}
                              className="btn btn-danger btn-sm"
                              title="លុប"
                            >
                              <Trash2 size={14} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: NOTIFICATION SCHEDULES                                             */}
      {/* ========================================================================= */}
      {activeTab === 'schedules' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
          {/* Create/Edit Schedule Form */}
          <div className="hrm-card" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px', borderBottom: '1px solid #f1f5f9', paddingBottom: '12px' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Calendar size={18} style={{ color: 'var(--primary)' }} />
                <span>{scheduleForm.id > 0 ? 'កែប្រែកាលវិភាគ (Edit Schedule)' : 'បង្កើតកាលវិភាគស្វ័យប្រវត្តិថ្មី (New Schedule)'}</span>
              </h3>
              {scheduleForm.id > 0 && (
                <button
                  type="button"
                  onClick={() => setScheduleForm({
                    id: 0,
                    schedule_name: '',
                    template_id: 0,
                    frequency: 'once',
                    scheduled_at: '',
                    time_of_day: '09:00',
                    day_of_week: 1,
                    day_of_month: 1,
                    title_override: '',
                    message_override: '',
                    target_type: '',
                    target_roles_text: '',
                    target_users_text: '',
                    image_url: '',
                    is_active: 1
                  })}
                  className="btn btn-secondary btn-sm"
                >
                  <RotateCw size={12} /> បោះបង់ការកែប្រែ
                </button>
              )}
            </div>

            <form onSubmit={handleSaveSchedule}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                  <div className="form-group">
                    <label className="form-label" style={{ fontWeight: 700 }}>ឈ្មោះកាលវិភាគ (Schedule Name) *</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="ឧ. រំលឹកស្កេនម៉ោង 8:30 ព្រឹក"
                      value={scheduleForm.schedule_name}
                      onChange={(e) => setScheduleForm({ ...scheduleForm, schedule_name: e.target.value })}
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label" style={{ fontWeight: 700 }}>ភ្ជាប់ជាមួយ Template (ស្រេចចិត្ត)</label>
                    <select
                      className="form-select"
                      value={scheduleForm.template_id}
                      onChange={(e) => setScheduleForm({ ...scheduleForm, template_id: Number(e.target.value) })}
                    >
                      <option value={0}>-- មិនប្រើ Template (Custom) --</option>
                      {templates.map(t => (
                        <option key={t.id} value={t.id}>{t.template_name}</option>
                      ))}
                    </select>
                  </div>
                </div>

                {/* Frequency & Dynamic Time Inputs */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px', background: '#f8fafc', padding: '14px', borderRadius: '12px', border: '1px solid #e2e8f0' }}>
                  <div className="form-group">
                    <label className="form-label" style={{ fontWeight: 700 }}>ភាពញឹកញាប់ (Frequency) *</label>
                    <select
                      className="form-select"
                      value={scheduleForm.frequency}
                      onChange={(e) => setScheduleForm({ ...scheduleForm, frequency: e.target.value })}
                    >
                      <option value="once">ម្តងគត់ (Once)</option>
                      <option value="daily">រាល់ថ្ងៃ (Daily)</option>
                      <option value="weekly">រាល់សប្តាហ៍ (Weekly)</option>
                      <option value="monthly">រាល់ខែ (Monthly)</option>
                    </select>
                  </div>

                  {scheduleForm.frequency === 'once' && (
                    <div className="form-group">
                      <label className="form-label" style={{ fontWeight: 700 }}>ថ្ងៃ & ម៉ោងត្រូវផ្ញើ (Scheduled At)</label>
                      <input
                        type="datetime-local"
                        className="form-input"
                        value={scheduleForm.scheduled_at}
                        onChange={(e) => setScheduleForm({ ...scheduleForm, scheduled_at: e.target.value })}
                      />
                    </div>
                  )}

                  {['daily', 'weekly', 'monthly'].includes(scheduleForm.frequency) && (
                    <div className="form-group">
                      <label className="form-label" style={{ fontWeight: 700 }}>ម៉ោងត្រូវផ្ញើ (Time of Day)</label>
                      <input
                        type="time"
                        className="form-input"
                        value={scheduleForm.time_of_day}
                        onChange={(e) => setScheduleForm({ ...scheduleForm, time_of_day: e.target.value })}
                      />
                    </div>
                  )}

                  {scheduleForm.frequency === 'weekly' && (
                    <div className="form-group">
                      <label className="form-label" style={{ fontWeight: 700 }}>ថ្ងៃនៃសប្តាហ៍ (Day of Week)</label>
                      <select
                        className="form-select"
                        value={scheduleForm.day_of_week}
                        onChange={(e) => setScheduleForm({ ...scheduleForm, day_of_week: Number(e.target.value) })}
                      >
                        <option value={0}>ថ្ងៃអាទិត្យ (Sunday)</option>
                        <option value={1}>ថ្ងៃច័ន្ទ (Monday)</option>
                        <option value={2}>ថ្ងៃអង្គារ (Tuesday)</option>
                        <option value={3}>ថ្ងៃពុធ (Wednesday)</option>
                        <option value={4}>ថ្ងៃព្រហស្បតិ៍ (Thursday)</option>
                        <option value={5}>ថ្ងៃសុក្រ (Friday)</option>
                        <option value={6}>ថ្ងៃសៅរ៍ (Saturday)</option>
                      </select>
                    </div>
                  )}

                  {scheduleForm.frequency === 'monthly' && (
                    <div className="form-group">
                      <label className="form-label" style={{ fontWeight: 700 }}>ថ្ងៃនៃខែ (Day of Month: 1-31)</label>
                      <input
                        type="number"
                        min={1}
                        max={31}
                        className="form-input"
                        value={scheduleForm.day_of_month}
                        onChange={(e) => setScheduleForm({ ...scheduleForm, day_of_month: Number(e.target.value) })}
                      />
                    </div>
                  )}
                </div>

                {/* Overrides */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                  <div className="form-group">
                    <label className="form-label" style={{ fontWeight: 700 }}>ចំណងជើង Override (Optional)</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="ប្រើប្រសិនបើចង់ប្តូរពី Template"
                      value={scheduleForm.title_override}
                      onChange={(e) => setScheduleForm({ ...scheduleForm, title_override: e.target.value })}
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label" style={{ fontWeight: 700 }}>រូបភាព URL (Optional)</label>
                    <input
                      type="url"
                      className="form-input"
                      placeholder="https://..."
                      value={scheduleForm.image_url}
                      onChange={(e) => setScheduleForm({ ...scheduleForm, image_url: e.target.value })}
                    />
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label" style={{ fontWeight: 700 }}>ខ្លឹមសារសារ Override (Optional)</label>
                  <textarea
                    className="form-textarea"
                    rows={2}
                    placeholder="ប្រើប្រសិនបើចង់ប្តូរខ្លឹមសារពី Template"
                    value={scheduleForm.message_override}
                    onChange={(e) => setScheduleForm({ ...scheduleForm, message_override: e.target.value })}
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <label style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', cursor: 'pointer', fontSize: '13px', fontWeight: 700 }}>
                    <input
                      type="checkbox"
                      checked={Boolean(scheduleForm.is_active)}
                      onChange={(e) => setScheduleForm({ ...scheduleForm, is_active: e.target.checked ? 1 : 0 })}
                      style={{ accentColor: 'var(--primary)' }}
                    />
                    <span>Active (ដំណើរការកាលវិភាគ)</span>
                  </label>

                  <button
                    type="submit"
                    disabled={savingSchedule}
                    className="btn btn-primary"
                    style={{ minWidth: '160px' }}
                  >
                    {savingSchedule ? 'កំពុងរក្សាទុក...' : (scheduleForm.id > 0 ? 'កែប្រែកាលវិភាគ' : 'រក្សាទុកកាលវិភាគ')}
                  </button>
                </div>
              </div>
            </form>
          </div>

          {/* Schedules Table */}
          <div className="hrm-card" style={{ padding: '0', overflow: 'hidden' }}>
            <div className="table-container">
              <table className="hrm-table">
                <thead>
                  <tr>
                    <th>ឈ្មោះកាលវិភាគ</th>
                    <th>ភាពញឹកញាប់</th>
                    <th>ពេលត្រូវដំណើរការបន្ទាប់</th>
                    <th>លទ្ធផលចុងក្រោយ</th>
                    <th>ស្ថានភាព</th>
                    <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
                  </tr>
                </thead>
                <tbody>
                  {loadingSchedules ? (
                    <tr><td colSpan={6} style={{ textAlign: 'center', padding: '30px' }}>កំពុងទាញយក Schedules...</td></tr>
                  ) : schedules.length === 0 ? (
                    <tr><td colSpan={6} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>មិនទាន់មានកាលវិភាគឡើយ</td></tr>
                  ) : (
                    schedules.map(sch => (
                      <tr key={sch.id}>
                        <td>
                          <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{sch.schedule_name}</div>
                          {sch.template_name && <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>tpl: {sch.template_name}</div>}
                        </td>
                        <td>
                          <span className="badge badge-primary" style={{ textTransform: 'uppercase' }}>
                            {sch.frequency}
                          </span>
                        </td>
                        <td style={{ fontSize: '13px', fontWeight: 600 }}>
                          {sch.next_run_at || '—'}
                        </td>
                        <td>
                          <span className={`badge ${sch.last_result === 'success' ? 'badge-success' : (sch.last_result === 'error' ? 'badge-danger' : 'badge-secondary')}`}>
                            {sch.last_result || 'waiting'}
                          </span>
                        </td>
                        <td>
                          <button
                            type="button"
                            onClick={() => handleToggleSchedule(sch.id)}
                            style={{
                              border: 'none',
                              padding: '4px 10px',
                              borderRadius: '999px',
                              fontSize: '11px',
                              fontWeight: 700,
                              cursor: 'pointer',
                              background: sch.is_active ? '#dcfce7' : '#f1f5f9',
                              color: sch.is_active ? '#166534' : '#64748b',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px'
                            }}
                          >
                            {sch.is_active ? <Pause size={10} /> : <Play size={10} />}
                            <span>{sch.is_active ? 'Active' : 'Paused'}</span>
                          </button>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                            <button
                              type="button"
                              onClick={() => handleEditSchedule(sch)}
                              className="btn btn-secondary btn-sm"
                              title="កែប្រែ"
                            >
                              <Edit3 size={14} />
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDeleteSchedule(sch.id)}
                              className="btn btn-danger btn-sm"
                              title="លុប"
                            >
                              <Trash2 size={14} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: NOTIFICATION HISTORY                                               */}
      {/* ========================================================================= */}
      {activeTab === 'history' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
          {/* Search & Bulk Action Bar */}
          <div
            className="hrm-card"
            style={{
              padding: '16px 20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '14px'
            }}
          >
            <div style={{ position: 'relative', flex: 1, minWidth: '240px' }}>
              <Search size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                type="text"
                className="form-input"
                placeholder="ស្វែងរកក្នុងប្រវត្តិផ្ញើ..."
                value={historySearch}
                onChange={(e) => setHistorySearch(e.target.value)}
                style={{ paddingLeft: '38px', borderRadius: '12px' }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              {selectedHistoryIds.length > 0 && (
                <button
                  type="button"
                  onClick={handleBulkDeleteHistory}
                  className="btn btn-danger btn-sm"
                  style={{ borderRadius: '10px' }}
                >
                  <Trash2 size={14} />
                  <span>លុបដែលបានជ្រើសរើស ({selectedHistoryIds.length})</span>
                </button>
              )}

              <button
                type="button"
                onClick={loadHistory}
                className="btn btn-secondary btn-sm"
                style={{ borderRadius: '10px' }}
              >
                <RotateCw size={14} className={loadingHistory ? 'fa-spin' : ''} />
                <span>ផ្ទុកឡើងវិញ</span>
              </button>
            </div>
          </div>

          {/* History Table */}
          <div className="hrm-card" style={{ padding: '0', overflow: 'hidden' }}>
            <div className="table-container">
              <table className="hrm-table">
                <thead>
                  <tr>
                    <th style={{ width: '40px', textAlign: 'center' }}>
                      <input
                        type="checkbox"
                        checked={filteredHistory.length > 0 && selectedHistoryIds.length === filteredHistory.length}
                        onChange={handleToggleSelectAllHistory}
                        style={{ accentColor: 'var(--primary)', cursor: 'pointer' }}
                      />
                    </th>
                    <th style={{ width: '60px' }}>ID</th>
                    <th>ចំណងជើង & ខ្លឹមសារសារ</th>
                    <th>អ្នកទទួល (Target)</th>
                    <th>រូបភាព</th>
                    <th>កាលបរិច្ឆេទផ្ញើ</th>
                    <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
                  </tr>
                </thead>
                <tbody>
                  {loadingHistory ? (
                    <tr><td colSpan={7} style={{ textAlign: 'center', padding: '30px' }}>កំពុងទាញយកប្រវត្តិ...</td></tr>
                  ) : filteredHistory.length === 0 ? (
                    <tr><td colSpan={7} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>មិនទាន់មានប្រវត្តិផ្ញើការជូនដំណឹងឡើយ</td></tr>
                  ) : (
                    filteredHistory.map(h => {
                      const isSelected = selectedHistoryIds.includes(h.id);
                      return (
                        <tr key={h.id} style={{ background: isSelected ? '#f8fafc' : 'transparent' }}>
                          <td style={{ textAlign: 'center' }}>
                            <input
                              type="checkbox"
                              checked={isSelected}
                              onChange={() => handleToggleHistoryItem(h.id)}
                              style={{ accentColor: 'var(--primary)', cursor: 'pointer' }}
                            />
                          </td>
                          <td style={{ fontWeight: 700, color: 'var(--text-muted)', fontSize: '12px' }}>
                            #{h.id}
                          </td>
                          <td>
                            <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{h.title}</div>
                            <div style={{ fontSize: '12px', color: 'var(--text-muted)', maxWidth: '380px', marginTop: '2px', lineHeight: 1.5 }}>
                              {h.message}
                            </div>
                          </td>
                          <td>
                            <span className="badge badge-primary">
                              {h.recipient_type || 'all'}
                            </span>
                            {h.recipient_info && h.recipient_type !== 'all' && (
                              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px', maxWidth: '140px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                {h.recipient_info}
                              </div>
                            )}
                          </td>
                          <td>
                            {h.image_url ? (
                              <div
                                onClick={() => setLightboxImage(h.image_url || null)}
                                style={{ width: '38px', height: '38px', borderRadius: '8px', overflow: 'hidden', cursor: 'pointer', border: '1px solid #cbd5e1' }}
                              >
                                <img src={h.image_url} alt="" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                              </div>
                            ) : (
                              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>—</span>
                            )}
                          </td>
                          <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                            {h.sent_at || h.created_at || '—'}
                          </td>
                          <td style={{ textAlign: 'right' }}>
                            <button
                              type="button"
                              onClick={() => handleDeleteHistory(h.id)}
                              className="btn btn-danger btn-sm"
                              title="លុប"
                            >
                              <Trash2 size={13} />
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* IMAGE LIGHTBOX MODAL                                                      */}
      {/* ========================================================================= */}
      {lightboxImage && (
        <div
          onClick={() => setLightboxImage(null)}
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 9999,
            background: 'rgba(0, 0, 0, 0.85)',
            backdropFilter: 'blur(8px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '20px'
          }}
        >
          <button
            onClick={() => setLightboxImage(null)}
            style={{
              position: 'absolute',
              top: '20px',
              right: '20px',
              background: 'rgba(255, 255, 255, 0.2)',
              color: '#fff',
              border: 'none',
              borderRadius: '50%',
              width: '40px',
              height: '40px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer',
              fontSize: '20px'
            }}
          >
            <X size={24} />
          </button>
          <img
            src={lightboxImage}
            alt="Preview"
            onClick={(e) => e.stopPropagation()}
            style={{
              maxWidth: '90vw',
              maxHeight: '90vh',
              objectFit: 'contain',
              borderRadius: '12px',
              boxShadow: '0 20px 50px rgba(0,0,0,0.5)'
            }}
          />
        </div>
      )}
    </div>
  );
};
