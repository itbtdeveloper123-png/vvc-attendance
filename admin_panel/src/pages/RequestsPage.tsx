import React, { useState, useEffect } from 'react';
import {
  FileText,
  CheckCircle,
  XCircle,
  Clock,
  Search,
  Filter,
  Check,
  X,
  Plus,
  Trash2,
  MessageSquare,
  RotateCw,
} from 'lucide-react';
import { StatusBadge } from '../components/common/StatusBadge';
import { Modal } from '../components/common/Modal';
import { ViewModeToggle, ViewMode } from '../components/common/ViewModeToggle';
import { adminApi, RequestItem } from '../api/adminApi';

export const RequestsPage: React.FC = () => {
  const [requests, setRequests] = useState<RequestItem[]>([]);
  const [viewMode, setViewMode] = useState<ViewMode>('table');
  const [loading, setLoading] = useState(false);
  const [statusFilter, setStatusFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [createModal, setCreateModal] = useState(false);
  const [newReq, setNewReq] = useState({
    employee_id: '',
    requester_name: '',
    request_type: 'ច្បាប់ឈប់សម្រាកប្រចាំឆ្នាំ (Annual Leave)',
    department: 'Store 318',
    position: 'Staff',
    request_date: new Date().toISOString().split('T')[0],
    return_date: '',
    reason: '',
  });

  const [actionModal, setActionModal] = useState<{
    open: boolean;
    item: RequestItem | null;
    type: 'Approved' | 'Rejected';
    comment: string;
  }>({
    open: false,
    item: null,
    type: 'Approved',
    comment: '',
  });

  const loadRequests = async () => {
    setLoading(true);
    try {
      const data = await adminApi.fetchRequests(statusFilter !== 'all' ? statusFilter : undefined);
      if (data && data.success && Array.isArray(data.requests)) {
        setRequests(data.requests);
      }
    } catch (err) {
      console.error('Error loading requests:', err);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadRequests();
  }, [statusFilter]);

  const filteredRequests = requests.filter((r) => {
    const q = search.toLowerCase();
    const matchSearch =
      (r.requester_name || '').toLowerCase().includes(q) ||
      (r.employee_id || '').toLowerCase().includes(q) ||
      (r.request_type || '').toLowerCase().includes(q);
    const matchStatus = statusFilter === 'all' || r.status === statusFilter;
    return matchSearch && matchStatus;
  });

  const handleOpenAction = (item: RequestItem, type: 'Approved' | 'Rejected') => {
    setActionModal({
      open: true,
      item,
      type,
      comment: '',
    });
  };

  const handleConfirmAction = async () => {
    if (!actionModal.item) return;
    try {
      await adminApi.updateRequestStatus(actionModal.item.id, actionModal.type, actionModal.comment);
      loadRequests();
    } catch (err) {
      alert('កំហុសក្នុងការកែប្រែស្ថានភាពសំណើរ');
    }
    setActionModal({ open: false, item: null, type: 'Approved', comment: '' });
  };

  const handleDeleteRequest = async (id: number | string) => {
    if (window.confirm('តើអ្នកពិតជាចង់លុបសំណើរនេះមែនទេ?')) {
      try {
        await adminApi.deleteRequest(id);
        loadRequests();
      } catch (err) {
        alert('កំហុសក្នុងការលុបសំណើរ');
      }
    }
  };

  const handleCreateRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newReq.requester_name || !newReq.reason) {
      alert('សូមបំពេញឈ្មោះ និងមូលហេតុ!');
      return;
    }
    try {
      await adminApi.createRequest(newReq);
      setCreateModal(false);
      setNewReq({
        employee_id: '',
        requester_name: '',
        request_type: 'ច្បាប់ឈប់សម្រាកប្រចាំឆ្នាំ (Annual Leave)',
        department: 'Store 318',
        position: 'Staff',
        request_date: new Date().toISOString().split('T')[0],
        return_date: '',
        reason: '',
      });
      loadRequests();
    } catch (err) {
      alert('កំហុសក្នុងការបង្កើតសំណើរ');
    }
  };

  const pendingCount = requests.filter(r => r.status === 'Pending').length;

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
          border: '1px solid rgba(99, 102, 241, 0.15)',
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
                boxShadow: '0 4px 10px rgba(99, 102, 241, 0.3)',
              }}
            >
              <FileText size={20} />
            </span>
            <h2 style={{ fontSize: '22px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              គ្រប់គ្រង & អនុម័តសំណើរ (Requests & Approvals)
            </h2>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0 }}>
            ពិនិត្យសំណើរសុំច្បាប់ ថែមម៉ោង (OT) បេសកកម្ម ភ្លេចស្កេន និងសំណើរសម្ភារៈ
          </p>
        </div>

        <button
          onClick={() => setCreateModal(true)}
          className="btn btn-primary"
          style={{ borderRadius: '12px', padding: '11px 20px', fontWeight: 700 }}
        >
          <Plus size={16} />
          <span>+ បង្កើតសំណើរថ្មី</span>
        </button>
      </div>

      {/* Filter Toolbar & Segmented Status Switcher */}
      <div
        className="hrm-card"
        style={{
          padding: '14px 18px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '14px',
          borderRadius: '16px',
        }}
      >
        {/* Status Pills */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'var(--surface-subtle, #f1f5f9)', padding: '5px', borderRadius: '12px', flexWrap: 'wrap' }}>
          <button
            onClick={() => setStatusFilter('all')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: '9px',
              fontWeight: 700,
              fontSize: '13px',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              background: statusFilter === 'all' ? '#fff' : 'transparent',
              color: statusFilter === 'all' ? 'var(--primary)' : 'var(--text-secondary)',
              boxShadow: statusFilter === 'all' ? '0 3px 10px rgba(0,0,0,0.06)' : 'none',
            }}
          >
            <span>ទាំងអស់ ({requests.length})</span>
          </button>

          <button
            onClick={() => setStatusFilter('Pending')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: '9px',
              fontWeight: 700,
              fontSize: '13px',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              background: statusFilter === 'Pending' ? '#fff' : 'transparent',
              color: statusFilter === 'Pending' ? '#d97706' : 'var(--text-secondary)',
              boxShadow: statusFilter === 'Pending' ? '0 3px 10px rgba(0,0,0,0.06)' : 'none',
            }}
          >
            <Clock size={14} />
            <span>រង់ចាំអនុម័ត {pendingCount > 0 && `(${pendingCount})`}</span>
          </button>

          <button
            onClick={() => setStatusFilter('Approved')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: '9px',
              fontWeight: 700,
              fontSize: '13px',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              background: statusFilter === 'Approved' ? '#fff' : 'transparent',
              color: statusFilter === 'Approved' ? '#059669' : 'var(--text-secondary)',
              boxShadow: statusFilter === 'Approved' ? '0 3px 10px rgba(0,0,0,0.06)' : 'none',
            }}
          >
            <CheckCircle size={14} />
            <span>បានអនុម័ត</span>
          </button>

          <button
            onClick={() => setStatusFilter('Rejected')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: '9px',
              fontWeight: 700,
              fontSize: '13px',
              border: 'none',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              background: statusFilter === 'Rejected' ? '#fff' : 'transparent',
              color: statusFilter === 'Rejected' ? '#dc2626' : 'var(--text-secondary)',
              boxShadow: statusFilter === 'Rejected' ? '0 3px 10px rgba(0,0,0,0.06)' : 'none',
            }}
          >
            <XCircle size={14} />
            <span>បានបដិសេធ</span>
          </button>
        </div>

        {/* Right Search, ViewModeToggle & Refresh */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <ViewModeToggle mode={viewMode} onChange={setViewMode} />

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              background: 'var(--surface-alt)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              padding: '8px 14px',
              width: '240px',
              gap: '8px',
            }}
          >
            <Search size={15} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="ស្វែងរកឈ្មោះ, ប្រភេទ..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{
                background: 'transparent',
                border: 'none',
                outline: 'none',
                fontSize: '13px',
                color: 'var(--text-primary)',
                fontFamily: 'inherit',
                width: '100%',
              }}
            />
          </div>

          <button onClick={loadRequests} className="btn btn-secondary btn-sm" title="ផ្ទុកឡើងវិញ">
            <RotateCw size={14} className={loading ? 'fa-spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* View Mode Switching: Grid Cards or Table */}
      {viewMode === 'grid' ? (
        filteredRequests.length === 0 ? (
          <div className="hrm-card" style={{ textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}>
            {loading ? 'កំពុងទាញយកបញ្ជីសំណើរ...' : 'គ្មានសំណើរដែលត្រូវបង្ហាញឡើយ'}
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '16px' }}>
            {filteredRequests.map((r) => (
              <div
                key={r.id}
                className="hrm-card"
                style={{
                  padding: '18px',
                  borderRadius: '16px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '14px',
                  border: '1px solid var(--border)',
                  boxShadow: 'var(--shadow-sm)',
                  background: 'var(--surface)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '10px' }}>
                  <div>
                    <div style={{ fontWeight: 800, fontSize: '15px', color: 'var(--text-primary)' }}>{r.requester_name}</div>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
                      <span style={{ fontFamily: "'Outfit', monospace", fontWeight: 700, color: 'var(--primary)' }}>{r.employee_id}</span>
                      {r.department && ` • ${r.department}`}
                    </div>
                  </div>
                  <StatusBadge status={r.status} />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', background: 'var(--surface-alt)', padding: '12px', borderRadius: '12px', fontSize: '12.5px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-muted)' }}>ប្រភេទ:</span>
                    <span style={{ fontWeight: 700, color: 'var(--primary)' }}>{r.request_type}</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-muted)' }}>កាលបរិច្ឆេទ:</span>
                    <span style={{ fontWeight: 600 }}>{r.request_date} {r.return_date ? `→ ${r.return_date}` : ''}</span>
                  </div>
                  {r.reason && (
                    <div style={{ borderTop: '1px dashed var(--border)', paddingTop: '6px', marginTop: '2px', color: 'var(--text-secondary)' }}>
                      <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>មូលហេតុ: </span>
                      {r.reason}
                    </div>
                  )}
                </div>

                {/* Footer Actions */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderTop: '1px solid var(--border)', paddingTop: '10px', marginTop: 'auto' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    {r.status === 'Pending' && (
                      <>
                        <button onClick={() => handleOpenAction(r, 'Approved')} className="btn btn-success btn-sm">
                          <Check size={13} />
                          <span>យល់ព្រម</span>
                        </button>
                        <button onClick={() => handleOpenAction(r, 'Rejected')} className="btn btn-danger btn-sm">
                          <X size={13} />
                          <span>បដិសេធ</span>
                        </button>
                      </>
                    )}
                  </div>
                  <button onClick={() => handleDeleteRequest(r.id)} className="btn btn-danger btn-sm" title="លុបសំណើរ">
                    <Trash2 size={13} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )
      ) : (
        /* Requests Table */
        <div className="table-container">
          <table className="hrm-table">
            <thead>
              <tr>
                <th>អ្នកស្នើសុំ</th>
                <th>ប្រភេទសំណើរ</th>
                <th>កាលបរិច្ឆេទ</th>
                <th>មូលហេតុ / ព័ត៌មានលម្អិត</th>
                <th>ស្ថានភាព</th>
                <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
              </tr>
            </thead>
            <tbody>
              {filteredRequests.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                    {loading ? 'កំពុងទាញយកបញ្ជីសំណើរ...' : 'គ្មានសំណើរដែលត្រូវបង្ហាញឡើយ'}
                  </td>
                </tr>
              ) : (
                filteredRequests.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{r.requester_name}</div>
                      <div style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                        {r.employee_id} • {r.department}
                      </div>
                    </td>
                    <td>
                      <span style={{ fontWeight: 600, fontSize: '13px', color: 'var(--primary)' }}>
                        {r.request_type}
                      </span>
                    </td>
                    <td style={{ fontSize: '12.5px' }}>
                      {r.request_date} {r.return_date ? `→ ${r.return_date}` : ''}
                    </td>
                    <td style={{ fontSize: '12.5px', maxWidth: '280px' }}>
                      {r.reason || '-'}
                    </td>
                    <td>
                      <StatusBadge status={r.status} />
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                        {r.status === 'Pending' && (
                          <>
                            <button
                              onClick={() => handleOpenAction(r, 'Approved')}
                              className="btn btn-success btn-sm"
                            >
                              <Check size={13} />
                              <span>យល់ព្រម</span>
                            </button>
                            <button
                              onClick={() => handleOpenAction(r, 'Rejected')}
                              className="btn btn-danger btn-sm"
                            >
                              <X size={13} />
                              <span>បដិសេធ</span>
                            </button>
                          </>
                        )}
                        <button
                          onClick={() => handleDeleteRequest(r.id)}
                          className="btn btn-danger btn-sm"
                          title="លុបសំណើរ"
                        >
                          <Trash2 size={13} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Create Request Modal */}
      {createModal && (
        <Modal
          isOpen={createModal}
          onClose={() => setCreateModal(false)}
          title="បង្កើតសំណើរថ្មី"
          maxWidth="540px"
        >
          <form onSubmit={handleCreateRequest}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">ឈ្មោះអ្នកស្នើសុំ *</label>
                  <input
                    type="text"
                    className="form-input"
                    value={newReq.requester_name}
                    onChange={(e) => setNewReq({ ...newReq, requester_name: e.target.value })}
                    placeholder="ឧ. សុខ គឹមហុង"
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">អត្តលេខបុគ្គលិក</label>
                  <input
                    type="text"
                    className="form-input"
                    value={newReq.employee_id}
                    onChange={(e) => setNewReq({ ...newReq, employee_id: e.target.value })}
                    placeholder="ឧ. VVC-101"
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">ប្រភេទសំណើរ *</label>
                <select
                  className="form-select"
                  value={newReq.request_type}
                  onChange={(e) => setNewReq({ ...newReq, request_type: e.target.value })}
                >
                  <option value="ច្បាប់ឈប់សម្រាកប្រចាំឆ្នាំ (Annual Leave)">ច្បាប់ឈប់សម្រាកប្រចាំឆ្នាំ (Annual Leave)</option>
                  <option value="ច្បាប់ឈប់សម្រាកឈឺ (Sick Leave)">ច្បាប់ឈប់សម្រាកឈឺ (Sick Leave)</option>
                  <option value="ស្នើសុំថែមម៉ោង (Overtime)">ស្នើសុំថែមម៉ោង (Overtime)</option>
                  <option value="ស្នើសុំចុះបេសកកម្ម (Mission)">ស្នើសុំចុះបេសកកម្ម (Mission)</option>
                  <option value="ស្នើសុំបំពេញម៉ោងស្កេន (Missed Scan)">ស្នើសុំបំពេញម៉ោងស្កេន (Missed Scan)</option>
                </select>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">ផ្នែក / សាខា</label>
                  <input
                    type="text"
                    className="form-input"
                    value={newReq.department}
                    onChange={(e) => setNewReq({ ...newReq, department: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">តួនាទី</label>
                  <input
                    type="text"
                    className="form-input"
                    value={newReq.position}
                    onChange={(e) => setNewReq({ ...newReq, position: e.target.value })}
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">កាលបរិច្ឆេទចាប់ផ្តើម</label>
                  <input
                    type="date"
                    className="form-input"
                    value={newReq.request_date}
                    onChange={(e) => setNewReq({ ...newReq, request_date: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">កាលបរិច្ឆេទបញ្ចប់</label>
                  <input
                    type="date"
                    className="form-input"
                    value={newReq.return_date}
                    onChange={(e) => setNewReq({ ...newReq, return_date: e.target.value })}
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">មូលហេតុ / ព័ត៌មានលម្អិត *</label>
                <textarea
                  className="form-textarea"
                  rows={3}
                  value={newReq.reason}
                  onChange={(e) => setNewReq({ ...newReq, reason: e.target.value })}
                  placeholder="បញ្ចូលមូលហេតុ..."
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
                <span>បង្កើតសំណើរ</span>
              </button>
            </div>
          </form>
        </Modal>
      )}

      {/* Action Comment Modal */}
      <Modal
        isOpen={actionModal.open}
        onClose={() => setActionModal({ ...actionModal, open: false })}
        title={`${actionModal.type === 'Approved' ? 'យល់ព្រមលើសំណើរ' : 'បដិសេធសំណើរ'} (${actionModal.item?.requester_name})`}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ fontSize: '13.5px', color: 'var(--text-secondary)' }}>
            តើអ្នកពិតជាចង់ <strong>{actionModal.type === 'Approved' ? 'យល់ព្រម' : 'បដិសេធ'}</strong> លើសំណើរ «{actionModal.item?.request_type}» របស់ {actionModal.item?.requester_name} មែនទេ?
          </div>

          <div className="form-group">
            <label className="form-label">មតិយោបល់របស់ Admin (Admin Comment - ស្រេចចិត្ត):</label>
            <textarea
              className="form-textarea"
              rows={3}
              placeholder="បញ្ចូលមតិយោបល់ ឬមូលហេតុ..."
              value={actionModal.comment}
              onChange={(e) => setActionModal({ ...actionModal, comment: e.target.value })}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
            <button
              onClick={() => setActionModal({ ...actionModal, open: false })}
              className="btn btn-secondary"
            >
              បោះបង់
            </button>
            <button
              onClick={handleConfirmAction}
              className={`btn ${actionModal.type === 'Approved' ? 'btn-success' : 'btn-danger'}`}
            >
              {actionModal.type === 'Approved' ? <Check size={16} /> : <X size={16} />}
              <span>បញ្ជាក់ {actionModal.type === 'Approved' ? 'យល់ព្រម' : 'បដិសេធ'}</span>
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};

