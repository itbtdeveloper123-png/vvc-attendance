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
  MessageSquare,
} from 'lucide-react';
import { StatusBadge } from '../components/common/StatusBadge';
import { Modal } from '../components/common/Modal';
import { adminApi, RequestItem } from '../api/adminApi';

export const RequestsPage: React.FC = () => {
  const [requests, setRequests] = useState<RequestItem[]>([
    {
      id: 1,
      user_id: 101,
      employee_id: 'VVC-101',
      requester_name: 'សុខ គឹមហុង',
      request_type: 'ច្បាប់ឈប់សម្រាកប្រចាំឆ្នាំ (Annual Leave)',
      department: 'Store 318',
      position: 'Staff',
      request_date: '2026-08-25',
      return_date: '2026-08-26',
      reason: 'មានធុរៈចាំបាច់នៅស្រុកកំណើត',
      status: 'Pending',
      created_at: '2026-08-24 08:30:00',
    },
    {
      id: 2,
      user_id: 102,
      employee_id: 'VVC-103',
      requester_name: 'ជា វណ្ណៈ',
      request_type: 'ស្នើសុំចុះបេសកកម្ម (Mission)',
      department: 'Warehouse PSP',
      position: 'Staff',
      request_date: '2026-08-24',
      return_date: '2026-08-24',
      reason: 'ដឹកជញ្ជូនទំនិញទៅសាខាកំពង់សោម',
      status: 'Pending',
      created_at: '2026-08-24 07:45:00',
    },
    {
      id: 3,
      user_id: 104,
      employee_id: 'VVC-104',
      requester_name: 'លឹម គឹមសាន',
      request_type: 'ស្នើសុំថែមម៉ោង (Overtime)',
      department: 'IT Department',
      position: 'IT Specialist',
      request_date: '2026-08-23',
      reason: 'ដំឡើងប្រព័ន្ធ Network Server យប់',
      status: 'Approved',
      approved_by: 'Super Admin',
      created_at: '2026-08-23 18:00:00',
    },
  ]);

  const [statusFilter, setStatusFilter] = useState('all');
  const [search, setSearch] = useState('');
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
    try {
      const data = await adminApi.fetchRequests(statusFilter !== 'all' ? statusFilter : undefined);
      if (data && data.success && Array.isArray(data.requests)) {
        setRequests(data.requests);
      }
    } catch {}
  };

  useEffect(() => {
    loadRequests();
  }, [statusFilter]);

  const filteredRequests = requests.filter((r) => {
    const q = search.toLowerCase();
    const matchSearch =
      r.requester_name.toLowerCase().includes(q) ||
      (r.employee_id || '').toLowerCase().includes(q) ||
      r.request_type.toLowerCase().includes(q);
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
    } catch {}

    setRequests((prev) =>
      prev.map((r) =>
        r.id === actionModal.item!.id
          ? { ...r, status: actionModal.type, approved_by: 'Super Admin' }
          : r
      )
    );
    setActionModal({ open: false, item: null, type: 'Approved', comment: '' });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-primary)' }}>
          គ្រប់គ្រង & អនុម័តសំណើរ (Manage Requests)
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
          ពិនិត្យសំណើរសុំច្បាប់ ថែមម៉ោង (OT) បេសកកម្ម ភ្លេចស្កេន និងសំណើរសម្ភារៈ
        </p>
      </div>

      {/* Filter Tabs */}
      <div
        className="hrm-card"
        style={{
          padding: '16px 20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '14px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {['all', 'Pending', 'Approved', 'Rejected'].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`btn btn-sm ${statusFilter === st ? 'btn-primary' : 'btn-secondary'}`}
            >
              {st === 'all'
                ? 'ទាំងអស់'
                : st === 'Pending'
                ? '⏳ រង់ចាំ (Pending)'
                : st === 'Approved'
                ? '✅ យល់ព្រម (Approved)'
                : '❌ បដិសេធ (Rejected)'}
            </button>
          ))}
        </div>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            background: 'var(--surface-alt)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            padding: '7px 12px',
            width: '260px',
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
      </div>

      {/* Requests Table */}
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
                  គ្មានសំណើរដែលត្រូវបង្ហាញឡើយ
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
                    {r.status === 'Pending' ? (
                      <div style={{ display: 'inline-flex', gap: '6px' }}>
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
                      </div>
                    ) : (
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                        ដោយ: {r.approved_by || 'Admin'}
                      </span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

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
