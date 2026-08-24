import React, { useState, useEffect } from 'react';
import {
  Users,
  UserPlus,
  Search,
  Filter,
  Edit2,
  Trash2,
  QrCode,
  Clock,
  ShieldCheck,
  Check,
  UserX,
  Sliders,
} from 'lucide-react';
import { Modal } from '../components/common/Modal';
import { adminApi, AdminUser } from '../api/adminApi';

export const UsersPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'list' | 'rules' | 'inactive'>('list');

  const [users, setUsers] = useState<AdminUser[]>([
    {
      id: '1',
      employee_id: 'VVC-101',
      name: 'សុខ គឹមហុង',
      user_role: 'Employee',
      department: 'Store 318',
      position: 'Staff',
      is_active: 1,
    },
    {
      id: '2',
      employee_id: 'VVC-102',
      name: 'កែវ សុភា',
      user_role: 'Store318Head',
      department: 'Store 318',
      position: 'ប្រធានហាង',
      is_active: 1,
    },
    {
      id: '3',
      employee_id: 'VVC-103',
      name: 'ជា វណ្ណៈ',
      user_role: 'WarehousePSPHead',
      department: 'Warehouse PSP',
      position: 'ប្រធានឃ្លាំង',
      is_active: 1,
    },
    {
      id: '4',
      employee_id: 'VVC-104',
      name: 'លឹម គឹមសាន',
      user_role: 'IT',
      department: 'IT Department',
      position: 'IT Specialist',
      is_active: 1,
    },
    {
      id: '5',
      employee_id: 'VVC-099',
      name: 'អ៊ុក សារ៉េត',
      user_role: 'Employee',
      department: 'Store SKKS2',
      position: 'Staff (ឈប់សម្រាក)',
      is_active: 0,
    },
  ]);

  const [search, setSearch] = useState('');
  const [deptFilter, setDeptFilter] = useState('all');
  const [modalOpen, setModalOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<Partial<AdminUser> | null>(null);

  const [formData, setFormData] = useState({
    employee_id: '',
    name: '',
    department: 'Store 318',
    position: '',
    user_role: 'Employee',
    password: '',
  });

  const loadUsers = async () => {
    try {
      const data = await adminApi.fetchUsers();
      if (data && data.success && Array.isArray(data.users)) {
        setUsers(data.users);
      }
    } catch {}
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const filteredUsers = users.filter((u) => {
    const q = search.toLowerCase();
    const matchSearch =
      (u.name || '').toLowerCase().includes(q) ||
      (u.employee_id || '').toLowerCase().includes(q) ||
      (u.position || '').toLowerCase().includes(q);
    const matchDept = deptFilter === 'all' || u.department === deptFilter;

    if (activeTab === 'inactive') {
      return matchSearch && matchDept && Number(u.is_active) === 0;
    }
    return matchSearch && matchDept && Number(u.is_active) !== 0;
  });

  const handleOpenCreate = () => {
    setEditingUser(null);
    setFormData({
      employee_id: `VVC-${Math.floor(100 + Math.random() * 900)}`,
      name: '',
      department: 'Store 318',
      position: '',
      user_role: 'Employee',
      password: '',
    });
    setModalOpen(true);
  };

  const handleOpenEdit = (u: AdminUser) => {
    setEditingUser(u);
    setFormData({
      employee_id: u.employee_id,
      name: u.name,
      department: u.department || 'Store 318',
      position: u.position || '',
      user_role: u.user_role || 'Employee',
      password: '',
    });
    setModalOpen(true);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name.trim() || !formData.employee_id.trim()) {
      alert('សូមបំពេញឈ្មោះ និង Employee ID!');
      return;
    }

    try {
      await adminApi.saveUser(formData);
    } catch {}

    if (editingUser) {
      setUsers((prev) =>
        prev.map((u) =>
          u.employee_id === editingUser.employee_id
            ? { ...u, ...formData }
            : u
        )
      );
    } else {
      setUsers((prev) => [
        {
          id: Date.now(),
          ...formData,
          is_active: 1,
        },
        ...prev,
      ]);
    }
    setModalOpen(false);
  };

  const handleDelete = async (employeeId: string) => {
    if (!window.confirm('តើអ្នកពិតជាចង់លុបគណនីបុគ្គលិកនេះមែនទេ?')) return;
    try {
      await adminApi.deleteUser(employeeId);
    } catch {}
    setUsers((prev) => prev.filter((u) => u.employee_id !== employeeId));
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header & Controls */}
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
            គ្រប់គ្រងបុគ្គលិក & អ្នកប្រើប្រាស់ (Employees Management)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            គ្រប់គ្រងបញ្ជីបុគ្គលិក ច្បាប់ម៉ោងចូល/ចេញ បង្កើតគណនី Admin និងគណនីអសកម្ម
          </p>
        </div>

        <button onClick={handleOpenCreate} className="btn btn-primary">
          <UserPlus size={16} />
          <span>បង្កើតបុគ្គលិកថ្មី (Create User)</span>
        </button>
      </div>

      {/* Sub-Tabs Bar */}
      <div
        className="hrm-card"
        style={{
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          overflowX: 'auto',
        }}
      >
        <button
          onClick={() => setActiveTab('list')}
          className={`btn btn-sm ${activeTab === 'list' ? 'btn-primary' : 'btn-secondary'}`}
        >
          <Users size={14} />
          <span>បញ្ជីបុគ្គលិកសកម្ម ({users.filter((u) => Number(u.is_active) !== 0).length})</span>
        </button>

        <button
          onClick={() => setActiveTab('rules')}
          className={`btn btn-sm ${activeTab === 'rules' ? 'btn-primary' : 'btn-secondary'}`}
        >
          <Clock size={14} />
          <span>គ្រប់គ្រងច្បាប់ម៉ោង (Work Rules & Schedule)</span>
        </button>

        <button
          onClick={() => setActiveTab('inactive')}
          className={`btn btn-sm ${activeTab === 'inactive' ? 'btn-primary' : 'btn-secondary'}`}
        >
          <UserX size={14} />
          <span>គណនីដែលបានបិទ ({users.filter((u) => Number(u.is_active) === 0).length})</span>
        </button>
      </div>

      {activeTab === 'rules' ? (
        /* Work Rules Editor Tab */
        <div className="hrm-card" style={{ padding: '24px' }}>
          <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '16px' }}>
            ច្បាប់កំណត់ម៉ោងចូល & ចេញធ្វើការ (Shift Schedule Rules)
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '18px' }}>
            <div style={{ padding: '16px', borderRadius: '12px', background: 'var(--surface-alt)', border: '1px solid var(--border)' }}>
              <div style={{ fontWeight: 700, fontSize: '14px', marginBottom: '8px', color: 'var(--primary)' }}>
                ☀️ វេនព្រឹក (Morning Shift)
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.8 }}>
                <div>• ម៉ោង Check-In: <strong>08:00 AM</strong></div>
                <div>• កម្រិតអនុញ្ញាតយឺត: <strong>15 នាទី</strong> (រហូតដល់ 08:15 AM)</div>
                <div>• ម៉ោង Check-Out: <strong>12:00 PM</strong></div>
              </div>
            </div>

            <div style={{ padding: '16px', borderRadius: '12px', background: 'var(--surface-alt)', border: '1px solid var(--border)' }}>
              <div style={{ fontWeight: 700, fontSize: '14px', marginBottom: '8px', color: 'var(--accent-gold)' }}>
                🌆 វេនរសៀល (Afternoon Shift)
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.8 }}>
                <div>• ម៉ោង Check-In: <strong>01:30 PM</strong></div>
                <div>• កម្រិតអនុញ្ញាតយឺត: <strong>15 នាទី</strong> (រហូតដល់ 01:45 PM)</div>
                <div>• ម៉ោង Check-Out: <strong>05:30 PM</strong></div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* User List / Inactive Users Tab */
        <>
          {/* Filter Toolbar */}
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
            {/* Search */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                background: 'var(--surface-alt)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                padding: '8px 14px',
                width: '320px',
                gap: '8px',
              }}
            >
              <Search size={16} color="var(--text-muted)" />
              <input
                type="text"
                placeholder="ស្វែងរកតាមឈ្មោះ, ID, មុខតំណែង..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  outline: 'none',
                  fontSize: '13.5px',
                  color: 'var(--text-primary)',
                  fontFamily: 'inherit',
                  width: '100%',
                }}
              />
            </div>

            {/* Department Filter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                ផ្នែក/សាខា:
              </span>
              <select
                className="form-select"
                value={deptFilter}
                onChange={(e) => setDeptFilter(e.target.value)}
                style={{ width: '180px', padding: '8px 12px', fontSize: '13px' }}
              >
                <option value="all">ទាំងអស់ (All Departments)</option>
                <option value="Store 318">Store 318</option>
                <option value="Store SKKS2">Store SKKS2</option>
                <option value="Warehouse PSP">Warehouse PSP</option>
                <option value="Warehouse PRV">Warehouse PRV</option>
                <option value="IT Department">IT Department</option>
              </select>
            </div>
          </div>

          {/* User Table */}
          <div className="table-container">
            <table className="hrm-table">
              <thead>
                <tr>
                  <th>អត្តលេខ (ID)</th>
                  <th>ឈ្មោះបុគ្គលិក</th>
                  <th>ផ្នែក / សាខា</th>
                  <th>មុខតំណែង</th>
                  <th>តួនាទីប្រព័ន្ធ</th>
                  <th>ស្ថានភាព</th>
                  <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                      រកមិនឃើញបុគ្គលិកត្រូវនឹងការស្វែងរកឡើយ
                    </td>
                  </tr>
                ) : (
                  filteredUsers.map((u) => (
                    <tr key={u.id}>
                      <td style={{ fontFamily: "'Outfit', monospace", fontWeight: 700, color: 'var(--primary)' }}>
                        {u.employee_id}
                      </td>
                      <td>
                        <div style={{ fontWeight: 600 }}>{u.name}</div>
                      </td>
                      <td style={{ color: 'var(--text-secondary)' }}>{u.department || 'N/A'}</td>
                      <td>{u.position || 'N/A'}</td>
                      <td>
                        <span className="badge badge-primary">{u.user_role || 'Employee'}</span>
                      </td>
                      <td>
                        <span className={`badge ${Number(u.is_active) !== 0 ? 'badge-good' : 'badge-absent'}`}>
                          {Number(u.is_active) !== 0 ? 'សកម្ម (Active)' : 'អសកម្ម (Inactive)'}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: '6px' }}>
                          <button
                            onClick={() => handleOpenEdit(u)}
                            className="btn btn-secondary btn-sm"
                            title="កែសម្រួល"
                          >
                            <Edit2 size={13} />
                          </button>
                          <button
                            onClick={() => handleDelete(u.employee_id)}
                            className="btn btn-danger btn-sm"
                            title="លុប"
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
        </>
      )}

      {/* Create / Edit Modal */}
      <Modal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        title={editingUser ? 'កែសម្រួលព័ត៌មានបុគ្គលិក' : 'បង្កើតគណនីបុគ្គលិកថ្មី'}
      >
        <form onSubmit={handleSave}>
          <div className="form-group">
            <label className="form-label">អត្តលេខបុគ្គលិក (Employee ID)</label>
            <input
              type="text"
              className="form-input"
              value={formData.employee_id}
              onChange={(e) => setFormData({ ...formData, employee_id: e.target.value })}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">ឈ្មោះពេញ (Full Name)</label>
            <input
              type="text"
              className="form-input"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              placeholder="ឧ. សុខ គឹមហុង"
              required
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
            <div className="form-group">
              <label className="form-label">ផ្នែក / សាខា (Department)</label>
              <select
                className="form-select"
                value={formData.department}
                onChange={(e) => setFormData({ ...formData, department: e.target.value })}
              >
                <option value="Store 318">Store 318</option>
                <option value="Store SKKS2">Store SKKS2</option>
                <option value="Warehouse PSP">Warehouse PSP</option>
                <option value="Warehouse PRV">Warehouse PRV</option>
                <option value="IT Department">IT Department</option>
              </select>
            </div>

            <div className="form-group">
              <label className="form-label">មុខតំណែង (Position)</label>
              <input
                type="text"
                className="form-input"
                value={formData.position}
                onChange={(e) => setFormData({ ...formData, position: e.target.value })}
                placeholder="ឧ. Staff / IT"
              />
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">តួនាទីប្រព័ន្ធ (System Role)</label>
            <select
              className="form-select"
              value={formData.user_role}
              onChange={(e) => setFormData({ ...formData, user_role: e.target.value })}
            >
              <option value="Employee">បុគ្គលិក (Employee)</option>
              <option value="Store318Head">ប្រធានហាង 318</option>
              <option value="WarehousePSPHead">ប្រធានឃ្លាំង PSP</option>
              <option value="IT">IT Specialist</option>
              <option value="HRM">HRM Administrator</option>
              <option value="Admin">System Admin</option>
            </select>
          </div>

          <div className="form-group">
            <label className="form-label">
              លេខសម្ងាត់ថ្មី (Password {editingUser ? '- ទុកទទេបើមិនប្តូរ' : ''})
            </label>
            <input
              type="password"
              className="form-input"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              placeholder={editingUser ? '••••••••' : 'កំណត់លេខសម្ងាត់'}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '24px' }}>
            <button
              type="button"
              onClick={() => setModalOpen(false)}
              className="btn btn-secondary"
            >
              បោះបង់
            </button>
            <button type="submit" className="btn btn-primary">
              <Check size={16} />
              <span>រក្សាទុក (Save)</span>
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
