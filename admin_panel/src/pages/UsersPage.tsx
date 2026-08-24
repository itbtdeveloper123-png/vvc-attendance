import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Users,
  UserPlus,
  Search,
  Filter,
  Edit2,
  Trash2,
  Clock,
  UserX,
  Save,
  IdCard,
  Briefcase,
  Images,
  FileSpreadsheet,
  Building,
  Mail,
  Phone,
  MapPin,
  Calendar,
  DollarSign,
  QrCode,
  FileText,
  Heart,
  UserCheck,
  ShieldAlert,
  Shield,
  ShieldCheck,
  ArrowLeft,
  Check,
  KeyRound,
  Lock,
  Copy,
  Download,
  RotateCw,
  MoreVertical,
  X,
} from 'lucide-react';
import { Modal } from '../components/common/Modal';
import { adminApi, AdminUser } from '../api/adminApi';

export const UsersPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const actionParam = searchParams.get('action') || 'list_users';
  const [activeTab, setActiveTab] = useState<'list_users' | 'create_user' | 'create_admin' | 'edit_rules' | 'inactive_users'>('list_users');
  const [formTab, setFormTab] = useState<'basic' | 'employment' | 'documents' | 'payroll'>('basic');

  const [users, setUsers] = useState<AdminUser[]>([]);
  const [search, setSearch] = useState('');
  const [deptFilter, setDeptFilter] = useState('all');
  const [roleFilter, setRoleFilter] = useState('all');
  const [loading, setLoading] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  // Edit Modal State
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<AdminUser | null>(null);

  // Duplicate Modal State
  const [isDuplicateModalOpen, setIsDuplicateModalOpen] = useState(false);
  const [duplicateData, setDuplicateData] = useState({
    source_id: '',
    source_name: '',
    new_id: '',
    new_name: '',
  });

  // User Form State
  const [formData, setFormData] = useState({
    employee_id: `VVC-${Math.floor(100 + Math.random() * 900)}`,
    name: '',
    latin_name: '',
    user_role: 'User',
    system_role: 'employee',
    system_role_label: '',
    position: '',
    department: 'Store 318',
    branch: 'VVC-HQ',
    username: '',
    email: '',
    phone: '',
    current_address: '',
    password: '',
    joined_at: new Date().toISOString().split('T')[0],
    marital_status: 'Single',
    contract_start: new Date().toISOString().split('T')[0],
    contract_end: '',
    contract_type: 'UDC',
    manager_id: '',
    al_total: 18,
    al_remaining: 18,
    base_salary: '0.00',
    nssf_id: '',
    bank_data_str: '',
    custom_data: '{}',
  });

  // Admin Form State (for create_admin)
  const [adminFormData, setAdminFormData] = useState({
    employee_id: `ADM-${Math.floor(100 + Math.random() * 900)}`,
    name: '',
    username: '',
    email: '',
    phone: '',
    password: '',
    user_role: 'Admin',
    system_role: 'super_admin',
    department: 'Management',
    position: 'Administrator',
    permissions: {
      users: true,
      reports: true,
      requests: true,
      stock: true,
      gps: true,
      payroll: true,
      notifications: true,
      settings: true,
    },
  });

  // Sync activeTab with URL action parameter
  useEffect(() => {
    if (actionParam === 'create_user') {
      setActiveTab('create_user');
    } else if (actionParam === 'create_admin') {
      setActiveTab('create_admin');
    } else if (actionParam === 'edit_rules') {
      setActiveTab('edit_rules');
    } else if (actionParam === 'inactive_users') {
      setActiveTab('inactive_users');
    } else {
      setActiveTab('list_users');
    }
  }, [actionParam]);

  const loadUsers = async () => {
    setLoading(true);
    try {
      const data = await adminApi.fetchUsers();
      if (data && data.success && Array.isArray(data.users)) {
        setUsers(data.users);
      }
    } catch {}
    setLoading(false);
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const handleTabChange = (tab: 'list_users' | 'create_user' | 'create_admin' | 'edit_rules' | 'inactive_users') => {
    setActiveTab(tab);
    setSearchParams({ action: tab });
  };

  const openEditModal = (u: AdminUser) => {
    setEditingUser(u);
    setFormData({
      employee_id: u.employee_id,
      name: u.name,
      latin_name: u.latin_name || '',
      user_role: u.user_role || 'User',
      system_role: u.system_role || 'employee',
      system_role_label: u.system_role_label || '',
      position: u.position || '',
      department: u.department || 'Store 318',
      branch: u.branch || 'VVC-HQ',
      username: u.username || '',
      email: u.email || '',
      phone: u.phone || '',
      current_address: u.current_address || '',
      password: '',
      joined_at: u.joined_at || new Date().toISOString().split('T')[0],
      marital_status: u.marital_status || 'Single',
      contract_start: u.contract_start || '',
      contract_end: u.contract_end || '',
      contract_type: u.contract_type || 'UDC',
      manager_id: u.manager_id || '',
      al_total: u.al_total || 18,
      al_remaining: u.al_remaining || 18,
      base_salary: String(u.base_salary || '0.00'),
      nssf_id: u.nssf_id || '',
      bank_data_str: u.bank_data_str || '',
      custom_data: u.custom_data ? JSON.stringify(u.custom_data) : '{}',
    });
    setFormTab('basic');
    setIsEditModalOpen(true);
  };

  const openDuplicateModal = (u: AdminUser) => {
    setDuplicateData({
      source_id: u.employee_id,
      source_name: u.name,
      new_id: `VVC-${Math.floor(100 + Math.random() * 900)}`,
      new_name: `${u.name} (Copy)`,
    });
    setIsDuplicateModalOpen(true);
  };

  const handleConfirmDuplicate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!duplicateData.new_id || !duplicateData.new_name) return;
    try {
      const srcUser = users.find((x) => x.employee_id === duplicateData.source_id);
      if (srcUser) {
        await adminApi.saveUser({
          ...srcUser,
          employee_id: duplicateData.new_id,
          name: duplicateData.new_name,
        });
        setIsDuplicateModalOpen(false);
        loadUsers();
      }
    } catch {
      alert('មានបញ្ហាក្នុងការចម្លងអ្នកប្រើប្រាស់');
    }
  };

  const handleSaveUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name.trim() || !formData.employee_id.trim()) {
      alert('សូមបំពេញឈ្មោះ និង អត្តលេខ (Employee ID)!');
      return;
    }

    try {
      await adminApi.saveUser(formData);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
      setIsEditModalOpen(false);
      loadUsers();
    } catch (err) {
      alert('មានបញ្ហាក្នុងការរក្សាទុកទិន្នន័យ');
    }
  };

  const handleSaveAdmin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!adminFormData.name.trim() || !adminFormData.username.trim() || !adminFormData.password.trim()) {
      alert('សូមបំពេញឈ្មោះ, Username និងលេខសម្ងាត់សម្រាប់ Admin!');
      return;
    }

    try {
      await adminApi.saveUser({
        employee_id: adminFormData.employee_id,
        name: adminFormData.name,
        username: adminFormData.username,
        email: adminFormData.email,
        phone: adminFormData.phone,
        password: adminFormData.password,
        user_role: 'Admin',
        system_role: adminFormData.system_role,
        department: adminFormData.department,
        position: adminFormData.position,
        custom_data: { permissions: adminFormData.permissions },
      });
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
      loadUsers();
    } catch (err) {
      alert('មានបញ្ហាក្នុងការបង្កើត Admin');
    }
  };

  const handleExportCSV = () => {
    const headers = ['Employee ID', 'Name', 'Latin Name', 'Department', 'Position', 'Role', 'Status'];
    const rows = filteredUsers.map((u) => [
      u.employee_id,
      `"${u.name}"`,
      `"${u.latin_name || ''}"`,
      `"${u.department || ''}"`,
      `"${u.position || ''}"`,
      u.user_role || 'User',
      Number(u.is_active) !== 0 ? 'Active' : 'Inactive',
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,\uFEFF' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `VVC_Users_List_${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const filteredUsers = users.filter((u) => {
    const q = search.toLowerCase();
    const matchSearch =
      (u.name || '').toLowerCase().includes(q) ||
      (u.employee_id || '').toLowerCase().includes(q) ||
      (u.position || '').toLowerCase().includes(q);
    const matchDept = deptFilter === 'all' || u.department === deptFilter;
    const matchRole = roleFilter === 'all' || u.user_role === roleFilter;

    if (activeTab === 'inactive_users') {
      return matchSearch && matchDept && matchRole && Number(u.is_active) === 0;
    }
    return matchSearch && matchDept && matchRole && Number(u.is_active) !== 0;
  });

  const totalUsersCount = users.length;
  const activeUsersCount = users.filter((u) => Number(u.is_active) !== 0).length;
  const adminsCount = users.filter((u) => u.user_role === 'Admin').length;
  const inactiveUsersCount = users.filter((u) => Number(u.is_active) === 0).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%' }}>
      {/* Sub-Tabs Bar Matching admin_attendance.php */}
      <div
        className="hrm-card"
        style={{
          padding: '8px 12px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          overflowX: 'auto',
          borderRadius: '14px',
        }}
      >
        <button
          onClick={() => handleTabChange('list_users')}
          className={`btn btn-sm ${activeTab === 'list_users' ? 'btn-primary' : 'btn-secondary'}`}
          style={{ borderRadius: '10px' }}
        >
          <Users size={14} />
          <span>បញ្ជីអ្នកប្រើប្រាស់ (Users List)</span>
        </button>

        <button
          onClick={() => handleTabChange('create_user')}
          className={`btn btn-sm ${activeTab === 'create_user' ? 'btn-primary' : 'btn-secondary'}`}
          style={{ borderRadius: '10px' }}
        >
          <UserPlus size={14} />
          <span>បង្កើតអ្នកប្រើប្រាស់ (Create User)</span>
        </button>

        <button
          onClick={() => handleTabChange('create_admin')}
          className={`btn btn-sm ${activeTab === 'create_admin' ? 'btn-primary' : 'btn-secondary'}`}
          style={{ borderRadius: '10px' }}
        >
          <ShieldCheck size={14} />
          <span>បង្កើតគណនី Admin (Create Admin)</span>
        </button>

        <button
          onClick={() => handleTabChange('edit_rules')}
          className={`btn btn-sm ${activeTab === 'edit_rules' ? 'btn-primary' : 'btn-secondary'}`}
          style={{ borderRadius: '10px' }}
        >
          <Clock size={14} />
          <span>ច្បាប់ម៉ោងបុគ្គលិក (Work Rules)</span>
        </button>

        <button
          onClick={() => handleTabChange('inactive_users')}
          className={`btn btn-sm ${activeTab === 'inactive_users' ? 'btn-primary' : 'btn-secondary'}`}
          style={{ borderRadius: '10px' }}
        >
          <UserX size={14} />
          <span>គណនីដែលបានបិទ (Inactive)</span>
        </button>
      </div>

      {/* ======================================================== */}
      {/* 1. LIST USERS & INACTIVE USERS (Matching admin_attendance) */}
      {/* ======================================================== */}
      {(activeTab === 'list_users' || activeTab === 'inactive_users') && (
        <>
          {/* Top Quick Stats Header */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
            <div className="hrm-card" style={{ padding: '16px 20px', borderRadius: '14px', display: 'flex', alignItems: 'center', gap: '14px' }}>
              <div style={{ width: '42px', height: '42px', borderRadius: '12px', background: 'rgba(79, 70, 229, 0.12)', color: 'var(--primary)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Users size={22} />
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>បុគ្គលិកសរុប (USERS)</div>
                <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-primary)' }}>{totalUsersCount}</div>
              </div>
            </div>

            <div className="hrm-card" style={{ padding: '16px 20px', borderRadius: '14px', display: 'flex', alignItems: 'center', gap: '14px' }}>
              <div style={{ width: '42px', height: '42px', borderRadius: '12px', background: 'rgba(16, 185, 129, 0.12)', color: 'var(--success)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <UserCheck size={22} />
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>កំពុងដំណើរការ (ACTIVE)</div>
                <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--success)' }}>{activeUsersCount}</div>
              </div>
            </div>

            <div className="hrm-card" style={{ padding: '16px 20px', borderRadius: '14px', display: 'flex', alignItems: 'center', gap: '14px' }}>
              <div style={{ width: '42px', height: '42px', borderRadius: '12px', background: 'rgba(212, 175, 55, 0.15)', color: 'var(--accent-gold-dark)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Shield size={22} />
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>អ្នកគ្រប់គ្រង (ADMINS)</div>
                <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--accent-gold-dark)' }}>{adminsCount}</div>
              </div>
            </div>

            <div className="hrm-card" style={{ padding: '16px 20px', borderRadius: '14px', display: 'flex', alignItems: 'center', gap: '14px' }}>
              <div style={{ width: '42px', height: '42px', borderRadius: '12px', background: 'rgba(239, 68, 68, 0.12)', color: 'var(--danger)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <UserX size={22} />
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>គណនីបានបិទ (INACTIVE)</div>
                <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--danger)' }}>{inactiveUsersCount}</div>
              </div>
            </div>
          </div>

          {/* Filter Toolbar Matching admin_attendance.php */}
          <div
            className="hrm-card"
            style={{
              padding: '16px 20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '14px',
              borderRadius: '14px',
            }}
          >
            {/* Left Controls: Search & Filters */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
              {/* Search */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  background: 'var(--surface-alt)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius)',
                  padding: '8px 14px',
                  width: '280px',
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
                    fontSize: '13px',
                    color: 'var(--text-primary)',
                    fontFamily: 'inherit',
                    width: '100%',
                  }}
                />
              </div>

              {/* Department Filter */}
              <select
                className="form-control"
                value={deptFilter}
                onChange={(e) => setDeptFilter(e.target.value)}
                style={{ width: '180px', padding: '8px 12px', fontSize: '13px' }}
              >
                <option value="all">គ្រប់ផ្នែក (All Departments)</option>
                <option value="Store 318">Store 318</option>
                <option value="Store SKKS2">Store SKKS2</option>
                <option value="Warehouse PSP">Warehouse PSP</option>
                <option value="Warehouse PRV">Warehouse PRV</option>
                <option value="IT Department">IT Department</option>
              </select>

              {/* Role Filter */}
              <select
                className="form-control"
                value={roleFilter}
                onChange={(e) => setRoleFilter(e.target.value)}
                style={{ width: '150px', padding: '8px 12px', fontSize: '13px' }}
              >
                <option value="all">គ្រប់សិទ្ធិ (All Roles)</option>
                <option value="User">User (បុគ្គលិក)</option>
                <option value="Admin">Admin (អ្នកគ្រប់គ្រង)</option>
              </select>
            </div>

            {/* Right Action Buttons */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <button onClick={loadUsers} className="btn btn-secondary btn-sm" title="ផ្ទុកឡើងវិញ">
                <RotateCw size={14} className={loading ? 'fa-spin' : ''} />
                <span>Refresh</span>
              </button>

              <button onClick={handleExportCSV} className="btn btn-secondary btn-sm" title="ទាញយកជា CSV">
                <Download size={14} />
                <span>Export CSV</span>
              </button>

              <button
                onClick={() => handleTabChange('create_user')}
                className="btn btn-primary btn-sm"
              >
                <UserPlus size={14} />
                <span>+ បង្កើតបុគ្គលិក</span>
              </button>
            </div>
          </div>

          {/* User Table Matching admin_attendance.php */}
          <div className="table-container">
            <table className="hrm-table">
              <thead>
                <tr>
                  <th style={{ width: '50px' }}>#</th>
                  <th>អត្តលេខ (ID)</th>
                  <th>ឈ្មោះបុគ្គលិក</th>
                  <th>ផ្នែក / សាខា</th>
                  <th>មុខតំណែង</th>
                  <th>សិទ្ធិប្រើប្រាស់</th>
                  <th>ស្ថានភាព</th>
                  <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                      {loading ? 'កំពុងទាញយកទិន្នន័យពី Server...' : 'រកមិនឃើញបុគ្គលិកត្រូវនឹងការស្វែងរកឡើយ'}
                    </td>
                  </tr>
                ) : (
                  filteredUsers.map((u, idx) => {
                    const initials = (u.name || u.employee_id).substring(0, 2).toUpperCase();
                    return (
                      <tr key={u.id}>
                        <td style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{idx + 1}</td>
                        <td>
                          <div style={{ fontFamily: "'Outfit', monospace", fontWeight: 700, color: 'var(--primary)' }}>
                            {u.employee_id}
                          </div>
                          {u.username && (
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>@{u.username}</div>
                          )}
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                            <div
                              style={{
                                width: '34px',
                                height: '34px',
                                borderRadius: '10px',
                                background: u.user_role === 'Admin' ? 'rgba(212, 175, 55, 0.15)' : 'var(--primary-light)',
                                color: u.user_role === 'Admin' ? 'var(--accent-gold-dark)' : 'var(--primary)',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                fontWeight: 700,
                                fontSize: '12px',
                              }}
                            >
                              {initials}
                            </div>
                            <div>
                              <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{u.name}</div>
                              {u.latin_name && (
                                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{u.latin_name}</div>
                              )}
                            </div>
                          </div>
                        </td>
                        <td>
                          <div style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{u.department || 'Store 318'}</div>
                          {u.branch && <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{u.branch}</div>}
                        </td>
                        <td>{u.position || 'Staff'}</td>
                        <td>
                          <span className={`badge ${u.user_role === 'Admin' ? 'badge-primary' : 'badge-good'}`}>
                            {u.user_role === 'Admin' ? '👑 Admin' : '👤 User'}
                          </span>
                        </td>
                        <td>
                          <span className={`badge ${Number(u.is_active) !== 0 ? 'badge-good' : 'badge-absent'}`}>
                            {Number(u.is_active) !== 0 ? '✓ សកម្ម' : '✕ អសកម្ម'}
                          </span>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <div style={{ display: 'inline-flex', gap: '6px' }}>
                            <button
                              onClick={() => openEditModal(u)}
                              className="btn btn-secondary btn-sm"
                              title="កែសម្រួល"
                            >
                              <Edit2 size={13} />
                            </button>
                            <button
                              onClick={() => openDuplicateModal(u)}
                              className="btn btn-secondary btn-sm"
                              title="ចម្លង (Duplicate)"
                            >
                              <Copy size={13} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* ======================================================== */}
      {/* 2. CREATE USER / ADD USER (Matching admin_attendance.php) */}
      {/* ======================================================== */}
      {activeTab === 'create_user' && (
        <div className="hrm-card" style={{ padding: '24px', borderRadius: '18px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', borderBottom: '1px solid var(--border)', paddingBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ width: '38px', height: '38px', borderRadius: '10px', background: 'rgba(99, 102, 241, 0.12)', color: 'var(--primary)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <UserPlus size={20} />
              </div>
              <div>
                <h3 style={{ fontSize: '17px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                  បង្កើតអ្នកប្រើប្រាស់ថ្មី (Create New User)
                </h3>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  បំពេញព័ត៌មានបុគ្គលិក សិទ្ធិប្រើប្រាស់ ឯកសារ និងប្រាក់បៀវត្ស
                </span>
              </div>
            </div>

            {saveSuccess && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--success)', fontWeight: 700, fontSize: '13px', background: 'var(--success-light)', padding: '6px 14px', borderRadius: '8px' }}>
                <Check size={16} />
                <span>បានបង្កើតគណនីបុគ្គលិកជោគជ័យ!</span>
              </div>
            )}
          </div>

          <form onSubmit={handleSaveUser}>
            {/* 4 Form Sub-Tabs */}
            <div className="hrm-tabs">
              {[
                { id: 'basic', label: 'ព័ត៌មានមូលដ្ឋាន (Basic Info)', icon: IdCard },
                { id: 'employment', label: 'ព័ត៌មានបុគ្គលិក (Employment Info)', icon: Briefcase },
                { id: 'documents', label: 'ឯកសារ & រូបភាព (Documents & Photos)', icon: Images },
                { id: 'payroll', label: 'Payroll & Other', icon: FileSpreadsheet },
              ].map((t) => {
                const Icon = t.icon;
                const active = formTab === t.id;
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setFormTab(t.id as any)}
                    className={`hrm-tab-btn ${active ? 'active' : ''}`}
                  >
                    <Icon size={16} />
                    <span>{t.label}</span>
                  </button>
                );
              })}
            </div>

            {/* TAB 1: ព័ត៌មានមូលដ្ឋាន (Basic Info) */}
            {formTab === 'basic' && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '18px' }}>
                <div className="form-group">
                  <label className="form-label">អត្តលេខ (Employee ID) *</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formData.employee_id}
                    onChange={(e) => setFormData({ ...formData, employee_id: e.target.value })}
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">ឈ្មោះបុគ្គលិក (Khmer Name) *</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="ឧ. សុខ គឹមហុង"
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">ឈ្មោះអក្សរឡាតាំង (Latin Name)</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formData.latin_name}
                    onChange={(e) => setFormData({ ...formData, latin_name: e.target.value })}
                    placeholder="SOK KIMHONG"
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">សិទ្ធិប្រើប្រាស់ (User Role) *</label>
                  <select
                    className="form-control"
                    value={formData.user_role}
                    onChange={(e) => setFormData({ ...formData, user_role: e.target.value })}
                  >
                    <option value="User">User (បុគ្គលិកទូទៅ)</option>
                    <option value="Admin">Admin (អ្នកគ្រប់គ្រងប្រព័ន្ធ)</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">តួនាទីក្នុងប្រព័ន្ធ (App Role) *</label>
                  <select
                    className="form-control"
                    value={formData.system_role}
                    onChange={(e) => setFormData({ ...formData, system_role: e.target.value })}
                    style={{ borderColor: 'var(--primary)' }}
                  >
                    <option value="employee">បុគ្គលិក (Employee)</option>
                    <option value="store_head">ប្រធានហាង (Store Head)</option>
                    <option value="warehouse_head">ប្រធានឃ្លាំង (Warehouse Head)</option>
                    <option value="it_specialist">IT Specialist</option>
                    <option value="hrm_admin">HRM Administrator</option>
                    <option value="super_admin">Super Administrator</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">ឈ្មោះតួនាទីជំនួស (Custom Label)</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formData.system_role_label}
                    onChange={(e) => setFormData({ ...formData, system_role_label: e.target.value })}
                    placeholder="ឧ. Project Manager"
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">មុខតំណែង (Position) *</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formData.position}
                    onChange={(e) => setFormData({ ...formData, position: e.target.value })}
                    placeholder="Staff / IT"
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">ផ្នែក/ដេប៉ាតឺម៉ង់ (Department)</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formData.department}
                    onChange={(e) => setFormData({ ...formData, department: e.target.value })}
                    placeholder="Store 318"
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">សាខា (Branch)</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formData.branch}
                    onChange={(e) => setFormData({ ...formData, branch: e.target.value })}
                    placeholder="VVC-HQ"
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">ឈ្មោះគណនី (Username) *</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formData.username}
                    onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                    placeholder="user123"
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">អ៊ីមែល (Email) *</label>
                  <input
                    type="email"
                    className="form-control"
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                    placeholder="user@vvc.asia"
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">លេខទូរស័ព្ទ (Phone)</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formData.phone}
                    onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                    placeholder="012 345 678"
                  />
                </div>

                <div className="form-group" style={{ gridColumn: 'span 2' }}>
                  <label className="form-label">អាសយដ្ឋានបច្ចុប្បន្ន (Current Address)</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formData.current_address}
                    onChange={(e) => setFormData({ ...formData, current_address: e.target.value })}
                    placeholder="រាជធានីភ្នំពេញ"
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">លេខសម្ងាត់ (Password)</label>
                  <input
                    type="password"
                    className="form-control"
                    value={formData.password}
                    onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                    placeholder="កំណត់លេខសម្ងាត់"
                  />
                </div>
              </div>
            )}

            {/* TAB 2: ព័ត៌មានបុគ្គលិក (Employment Info) */}
            {formTab === 'employment' && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '18px' }}>
                <div className="form-group">
                  <label className="form-label">ថ្ងៃចូលធ្វើការ (Joined Date)</label>
                  <input
                    type="date"
                    className="form-control"
                    value={formData.joined_at}
                    onChange={(e) => setFormData({ ...formData, joined_at: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">ស្ថានភាពគ្រួសារ (Marital Status)</label>
                  <select
                    className="form-control"
                    value={formData.marital_status}
                    onChange={(e) => setFormData({ ...formData, marital_status: e.target.value })}
                  >
                    <option value="Single">នៅលីវ (Single)</option>
                    <option value="Married">រៀបការរួច (Married)</option>
                    <option value="Divorced">លែងលះ (Divorced)</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">កិច្ចសន្យា - ចាប់ផ្តើម</label>
                  <input
                    type="date"
                    className="form-control"
                    value={formData.contract_start}
                    onChange={(e) => setFormData({ ...formData, contract_start: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">កិច្ចសន្យា - បញ្ចប់</label>
                  <input
                    type="date"
                    className="form-control"
                    value={formData.contract_end}
                    onChange={(e) => setFormData({ ...formData, contract_end: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">ប្រភេទកិច្ចសន្យា (Contract Type)</label>
                  <select
                    className="form-control"
                    value={formData.contract_type}
                    onChange={(e) => setFormData({ ...formData, contract_type: e.target.value })}
                  >
                    <option value="UDC">UDC (មិនកំណត់ថិរវេលា)</option>
                    <option value="FDC">FDC (មានកំណត់ថិរវេលា)</option>
                    <option value="Probation">សាកល្បង (Probation)</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">អ្នកគ្រប់គ្រងផ្ទាល់ (Manager)</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formData.manager_id}
                    onChange={(e) => setFormData({ ...formData, manager_id: e.target.value })}
                    placeholder="ឧ. EMP001"
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">ច្បាប់សម្រាកប្រចាំឆ្នាំ (AL Total)</label>
                  <input
                    type="number"
                    className="form-control"
                    value={formData.al_total}
                    onChange={(e) => setFormData({ ...formData, al_total: Number(e.target.value) })}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">AL នៅសល់ (Live Balance)</label>
                  <input
                    type="number"
                    step="0.5"
                    className="form-control"
                    value={formData.al_remaining}
                    onChange={(e) => setFormData({ ...formData, al_remaining: Number(e.target.value) })}
                  />
                </div>
              </div>
            )}

            {/* TAB 3: ឯកសារ & រូបភាព (Documents & Photos) */}
            {formTab === 'documents' && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '18px' }}>
                <div className="form-group">
                  <label className="form-label">រូបភាព Profile (Avatar)</label>
                  <input type="file" accept="image/*" className="form-control" />
                </div>

                <div className="form-group">
                  <label className="form-label">ឯកសារ JD (Job Description PDF)</label>
                  <input type="file" accept="application/pdf" className="form-control" />
                </div>

                <div className="form-group">
                  <label className="form-label">ឯកសារ Workflow (PDF)</label>
                  <input type="file" accept="application/pdf" className="form-control" />
                </div>
              </div>
            )}

            {/* TAB 4: Payroll & Other */}
            {formTab === 'payroll' && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '18px' }}>
                <div className="form-group">
                  <label className="form-label">ប្រាក់ខែគោល (Base Salary $)</label>
                  <input
                    type="number"
                    step="0.01"
                    className="form-control"
                    value={formData.base_salary}
                    onChange={(e) => setFormData({ ...formData, base_salary: e.target.value })}
                    style={{ fontWeight: 800, color: 'var(--success)' }}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">លេខប័ណ្ណ ប.ស.ស (NSSF ID)</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formData.nssf_id}
                    onChange={(e) => setFormData({ ...formData, nssf_id: e.target.value })}
                    placeholder="12345678"
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Bank QR Code (ABA/Other)</label>
                  <input type="file" accept="image/*" className="form-control" />
                </div>

                <div className="form-group">
                  <label className="form-label">ព័ត៌មានធនាគារ (Bank Details)</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formData.bank_data_str}
                    onChange={(e) => setFormData({ ...formData, bank_data_str: e.target.value })}
                    placeholder="ABA: 000 111 222 (NAME)"
                  />
                </div>

                <div className="form-group" style={{ gridColumn: 'span 2' }}>
                  <label className="form-label">កំណត់សម្គាល់/JSON Settings</label>
                  <textarea
                    className="form-control"
                    rows={3}
                    value={formData.custom_data}
                    onChange={(e) => setFormData({ ...formData, custom_data: e.target.value })}
                    style={{ fontFamily: 'monospace', fontSize: '12px' }}
                  />
                </div>
              </div>
            )}

            {/* Bottom Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '28px', borderTop: '1px solid var(--border)', paddingTop: '18px' }}>
              <button
                type="button"
                onClick={() => handleTabChange('list_users')}
                className="btn btn-secondary"
              >
                បោះបង់ (Cancel)
              </button>
              <button type="submit" className="btn btn-primary" style={{ padding: '10px 30px' }}>
                <Save size={16} />
                <span>រក្សាទុកអ្នកប្រើប្រាស់ (Save User)</span>
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ======================================================== */}
      {/* 3. CREATE ADMIN (Matching admin_attendance.php)          */}
      {/* ======================================================== */}
      {activeTab === 'create_admin' && (
        <div className="hrm-card" style={{ padding: '24px', borderRadius: '18px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', borderBottom: '1px solid var(--border)', paddingBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ width: '38px', height: '38px', borderRadius: '10px', background: 'rgba(212, 175, 55, 0.15)', color: 'var(--accent-gold-dark)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <ShieldCheck size={20} />
              </div>
              <div>
                <h3 style={{ fontSize: '17px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                  បង្កើតគណនី Admin ថ្មី (Create Admin Account)
                </h3>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  កំណត់សិទ្ធិ និងបង្កើតគណនីគ្រប់គ្រងប្រព័ន្ធ (Administrator)
                </span>
              </div>
            </div>

            {saveSuccess && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--success)', fontWeight: 700, fontSize: '13px', background: 'var(--success-light)', padding: '6px 14px', borderRadius: '8px' }}>
                <Check size={16} />
                <span>បានបង្កើតគណនី Admin ជោគជ័យ!</span>
              </div>
            )}
          </div>

          <form onSubmit={handleSaveAdmin}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '18px' }}>
              <div className="form-group">
                <label className="form-label">អត្តលេខ Admin ID *</label>
                <input
                  type="text"
                  className="form-control"
                  value={adminFormData.employee_id}
                  onChange={(e) => setAdminFormData({ ...adminFormData, employee_id: e.target.value })}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">ឈ្មោះពេញ (Admin Full Name) *</label>
                <input
                  type="text"
                  className="form-control"
                  value={adminFormData.name}
                  onChange={(e) => setAdminFormData({ ...adminFormData, name: e.target.value })}
                  placeholder="ឧ. សុខ វិសាល"
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">ឈ្មោះគណនី (Username) *</label>
                <input
                  type="text"
                  className="form-control"
                  value={adminFormData.username}
                  onChange={(e) => setAdminFormData({ ...adminFormData, username: e.target.value })}
                  placeholder="admin_visal"
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">លេខសម្ងាត់ (Password) *</label>
                <input
                  type="password"
                  className="form-control"
                  value={adminFormData.password}
                  onChange={(e) => setAdminFormData({ ...adminFormData, password: e.target.value })}
                  placeholder="បញ្ចូលលេខសម្ងាត់រឹងមាំ"
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">កម្រិតសិទ្ធិប្រព័ន្ធ (System Role) *</label>
                <select
                  className="form-control"
                  value={adminFormData.system_role}
                  onChange={(e) => setAdminFormData({ ...adminFormData, system_role: e.target.value })}
                >
                  <option value="super_admin">Super Administrator (សិទ្ធិពេញលេញ)</option>
                  <option value="hrm_admin">HRM Administrator</option>
                  <option value="store_head">Store Head Admin</option>
                  <option value="warehouse_head">Warehouse Head Admin</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">អ៊ីមែល (Email)</label>
                <input
                  type="email"
                  className="form-control"
                  value={adminFormData.email}
                  onChange={(e) => setAdminFormData({ ...adminFormData, email: e.target.value })}
                  placeholder="admin@vvc.asia"
                />
              </div>
            </div>

            {/* Permission Checkboxes */}
            <div style={{ marginTop: '24px', padding: '18px', borderRadius: '14px', background: 'var(--surface-alt)', border: '1px solid var(--border)' }}>
              <div style={{ fontWeight: 700, fontSize: '14px', marginBottom: '14px', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <KeyRound size={16} color="var(--primary)" />
                <span>កំណត់សិទ្ធិចូលដំណើរការម៉ូឌុល (Module Access Permissions)</span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
                {[
                  { key: 'users', label: 'គ្រប់គ្រងបុគ្គលិក (Users)' },
                  { key: 'reports', label: 'របាយការណ៍វត្តមាន (Reports)' },
                  { key: 'requests', label: 'គ្រប់គ្រងសំណើរ (Requests)' },
                  { key: 'stock', label: 'គ្រប់គ្រងស្តុក (Stock)' },
                  { key: 'gps', label: 'តាមដាន GPS (GPS Trips)' },
                  { key: 'payroll', label: 'ប្រាក់បៀវត្ស (Payroll)' },
                  { key: 'notifications', label: 'ការជូនដំណឹង (Notifications)' },
                  { key: 'settings', label: 'ការកំណត់ប្រព័ន្ធ (Settings)' },
                ].map((p) => (
                  <label key={p.key} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: 'var(--text-primary)', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={(adminFormData.permissions as any)[p.key]}
                      onChange={(e) =>
                        setAdminFormData({
                          ...adminFormData,
                          permissions: {
                            ...adminFormData.permissions,
                            [p.key]: e.target.checked,
                          },
                        })
                      }
                      style={{ width: '16px', height: '16px', accentColor: 'var(--primary)' }}
                    />
                    <span>{p.label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Bottom Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '28px', borderTop: '1px solid var(--border)', paddingTop: '18px' }}>
              <button
                type="button"
                onClick={() => handleTabChange('list_users')}
                className="btn btn-secondary"
              >
                បោះបង់ (Cancel)
              </button>
              <button type="submit" className="btn btn-gold" style={{ padding: '10px 30px' }}>
                <ShieldCheck size={16} />
                <span>បង្កើតគណនី Admin (Create Admin)</span>
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ======================================================== */}
      {/* 4. WORK RULES & SCHEDULE                                */}
      {/* ======================================================== */}
      {activeTab === 'edit_rules' && (
        <div className="hrm-card" style={{ padding: '24px', borderRadius: '18px' }}>
          <h3 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--text-primary)', marginBottom: '16px' }}>
            ច្បាប់កំណត់ម៉ោងចូល & ចេញធ្វើការ (Shift Schedule Rules)
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '18px' }}>
            <div style={{ padding: '18px', borderRadius: '14px', background: 'var(--surface-alt)', border: '1px solid var(--border)' }}>
              <div style={{ fontWeight: 700, fontSize: '14px', marginBottom: '8px', color: 'var(--primary)' }}>
                ☀️ វេនព្រឹក (Morning Shift)
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.8 }}>
                <div>• ម៉ោង Check-In: <strong>08:00 AM</strong></div>
                <div>• កម្រិតអនុញ្ញាតយឺត: <strong>15 នាទី</strong> (រហូតដល់ 08:15 AM)</div>
                <div>• ម៉ោង Check-Out: <strong>12:00 PM</strong></div>
              </div>
            </div>

            <div style={{ padding: '18px', borderRadius: '14px', background: 'var(--surface-alt)', border: '1px solid var(--border)' }}>
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
      )}

      {/* ======================================================== */}
      {/* 5. EDIT USER MODAL (Matching admin_attendance.php)       */}
      {/* ======================================================== */}
      {isEditModalOpen && (
        <Modal
          isOpen={isEditModalOpen}
          onClose={() => setIsEditModalOpen(false)}
          title={`កែសម្រួលព័ត៌មានបុគ្គលិក: ${formData.name} (${formData.employee_id})`}
          maxWidth="750px"
        >
          <form onSubmit={handleSaveUser}>
            <div className="hrm-tabs" style={{ marginBottom: '16px' }}>
              {[
                { id: 'basic', label: 'ព័ត៌មានមូលដ្ឋាន', icon: IdCard },
                { id: 'employment', label: 'ព័ត៌មានបុគ្គលិក', icon: Briefcase },
                { id: 'documents', label: 'ឯកសារ & រូបភាព', icon: Images },
                { id: 'payroll', label: 'Payroll & Other', icon: FileSpreadsheet },
              ].map((t) => {
                const Icon = t.icon;
                const active = formTab === t.id;
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setFormTab(t.id as any)}
                    className={`hrm-tab-btn ${active ? 'active' : ''}`}
                  >
                    <Icon size={14} />
                    <span>{t.label}</span>
                  </button>
                );
              })}
            </div>

            {formTab === 'basic' && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                <div className="form-group">
                  <label className="form-label">អត្តលេខ (ID) *</label>
                  <input type="text" className="form-control" value={formData.employee_id} readOnly style={{ background: 'var(--surface-alt)' }} />
                </div>
                <div className="form-group">
                  <label className="form-label">ឈ្មោះបុគ្គលិក *</label>
                  <input type="text" className="form-control" value={formData.name} onChange={(e) => setFormData({ ...formData, name: e.target.value })} required />
                </div>
                <div className="form-group">
                  <label className="form-label">មុខតំណែង *</label>
                  <input type="text" className="form-control" value={formData.position} onChange={(e) => setFormData({ ...formData, position: e.target.value })} required />
                </div>
                <div className="form-group">
                  <label className="form-label">ផ្នែក/ដេប៉ាតឺម៉ង់</label>
                  <input type="text" className="form-control" value={formData.department} onChange={(e) => setFormData({ ...formData, department: e.target.value })} />
                </div>
                <div className="form-group">
                  <label className="form-label">Username</label>
                  <input type="text" className="form-control" value={formData.username} onChange={(e) => setFormData({ ...formData, username: e.target.value })} />
                </div>
                <div className="form-group">
                  <label className="form-label">លេខសម្ងាត់ថ្មី (Password)</label>
                  <input type="password" className="form-control" value={formData.password} onChange={(e) => setFormData({ ...formData, password: e.target.value })} placeholder="ទុកទទេរបើមិនប្តូរ" />
                </div>
              </div>
            )}

            {formTab === 'employment' && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                <div className="form-group">
                  <label className="form-label">ថ្ងៃចូលធ្វើការ</label>
                  <input type="date" className="form-control" value={formData.joined_at} onChange={(e) => setFormData({ ...formData, joined_at: e.target.value })} />
                </div>
                <div className="form-group">
                  <label className="form-label">ស្ថានភាពគ្រួសារ</label>
                  <select className="form-control" value={formData.marital_status} onChange={(e) => setFormData({ ...formData, marital_status: e.target.value })}>
                    <option value="Single">នៅលីវ (Single)</option>
                    <option value="Married">រៀបការរួច (Married)</option>
                    <option value="Divorced">លែងលះ (Divorced)</option>
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">AL Total</label>
                  <input type="number" className="form-control" value={formData.al_total} onChange={(e) => setFormData({ ...formData, al_total: Number(e.target.value) })} />
                </div>
                <div className="form-group">
                  <label className="form-label">AL នៅសល់</label>
                  <input type="number" step="0.5" className="form-control" value={formData.al_remaining} onChange={(e) => setFormData({ ...formData, al_remaining: Number(e.target.value) })} />
                </div>
              </div>
            )}

            {formTab === 'documents' && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '14px' }}>
                <div className="form-group">
                  <label className="form-label">រូបភាព Profile (Avatar)</label>
                  <input type="file" accept="image/*" className="form-control" />
                </div>
              </div>
            )}

            {formTab === 'payroll' && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                <div className="form-group">
                  <label className="form-label">ប្រាក់ខែគោល ($)</label>
                  <input type="number" step="0.01" className="form-control" value={formData.base_salary} onChange={(e) => setFormData({ ...formData, base_salary: e.target.value })} style={{ fontWeight: 700, color: 'var(--success)' }} />
                </div>
                <div className="form-group">
                  <label className="form-label">NSSF ID</label>
                  <input type="text" className="form-control" value={formData.nssf_id} onChange={(e) => setFormData({ ...formData, nssf_id: e.target.value })} />
                </div>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '24px', borderTop: '1px solid var(--border)', paddingTop: '16px' }}>
              <button type="button" onClick={() => setIsEditModalOpen(false)} className="btn btn-secondary">
                បោះបង់
              </button>
              <button type="submit" className="btn btn-primary" style={{ padding: '10px 24px' }}>
                <Save size={15} />
                <span>រក្សាទុកការកែប្រែ</span>
              </button>
            </div>
          </form>
        </Modal>
      )}

      {/* ======================================================== */}
      {/* 6. DUPLICATE USER MODAL (Matching admin_attendance.php)  */}
      {/* ======================================================== */}
      {isDuplicateModalOpen && (
        <Modal
          isOpen={isDuplicateModalOpen}
          onClose={() => setIsDuplicateModalOpen(false)}
          title="ចម្លងអ្នកប្រើប្រាស់ (Duplicate User)"
          maxWidth="480px"
        >
          <form onSubmit={handleConfirmDuplicate}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div className="form-group">
                <label className="form-label">គណនីប្រភព (Source User)</label>
                <input
                  type="text"
                  className="form-control"
                  value={`${duplicateData.source_id} - ${duplicateData.source_name}`}
                  readOnly
                  style={{ background: 'var(--surface-alt)' }}
                />
              </div>

              <div className="form-group">
                <label className="form-label">អត្តលេខថ្មី (New Employee ID) *</label>
                <input
                  type="text"
                  className="form-control"
                  value={duplicateData.new_id}
                  onChange={(e) => setDuplicateData({ ...duplicateData, new_id: e.target.value })}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">ឈ្មោះថ្មី (New Name) *</label>
                <input
                  type="text"
                  className="form-control"
                  value={duplicateData.new_name}
                  onChange={(e) => setDuplicateData({ ...duplicateData, new_name: e.target.value })}
                  required
                />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px', borderTop: '1px solid var(--border)', paddingTop: '14px' }}>
              <button type="button" onClick={() => setIsDuplicateModalOpen(false)} className="btn btn-secondary">
                បោះបង់
              </button>
              <button type="submit" className="btn btn-primary">
                <Copy size={15} />
                <span>ចម្លងគណនី</span>
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
};
