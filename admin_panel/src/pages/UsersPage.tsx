import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Users,
  UserPlus,
  Search,
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
  Check,
  Shield,
  ShieldCheck,
  Copy,
  Download,
  RotateCw,
  MoreVertical,
  GripVertical,
  Store,
  CheckCircle2,
  Calendar,
  KeyRound,
  ArrowLeft,
  LogIn,
  LogOut,
  Play,
  Square,
  PlusCircle,
  RotateCcw,
  Sparkles,
  AlertTriangle,
} from 'lucide-react';
import { Modal } from '../components/common/Modal';
import { adminApi, AdminUser } from '../api/adminApi';

interface DepartmentGroup {
  id: string | number;
  name: string;
  groupId: number;
  users: AdminUser[];
}

export interface TimeRuleItem {
  id?: string | number;
  type: 'checkin' | 'checkout';
  start_time: string;
  end_time: string;
  status: 'Good' | 'Late' | 'Absent';
}

export const UsersPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();

  const actionParam = searchParams.get('action') || 'list_users';
  const idParam = searchParams.get('id') || '';
  const [activeTab, setActiveTab] = useState<'list_users' | 'create_user' | 'create_admin' | 'edit_rules' | 'inactive_users'>('list_users');
  const [formTab, setFormTab] = useState<'basic' | 'employment' | 'documents' | 'payroll'>('basic');

  const [users, setUsers] = useState<AdminUser[]>([]);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [selectAll, setSelectAll] = useState(false);
  const [search, setSearch] = useState('');
  const [deptFilter, setDeptFilter] = useState('all');
  const [roleFilter, setRoleFilter] = useState('all');
  const [loading, setLoading] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  // Active Context Menu for row
  const [activeMenuRowId, setActiveMenuRowId] = useState<string | number | null>(null);

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

  // Work Rules / Shift Schedule State (matching admin_attendance.php?page=users&action=edit_rules&id=...)
  const [selectedRuleUserId, setSelectedRuleUserId] = useState<string>(idParam);
  const [rules, setRules] = useState<TimeRuleItem[]>([]);
  const [rulesLoading, setRulesLoading] = useState(false);
  const [rulesSaving, setRulesSaving] = useState(false);
  const [rulesSuccess, setRulesSuccess] = useState(false);
  const [isCopyRulesModalOpen, setIsCopyRulesModalOpen] = useState(false);
  const [copyFromUserId, setCopyFromUserId] = useState('');

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

  // Close context menu on outside click
  useEffect(() => {
    const handleOutsideClick = (e: MouseEvent) => {
      if (!(e.target as HTMLElement).closest('.action-menu-container')) {
        setActiveMenuRowId(null);
      }
    };
    window.addEventListener('click', handleOutsideClick);
    return () => window.removeEventListener('click', handleOutsideClick);
  }, []);

  // Sync activeTab and selectedRuleUserId with URL parameters
  useEffect(() => {
    if (actionParam === 'create_user') {
      setActiveTab('create_user');
    } else if (actionParam === 'create_admin') {
      setActiveTab('create_admin');
    } else if (actionParam === 'edit_rules') {
      setActiveTab('edit_rules');
      if (idParam) {
        setSelectedRuleUserId(idParam);
      }
    } else if (actionParam === 'inactive_users') {
      setActiveTab('inactive_users');
    } else {
      setActiveTab('list_users');
    }
  }, [actionParam, idParam]);

  const loadUsers = async () => {
    setLoading(true);
    try {
      const data = await adminApi.fetchUsers();
      if (data && data.success && Array.isArray(data.users)) {
        setUsers(data.users);
        if (!selectedRuleUserId && data.users.length > 0) {
          setSelectedRuleUserId(idParam || data.users[0].employee_id);
        }
      }
    } catch {}
    setLoading(false);
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const loadTimeRules = async (empId: string) => {
    if (!empId) return;
    setRulesLoading(true);
    try {
      const res = await adminApi.getTimeRules(empId);
      if (res && (res.success || res.status === 'success') && Array.isArray(res.rules) && res.rules.length > 0) {
        setRules(
          res.rules.map((r: any) => ({
            id: r.id,
            type: r.type === 'checkout' ? 'checkout' : 'checkin',
            start_time: r.start_time || (r.type === 'checkout' ? '17:00:00' : '08:00:00'),
            end_time: r.end_time || (r.type === 'checkout' ? '23:59:59' : '08:15:00'),
            status: r.status === 'Late' || r.status === 'Absent' ? r.status : 'Good',
          }))
        );
      } else {
        // Standard default schedule preset if user doesn't have any rules yet
        setRules([
          { type: 'checkin', start_time: '07:30:00', end_time: '08:15:00', status: 'Good' },
          { type: 'checkin', start_time: '08:16:00', end_time: '09:00:00', status: 'Late' },
          { type: 'checkin', start_time: '09:01:00', end_time: '12:00:00', status: 'Absent' },
          { type: 'checkout', start_time: '17:00:00', end_time: '23:59:59', status: 'Good' },
          { type: 'checkout', start_time: '12:00:00', end_time: '16:59:59', status: 'Late' },
        ]);
      }
    } catch (err) {
      console.error('Error fetching time rules:', err);
    }
    setRulesLoading(false);
  };

  // Load rules when activeTab is edit_rules or selectedRuleUserId changes
  useEffect(() => {
    if (activeTab === 'edit_rules' && selectedRuleUserId) {
      loadTimeRules(selectedRuleUserId);
    }
  }, [activeTab, selectedRuleUserId]);

  const handleSaveTimeRules = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!selectedRuleUserId) {
      alert('សូមជ្រើសរើសបុគ្គលិកជាមុនសិន!');
      return;
    }
    setRulesSaving(true);
    try {
      const res = await adminApi.saveTimeRules(selectedRuleUserId, rules);
      if (res && (res.success || res.status === 'success')) {
        setRulesSuccess(true);
        setTimeout(() => setRulesSuccess(false), 3500);
      } else {
        alert(res?.message || 'កំហុសក្នុងការរក្សាទុកច្បាប់ម៉ោង');
      }
    } catch (err) {
      alert('Network error saving time rules');
    }
    setRulesSaving(false);
  };

  const handleCopyTimeRules = async () => {
    if (!copyFromUserId || !selectedRuleUserId) {
      alert('សូមជ្រើសរើសបុគ្គលិកប្រភពដែលត្រូវចម្លងពី!');
      return;
    }
    setRulesSaving(true);
    try {
      const res = await adminApi.copyTimeRules(copyFromUserId, selectedRuleUserId);
      if (res && (res.success || res.status === 'success')) {
        setIsCopyRulesModalOpen(false);
        setRulesSuccess(true);
        setTimeout(() => setRulesSuccess(false), 3500);
        loadTimeRules(selectedRuleUserId);
      } else {
        alert(res?.message || 'កំហុសក្នុងការចម្លង');
      }
    } catch (err) {
      alert('Network error copying rules');
    }
    setRulesSaving(false);
  };

  const addTimeRule = (type: 'checkin' | 'checkout') => {
    const newRule: TimeRuleItem = {
      type,
      start_time: type === 'checkin' ? '08:00:00' : '17:00:00',
      end_time: type === 'checkin' ? '08:15:00' : '23:59:59',
      status: 'Good',
    };
    setRules([...rules, newRule]);
  };

  const updateTimeRule = (index: number, field: keyof TimeRuleItem, value: any) => {
    const updated = [...rules];
    updated[index] = { ...updated[index], [field]: value };
    setRules(updated);
  };

  const removeTimeRule = (index: number) => {
    setRules(rules.filter((_, i) => i !== index));
  };

  const applyPreset = (preset: 'standard' | 'morning' | 'afternoon') => {
    if (preset === 'standard') {
      setRules([
        { type: 'checkin', start_time: '07:30:00', end_time: '08:15:00', status: 'Good' },
        { type: 'checkin', start_time: '08:16:00', end_time: '09:00:00', status: 'Late' },
        { type: 'checkin', start_time: '09:01:00', end_time: '12:00:00', status: 'Absent' },
        { type: 'checkout', start_time: '17:00:00', end_time: '23:59:59', status: 'Good' },
        { type: 'checkout', start_time: '12:00:00', end_time: '16:59:59', status: 'Late' },
      ]);
    } else if (preset === 'morning') {
      setRules([
        { type: 'checkin', start_time: '07:30:00', end_time: '08:15:00', status: 'Good' },
        { type: 'checkin', start_time: '08:16:00', end_time: '08:45:00', status: 'Late' },
        { type: 'checkin', start_time: '08:46:00', end_time: '12:00:00', status: 'Absent' },
        { type: 'checkout', start_time: '12:00:00', end_time: '14:00:00', status: 'Good' },
      ]);
    } else if (preset === 'afternoon') {
      setRules([
        { type: 'checkin', start_time: '13:00:00', end_time: '13:45:00', status: 'Good' },
        { type: 'checkin', start_time: '13:46:00', end_time: '14:15:00', status: 'Late' },
        { type: 'checkin', start_time: '14:16:00', end_time: '17:00:00', status: 'Absent' },
        { type: 'checkout', start_time: '17:30:00', end_time: '23:59:59', status: 'Good' },
      ]);
    }
  };

  const handleTabChange = (tab: 'list_users' | 'create_user' | 'create_admin' | 'edit_rules' | 'inactive_users', empId?: string) => {
    setActiveTab(tab);
    if (tab === 'edit_rules') {
      const targetId = empId || selectedRuleUserId || (users.length > 0 ? users[0].employee_id : '0016');
      setSelectedRuleUserId(targetId);
      setSearchParams({ action: tab, id: targetId });
    } else {
      setSearchParams({ action: tab });
    }
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
    setActiveMenuRowId(null);
  };

  const openDuplicateModal = (u: AdminUser) => {
    setDuplicateData({
      source_id: u.employee_id,
      source_name: u.name,
      new_id: `VVC-${Math.floor(100 + Math.random() * 900)}`,
      new_name: `${u.name} (Copy)`,
    });
    setIsDuplicateModalOpen(true);
    setActiveMenuRowId(null);
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

  const handleDeleteUser = async (empId: string) => {
    if (!confirm(`តើអ្នកប្រាកដថាចង់បិទ/លុបគណនីបុគ្គលិក ${empId} នេះទេ?`)) return;
    try {
      await adminApi.deleteUser(empId);
      loadUsers();
      setActiveMenuRowId(null);
    } catch {
      alert('មានបញ្ហាក្នុងការបិទគណនី');
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

  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSelectAll(e.target.checked);
    if (e.target.checked) {
      setSelectedIds(filteredUsers.map((u) => String(u.employee_id)));
    } else {
      setSelectedIds([]);
    }
  };

  const handleSelectRow = (id: string) => {
    if (selectedIds.includes(id)) {
      setSelectedIds(selectedIds.filter((x) => x !== id));
    } else {
      setSelectedIds([...selectedIds, id]);
    }
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

  // Group Users by Department (matching admin_attendance.php UI group headers)
  const groupedDepartments: DepartmentGroup[] = [];
  const deptMap: { [key: string]: AdminUser[] } = {};

  filteredUsers.forEach((u) => {
    const dept = u.department || 'Store 318';
    if (!deptMap[dept]) deptMap[dept] = [];
    deptMap[dept].push(u);
  });

  let gId = 4;
  Object.keys(deptMap).forEach((deptName) => {
    groupedDepartments.push({
      id: deptName,
      name: deptName,
      groupId: gId++,
      users: deptMap[deptName],
    });
  });

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

          {/* User Table Matching Exact Screenshot Design */}
          <div
            className="hrm-card"
            style={{
              padding: 0,
              borderRadius: '16px',
              overflow: 'visible',
              border: '1px solid var(--border)',
              boxShadow: 'var(--shadow-sm)',
            }}
          >
            <div style={{ overflowX: 'auto', borderRadius: '16px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                {/* Table Header */}
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--surface)' }}>
                    <th style={{ padding: '16px 18px', width: '40px', textAlign: 'center' }}>
                      <input
                        type="checkbox"
                        checked={selectAll}
                        onChange={handleSelectAll}
                        style={{ width: '16px', height: '16px', accentColor: 'var(--primary)', cursor: 'pointer' }}
                      />
                    </th>
                    <th style={{ padding: '16px 14px', fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.4px', width: '90px' }}>
                      ID
                    </th>
                    <th style={{ padding: '16px 18px', fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.4px' }}>
                      ព័ត៌មានបុគ្គលិក (EMPLOYEE INFO)
                    </th>
                    <th style={{ padding: '16px 18px', fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.4px', textAlign: 'center', width: '160px' }}>
                      ស្ថានភាព (STATUS)
                    </th>
                    <th style={{ padding: '16px 18px', fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.4px', width: '180px' }}>
                      ថ្ងៃបញ្ចប់ការងារ
                    </th>
                    <th style={{ padding: '16px 18px', fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.4px', textAlign: 'center', width: '90px' }}>
                      ACTIONS
                    </th>
                  </tr>
                </thead>

                {/* Table Body with Department Groups */}
                <tbody>
                  {filteredUsers.length === 0 ? (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}>
                        {loading ? 'កំពុងទាញយកទិន្នន័យ...' : 'មិនមានទិន្នន័យបុគ្គលិកឡើយ'}
                      </td>
                    </tr>
                  ) : (
                    groupedDepartments.map((group) => (
                      <React.Fragment key={group.id}>
                        {/* Group Header Banner Row */}
                        <tr
                          style={{
                            background: 'rgba(99, 102, 241, 0.04)',
                            borderTop: '1px solid var(--border)',
                            borderBottom: '1px solid var(--border)',
                          }}
                        >
                          <td
                            colSpan={6}
                            style={{
                              padding: '12px 18px',
                              borderLeft: '4px solid var(--primary)',
                            }}
                          >
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                              <GripVertical size={16} color="var(--text-muted)" style={{ cursor: 'grab' }} />
                              <Store size={18} color="var(--primary)" />
                              <span style={{ fontWeight: 800, fontSize: '15px', color: 'var(--text-primary)' }}>
                                {group.name}
                              </span>
                              <span
                                style={{
                                  background: 'rgba(99, 102, 241, 0.12)',
                                  color: 'var(--primary)',
                                  fontSize: '11px',
                                  fontWeight: 700,
                                  padding: '2px 8px',
                                  borderRadius: '6px',
                                }}
                              >
                                Group ID: {group.groupId}
                              </span>
                            </div>
                          </td>
                        </tr>

                        {/* Employee Rows in Group */}
                        {group.users.map((u) => {
                          const isSelected = selectedIds.includes(String(u.employee_id));
                          const initials = (u.name || u.employee_id).substring(0, 2).toUpperCase();

                          return (
                            <tr
                              key={u.id}
                              style={{
                                borderBottom: '1px solid var(--border)',
                                background: isSelected ? 'rgba(99, 102, 241, 0.03)' : 'var(--surface)',
                                transition: 'background-color 0.15s ease',
                              }}
                            >
                              {/* Checkbox */}
                              <td style={{ padding: '14px 18px', textAlign: 'center' }}>
                                <input
                                  type="checkbox"
                                  checked={isSelected}
                                  onChange={() => handleSelectRow(String(u.employee_id))}
                                  style={{ width: '16px', height: '16px', accentColor: 'var(--primary)', cursor: 'pointer' }}
                                />
                              </td>

                              {/* ID */}
                              <td style={{ padding: '14px', fontFamily: "'Outfit', monospace", fontWeight: 700, fontSize: '14px', color: 'var(--text-primary)' }}>
                                {u.employee_id}
                              </td>

                              {/* Employee Info */}
                              <td style={{ padding: '14px 18px' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                                  {/* Avatar Image / Squircle */}
                                  <div
                                    style={{
                                      width: '46px',
                                      height: '46px',
                                      borderRadius: '12px',
                                      background: u.avatar ? 'transparent' : 'rgba(99, 102, 241, 0.12)',
                                      color: 'var(--primary)',
                                      display: 'flex',
                                      alignItems: 'center',
                                      justifyContent: 'center',
                                      fontWeight: 800,
                                      fontSize: '14px',
                                      overflow: 'hidden',
                                      flexShrink: 0,
                                      border: '1px solid var(--border)',
                                      boxShadow: '0 2px 5px rgba(0,0,0,0.04)',
                                    }}
                                  >
                                    {u.avatar ? (
                                      <img
                                        src={u.avatar}
                                        alt={u.name}
                                        style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                                      />
                                    ) : (
                                      initials
                                    )}
                                  </div>

                                  {/* Name and Role Info */}
                                  <div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '3px' }}>
                                      <span style={{ fontWeight: 800, fontSize: '15px', color: 'var(--text-primary)' }}>
                                        {u.name}
                                      </span>
                                      <CheckCircle2 size={14} color="#94a3b8" />
                                    </div>
                                    <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                                      <span style={{ color: 'var(--primary)', fontWeight: 700 }}>•</span>
                                      <span>{u.user_role === 'Admin' ? 'អ្នកគ្រប់គ្រង (Admin)' : 'បុគ្គលិក (Employee)'}</span>
                                      <span style={{ color: 'var(--text-muted)' }}>•</span>
                                      <span style={{ color: 'var(--text-secondary)' }}>{u.position || 'Staff'}</span>
                                    </div>
                                  </div>
                                </div>
                              </td>

                              {/* Status Badge + Dropdown */}
                              <td style={{ padding: '14px 18px', textAlign: 'center' }}>
                                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '6px' }}>
                                  <span
                                    style={{
                                      background: Number(u.is_active) !== 0 ? '#dcfce7' : '#fee2e2',
                                      color: Number(u.is_active) !== 0 ? '#16a34a' : '#dc2626',
                                      fontWeight: 700,
                                      fontSize: '11.5px',
                                      borderRadius: '9999px',
                                      padding: '3px 14px',
                                      display: 'inline-block',
                                    }}
                                  >
                                    {Number(u.is_active) !== 0 ? 'Active' : 'Inactive'}
                                  </span>
                                  <select
                                    className="form-control"
                                    value={Number(u.is_active) !== 0 ? 'Active' : 'Inactive'}
                                    onChange={(e) => {
                                      const active = e.target.value === 'Active' ? 1 : 0;
                                      setUsers(
                                        users.map((x) =>
                                          x.id === u.id ? { ...x, is_active: active } : x
                                        )
                                      );
                                    }}
                                    style={{
                                      padding: '4px 8px',
                                      fontSize: '12px',
                                      borderRadius: '8px',
                                      width: '100px',
                                      textAlign: 'center',
                                      borderColor: 'var(--border)',
                                    }}
                                  >
                                    <option value="Active">Active</option>
                                    <option value="Inactive">Inactive</option>
                                  </select>
                                </div>
                              </td>

                              {/* ថ្ងៃបញ្ចប់ការងារ (End Date Input) */}
                              <td style={{ padding: '14px 18px' }}>
                                <input
                                  type="date"
                                  className="form-control"
                                  defaultValue={u.contract_end || ''}
                                  style={{
                                    fontSize: '12.5px',
                                    padding: '6px 10px',
                                    borderRadius: '10px',
                                    width: '150px',
                                    borderColor: 'var(--border)',
                                  }}
                                />
                              </td>

                              {/* ACTIONS 3-Dots Menu */}
                              <td style={{ padding: '14px 18px', textAlign: 'center', position: 'relative' }}>
                                <div className="action-menu-container" style={{ display: 'inline-block', position: 'relative' }}>
                                  <button
                                    type="button"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setActiveMenuRowId(activeMenuRowId === u.id ? null : u.id);
                                    }}
                                    style={{
                                      width: '36px',
                                      height: '36px',
                                      borderRadius: '10px',
                                      border: '1px solid var(--border)',
                                      background: 'var(--surface)',
                                      display: 'flex',
                                      alignItems: 'center',
                                      justifyContent: 'center',
                                      color: 'var(--primary)',
                                      cursor: 'pointer',
                                      transition: 'all 0.15s ease',
                                    }}
                                    title="សកម្មភាព (Actions)"
                                  >
                                    <MoreVertical size={16} />
                                  </button>

                                  {/* Floating Dropdown Menu (Exact match to screenshot) */}
                                  {activeMenuRowId === u.id && (
                                    <div
                                      style={{
                                        position: 'absolute',
                                        right: 0,
                                        top: '42px',
                                        background: 'var(--surface)',
                                        border: '1px solid var(--border)',
                                        borderRadius: '14px',
                                        boxShadow: 'var(--shadow-lg)',
                                        minWidth: '185px',
                                        zIndex: 100,
                                        padding: '6px 0',
                                        textAlign: 'left',
                                        animation: 'scaleUp 0.18s cubic-bezier(0.16, 1, 0.3, 1)',
                                      }}
                                    >
                                      <button
                                        type="button"
                                        onClick={() => {
                                          handleTabChange('edit_rules', u.employee_id);
                                          setActiveMenuRowId(null);
                                        }}
                                        style={{
                                          display: 'flex',
                                          alignItems: 'center',
                                          gap: '10px',
                                          width: '100%',
                                          padding: '9px 16px',
                                          border: 'none',
                                          background: 'transparent',
                                          fontSize: '13px',
                                          color: 'var(--text-primary)',
                                          cursor: 'pointer',
                                          textAlign: 'left',
                                        }}
                                        onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-alt)')}
                                        onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                                      >
                                        <Clock size={15} color="var(--text-secondary)" />
                                        <span>Shift / Schedule</span>
                                      </button>

                                      <button
                                        type="button"
                                        onClick={() => openDuplicateModal(u)}
                                        style={{
                                          display: 'flex',
                                          alignItems: 'center',
                                          gap: '10px',
                                          width: '100%',
                                          padding: '9px 16px',
                                          border: 'none',
                                          background: 'transparent',
                                          fontSize: '13px',
                                          color: 'var(--text-primary)',
                                          cursor: 'pointer',
                                          textAlign: 'left',
                                        }}
                                        onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-alt)')}
                                        onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                                      >
                                        <Copy size={15} color="var(--text-secondary)" />
                                        <span>ចម្លង (Duplicate)</span>
                                      </button>

                                      <button
                                        type="button"
                                        onClick={() => openEditModal(u)}
                                        style={{
                                          display: 'flex',
                                          alignItems: 'center',
                                          gap: '10px',
                                          width: '100%',
                                          padding: '9px 16px',
                                          border: 'none',
                                          background: 'transparent',
                                          fontSize: '13px',
                                          color: 'var(--text-primary)',
                                          cursor: 'pointer',
                                          textAlign: 'left',
                                        }}
                                        onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-alt)')}
                                        onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                                      >
                                        <Edit2 size={15} color="var(--primary)" />
                                        <span>Edit Info</span>
                                      </button>

                                      <div style={{ height: '1px', background: 'var(--border)', margin: '4px 0' }} />

                                      <button
                                        type="button"
                                        onClick={() => handleDeleteUser(u.employee_id)}
                                        style={{
                                          display: 'flex',
                                          alignItems: 'center',
                                          gap: '10px',
                                          width: '100%',
                                          padding: '9px 16px',
                                          border: 'none',
                                          background: 'transparent',
                                          fontSize: '13px',
                                          color: 'var(--danger)',
                                          cursor: 'pointer',
                                          textAlign: 'left',
                                        }}
                                        onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--danger-light)')}
                                        onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                                      >
                                        <Trash2 size={15} color="var(--danger)" />
                                        <span>លុប (Delete)</span>
                                      </button>
                                    </div>
                                  )}
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </React.Fragment>
                    ))
                  )}
                </tbody>
              </table>
            </div>
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
      {/* 4. WORK RULES & SCHEDULE (Matching admin_attendance.php) */}
      {/* ======================================================== */}
      {activeTab === 'edit_rules' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%' }}>
          {/* Header Bar matching admin_attendance.php */}
          <div
            className="hrm-card"
            style={{
              padding: '18px 24px',
              borderRadius: '18px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '16px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <button
                type="button"
                onClick={() => handleTabChange('list_users')}
                className="btn btn-secondary"
                style={{
                  width: '42px',
                  height: '42px',
                  borderRadius: '12px',
                  padding: 0,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
                title="ត្រឡប់ក្រោយ (Back to Users)"
              >
                <ArrowLeft size={18} />
              </button>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <h2 style={{ fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <RotateCcw size={20} color="var(--primary)" />
                    <span>កំណត់ច្បាប់ម៉ោងចូល/ចេញ</span>
                  </h2>
                  <span
                    style={{
                      background: 'rgba(99, 102, 241, 0.12)',
                      color: 'var(--primary)',
                      fontSize: '12px',
                      fontWeight: 800,
                      padding: '3px 10px',
                      borderRadius: '8px',
                    }}
                  >
                    ID: {selectedRuleUserId || '0016'}
                  </span>
                </div>
                <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px', fontWeight: 600 }}>
                  បុគ្គលិក:{' '}
                  <strong style={{ color: 'var(--text-primary)' }}>
                    {users.find((u) => u.employee_id === selectedRuleUserId)?.name ||
                      (selectedRuleUserId === '0016' ? 'ខឿន ដានីន' : selectedRuleUserId)}
                  </strong>{' '}
                  • ផ្នែក: {users.find((u) => u.employee_id === selectedRuleUserId)?.department || 'Store 318'}
                </div>
              </div>
            </div>

            {/* Top Right Actions: User Switcher & Copy Rules */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              {/* Employee Selector */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-muted)' }}>ប្តូរបុគ្គលិក:</span>
                <select
                  className="form-control"
                  value={selectedRuleUserId}
                  onChange={(e) => {
                    setSelectedRuleUserId(e.target.value);
                    setSearchParams({ action: 'edit_rules', id: e.target.value });
                  }}
                  style={{ minWidth: '180px', padding: '7px 12px', fontSize: '12.5px', borderRadius: '10px' }}
                >
                  {users.map((u) => (
                    <option key={u.employee_id} value={u.employee_id}>
                      {u.employee_id} - {u.name}
                    </option>
                  ))}
                  {users.length === 0 && <option value="0016">0016 - ខឿន ដានីន</option>}
                </select>
              </div>

              <button
                type="button"
                onClick={() => {
                  setCopyFromUserId(users.find((u) => u.employee_id !== selectedRuleUserId)?.employee_id || '');
                  setIsCopyRulesModalOpen(true);
                }}
                className="btn btn-secondary btn-sm"
                style={{ borderRadius: '10px', padding: '8px 14px', fontWeight: 700 }}
              >
                <Copy size={14} />
                <span>ចម្លងពីអ្នកផ្សេង (Copy Rules)</span>
              </button>
            </div>
          </div>

          {/* Quick Presets Bar */}
          <div
            className="hrm-card"
            style={{
              padding: '12px 20px',
              borderRadius: '14px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '10px',
              background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.04), rgba(59, 130, 246, 0.04))',
              border: '1px dashed var(--border)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12.5px', color: 'var(--text-secondary)', fontWeight: 600 }}>
              <Sparkles size={16} color="var(--primary)" />
              <span>ម៉ោងគំរូទូទៅ (Presets):</span>
            </div>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <button
                type="button"
                onClick={() => applyPreset('standard')}
                className="btn btn-sm btn-secondary"
                style={{ borderRadius: '8px', fontSize: '12px', padding: '5px 12px' }}
              >
                🏢 ម៉ោងស្តង់ដារពេញម៉ោង (08:00 - 17:00)
              </button>
              <button
                type="button"
                onClick={() => applyPreset('morning')}
                className="btn btn-sm btn-secondary"
                style={{ borderRadius: '8px', fontSize: '12px', padding: '5px 12px' }}
              >
                ☀️ វេនព្រឹក (08:00 - 12:00)
              </button>
              <button
                type="button"
                onClick={() => applyPreset('afternoon')}
                className="btn btn-sm btn-secondary"
                style={{ borderRadius: '8px', fontSize: '12px', padding: '5px 12px' }}
              >
                🌆 វេនរសៀល (13:30 - 17:30)
              </button>
            </div>
          </div>

          {/* Success Banner */}
          {rulesSuccess && (
            <div
              style={{
                padding: '12px 18px',
                borderRadius: '12px',
                background: 'rgba(34, 197, 94, 0.12)',
                border: '1px solid rgba(34, 197, 94, 0.3)',
                color: '#15803d',
                fontSize: '13.5px',
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                animation: 'scaleUp 0.2s ease',
              }}
            >
              <CheckCircle2 size={18} color="#15803d" />
              <span>បានរក្សាទុកច្បាប់ម៉ោងចូល/ចេញដោយជោគជ័យ!</span>
            </div>
          )}

          {/* Main 2-Column Rules Cards */}
          <form onSubmit={handleSaveTimeRules}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '22px' }}>
              {/* Check-In Card */}
              <div
                className="hrm-card"
                style={{
                  padding: '22px',
                  borderRadius: '18px',
                  border: '1px solid var(--border)',
                  boxShadow: 'var(--shadow-sm)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '14px',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    paddingBottom: '12px',
                    borderBottom: '1px solid var(--border)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <div
                      style={{
                        width: '34px',
                        height: '34px',
                        borderRadius: '10px',
                        background: 'rgba(16, 185, 129, 0.12)',
                        color: '#10b981',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      <LogIn size={18} />
                    </div>
                    <h3 style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                      ច្បាប់ម៉ោងចូល (Check-In)
                    </h3>
                  </div>
                  <span style={{ fontSize: '12px', fontWeight: 700, color: '#10b981', background: 'rgba(16, 185, 129, 0.1)', padding: '2px 8px', borderRadius: '6px' }}>
                    {rules.filter((r) => r.type === 'checkin').length} ច្បាប់
                  </span>
                </div>

                {/* Rules Container */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {rules
                    .map((r, originalIdx) => ({ rule: r, idx: originalIdx }))
                    .filter((item) => item.rule.type === 'checkin')
                    .map(({ rule: r, idx }) => (
                      <div
                        key={idx}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '8px',
                          padding: '10px 14px',
                          borderRadius: '12px',
                          background: 'var(--surface-alt)',
                          border: '1px solid var(--border)',
                          flexWrap: 'wrap',
                        }}
                      >
                        {/* Start Time */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                          <Play size={12} color="#10b981" />
                          <input
                            type="time"
                            step="1"
                            value={r.start_time}
                            onChange={(e) => updateTimeRule(idx, 'start_time', e.target.value)}
                            className="form-control"
                            style={{ padding: '6px 8px', fontSize: '13px', borderRadius: '8px', width: '115px' }}
                            required
                          />
                        </div>

                        <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>→</span>

                        {/* End Time */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                          <Square size={12} color="#ef4444" />
                          <input
                            type="time"
                            step="1"
                            value={r.end_time}
                            onChange={(e) => updateTimeRule(idx, 'end_time', e.target.value)}
                            className="form-control"
                            style={{ padding: '6px 8px', fontSize: '13px', borderRadius: '8px', width: '115px' }}
                            required
                          />
                        </div>

                        {/* Status Select */}
                        <select
                          value={r.status}
                          onChange={(e) => updateTimeRule(idx, 'status', e.target.value as any)}
                          className="form-control"
                          style={{
                            padding: '6px 10px',
                            fontSize: '12.5px',
                            borderRadius: '8px',
                            flex: '1',
                            minWidth: '105px',
                            fontWeight: 700,
                            color:
                              r.status === 'Good'
                                ? '#15803d'
                                : r.status === 'Late'
                                ? '#b45309'
                                : '#b91c1c',
                            background:
                              r.status === 'Good'
                                ? 'rgba(34, 197, 94, 0.1)'
                                : r.status === 'Late'
                                ? 'rgba(245, 158, 11, 0.1)'
                                : 'rgba(239, 68, 68, 0.1)',
                          }}
                        >
                          <option value="Good">✅ Good</option>
                          <option value="Late">⚠️ Late</option>
                          <option value="Absent">❌ Absent</option>
                        </select>

                        {/* Delete button */}
                        <button
                          type="button"
                          onClick={() => removeTimeRule(idx)}
                          className="btn btn-secondary btn-sm"
                          style={{
                            width: '34px',
                            height: '34px',
                            padding: 0,
                            borderRadius: '8px',
                            color: '#ef4444',
                            borderColor: 'rgba(239, 68, 68, 0.2)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                          }}
                          title="លុបច្បាប់នេះ"
                        >
                          <Trash2 size={15} />
                        </button>
                      </div>
                    ))}

                  {rules.filter((r) => r.type === 'checkin').length === 0 && (
                    <div style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)', fontSize: '13px' }}>
                      មិនទាន់មានច្បាប់ Check-In នៅឡើយទេ
                    </div>
                  )}
                </div>

                {/* Add Check-in Rule button */}
                <button
                  type="button"
                  onClick={() => addTimeRule('checkin')}
                  className="btn btn-secondary"
                  style={{
                    width: '100%',
                    borderStyle: 'dashed',
                    padding: '12px',
                    fontWeight: 700,
                    borderRadius: '12px',
                    borderColor: 'var(--primary)',
                    color: 'var(--primary)',
                    marginTop: '4px',
                  }}
                >
                  <PlusCircle size={16} />
                  <span>+ បន្ថែមច្បាប់ Check-In</span>
                </button>
              </div>

              {/* Check-Out Card */}
              <div
                className="hrm-card"
                style={{
                  padding: '22px',
                  borderRadius: '18px',
                  border: '1px solid var(--border)',
                  boxShadow: 'var(--shadow-sm)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '14px',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    paddingBottom: '12px',
                    borderBottom: '1px solid var(--border)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <div
                      style={{
                        width: '34px',
                        height: '34px',
                        borderRadius: '10px',
                        background: 'rgba(239, 68, 68, 0.12)',
                        color: '#ef4444',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      <LogOut size={18} />
                    </div>
                    <h3 style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                      ច្បាប់ម៉ោងចេញ (Check-Out)
                    </h3>
                  </div>
                  <span style={{ fontSize: '12px', fontWeight: 700, color: '#ef4444', background: 'rgba(239, 68, 68, 0.1)', padding: '2px 8px', borderRadius: '6px' }}>
                    {rules.filter((r) => r.type === 'checkout').length} ច្បាប់
                  </span>
                </div>

                {/* Rules Container */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {rules
                    .map((r, originalIdx) => ({ rule: r, idx: originalIdx }))
                    .filter((item) => item.rule.type === 'checkout')
                    .map(({ rule: r, idx }) => (
                      <div
                        key={idx}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '8px',
                          padding: '10px 14px',
                          borderRadius: '12px',
                          background: 'var(--surface-alt)',
                          border: '1px solid var(--border)',
                          flexWrap: 'wrap',
                        }}
                      >
                        {/* Start Time */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                          <Play size={12} color="#10b981" />
                          <input
                            type="time"
                            step="1"
                            value={r.start_time}
                            onChange={(e) => updateTimeRule(idx, 'start_time', e.target.value)}
                            className="form-control"
                            style={{ padding: '6px 8px', fontSize: '13px', borderRadius: '8px', width: '115px' }}
                            required
                          />
                        </div>

                        <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>→</span>

                        {/* End Time */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                          <Square size={12} color="#ef4444" />
                          <input
                            type="time"
                            step="1"
                            value={r.end_time}
                            onChange={(e) => updateTimeRule(idx, 'end_time', e.target.value)}
                            className="form-control"
                            style={{ padding: '6px 8px', fontSize: '13px', borderRadius: '8px', width: '115px' }}
                            required
                          />
                        </div>

                        {/* Status Select */}
                        <select
                          value={r.status}
                          onChange={(e) => updateTimeRule(idx, 'status', e.target.value as any)}
                          className="form-control"
                          style={{
                            padding: '6px 10px',
                            fontSize: '12.5px',
                            borderRadius: '8px',
                            flex: '1',
                            minWidth: '105px',
                            fontWeight: 700,
                            color:
                              r.status === 'Good'
                                ? '#15803d'
                                : r.status === 'Late'
                                ? '#b45309'
                                : '#b91c1c',
                            background:
                              r.status === 'Good'
                                ? 'rgba(34, 197, 94, 0.1)'
                                : r.status === 'Late'
                                ? 'rgba(245, 158, 11, 0.1)'
                                : 'rgba(239, 68, 68, 0.1)',
                          }}
                        >
                          <option value="Good">✅ Good</option>
                          <option value="Late">⚠️ Late / Early</option>
                          <option value="Absent">❌ Absent</option>
                        </select>

                        {/* Delete button */}
                        <button
                          type="button"
                          onClick={() => removeTimeRule(idx)}
                          className="btn btn-secondary btn-sm"
                          style={{
                            width: '34px',
                            height: '34px',
                            padding: 0,
                            borderRadius: '8px',
                            color: '#ef4444',
                            borderColor: 'rgba(239, 68, 68, 0.2)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                          }}
                          title="លុបច្បាប់នេះ"
                        >
                          <Trash2 size={15} />
                        </button>
                      </div>
                    ))}

                  {rules.filter((r) => r.type === 'checkout').length === 0 && (
                    <div style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)', fontSize: '13px' }}>
                      មិនទាន់មានច្បាប់ Check-Out នៅឡើយទេ
                    </div>
                  )}
                </div>

                {/* Add Check-out Rule button */}
                <button
                  type="button"
                  onClick={() => addTimeRule('checkout')}
                  className="btn btn-secondary"
                  style={{
                    width: '100%',
                    borderStyle: 'dashed',
                    padding: '12px',
                    fontWeight: 700,
                    borderRadius: '12px',
                    borderColor: '#ef4444',
                    color: '#ef4444',
                    marginTop: '4px',
                  }}
                >
                  <PlusCircle size={16} />
                  <span>+ បន្ថែមច្បាប់ Check-Out</span>
                </button>
              </div>
            </div>

            {/* Bottom Action Footer matching admin_attendance.php */}
            <div
              style={{
                marginTop: '32px',
                borderTop: '1px solid var(--border)',
                paddingTop: '20px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '14px',
              }}
            >
              <button
                type="button"
                onClick={() => handleTabChange('list_users')}
                className="btn btn-secondary"
                style={{ padding: '12px 24px', borderRadius: '12px' }}
              >
                <ArrowLeft size={16} />
                <span>ត្រឡប់ក្រោយ (Back to Users)</span>
              </button>

              <button
                type="submit"
                disabled={rulesSaving}
                className="btn btn-primary"
                style={{
                  padding: '12px 36px',
                  borderRadius: '14px',
                  fontSize: '14.5px',
                  fontWeight: 800,
                  boxShadow: '0 8px 24px -6px rgba(99, 102, 241, 0.4)',
                }}
              >
                {rulesSaving ? (
                  <>
                    <RotateCw size={16} className="fa-spin" />
                    <span>កំពុងរក្សាទុក...</span>
                  </>
                ) : (
                  <>
                    <Save size={16} />
                    <span>រក្សាសិទ្ធិ និងច្បាប់ម៉ោង</span>
                  </>
                )}
              </button>
            </div>
          </form>
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

      {/* ======================================================== */}
      {/* 7. COPY RULES MODAL (Matching admin_attendance.php)      */}
      {/* ======================================================== */}
      {isCopyRulesModalOpen && (
        <Modal
          isOpen={isCopyRulesModalOpen}
          onClose={() => setIsCopyRulesModalOpen(false)}
          title="ចម្លងច្បាប់ម៉ោងពីបុគ្គលិកផ្សេង (Copy Work Rules)"
          maxWidth="500px"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div className="form-group">
              <label className="form-label">បុគ្គលិកប្រភព (Copy From Employee) *</label>
              <select
                className="form-control"
                value={copyFromUserId}
                onChange={(e) => setCopyFromUserId(e.target.value)}
                style={{ padding: '10px 14px', fontSize: '13px' }}
              >
                <option value="">-- ជ្រើសរើសបុគ្គលិកដើម្បីចម្លងច្បាប់ --</option>
                {users
                  .filter((u) => u.employee_id !== selectedRuleUserId)
                  .map((u) => (
                    <option key={u.employee_id} value={u.employee_id}>
                      {u.employee_id} - {u.name} ({u.department || 'Staff'})
                    </option>
                  ))}
              </select>
            </div>

            <div className="form-group">
              <label className="form-label">ចម្លងទៅកាន់បុគ្គលិក (Target Employee)</label>
              <input
                type="text"
                className="form-control"
                value={`${selectedRuleUserId} - ${users.find((u) => u.employee_id === selectedRuleUserId)?.name || selectedRuleUserId}`}
                readOnly
                style={{ background: 'var(--surface-alt)', fontWeight: 700 }}
              />
            </div>

            <div style={{ padding: '12px 14px', borderRadius: '10px', background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.25)', color: '#b45309', fontSize: '12px', lineHeight: 1.5 }}>
              ⚠️ ចំណាំ: ច្បាប់ម៉ោងចាស់របស់បុគ្គលិកគោលដៅ នឹងត្រូវជំនួសទាំងស្រុងដោយច្បាប់ម៉ោងថ្មីពីបុគ្គលិកប្រភព។
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px', borderTop: '1px solid var(--border)', paddingTop: '14px' }}>
              <button type="button" onClick={() => setIsCopyRulesModalOpen(false)} className="btn btn-secondary">
                បោះបង់
              </button>
              <button
                type="button"
                onClick={handleCopyTimeRules}
                disabled={rulesSaving || !copyFromUserId}
                className="btn btn-primary"
                style={{ padding: '10px 22px' }}
              >
                {rulesSaving ? <RotateCw size={15} className="fa-spin" /> : <Copy size={15} />}
                <span>ចម្លងច្បាប់ម៉ោងឥឡូវនេះ</span>
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
