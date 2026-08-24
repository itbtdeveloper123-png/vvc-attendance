import React, { useState, useEffect } from 'react';
import {
  Layers,
  Plus,
  Search,
  Trash2,
  Check,
  RotateCw,
  CheckCircle2,
  Users,
  GripVertical,
  Send,
  Save,
  MoreVertical,
  Info,
  AlertTriangle,
} from 'lucide-react';
import { adminApi, CategoryItem, GroupUserItem } from '../api/adminApi';

export const CategoriesPage: React.FC = () => {
  const [groups, setGroups] = useState<CategoryItem[]>([]);
  const [users, setUsers] = useState<GroupUserItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const [editingGroupNames, setEditingGroupNames] = useState<Record<number, string>>({});
  const [sortOrders, setSortOrders] = useState<Record<number, number>>({});

  // User Assignments State
  const [userSearch, setUserSearch] = useState('');
  const [selectedUserIds, setSelectedUserIds] = useState<string[]>([]);
  const [targetGroupId, setTargetGroupId] = useState<string>('none');
  const [openDropdownId, setOpenDropdownId] = useState<number | null>(null);

  // Banner
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const showBanner = (type: 'success' | 'error', text: string) => {
    setBanner({ type, text });
    setTimeout(() => setBanner(null), 3500);
  };

  const loadData = async () => {
    setLoading(true);
    try {
      const res = await adminApi.fetchCategories();
      if (res && (res.success || res.status === 'success')) {
        const groupList = Array.isArray(res.groups)
          ? res.groups
          : Array.isArray(res.categories)
          ? res.categories
          : Array.isArray(res.data)
          ? res.data
          : [];
        setGroups(groupList);

        const nameMap: Record<number, string> = {};
        const sortMap: Record<number, number> = {};
        groupList.forEach((g: CategoryItem) => {
          nameMap[g.id] = g.group_name || g.name || '';
          sortMap[g.id] = g.sort_order ?? 0;
        });
        setEditingGroupNames(nameMap);
        setSortOrders(sortMap);

        if (Array.isArray(res.users)) {
          setUsers(res.users);
        }
      }
    } catch (err) {
      console.error('Error fetching categories & skill groups:', err);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadData();
  }, []);

  // Add Group
  const handleAddGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newGroupName.trim()) {
      alert('សូមបញ្ចូលឈ្មោះក្រុមថ្មី!');
      return;
    }
    try {
      const res = await adminApi.saveCategory({ group_name: newGroupName, name: newGroupName });
      if (res && (res.success || res.status === 'success')) {
        showBanner('success', res.message || 'បានបង្កើតក្រុមថ្មីជោគជ័យ!');
        setNewGroupName('');
        loadData();
      } else {
        showBanner('error', res?.message || 'Error creating group');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការបង្កើតក្រុម');
    }
  };

  // Inline Rename Group
  const handleSaveGroupName = async (id: number) => {
    const updatedName = editingGroupNames[id];
    if (!updatedName || !updatedName.trim()) {
      alert('សូមបញ្ចូលឈ្មោះក្រុម!');
      return;
    }
    try {
      const res = await adminApi.saveCategory({ id, group_name: updatedName, name: updatedName, sort_order: sortOrders[id] });
      if (res && (res.success || res.status === 'success')) {
        showBanner('success', res.message || 'បានប្តូរឈ្មោះក្រុមជោគជ័យ!');
        loadData();
      } else {
        showBanner('error', res?.message || 'Error updating group');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការកែប្រែឈ្មោះក្រុម');
    }
  };

  // Delete Group
  const handleDeleteGroup = async (id: number, name: string) => {
    if (window.confirm(`តើអ្នកពិតជាចង់លុបក្រុម "${name}" នេះមែនទេ?`)) {
      try {
        const res = await adminApi.deleteCategory(id);
        if (res && (res.success || res.status === 'success')) {
          showBanner('success', res.message || 'បានលុបក្រុមរួចរាល់!');
          setOpenDropdownId(null);
          loadData();
        } else {
          showBanner('error', res?.message || 'Error deleting group');
        }
      } catch (err) {
        showBanner('error', 'កំហុសក្នុងការលុប');
      }
    }
  };

  // Update Sort Order
  const handleUpdateSortOrder = async () => {
    try {
      const orders = Object.entries(sortOrders).map(([idStr, sort]) => ({
        id: Number(idStr),
        sort: Number(sort),
      }));
      const res = await adminApi.updateGroupSort(orders);
      if (res && (res.success || res.status === 'success')) {
        showBanner('success', res.message || 'រក្សាទុកលំដាប់ជោគជ័យ!');
        loadData();
      } else {
        showBanner('error', res?.message || 'Error updating sort order');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការរក្សាទុកលំដាប់');
    }
  };

  // Filtered Users
  const filteredUsers = users.filter((u) => {
    const q = userSearch.toLowerCase();
    return (
      (u.name || '').toLowerCase().includes(q) ||
      (u.employee_id || '').toLowerCase().includes(q) ||
      (u.department || '').toLowerCase().includes(q)
    );
  });

  // Toggle Single User
  const toggleUserSelection = (empId: string) => {
    setSelectedUserIds((prev) =>
      prev.includes(empId) ? prev.filter((id) => id !== empId) : [...prev, empId]
    );
  };

  // Select All Users
  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      const allFilteredIds = filteredUsers.map((u) => u.employee_id);
      setSelectedUserIds(Array.from(new Set([...selectedUserIds, ...allFilteredIds])));
    } else {
      const filteredSet = new Set(filteredUsers.map((u) => u.employee_id));
      setSelectedUserIds(selectedUserIds.filter((id) => !filteredSet.has(id)));
    }
  };

  const isAllSelected =
    filteredUsers.length > 0 &&
    filteredUsers.every((u) => selectedUserIds.includes(u.employee_id));

  // Save Assignment (Move to Group or Remove)
  const handleSaveAssignment = async () => {
    if (selectedUserIds.length === 0) {
      alert('សូមជ្រើសរើសបុគ្គលិកយ៉ាងតិចម្នាក់!');
      return;
    }
    try {
      if (targetGroupId === 'none' || !targetGroupId) {
        const res = await adminApi.removeUsersFromGroup(selectedUserIds);
        if (res && (res.success || res.status === 'success')) {
          showBanner('success', res.message || 'បានដកបុគ្គលិកចេញពីក្រុមជោគជ័យ!');
          setSelectedUserIds([]);
          loadData();
        }
      } else {
        const res = await adminApi.assignUsersToGroup(selectedUserIds, Number(targetGroupId));
        if (res && (res.success || res.status === 'success')) {
          showBanner('success', res.message || 'បានកំណត់ក្រុមជូនបុគ្គលិកជោគជ័យ!');
          setSelectedUserIds([]);
          loadData();
        }
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការរក្សាទុកការផ្លាស់ប្តូរ');
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '26px', maxWidth: '1200px', margin: '0 auto', width: '100%' }}>
      {banner && (
        <div
          style={{
            padding: '12px 18px',
            borderRadius: '12px',
            background: banner.type === 'success' ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
            border: `1px solid ${banner.type === 'success' ? '#10b981' : '#ef4444'}`,
            color: banner.type === 'success' ? '#10b981' : '#ef4444',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '13.5px',
            fontWeight: 600,
          }}
        >
          <CheckCircle2 size={16} />
          <span>{banner.text}</span>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 1. SKILL GROUPS LIST (គ្រប់គ្រងក្រុមអ្នកប្រើប្រាស់)                            */}
      {/* ========================================================================= */}
      <div className="hrm-card" style={{ padding: '24px', borderRadius: '18px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px', flexWrap: 'wrap', gap: '10px' }}>
          <h3 style={{ fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Layers size={20} color="var(--primary)" />
            <span>គ្រប់គ្រងក្រុមអ្នកប្រើប្រាស់ (Skill Groups)</span>
          </h3>

          <button onClick={loadData} className="btn btn-secondary btn-sm" style={{ borderRadius: '10px' }}>
            <RotateCw size={13} className={loading ? 'fa-spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>

        <p style={{ color: 'var(--text-secondary)', fontSize: '13px', margin: '0 0 20px 0' }}>
          បង្កើតក្រុមជំនាញ ឬផ្នែកសម្រាប់បែងចែកបុគ្គលិក ដើម្បីងាយស្រួលក្នុងការគ្រប់គ្រង និងតាមដានវត្តមាន។
        </p>

        {/* Create Group Form */}
        <form
          onSubmit={handleAddGroup}
          style={{
            display: 'flex',
            gap: '12px',
            alignItems: 'flex-end',
            flexWrap: 'wrap',
            background: 'var(--surface-alt)',
            padding: '18px 20px',
            borderRadius: '14px',
            border: '1px dashed var(--border)',
            marginBottom: '22px',
          }}
        >
          <div style={{ flex: 1, minWidth: '260px' }}>
            <label style={{ fontWeight: 700, fontSize: '12.5px', color: 'var(--text-secondary)', marginBottom: '6px', display: 'block' }}>
              ឈ្មោះក្រុមថ្មី (NEW GROUP NAME):
            </label>
            <input
              type="text"
              className="form-input"
              value={newGroupName}
              onChange={(e) => setNewGroupName(e.target.value)}
              placeholder="ឧ. ផ្នែកគណនេយ្យ"
              required
              style={{ height: '42px', borderRadius: '10px' }}
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            style={{ height: '42px', padding: '0 24px', borderRadius: '10px', fontWeight: 700 }}
          >
            <Plus size={16} />
            <span>បង្កើតក្រុមថ្មី</span>
          </button>
        </form>

        {/* Groups Table Matching admin_attendance.php */}
        <div className="table-container" style={{ border: 'none', boxShadow: 'none' }}>
          <table className="hrm-table">
            <thead>
              <tr>
                <th style={{ width: '50px', textAlign: 'center' }}>DRAG</th>
                <th style={{ width: '110px', textAlign: 'center' }}>លំដាប់ (SORT)</th>
                <th>ឈ្មោះក្រុម (GROUP NAME)</th>
                <th style={{ width: '150px', textAlign: 'center' }}>ចំនួនបុគ្គលិក</th>
                <th style={{ width: '100px', textAlign: 'center' }}>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {groups.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                    {loading ? 'កំពុងទាញយកទិន្នន័យ...' : 'មិនទាន់មានក្រុមនៅឡើយទេ'}
                  </td>
                </tr>
              ) : (
                groups.map((gr) => {
                  const isMenuOpen = openDropdownId === gr.id;

                  return (
                    <tr key={gr.id}>
                      <td style={{ textAlign: 'center', color: 'var(--text-muted)', cursor: 'grab' }}>
                        <GripVertical size={16} />
                      </td>

                      <td style={{ textAlign: 'center' }}>
                        <input
                          type="number"
                          className="form-input"
                          value={sortOrders[gr.id] ?? 0}
                          onChange={(e) =>
                            setSortOrders({ ...sortOrders, [gr.id]: Number(e.target.value) })
                          }
                          style={{
                            height: '32px',
                            fontSize: '13px',
                            textAlign: 'center',
                            width: '70px',
                            margin: '0 auto',
                            padding: '0',
                            borderRadius: '8px',
                          }}
                        />
                      </td>

                      <td>
                        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                          <input
                            type="text"
                            className="form-input"
                            value={editingGroupNames[gr.id] ?? gr.group_name ?? gr.name}
                            onChange={(e) =>
                              setEditingGroupNames({ ...editingGroupNames, [gr.id]: e.target.value })
                            }
                            style={{ height: '36px', fontWeight: 700, fontSize: '13.5px', maxWidth: '400px' }}
                          />
                          <button
                            type="button"
                            onClick={() => handleSaveGroupName(gr.id)}
                            className="btn btn-secondary btn-sm"
                            style={{ padding: '6px 14px', borderRadius: '8px', fontSize: '11.5px', fontWeight: 700 }}
                          >
                            <Save size={12} />
                            <span>Save</span>
                          </button>
                        </div>
                      </td>

                      <td style={{ textAlign: 'center' }}>
                        <span
                          className="badge badge-good"
                          style={{ minWidth: '40px', justifyContent: 'center', fontSize: '13px', fontWeight: 800 }}
                        >
                          {gr.user_count ?? gr.item_count ?? 0}
                        </span>
                      </td>

                      <td style={{ textAlign: 'center', position: 'relative' }}>
                        <button
                          type="button"
                          onClick={() => setOpenDropdownId(isMenuOpen ? null : gr.id)}
                          className="btn btn-secondary btn-sm"
                          style={{ padding: '6px 10px', borderRadius: '8px' }}
                          title="Actions"
                        >
                          <MoreVertical size={14} />
                        </button>

                        {isMenuOpen && (
                          <div
                            style={{
                              position: 'absolute',
                              right: '10px',
                              top: '40px',
                              background: '#fff',
                              borderRadius: '10px',
                              boxShadow: '0 8px 24px rgba(0,0,0,0.15)',
                              border: '1px solid var(--border)',
                              zIndex: 100,
                              minWidth: '120px',
                              overflow: 'hidden',
                            }}
                          >
                            <button
                              type="button"
                              onClick={() => handleDeleteGroup(gr.id, gr.group_name || gr.name)}
                              style={{
                                width: '100%',
                                padding: '10px 14px',
                                border: 'none',
                                background: 'transparent',
                                color: '#ef4444',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '8px',
                                fontSize: '12.5px',
                                fontWeight: 700,
                                cursor: 'pointer',
                                textAlign: 'left',
                              }}
                            >
                              <Trash2 size={13} />
                              <span>Delete</span>
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Update Sort Button Bar */}
        <div
          style={{
            marginTop: '16px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            background: 'var(--surface-alt)',
            padding: '12px 20px',
            borderRadius: '12px',
            flexWrap: 'wrap',
            gap: '12px',
          }}
        >
          <span style={{ color: 'var(--text-secondary)', fontSize: '12.5px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Info size={14} />
            <span>អូសជួរដេកដើម្បីរៀបលំដាប់រូបភាព ឬកែប្រែលំដាប់ដោយផ្ទាល់</span>
          </span>

          <button
            type="button"
            onClick={handleUpdateSortOrder}
            className="btn btn-primary"
            style={{ padding: '8px 22px', fontSize: '13px', borderRadius: '10px', fontWeight: 700 }}
          >
            <Save size={14} />
            <span>រក្សាទុកលំដាប់ (Update Order)</span>
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 2. USER ASSIGNMENTS TO GROUPS (កំណត់បុគ្គលិកទៅកាន់ក្រុម)                   */}
      {/* ========================================================================= */}
      <div className="hrm-card" style={{ padding: '24px', borderRadius: '18px' }}>
        <div style={{ marginBottom: '18px' }}>
          <h3 style={{ fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Users size={20} color="var(--primary)" />
            <span>កំណត់បុគ្គលិកទៅកាន់ក្រុម (User Assignments)</span>
          </h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '13px', margin: '4px 0 0 0' }}>
            ជ្រើសរើសបុគ្គលិកមួយ ឬច្រើន ដើម្បីប្តូរក្រុម ឬដកចេញពីក្រុម។
          </p>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 340px',
            gap: '24px',
            alignItems: 'start',
          }}
        >
          {/* Left Column: Employee List matching admin_attendance.php */}
          <div
            style={{
              background: '#fff',
              border: '1px solid var(--border)',
              borderRadius: '16px',
              overflow: 'hidden',
              display: 'flex',
              flexDirection: 'column',
              minHeight: '480px',
            }}
          >
            {/* Header / Filter Toolbar */}
            <div
              style={{
                padding: '16px 20px',
                background: 'var(--surface-alt)',
                borderBottom: '1px solid var(--border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '12px',
              }}
            >
              <h4 style={{ margin: 0, fontSize: '14px', fontWeight: 800, color: 'var(--text-primary)' }}>
                បញ្ជីវត្តមានបុគ្គលិក ({filteredUsers.length})
              </h4>

              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    background: '#fff',
                    border: '1px solid var(--border)',
                    borderRadius: '10px',
                    padding: '6px 12px',
                    width: '220px',
                    gap: '6px',
                  }}
                >
                  <Search size={14} color="var(--text-muted)" />
                  <input
                    type="text"
                    placeholder="ស្វែងរកឈ្មោះ ឬ ID..."
                    value={userSearch}
                    onChange={(e) => setUserSearch(e.target.value)}
                    style={{
                      background: 'transparent',
                      border: 'none',
                      outline: 'none',
                      fontSize: '12.5px',
                      color: 'var(--text-primary)',
                      width: '100%',
                    }}
                  />
                </div>

                <label
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    fontWeight: 700,
                    fontSize: '12.5px',
                    cursor: 'pointer',
                    color: 'var(--primary)',
                    background: 'var(--primary-light)',
                    padding: '7px 14px',
                    borderRadius: '8px',
                    userSelect: 'none',
                  }}
                >
                  <input
                    type="checkbox"
                    checked={isAllSelected}
                    onChange={(e) => handleSelectAll(e.target.checked)}
                    style={{ cursor: 'pointer' }}
                  />
                  <span>ជ្រើសរើសទាំងអស់</span>
                </label>
              </div>
            </div>

            {/* Employee Cards Grid (3 columns matching admin_attendance.php) */}
            <div
              style={{
                flex: 1,
                overflowY: 'auto',
                padding: '20px',
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
                gap: '12px',
                maxHeight: '520px',
              }}
            >
              {filteredUsers.length === 0 ? (
                <div style={{ gridColumn: '1/-1', textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                  {loading ? 'កំពុងទាញយកទិន្នន័យបុគ្គលិក...' : 'រកមិនឃើញបុគ្គលិកឡើយ'}
                </div>
              ) : (
                filteredUsers.map((u) => {
                  const isSelected = selectedUserIds.includes(u.employee_id);
                  const initials = (u.name || u.employee_id).substring(0, 2).toUpperCase();

                  return (
                    <div
                      key={u.employee_id}
                      onClick={() => toggleUserSelection(u.employee_id)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '10px',
                        padding: '10px 12px',
                        border: isSelected ? '2px solid var(--primary)' : '1px solid var(--border)',
                        background: isSelected ? 'var(--primary-light)' : '#fff',
                        borderRadius: '14px',
                        cursor: 'pointer',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => {}} // handled by container onClick
                        style={{ cursor: 'pointer', accentColor: 'var(--primary)', width: '16px', height: '16px' }}
                      />

                      <div
                        style={{
                          width: '38px',
                          height: '38px',
                          borderRadius: '10px',
                          background: u.avatar ? 'transparent' : '#3b82f6',
                          color: '#fff',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontWeight: 800,
                          fontSize: '13px',
                          flexShrink: 0,
                          overflow: 'hidden',
                          border: '1px solid rgba(0,0,0,0.06)',
                        }}
                      >
                        {u.avatar ? (
                          <img src={u.avatar} alt="" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                        ) : (
                          initials
                        )}
                      </div>

                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div style={{ fontSize: '13px', fontWeight: 800, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {u.name}
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                          #{u.employee_id}
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Right Column: Actions matching admin_attendance.php */}
          <div
            style={{
              background: 'var(--surface-alt)',
              border: '1px solid var(--border)',
              borderRadius: '16px',
              padding: '24px',
              display: 'flex',
              flexDirection: 'column',
              gap: '18px',
              position: 'sticky',
              top: '20px',
            }}
          >
            <div>
              <h4 style={{ margin: '0 0 6px 0', fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Send size={16} color="var(--primary)" />
                <span>ប្តូរទៅក្រុមថ្មី</span>
              </h4>
              <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--text-secondary)' }}>
                បានជ្រើសរើសបុគ្គលិក៖ <strong style={{ color: 'var(--primary)' }}>{selectedUserIds.length} នាក់</strong>
              </p>
            </div>

            {/* Target Group Selector */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <label style={{ fontSize: '12.5px', fontWeight: 700, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Layers size={14} color="var(--primary)" />
                <span>ជ្រើសរើសក្រុមគោលដៅ:</span>
              </label>

              <select
                className="form-control"
                value={targetGroupId}
                onChange={(e) => setTargetGroupId(e.target.value)}
                style={{ height: '42px', borderRadius: '10px', fontSize: '13px', background: '#fff' }}
              >
                <option value="none">— ដកចេញពីក្រុម (Remove) —</option>
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.group_name || g.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Notification / Note Alert Box */}
            <div
              style={{
                padding: '14px',
                borderRadius: '12px',
                background: 'rgba(245, 158, 11, 0.1)',
                border: '1px dashed #f59e0b',
                color: '#b45309',
                fontSize: '12px',
                lineHeight: '1.5',
                display: 'flex',
                alignItems: 'flex-start',
                gap: '8px',
              }}
            >
              <AlertTriangle size={16} style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <strong>បញ្ជាក់:</strong> ការកំណត់នេះនឹងជំនួសក្រុមចាស់របស់បុគ្គលិកដែលបានជ្រើសរើស។ បុគ្គលិកដែលមិនមានក្រុម រូបភាពផ្ទាំងការបោះឆ្នោតនឹងមិនបង្ហាញឡើយ។
              </div>
            </div>

            {/* Save Button */}
            <button
              type="button"
              onClick={handleSaveAssignment}
              disabled={selectedUserIds.length === 0}
              className="btn btn-primary"
              style={{
                width: '100%',
                height: '44px',
                borderRadius: '10px',
                fontSize: '13.5px',
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
              }}
            >
              <Save size={15} />
              <span>រក្សាទុកការផ្លាស់ប្តូរ</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
