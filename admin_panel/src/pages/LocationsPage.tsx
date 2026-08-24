import React, { useState, useEffect, useRef } from 'react';
import {
  MapPin,
  QrCode,
  Plus,
  Download,
  Edit2,
  Trash2,
  Check,
  RotateCw,
  Search,
  Users,
  Compass,
  Layers,
  Table as TableIcon,
  LayoutGrid,
  ExternalLink,
  Printer,
  Sparkles,
  UserCheck,
  Building2,
  Unlink,
  Navigation,
  Globe,
  Sliders,
  X,
  Palette
} from 'lucide-react';
import { Modal } from '../components/common/Modal';
import {
  adminApi,
  LocationItem,
  UserLocationAssignment,
  NotificationRecipientUser
} from '../api/adminApi';

export const LocationsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'list' | 'create' | 'assign' | 'assignments'>('list');

  // Locations state
  const [locations, setLocations] = useState<LocationItem[]>([]);
  const [loadingLocations, setLoadingLocations] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [viewMode, setViewMode] = useState<'grid' | 'table'>('grid');

  // Modals
  const [editModalLoc, setEditModalLoc] = useState<LocationItem | null>(null);
  const [qrModalLoc, setQrModalLoc] = useState<LocationItem | null>(null);
  const [qrDesignerLoc, setQrDesignerLoc] = useState<LocationItem | null>(null);

  // QR Designer customization state
  const [qrColor, setQrColor] = useState('#0f172a');
  const [qrBgColor, setQrBgColor] = useState('#ffffff');
  const [qrTitle, setQrTitle] = useState('');
  const [qrSubtitle, setQrSubtitle] = useState('ស្កេនដើម្បីកត់ត្រាវត្តមាន (Check-In / Out)');
  const [qrSize, setQrSize] = useState(300);

  // Create/Edit Location form state
  const [locFormData, setLocFormData] = useState({
    id: 0,
    name: '',
    address: '',
    latitude: 11.5564,
    longitude: 104.9282,
    radius_meters: 100,
    qr_secret: '',
  });
  const [gettingGPS, setGettingGPS] = useState(false);
  const [savingLoc, setSavingLoc] = useState(false);
  const [locSuccess, setLocSuccess] = useState(false);

  // Employee Assignment state
  const [usersList, setUsersList] = useState<NotificationRecipientUser[]>([]);
  const [selectedUserIds, setSelectedUserIds] = useState<string[]>([]);
  const [selectedLocationIds, setSelectedLocationIds] = useState<number[]>([]);
  const [assignRadius, setAssignRadius] = useState<number>(100);
  const [userSearchTerm, setUserSearchTerm] = useState('');
  const [userDeptFilter, setUserDeptFilter] = useState('ALL');
  const [savingAssign, setSavingAssign] = useState(false);
  const [assignSuccess, setAssignSuccess] = useState(false);

  // Assignments List state
  const [assignments, setAssignments] = useState<UserLocationAssignment[]>([]);
  const [loadingAssignments, setLoadingAssignments] = useState(false);
  const [assignmentSearch, setAssignmentSearch] = useState('');

  // Load All Data
  const loadLocations = async () => {
    setLoadingLocations(true);
    try {
      const res = await adminApi.fetchLocations();
      if (res && res.success && Array.isArray(res.locations)) {
        setLocations(res.locations);
      }
    } catch (err) {
      console.error('Error fetching locations:', err);
    }
    setLoadingLocations(false);
  };

  const loadAssignments = async () => {
    setLoadingAssignments(true);
    try {
      const res = await adminApi.fetchUserLocations();
      if (res && res.success && Array.isArray(res.assignments || res.data)) {
        setAssignments(res.assignments || res.data);
      }
    } catch (err) {
      console.error('Error fetching assignments:', err);
    }
    setLoadingAssignments(false);
  };

  const loadMeta = async () => {
    try {
      const res = await adminApi.fetchLocationsMeta();
      if (res && res.success && Array.isArray(res.users)) {
        setUsersList(res.users);
      }
    } catch (err) {
      console.error('Error fetching meta:', err);
    }
  };

  useEffect(() => {
    loadLocations();
    loadAssignments();
    loadMeta();
  }, []);

  // Browser Geolocation Helper
  const handleGetCurrentGPS = () => {
    if (!navigator.geolocation) {
      alert('កម្មវិធីរុករក (Browser) របស់អ្នកមិនគាំទ្រ Geolocation ឡើយ');
      return;
    }
    setGettingGPS(true);
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setLocFormData((prev) => ({
          ...prev,
          latitude: parseFloat(pos.coords.latitude.toFixed(8)),
          longitude: parseFloat(pos.coords.longitude.toFixed(8)),
        }));
        setGettingGPS(false);
      },
      (err) => {
        alert(`មិនអាចទាញយក GPS បានទេ: ${err.message}`);
        setGettingGPS(false);
      },
      { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
    );
  };

  // Submit Create/Edit Location
  const handleSaveLocation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!locFormData.name.trim()) {
      alert('សូមបញ្ចូលឈ្មោះទីតាំង!');
      return;
    }

    setSavingLoc(true);
    try {
      const payload = {
        ...locFormData,
        qr_secret: locFormData.qr_secret || `vvc_loc_${Math.floor(1000 + Math.random() * 9000)}_qr`
      };
      const res = await adminApi.saveLocation(payload);
      if (res && (res.success || res.status === 'success')) {
        setLocSuccess(true);
        loadLocations();
        setEditModalLoc(null);
        if (activeTab === 'create') {
          setTimeout(() => {
            setLocSuccess(false);
            setActiveTab('list');
          }, 1500);
        }
      } else {
        alert(res.message || 'កំហុសក្នុងការរក្សាទុកទីតាំង');
      }
    } catch (err: any) {
      alert(err?.message || 'កំហុសក្នុងការតភ្ជាប់ទៅកាន់ Server');
    }
    setSavingLoc(false);
  };

  const handleOpenEditModal = (loc: LocationItem) => {
    setLocFormData({
      id: loc.id,
      name: loc.name || loc.location_name || '',
      address: loc.address || '',
      latitude: Number(loc.latitude) || 11.5564,
      longitude: Number(loc.longitude) || 104.9282,
      radius_meters: Number(loc.radius_meters) || 100,
      qr_secret: loc.qr_secret || '',
    });
    setEditModalLoc(loc);
  };

  const handleDeleteLocation = async (id: number, name: string) => {
    if (window.confirm(`តើអ្នកពិតជាចង់លុបទីតាំង "${name}" នេះមែនទេ? សកម្មភាពនេះនឹងលុបការកំណត់បុគ្គលិកទាំងអស់ក្នុងទីតាំងនេះផងដែរ។`)) {
      try {
        await adminApi.deleteLocation(id);
        loadLocations();
        loadAssignments();
      } catch (err) {
        alert('កំហុសក្នុងការលុប');
      }
    }
  };

  // Assign Employees to Locations
  const handleToggleSelectUser = (empId: string) => {
    setSelectedUserIds((prev) =>
      prev.includes(empId) ? prev.filter((id) => id !== empId) : [...prev, empId]
    );
  };

  const handleToggleSelectLocation = (locId: number) => {
    setSelectedLocationIds((prev) =>
      prev.includes(locId) ? prev.filter((id) => id !== locId) : [...prev, locId]
    );
  };

  const handleSelectAllFilteredUsers = () => {
    if (selectedUserIds.length === filteredUsers.length) {
      setSelectedUserIds([]);
    } else {
      setSelectedUserIds(filteredUsers.map((u) => u.employee_id));
    }
  };

  const handleSaveAssignment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (selectedUserIds.length === 0) {
      alert('សូមជ្រើសរើសបុគ្គលិកយ៉ាងហោចណាស់ម្នាក់!');
      return;
    }
    if (selectedLocationIds.length === 0) {
      alert('សូមជ្រើសរើសទីតាំងយ៉ាងហោចណាស់មួយ!');
      return;
    }

    setSavingAssign(true);
    setAssignSuccess(false);
    try {
      const res = await adminApi.assignUserLocation({
        employee_ids: selectedUserIds,
        location_ids: selectedLocationIds,
        custom_radius_meters: assignRadius,
      });
      if (res && (res.success || res.status === 'success')) {
        setAssignSuccess(true);
        setSelectedUserIds([]);
        setSelectedLocationIds([]);
        loadAssignments();
        loadLocations();
        setTimeout(() => {
          setAssignSuccess(false);
          setActiveTab('assignments');
        }, 1500);
      } else {
        alert(res.message || 'កំហុសក្នុងការកំណត់ទីតាំង');
      }
    } catch (err: any) {
      alert(err?.message || 'កំហុសក្នុងការតភ្ជាប់ទៅកាន់ Server');
    }
    setSavingAssign(false);
  };

  const handleUnassign = async (assignId: number, userName: string, locName: string) => {
    if (window.confirm(`តើអ្នកពិតជាចង់ដកទីតាំង "${locName}" ចេញពីបុគ្គលិក "${userName}" មែនទេ?`)) {
      try {
        await adminApi.unassignUserLocation(assignId);
        loadAssignments();
        loadLocations();
      } catch (err) {
        alert('កំហុសក្នុងការដកទីតាំង');
      }
    }
  };

  // Open QR Designer
  const handleOpenQrDesigner = (loc: LocationItem) => {
    setQrDesignerLoc(loc);
    setQrTitle(loc.name || loc.location_name || 'VVC Branch');
    setQrSubtitle('ស្កេនដើម្បីកត់ត្រាវត្តមាន (Check-In / Out)');
  };

  // Filter Locations
  const filteredLocations = locations.filter((loc) => {
    const s = searchTerm.toLowerCase();
    const name = (loc.name || loc.location_name || '').toLowerCase();
    const addr = (loc.address || '').toLowerCase();
    return !searchTerm || name.includes(s) || addr.includes(s);
  });

  // Filter Users
  const distinctDepartments = Array.from(new Set(usersList.map((u) => u.department).filter(Boolean))) as string[];
  const filteredUsers = usersList.filter((u) => {
    const s = userSearchTerm.toLowerCase();
    const matchesSearch = !userSearchTerm || u.name.toLowerCase().includes(s) || u.employee_id.toLowerCase().includes(s);
    const matchesDept = userDeptFilter === 'ALL' || u.department === userDeptFilter;
    return matchesSearch && matchesDept;
  });

  // Filter Assignments
  const filteredAssignments = assignments.filter((a) => {
    const s = assignmentSearch.toLowerCase();
    const uName = (a.user_name || '').toLowerCase();
    const empId = (a.employee_id || '').toLowerCase();
    const locName = (a.location_name || '').toLowerCase();
    return !assignmentSearch || uName.includes(s) || empId.includes(s) || locName.includes(s);
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
      {/* Page Header */}
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
              <MapPin size={20} />
            </span>
            <h2 style={{ fontSize: '22px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              ទីតាំង & QR Codes (Locations & QR Codes)
            </h2>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0 }}>
            កំណត់កូអរដោនេ GPS កាំស្កេន (Radius) បង្កើត QR Code តុបតែង QR (Designer) និងកំណត់ទីតាំងសម្រាប់បុគ្គលិក
          </p>
        </div>

        {/* 4 Navigation Tabs */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'var(--surface-subtle, #f1f5f9)', padding: '6px', borderRadius: '14px', flexWrap: 'wrap' }}>
          <button
            type="button"
            onClick={() => setActiveTab('list')}
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
              background: activeTab === 'list' ? '#fff' : 'transparent',
              color: activeTab === 'list' ? 'var(--primary)' : 'var(--text-secondary)',
              boxShadow: activeTab === 'list' ? '0 4px 12px rgba(0,0,0,0.06)' : 'none',
            }}
          >
            <Layers size={15} />
            <span>បញ្ជីទីតាំង ({locations.length})</span>
          </button>

          <button
            type="button"
            onClick={() => {
              setLocFormData({
                id: 0,
                name: '',
                address: '',
                latitude: 11.5564,
                longitude: 104.9282,
                radius_meters: 100,
                qr_secret: `vvc_loc_${Math.floor(1000 + Math.random() * 9000)}_qr`,
              });
              setActiveTab('create');
            }}
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
              background: activeTab === 'create' ? 'var(--primary)' : 'transparent',
              color: activeTab === 'create' ? '#fff' : 'var(--text-secondary)',
              boxShadow: activeTab === 'create' ? '0 4px 12px rgba(99, 102, 241, 0.28)' : 'none',
            }}
          >
            <Plus size={15} />
            <span>បង្កើតទីតាំងថ្មី (Create)</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('assign')}
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
              background: activeTab === 'assign' ? '#fff' : 'transparent',
              color: activeTab === 'assign' ? 'var(--primary)' : 'var(--text-secondary)',
              boxShadow: activeTab === 'assign' ? '0 4px 12px rgba(0,0,0,0.06)' : 'none',
            }}
          >
            <UserCheck size={15} />
            <span>កំណត់សម្រាប់បុគ្គលិក (Assign)</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('assignments')}
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
              background: activeTab === 'assignments' ? '#fff' : 'transparent',
              color: activeTab === 'assignments' ? 'var(--primary)' : 'var(--text-secondary)',
              boxShadow: activeTab === 'assignments' ? '0 4px 12px rgba(0,0,0,0.06)' : 'none',
            }}
          >
            <Users size={15} />
            <span>បញ្ជីកំណត់បុគ្គលិក ({assignments.length})</span>
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: LOCATIONS LIST & QR                                                */}
      {/* ========================================================================= */}
      {activeTab === 'list' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Toolbar: Search, View Switch, Refresh */}
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
            <div style={{ position: 'relative', flex: 1, minWidth: '240px' }}>
              <Search size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                type="text"
                className="form-input"
                placeholder="ស្វែងរកឈ្មោះទីតាំង ឬអាសយដ្ឋាន..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{ paddingLeft: '38px', borderRadius: '12px' }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ display: 'flex', background: 'var(--surface-subtle, #f1f5f9)', padding: '4px', borderRadius: '10px' }}>
                <button
                  type="button"
                  onClick={() => setViewMode('grid')}
                  style={{
                    padding: '6px 10px',
                    borderRadius: '8px',
                    border: 'none',
                    background: viewMode === 'grid' ? '#fff' : 'transparent',
                    color: viewMode === 'grid' ? 'var(--primary)' : 'var(--text-muted)',
                    cursor: 'pointer',
                    boxShadow: viewMode === 'grid' ? '0 2px 6px rgba(0,0,0,0.06)' : 'none',
                  }}
                  title="Grid View"
                >
                  <LayoutGrid size={16} />
                </button>
                <button
                  type="button"
                  onClick={() => setViewMode('table')}
                  style={{
                    padding: '6px 10px',
                    borderRadius: '8px',
                    border: 'none',
                    background: viewMode === 'table' ? '#fff' : 'transparent',
                    color: viewMode === 'table' ? 'var(--primary)' : 'var(--text-muted)',
                    cursor: 'pointer',
                    boxShadow: viewMode === 'table' ? '0 2px 6px rgba(0,0,0,0.06)' : 'none',
                  }}
                  title="Table View"
                >
                  <TableIcon size={16} />
                </button>
              </div>

              <button
                type="button"
                onClick={loadLocations}
                className="btn btn-secondary"
                style={{ borderRadius: '12px' }}
              >
                <RotateCw size={14} className={loadingLocations ? 'fa-spin' : ''} />
                <span>ផ្ទុកឡើងវិញ</span>
              </button>
            </div>
          </div>

          {/* Grid Mode */}
          {viewMode === 'grid' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(330px, 1fr))', gap: '20px' }}>
              {loadingLocations ? (
                <div className="hrm-card" style={{ gridColumn: '1/-1', padding: '50px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <RotateCw size={28} className="fa-spin" style={{ margin: '0 auto 12px auto', display: 'block', color: 'var(--primary)' }} />
                  <div>កំពុងទាញយកទិន្នន័យទីតាំង...</div>
                </div>
              ) : filteredLocations.length === 0 ? (
                <div className="hrm-card" style={{ gridColumn: '1/-1', padding: '50px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <MapPin size={40} style={{ margin: '0 auto 12px auto', display: 'block', opacity: 0.3 }} />
                  <div style={{ fontWeight: 700, fontSize: '15px', color: 'var(--text-primary)' }}>មិនមានទិន្នន័យទីតាំងឡើយ</div>
                  <p style={{ fontSize: '13px', marginTop: '4px' }}>ចុចលើ "បង្កើតទីតាំងថ្មី" ដើម្បីបន្ថែមសាខា ឬទីតាំងដំបូង</p>
                </div>
              ) : (
                filteredLocations.map((loc) => {
                  const qrDataStr = JSON.stringify({ location_id: loc.id, secret: loc.qr_secret });
                  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(qrDataStr)}`;
                  const mapsUrl = `https://www.google.com/maps?q=${loc.latitude},${loc.longitude}`;

                  return (
                    <div
                      key={loc.id}
                      className="hrm-card hover-lift"
                      style={{
                        padding: '22px',
                        display: 'flex',
                        flexDirection: 'column',
                        justifyContent: 'space-between',
                        borderRadius: '18px',
                        border: '1px solid #e2e8f0',
                      }}
                    >
                      <div>
                        {/* Card Top: Icon & Actions */}
                        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '14px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                            <div
                              style={{
                                width: '44px',
                                height: '44px',
                                borderRadius: '12px',
                                background: 'linear-gradient(135deg, #e0e7ff, #ede9fe)',
                                color: '#4f46e5',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                flexShrink: 0,
                              }}
                            >
                              <MapPin size={22} />
                            </div>
                            <div>
                              <h3 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                                {loc.name || loc.location_name}
                              </h3>
                              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                                ID: #{loc.id}
                              </span>
                            </div>
                          </div>

                          <div style={{ display: 'flex', gap: '4px' }}>
                            <button
                              type="button"
                              onClick={() => handleOpenEditModal(loc)}
                              className="btn btn-secondary btn-sm"
                              title="កែប្រែ"
                            >
                              <Edit2 size={13} />
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDeleteLocation(loc.id, loc.name || loc.location_name || '')}
                              className="btn btn-danger btn-sm"
                              title="លុប"
                            >
                              <Trash2 size={13} />
                            </button>
                          </div>
                        </div>

                        {/* Address */}
                        <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '14px', lineHeight: 1.5 }}>
                          {loc.address || 'មិនមានអាសយដ្ឋានជាក់លាក់'}
                        </div>

                        {/* Badges & GPS */}
                        <div style={{ background: '#f8fafc', padding: '12px 14px', borderRadius: '12px', border: '1px solid #e2e8f0', display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '16px', fontSize: '12px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                            <span style={{ color: 'var(--text-muted)' }}>📍 GPS Coordinates:</span>
                            <a
                              href={mapsUrl}
                              target="_blank"
                              rel="noreferrer"
                              style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: 'var(--primary)', fontWeight: 700, textDecoration: 'none' }}
                            >
                              <code>{loc.latitude}, {loc.longitude}</code>
                              <ExternalLink size={11} />
                            </a>
                          </div>

                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                            <span style={{ color: 'var(--text-muted)' }}>🎯 កាំស្កេន (Radius):</span>
                            <span className="badge badge-primary" style={{ fontSize: '11px' }}>
                              {loc.radius_meters} ម៉ែត្រ
                            </span>
                          </div>

                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                            <span style={{ color: 'var(--text-muted)' }}>👥 បុគ្គលិកដែលបានកំណត់:</span>
                            <span style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
                              {loc.assigned_employees_count || 0} នាក់
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Card Footer: QR Actions */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', paddingTop: '12px', borderTop: '1px solid #f1f5f9' }}>
                        <button
                          type="button"
                          onClick={() => setQrModalLoc(loc)}
                          className="btn btn-secondary btn-sm"
                          style={{ flex: 1, borderRadius: '8px', justifyContent: 'center' }}
                        >
                          <QrCode size={14} />
                          <span>មើល QR</span>
                        </button>

                        <button
                          type="button"
                          onClick={() => handleOpenQrDesigner(loc)}
                          className="btn btn-gold btn-sm"
                          style={{ flex: 1, borderRadius: '8px', justifyContent: 'center' }}
                        >
                          <Sparkles size={14} />
                          <span>QR Designer</span>
                        </button>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          )}

          {/* Table Mode */}
          {viewMode === 'table' && (
            <div className="hrm-card" style={{ padding: 0, overflow: 'hidden' }}>
              <div className="table-container">
                <table className="hrm-table">
                  <thead>
                    <tr>
                      <th style={{ width: '60px' }}>ID</th>
                      <th>ទីតាំង / សាខា</th>
                      <th>អាសយដ្ឋាន</th>
                      <th>GPS (Lat, Lng)</th>
                      <th>កាំស្កេន (Radius)</th>
                      <th>បុគ្គលិកកំណត់</th>
                      <th style={{ textAlign: 'center' }}>QR Code</th>
                      <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
                    </tr>
                  </thead>
                  <tbody>
                    {loadingLocations ? (
                      <tr><td colSpan={8} style={{ textAlign: 'center', padding: '30px' }}>កំពុងទាញយកទិន្នន័យ...</td></tr>
                    ) : filteredLocations.length === 0 ? (
                      <tr><td colSpan={8} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>មិនមានទីតាំងឡើយ</td></tr>
                    ) : (
                      filteredLocations.map((loc) => {
                        const qrDataStr = JSON.stringify({ location_id: loc.id, secret: loc.qr_secret });
                        const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=100x100&data=${encodeURIComponent(qrDataStr)}`;

                        return (
                          <tr key={loc.id}>
                            <td style={{ fontWeight: 700, color: 'var(--text-muted)' }}>#{loc.id}</td>
                            <td>
                              <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{loc.name || loc.location_name}</div>
                            </td>
                            <td style={{ fontSize: '12px', color: 'var(--text-secondary)', maxWidth: '240px' }}>
                              {loc.address || '—'}
                            </td>
                            <td>
                              <a
                                href={`https://www.google.com/maps?q=${loc.latitude},${loc.longitude}`}
                                target="_blank"
                                rel="noreferrer"
                                style={{ fontFamily: 'monospace', fontSize: '11px', color: 'var(--primary)', textDecoration: 'none' }}
                              >
                                {loc.latitude}, {loc.longitude}
                              </a>
                            </td>
                            <td>
                              <span className="badge badge-primary">{loc.radius_meters}m</span>
                            </td>
                            <td>
                              <strong>{loc.assigned_employees_count || 0} នាក់</strong>
                            </td>
                            <td style={{ textAlign: 'center' }}>
                              <img
                                src={qrUrl}
                                alt="QR"
                                onClick={() => setQrModalLoc(loc)}
                                style={{ width: '38px', height: '38px', borderRadius: '6px', cursor: 'pointer', border: '1px solid #cbd5e1' }}
                                title="Click to view QR"
                              />
                            </td>
                            <td style={{ textAlign: 'right' }}>
                              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                                <button
                                  type="button"
                                  onClick={() => handleOpenQrDesigner(loc)}
                                  className="btn btn-secondary btn-sm"
                                  title="QR Designer"
                                >
                                  <Sparkles size={13} />
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleOpenEditModal(loc)}
                                  className="btn btn-secondary btn-sm"
                                  title="កែប្រែ"
                                >
                                  <Edit2 size={13} />
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleDeleteLocation(loc.id, loc.name || loc.location_name || '')}
                                  className="btn btn-danger btn-sm"
                                  title="លុប"
                                >
                                  <Trash2 size={13} />
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
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: CREATE LOCATION                                                    */}
      {/* ========================================================================= */}
      {activeTab === 'create' && (
        <div className="hrm-card" style={{ padding: '28px', maxWidth: '780px', margin: '0 auto', width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', borderBottom: '1px solid #f1f5f9', paddingBottom: '14px' }}>
            <h3 style={{ fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Plus size={20} style={{ color: 'var(--primary)' }} />
              បង្កើតទីតាំង Check-In/Out ថ្មី (Create Location)
            </h3>
            <button
              type="button"
              onClick={() => setActiveTab('list')}
              className="btn btn-secondary btn-sm"
            >
              ត្រឡប់ទៅបញ្ជីទីតាំង
            </button>
          </div>

          {locSuccess && (
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
                marginBottom: '20px',
              }}
            >
              <Check size={18} />
              <span>ទីតាំងថ្មីត្រូវបានបង្កើត និងបង្កើត QR Code ដោយជោគជ័យ!</span>
            </div>
          )}

          <form onSubmit={handleSaveLocation}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              {/* Location Name */}
              <div className="form-group">
                <label className="form-label" style={{ fontWeight: 700 }}>
                  ឈ្មោះទីតាំង / សាខា (Location Name) *
                </label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="ឧ. សាខា Store 318, ឃ្លាំងទំនិញ PSP..."
                  value={locFormData.name}
                  onChange={(e) => setLocFormData({ ...locFormData, name: e.target.value })}
                  required
                  style={{ fontSize: '15px', padding: '12px 14px' }}
                />
              </div>

              {/* Address */}
              <div className="form-group">
                <label className="form-label" style={{ fontWeight: 700 }}>
                  អាសយដ្ឋានលម្អិត (Address)
                </label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="ឧ. ផ្ទះលេខ 318 ផ្លូវកម្ពុជាក្រោម សង្កាត់មិត្តភាព ខណ្ឌ៧មករា..."
                  value={locFormData.address}
                  onChange={(e) => setLocFormData({ ...locFormData, address: e.target.value })}
                  style={{ padding: '12px 14px' }}
                />
              </div>

              {/* GPS Coordinates & Current GPS Button */}
              <div style={{ background: '#f8fafc', padding: '18px', borderRadius: '14px', border: '1px solid #e2e8f0' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
                  <label className="form-label" style={{ fontWeight: 700, margin: 0, display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Navigation size={16} style={{ color: 'var(--primary)' }} />
                    <span>កូអរដោនេ GPS (Latitude & Longitude) *</span>
                  </label>

                  <button
                    type="button"
                    onClick={handleGetCurrentGPS}
                    disabled={gettingGPS}
                    className="btn btn-secondary btn-sm"
                    style={{ borderRadius: '8px', color: 'var(--primary)', fontWeight: 700 }}
                  >
                    <Compass size={14} className={gettingGPS ? 'fa-spin' : ''} />
                    <span>{gettingGPS ? 'កំពុងចាប់យក GPS...' : '📍 យកទីតាំង GPS ខ្ញុំបច្ចុប្បន្ន'}</span>
                  </button>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                  <div className="form-group">
                    <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Latitude (រយៈទទឹង):</label>
                    <input
                      type="number"
                      step="any"
                      className="form-input"
                      value={locFormData.latitude}
                      onChange={(e) => setLocFormData({ ...locFormData, latitude: Number(e.target.value) })}
                      required
                    />
                  </div>

                  <div className="form-group">
                    <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Longitude (រយៈបណ្តោយ):</label>
                    <input
                      type="number"
                      step="any"
                      className="form-input"
                      value={locFormData.longitude}
                      onChange={(e) => setLocFormData({ ...locFormData, longitude: Number(e.target.value) })}
                      required
                    />
                  </div>
                </div>

                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '8px' }}>
                  💡 ព័ត៌មានជំនួយ: អ្នកអាចបើក Google Maps ចុចលើទីតាំងសាខាដើម្បីចម្លង Latitude និង Longitude មកដាក់ទីនេះ។
                </div>
              </div>

              {/* Radius Meters */}
              <div className="form-group">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <label className="form-label" style={{ fontWeight: 700, margin: 0 }}>
                    កាំស្កេនអនុញ្ញាត (Radius Meters) *
                  </label>
                  <div style={{ display: 'flex', gap: '6px' }}>
                    {[50, 100, 150, 200, 500].map((r) => (
                      <button
                        key={r}
                        type="button"
                        onClick={() => setLocFormData({ ...locFormData, radius_meters: r })}
                        style={{
                          border: locFormData.radius_meters === r ? '1px solid var(--primary)' : '1px solid #cbd5e1',
                          background: locFormData.radius_meters === r ? '#eef2ff' : '#fff',
                          color: locFormData.radius_meters === r ? 'var(--primary)' : '#475569',
                          padding: '2px 8px',
                          borderRadius: '6px',
                          fontSize: '11px',
                          fontWeight: 700,
                          cursor: 'pointer',
                        }}
                      >
                        {r}m
                      </button>
                    ))}
                  </div>
                </div>
                <input
                  type="number"
                  min={10}
                  max={5000}
                  className="form-input"
                  value={locFormData.radius_meters}
                  onChange={(e) => setLocFormData({ ...locFormData, radius_meters: Number(e.target.value) })}
                  required
                />
              </div>

              {/* QR Secret Key */}
              <div className="form-group">
                <label className="form-label" style={{ fontWeight: 700 }}>
                  QR Secret Key (កូដសម្ងាត់សម្រាប់ QR ស្កេន)
                </label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="ស្វ័យប្រវត្ត"
                  value={locFormData.qr_secret}
                  onChange={(e) => setLocFormData({ ...locFormData, qr_secret: e.target.value })}
                />
              </div>

              {/* Submit Buttons */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '12px' }}>
                <button
                  type="button"
                  onClick={() => setActiveTab('list')}
                  className="btn btn-secondary"
                  disabled={savingLoc}
                >
                  បោះបង់
                </button>
                <button
                  type="submit"
                  disabled={savingLoc}
                  className="btn btn-primary"
                  style={{ minWidth: '180px', justifyContent: 'center' }}
                >
                  {savingLoc ? (
                    <>
                      <RotateCw size={16} className="fa-spin" />
                      <span>កំពុងរក្សាទុក...</span>
                    </>
                  ) : (
                    <>
                      <Plus size={16} />
                      <span>បង្កើតទីតាំង (Save)</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </form>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: ASSIGN LOCATIONS TO EMPLOYEES                                      */}
      {/* ========================================================================= */}
      {activeTab === 'assign' && (
        <div className="hrm-card" style={{ padding: '26px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', borderBottom: '1px solid #f1f5f9', paddingBottom: '14px' }}>
            <h3 style={{ fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <UserCheck size={20} style={{ color: 'var(--primary)' }} />
              កំណត់ទីតាំងសម្រាប់បុគ្គលិក (Assign Locations to Employees)
            </h3>
            <span className="badge badge-primary" style={{ fontSize: '12px' }}>
              ជ្រើសរើសបុគ្គលិក & ទីតាំងដែលអនុញ្ញាតឱ្យស្កេន
            </span>
          </div>

          {assignSuccess && (
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
                marginBottom: '20px',
              }}
            >
              <Check size={18} />
              <span>បានកំណត់ទីតាំងសម្រាប់បុគ្គលិកដោយជោគជ័យ!</span>
            </div>
          )}

          <form onSubmit={handleSaveAssignment}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '24px' }}>
              {/* Column 1: Select Employees */}
              <div style={{ background: '#f8fafc', padding: '18px', borderRadius: '16px', border: '1px solid #e2e8f0', display: 'flex', flexDirection: 'column' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                  <label style={{ fontSize: '14px', fontWeight: 800, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Users size={16} style={{ color: 'var(--primary)' }} />
                    <span>១. ជ្រើសរើសបុគ្គលិក ({selectedUserIds.length} នាក់)</span>
                  </label>

                  <button
                    type="button"
                    onClick={handleSelectAllFilteredUsers}
                    style={{ border: 'none', background: 'transparent', color: 'var(--primary)', fontSize: '12px', fontWeight: 700, cursor: 'pointer' }}
                  >
                    {selectedUserIds.length === filteredUsers.length ? 'ដកជម្រើសទាំងអស់' : 'ជ្រើសទាំងអស់'}
                  </button>
                </div>

                {/* Filters */}
                <div style={{ display: 'flex', gap: '8px', marginBottom: '10px' }}>
                  <div style={{ position: 'relative', flex: 1 }}>
                    <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: '#94a3b8' }} />
                    <input
                      type="text"
                      className="form-input"
                      placeholder="ស្វែងរកបុគ្គលិក..."
                      value={userSearchTerm}
                      onChange={(e) => setUserSearchTerm(e.target.value)}
                      style={{ paddingLeft: '32px', fontSize: '12px', padding: '8px 10px 8px 32px' }}
                    />
                  </div>

                  <select
                    className="form-select"
                    value={userDeptFilter}
                    onChange={(e) => setUserDeptFilter(e.target.value)}
                    style={{ fontSize: '12px', padding: '6px 8px', maxWidth: '140px' }}
                  >
                    <option value="ALL">គ្រប់ផ្នែក</option>
                    {distinctDepartments.map((d) => (
                      <option key={d} value={d}>{d}</option>
                    ))}
                  </select>
                </div>

                {/* Users List Box */}
                <div style={{ maxHeight: '340px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px', paddingRight: '4px' }}>
                  {filteredUsers.map((u) => {
                    const isSelected = selectedUserIds.includes(u.employee_id);
                    return (
                      <div
                        key={u.employee_id}
                        onClick={() => handleToggleSelectUser(u.employee_id)}
                        style={{
                          padding: '10px 14px',
                          borderRadius: '10px',
                          background: isSelected ? '#eef2ff' : '#fff',
                          border: isSelected ? '1.5px solid var(--primary)' : '1px solid #e2e8f0',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          transition: 'all 0.15s ease',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <div
                            style={{
                              width: '32px',
                              height: '32px',
                              borderRadius: '50%',
                              background: isSelected ? 'var(--primary)' : '#e2e8f0',
                              color: isSelected ? '#fff' : '#475569',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              fontWeight: 800,
                              fontSize: '12px',
                            }}
                          >
                            {u.name ? u.name.charAt(0) : 'U'}
                          </div>
                          <div>
                            <div style={{ fontWeight: 700, fontSize: '13px', color: 'var(--text-primary)' }}>{u.name}</div>
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                              ID: {u.employee_id} • {u.department || 'General'}
                            </div>
                          </div>
                        </div>

                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {}}
                          style={{ accentColor: 'var(--primary)', width: '16px', height: '16px', cursor: 'pointer' }}
                        />
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Column 2: Select Locations & Radius */}
              <div style={{ background: '#f8fafc', padding: '18px', borderRadius: '16px', border: '1px solid #e2e8f0', display: 'flex', flexDirection: 'column' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                  <label style={{ fontSize: '14px', fontWeight: 800, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <MapPin size={16} style={{ color: 'var(--primary)' }} />
                    <span>២. ជ្រើសរើសទីតាំងសាខា ({selectedLocationIds.length} ទីតាំង)</span>
                  </label>
                </div>

                {/* Locations Checkbox List */}
                <div style={{ maxHeight: '240px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '16px' }}>
                  {locations.map((loc) => {
                    const isSelected = selectedLocationIds.includes(loc.id);
                    return (
                      <div
                        key={loc.id}
                        onClick={() => handleToggleSelectLocation(loc.id)}
                        style={{
                          padding: '12px 14px',
                          borderRadius: '10px',
                          background: isSelected ? '#eef2ff' : '#fff',
                          border: isSelected ? '1.5px solid var(--primary)' : '1px solid #e2e8f0',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          transition: 'all 0.15s ease',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <Building2 size={18} style={{ color: isSelected ? 'var(--primary)' : '#94a3b8' }} />
                          <div>
                            <div style={{ fontWeight: 700, fontSize: '13px', color: 'var(--text-primary)' }}>{loc.name || loc.location_name}</div>
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                              Radius លំនាំដើម: {loc.radius_meters}m
                            </div>
                          </div>
                        </div>

                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {}}
                          style={{ accentColor: 'var(--primary)', width: '16px', height: '16px', cursor: 'pointer' }}
                        />
                      </div>
                    );
                  })}
                </div>

                {/* Custom Radius for this assignment */}
                <div style={{ marginTop: 'auto', paddingTop: '14px', borderTop: '1px solid #e2e8f0' }}>
                  <label className="form-label" style={{ fontWeight: 700, fontSize: '13px' }}>
                    កំណត់កាំស្កេនផ្ទាល់ខ្លួន (Custom Radius Meters):
                  </label>
                  <input
                    type="number"
                    min={10}
                    max={5000}
                    className="form-input"
                    value={assignRadius}
                    onChange={(e) => setAssignRadius(Number(e.target.value))}
                    required
                  />
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                    កាំស្កេននេះនឹងត្រូវបានប្រើសម្រាប់បុគ្គលិកដែលបានជ្រើសរើសនៅគ្រប់ទីតាំងខាងលើ។
                  </div>
                </div>
              </div>
            </div>

            {/* Submit Action */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '20px', borderTop: '1px solid #f1f5f9', paddingTop: '16px' }}>
              <button
                type="submit"
                disabled={savingAssign}
                className="btn btn-primary"
                style={{ minWidth: '220px', justifyContent: 'center', padding: '12px' }}
              >
                {savingAssign ? (
                  <>
                    <RotateCw size={16} className="fa-spin" />
                    <span>កំពុងរក្សាទុកការកំណត់...</span>
                  </>
                ) : (
                  <>
                    <UserCheck size={16} />
                    <span>រក្សាទុកការកំណត់ ({selectedUserIds.length} នាក់ x {selectedLocationIds.length} ទីតាំង)</span>
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: EMPLOYEE ASSIGNMENTS TABLE                                         */}
      {/* ========================================================================= */}
      {activeTab === 'assignments' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
          {/* Search & Actions */}
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
            <div style={{ position: 'relative', flex: 1, minWidth: '240px' }}>
              <Search size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                type="text"
                className="form-input"
                placeholder="ស្វែងរកតាមឈ្មោះបុគ្គលិក ឬឈ្មោះទីតាំង..."
                value={assignmentSearch}
                onChange={(e) => setAssignmentSearch(e.target.value)}
                style={{ paddingLeft: '38px', borderRadius: '12px' }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <button
                type="button"
                onClick={() => setActiveTab('assign')}
                className="btn btn-primary btn-sm"
                style={{ borderRadius: '10px' }}
              >
                <Plus size={14} />
                <span>កំណត់ទីតាំងថ្មី</span>
              </button>

              <button
                type="button"
                onClick={loadAssignments}
                className="btn btn-secondary btn-sm"
                style={{ borderRadius: '10px' }}
              >
                <RotateCw size={14} className={loadingAssignments ? 'fa-spin' : ''} />
                <span>ផ្ទុកឡើងវិញ</span>
              </button>
            </div>
          </div>

          {/* Assignments Table */}
          <div className="hrm-card" style={{ padding: 0, overflow: 'hidden' }}>
            <div className="table-container">
              <table className="hrm-table">
                <thead>
                  <tr>
                    <th style={{ width: '80px' }}>Assign ID</th>
                    <th>បុគ្គលិក (Employee)</th>
                    <th>ផ្នែក / តួនាទី</th>
                    <th>ទីតាំងដែលបានកំណត់ (Assigned Location)</th>
                    <th>កាំស្កេន (Radius)</th>
                    <th>កាលបរិច្ឆេទកំណត់</th>
                    <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
                  </tr>
                </thead>
                <tbody>
                  {loadingAssignments ? (
                    <tr><td colSpan={7} style={{ textAlign: 'center', padding: '30px' }}>កំពុងទាញយកទិន្នន័យកំណត់បុគ្គលិក...</td></tr>
                  ) : filteredAssignments.length === 0 ? (
                    <tr><td colSpan={7} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>មិនទាន់មានការកំណត់ទីតាំងសម្រាប់បុគ្គលិកឡើយ</td></tr>
                  ) : (
                    filteredAssignments.map((a) => (
                      <tr key={a.assign_id}>
                        <td style={{ fontWeight: 700, color: 'var(--text-muted)', fontSize: '12px' }}>
                          #{a.assign_id}
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: '#e2e8f0', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '11px', fontWeight: 800, color: '#475569' }}>
                              {a.user_name ? a.user_name.charAt(0) : 'U'}
                            </div>
                            <div>
                              <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{a.user_name}</div>
                              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>ID: {a.employee_id}</div>
                            </div>
                          </div>
                        </td>
                        <td>
                          <span className="badge badge-secondary" style={{ fontSize: '11px' }}>
                            {a.department || a.system_role || 'Staff'}
                          </span>
                        </td>
                        <td>
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontWeight: 700, color: 'var(--primary)' }}>
                            <MapPin size={14} />
                            <span>{a.location_name}</span>
                          </div>
                        </td>
                        <td>
                          <span className="badge badge-primary">{a.custom_radius_meters}m</span>
                        </td>
                        <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                          {a.created_at || '—'}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            type="button"
                            onClick={() => handleUnassign(a.assign_id, a.user_name, a.location_name)}
                            className="btn btn-danger btn-sm"
                            title="ដកទីតាំងចេញ"
                          >
                            <Unlink size={13} />
                            <span>Unassign</span>
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
      )}

      {/* ========================================================================= */}
      {/* EDIT LOCATION MODAL                                                       */}
      {/* ========================================================================= */}
      {editModalLoc && (
        <Modal
          isOpen={!!editModalLoc}
          onClose={() => setEditModalLoc(null)}
          title={`កែប្រែទីតាំង - ${editModalLoc.name || editModalLoc.location_name}`}
          maxWidth="600px"
        >
          <form onSubmit={handleSaveLocation}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div className="form-group">
                <label className="form-label" style={{ fontWeight: 700 }}>ឈ្មោះទីតាំង *</label>
                <input
                  type="text"
                  className="form-input"
                  value={locFormData.name}
                  onChange={(e) => setLocFormData({ ...locFormData, name: e.target.value })}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label" style={{ fontWeight: 700 }}>អាសយដ្ឋាន</label>
                <input
                  type="text"
                  className="form-input"
                  value={locFormData.address}
                  onChange={(e) => setLocFormData({ ...locFormData, address: e.target.value })}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label" style={{ fontWeight: 700 }}>Latitude</label>
                  <input
                    type="number"
                    step="any"
                    className="form-input"
                    value={locFormData.latitude}
                    onChange={(e) => setLocFormData({ ...locFormData, latitude: Number(e.target.value) })}
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label" style={{ fontWeight: 700 }}>Longitude</label>
                  <input
                    type="number"
                    step="any"
                    className="form-input"
                    value={locFormData.longitude}
                    onChange={(e) => setLocFormData({ ...locFormData, longitude: Number(e.target.value) })}
                    required
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label" style={{ fontWeight: 700 }}>កាំស្កេនអនុញ្ញាត (Radius Meters)</label>
                <input
                  type="number"
                  min={10}
                  className="form-input"
                  value={locFormData.radius_meters}
                  onChange={(e) => setLocFormData({ ...locFormData, radius_meters: Number(e.target.value) })}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label" style={{ fontWeight: 700 }}>QR Secret Key</label>
                <input
                  type="text"
                  className="form-input"
                  value={locFormData.qr_secret}
                  onChange={(e) => setLocFormData({ ...locFormData, qr_secret: e.target.value })}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '12px', borderTop: '1px solid #f1f5f9', paddingTop: '14px' }}>
                <button
                  type="button"
                  onClick={() => setEditModalLoc(null)}
                  className="btn btn-secondary"
                  disabled={savingLoc}
                >
                  បោះបង់
                </button>
                <button
                  type="submit"
                  disabled={savingLoc}
                  className="btn btn-primary"
                >
                  {savingLoc ? 'កំពុងរក្សាទុក...' : 'រក្សាទុកការកែប្រែ'}
                </button>
              </div>
            </div>
          </form>
        </Modal>
      )}

      {/* ========================================================================= */}
      {/* QUICK VIEW QR MODAL                                                       */}
      {/* ========================================================================= */}
      {qrModalLoc && (
        <Modal
          isOpen={!!qrModalLoc}
          onClose={() => setQrModalLoc(null)}
          title={`QR Code វត្តមាន - ${qrModalLoc.name || qrModalLoc.location_name}`}
          maxWidth="460px"
        >
          {(() => {
            const qrDataStr = JSON.stringify({ location_id: qrModalLoc.id, secret: qrModalLoc.qr_secret });
            const qrUrlLarge = `https://api.qrserver.com/v1/create-qr-code/?size=360x360&data=${encodeURIComponent(qrDataStr)}`;

            return (
              <div style={{ textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '18px' }}>
                <div
                  style={{
                    background: '#ffffff',
                    padding: '24px',
                    borderRadius: '20px',
                    boxShadow: '0 10px 30px rgba(0,0,0,0.08)',
                    border: '2px dashed var(--primary)',
                    width: '100%',
                    maxWidth: '300px',
                  }}
                >
                  <img
                    src={qrUrlLarge}
                    alt="QR Code"
                    style={{ width: '100%', height: 'auto', display: 'block', borderRadius: '8px' }}
                  />
                  <div style={{ marginTop: '14px', fontWeight: 800, fontSize: '16px', color: '#0f172a' }}>
                    {qrModalLoc.name || qrModalLoc.location_name}
                  </div>
                  <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
                    ស្កេនដើម្បីកត់ត្រាវត្តមាន (Check-In / Out)
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                    Radius: {qrModalLoc.radius_meters}m
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '10px', width: '100%' }}>
                  <button
                    type="button"
                    onClick={() => {
                      const loc = qrModalLoc;
                      setQrModalLoc(null);
                      handleOpenQrDesigner(loc);
                    }}
                    className="btn btn-secondary"
                    style={{ flex: 1 }}
                  >
                    <Sparkles size={16} />
                    <span>QR Designer</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => window.print()}
                    className="btn btn-primary"
                    style={{ flex: 1 }}
                  >
                    <Printer size={16} />
                    <span>បោះពុម្ព (Print)</span>
                  </button>
                </div>
              </div>
            );
          })()}
        </Modal>
      )}

      {/* ========================================================================= */}
      {/* QR CODE DESIGNER & STYLER MODAL                                           */}
      {/* ========================================================================= */}
      {qrDesignerLoc && (
        <Modal
          isOpen={!!qrDesignerLoc}
          onClose={() => setQrDesignerLoc(null)}
          title={`🎨 QR Designer & Customizer - ${qrDesignerLoc.name || qrDesignerLoc.location_name}`}
          maxWidth="750px"
        >
          {(() => {
            const qrDataStr = JSON.stringify({ location_id: qrDesignerLoc.id, secret: qrDesignerLoc.qr_secret });
            const cleanColor = qrColor.replace('#', '');
            const cleanBgColor = qrBgColor.replace('#', '');
            const customQrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=${qrSize}x${qrSize}&color=${cleanColor}&bgcolor=${cleanBgColor}&data=${encodeURIComponent(qrDataStr)}`;

            return (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '22px', alignItems: 'start' }}>
                {/* Customization Controls */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  <div className="form-group">
                    <label className="form-label" style={{ fontWeight: 700 }}>ចំណងជើងផ្ទាំង QR (Header Title)</label>
                    <input
                      type="text"
                      className="form-input"
                      value={qrTitle}
                      onChange={(e) => setQrTitle(e.target.value)}
                    />
                  </div>

                  <div className="form-group">
                    <label className="form-label" style={{ fontWeight: 700 }}>អត្ថបទណែនាំ (Subtitle)</label>
                    <input
                      type="text"
                      className="form-input"
                      value={qrSubtitle}
                      onChange={(e) => setQrSubtitle(e.target.value)}
                    />
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                    <div className="form-group">
                      <label className="form-label" style={{ fontWeight: 700 }}>ពណ៌ QR Code</label>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <input
                          type="color"
                          value={qrColor}
                          onChange={(e) => setQrColor(e.target.value)}
                          style={{ width: '40px', height: '36px', border: 'none', borderRadius: '6px', cursor: 'pointer' }}
                        />
                        <input
                          type="text"
                          className="form-input"
                          value={qrColor}
                          onChange={(e) => setQrColor(e.target.value)}
                          style={{ fontSize: '12px' }}
                        />
                      </div>
                    </div>

                    <div className="form-group">
                      <label className="form-label" style={{ fontWeight: 700 }}>ពណ៌ផ្ទៃខាងក្រោយ (Bg)</label>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <input
                          type="color"
                          value={qrBgColor}
                          onChange={(e) => setQrBgColor(e.target.value)}
                          style={{ width: '40px', height: '36px', border: 'none', borderRadius: '6px', cursor: 'pointer' }}
                        />
                        <input
                          type="text"
                          className="form-input"
                          value={qrBgColor}
                          onChange={(e) => setQrBgColor(e.target.value)}
                          style={{ fontSize: '12px' }}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Preset Color Themes */}
                  <div>
                    <label style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
                      ពណ៌ស្អាតៗពេញនិយម (Color Presets):
                    </label>
                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      {[
                        { name: 'Dark Indigo', color: '#4f46e5', bg: '#ffffff' },
                        { name: 'Classic Black', color: '#0f172a', bg: '#ffffff' },
                        { name: 'Emerald', color: '#059669', bg: '#ffffff' },
                        { name: 'Rose', color: '#e11d48', bg: '#ffffff' },
                        { name: 'Royal Gold', color: '#d97706', bg: '#ffffff' },
                      ].map((preset) => (
                        <button
                          key={preset.name}
                          type="button"
                          onClick={() => {
                            setQrColor(preset.color);
                            setQrBgColor(preset.bg);
                          }}
                          style={{
                            padding: '4px 10px',
                            borderRadius: '6px',
                            border: '1px solid #cbd5e1',
                            background: '#fff',
                            fontSize: '11px',
                            fontWeight: 700,
                            cursor: 'pointer',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '6px',
                          }}
                        >
                          <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: preset.color }} />
                          <span>{preset.name}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Live Standee Preview Box */}
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '14px' }}>
                  <div
                    id="qr-printable-poster"
                    style={{
                      background: qrBgColor,
                      padding: '24px',
                      borderRadius: '18px',
                      boxShadow: '0 10px 30px rgba(0,0,0,0.12)',
                      border: `3px solid ${qrColor}`,
                      textAlign: 'center',
                      width: '100%',
                      maxWidth: '280px',
                    }}
                  >
                    {/* Header */}
                    <div style={{ fontSize: '11px', fontWeight: 900, letterSpacing: '1.5px', color: qrColor, textTransform: 'uppercase', marginBottom: '8px' }}>
                      VVC ATTENDANCE SYSTEM
                    </div>

                    <img
                      src={customQrUrl}
                      alt="Styled QR"
                      style={{ width: '100%', height: 'auto', display: 'block', borderRadius: '8px' }}
                    />

                    {/* Footer Info */}
                    <div style={{ marginTop: '12px', fontWeight: 900, fontSize: '16px', color: qrColor }}>
                      {qrTitle || 'Location QR'}
                    </div>
                    <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px', lineHeight: 1.4 }}>
                      {qrSubtitle}
                    </div>
                  </div>

                  {/* Export Buttons */}
                  <div style={{ display: 'flex', gap: '8px', width: '100%' }}>
                    <a
                      href={customQrUrl}
                      download={`QR_${qrDesignerLoc.name || 'Location'}.png`}
                      target="_blank"
                      rel="noreferrer"
                      className="btn btn-secondary"
                      style={{ flex: 1, textDecoration: 'none', justifyContent: 'center' }}
                    >
                      <Download size={14} />
                      <span>Download PNG</span>
                    </a>

                    <button
                      type="button"
                      onClick={() => window.print()}
                      className="btn btn-primary"
                      style={{ flex: 1, justifyContent: 'center' }}
                    >
                      <Printer size={14} />
                      <span>Print Standee</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })()}
        </Modal>
      )}
    </div>
  );
};
