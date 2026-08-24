import React, { useState, useEffect } from 'react';
import {
  Vote,
  Plus,
  BarChart3,
  CheckCircle2,
  Calendar,
  Trash2,
  Edit,
  RotateCw,
  Search,
  Building2,
  Trophy,
  Award,
  Users,
  Eye,
  Check,
  X,
  Lock,
} from 'lucide-react';
import { Modal } from '../components/common/Modal';
import { ViewModeToggle, ViewMode } from '../components/common/ViewModeToggle';
import { adminApi, PollItem, PollCandidate, GroupUserItem } from '../api/adminApi';

export const PollsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'manage' | 'results'>('manage');
  const [viewMode, setViewMode] = useState<ViewMode>('table');
  const [polls, setPolls] = useState<PollItem[]>([]);
  const [employees, setEmployees] = useState<GroupUserItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');

  // Modal State
  const [modalOpen, setModalOpen] = useState(false);
  const [editingPollId, setEditingPollId] = useState<number | null>(null);
  const [title, setTitle] = useState('');
  const [quarter, setQuarter] = useState('Q3');
  const [location, setLocation] = useState('ការិយាល័យកណ្តាល');
  const [startDate, setStartDate] = useState(new Date().toISOString().split('T')[0]);
  const [endDate, setEndDate] = useState(
    new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
  );
  const [accessCode, setAccessCode] = useState('');
  const [isActive, setIsActive] = useState(1);
  const [selectedCandidateIds, setSelectedCandidateIds] = useState<string[]>([]);
  const [candidateSearch, setCandidateSearch] = useState('');

  // Results View State
  const [selectedPollForResults, setSelectedPollForResults] = useState<number | null>(null);
  const [resultsData, setResultsData] = useState<any[]>([]);
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [voterModalCandidate, setVoterModalCandidate] = useState<PollCandidate | null>(null);

  // Banner notification
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const showBanner = (type: 'success' | 'error', text: string) => {
    setBanner({ type, text });
    setTimeout(() => setBanner(null), 3500);
  };

  const loadPolls = async () => {
    setLoading(true);
    try {
      const res = await adminApi.fetchPolls();
      if (res && (res.success || res.status === 'success')) {
        const pollList: PollItem[] = Array.isArray(res.polls)
          ? res.polls
          : Array.isArray(res.data)
          ? res.data
          : [];
        setPolls(pollList);
        if (pollList.length > 0 && selectedPollForResults === null) {
          setSelectedPollForResults(pollList[0].id);
        }
      }

      // Also load employees for candidate selector
      const catRes = await adminApi.fetchCategories();
      if (catRes && Array.isArray(catRes.users)) {
        setEmployees(catRes.users);
      }
    } catch (err) {
      console.error('Error fetching polls:', err);
    }
    setLoading(false);
  };

  const loadPollResults = async (pollId?: number) => {
    try {
      const res = await adminApi.fetchPollResults(pollId || selectedPollForResults || undefined);
      if (res && (res.success || res.status === 'success') && Array.isArray(res.data)) {
        setResultsData(res.data);
      }
    } catch (err) {
      console.error('Error loading results:', err);
    }
  };

  useEffect(() => {
    loadPolls();
  }, []);

  useEffect(() => {
    if (activeTab === 'results') {
      loadPollResults(selectedPollForResults || undefined);
    }
  }, [activeTab, selectedPollForResults]);

  const handleOpenCreate = () => {
    setEditingPollId(null);
    setTitle('');
    setQuarter('Q3');
    setLocation('ការិយាល័យកណ្តាល');
    setStartDate(new Date().toISOString().split('T')[0]);
    setEndDate(new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]);
    setAccessCode('');
    setIsActive(1);
    setSelectedCandidateIds([]);
    setCandidateSearch('');
    setModalOpen(true);
  };

  const handleOpenEdit = (poll: PollItem) => {
    setEditingPollId(poll.id);
    setTitle(poll.title || '');
    setQuarter(poll.quarter || 'Q3');
    setLocation(poll.location || 'ការិយាល័យកណ្តាល');
    setStartDate(poll.start_date || new Date().toISOString().split('T')[0]);
    setEndDate(poll.end_date || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]);
    setAccessCode(poll.access_code || '');
    setIsActive(poll.is_active !== undefined ? Number(poll.is_active) : poll.status === 'Active' ? 1 : 0);

    const candIds = poll.candidates ? poll.candidates.map((c) => c.employee_id) : [];
    setSelectedCandidateIds(candIds);
    setCandidateSearch('');
    setModalOpen(true);
  };

  const handleSavePoll = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) {
      alert('សូមបញ្ចូលចំណងជើងការបោះឆ្នោត!');
      return;
    }

    try {
      const candidatesPayload = selectedCandidateIds.map((eid) => ({
        employee_id: eid,
        category: location,
      }));

      const res = await adminApi.savePoll({
        id: editingPollId || undefined,
        title,
        quarter,
        location,
        start_date: startDate,
        end_date: endDate,
        access_code: accessCode,
        is_active: isActive,
        status: isActive === 1 ? 'Active' : 'Closed',
        candidates: candidatesPayload as any,
      });

      if (res && (res.success || res.status === 'success')) {
        showBanner('success', res.message || 'បានរក្សាទុកការបោះឆ្នោតជោគជ័យ!');
        setModalOpen(false);
        loadPolls();
      } else {
        showBanner('error', res?.message || 'Error saving poll');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការរក្សាទុក');
    }
  };

  const handleDeletePoll = async (id: number, pollTitle: string) => {
    if (window.confirm(`តើអ្នកពិតជាចង់លុបការបោះឆ្នោត "${pollTitle}" នេះមែនទេ?`)) {
      try {
        const res = await adminApi.deletePoll(id);
        if (res && (res.success || res.status === 'success')) {
          showBanner('success', res.message || 'បានលុបការបោះឆ្នោតជោគជ័យ!');
          loadPolls();
        } else {
          showBanner('error', res?.message || 'Error deleting poll');
        }
      } catch (err) {
        showBanner('error', 'កំហុសក្នុងការលុប');
      }
    }
  };

  const toggleCandidateSelection = (empId: string) => {
    setSelectedCandidateIds((prev) =>
      prev.includes(empId) ? prev.filter((id) => id !== empId) : [...prev, empId]
    );
  };

  // Filtered polls
  const filteredPolls = polls.filter((p) => {
    const q = search.toLowerCase();
    return (
      (p.title || '').toLowerCase().includes(q) ||
      (p.location || '').toLowerCase().includes(q) ||
      (p.quarter || '').toLowerCase().includes(q)
    );
  });

  // Filtered employees for modal
  const filteredEmployees = employees.filter((e) => {
    const q = candidateSearch.toLowerCase();
    return (
      (e.name || '').toLowerCase().includes(q) ||
      (e.employee_id || '').toLowerCase().includes(q) ||
      (e.department || '').toLowerCase().includes(q)
    );
  });

  // Active Poll Result object
  const currentResultBundle = resultsData.find(
    (r) => r.poll?.id === selectedPollForResults
  ) || resultsData[0];

  const currentCandidates: PollCandidate[] = currentResultBundle?.candidates || [];
  const filteredCandidates = currentCandidates.filter((c) => {
    if (categoryFilter === 'all') return true;
    return c.category === categoryFilter || c.department === categoryFilter;
  });

  // Stats
  const totalPolls = polls.length;
  const activePollsCount = polls.filter((p) => (p.is_active === 1 || p.status === 'Active')).length;
  const totalVotesSum = polls.reduce((sum, p) => sum + (p.total_votes || 0), 0);
  const totalCandidatesSum = polls.reduce((sum, p) => sum + (p.candidate_count || (p.candidates ? p.candidates.length : 0)), 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '1280px', margin: '0 auto', width: '100%' }}>
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

      {/* Header Banner */}
      <div
        className="hrm-card"
        style={{
          background: 'linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)',
          color: '#fff',
          padding: '24px 28px',
          borderRadius: '20px',
          boxShadow: '0 10px 30px rgba(79, 70, 229, 0.25)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '16px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
            <Vote size={26} color="#fff" />
            <h2 style={{ fontSize: '22px', fontWeight: 800, margin: 0, color: '#fff' }}>
              គ្រប់គ្រងការបោះឆ្នោត (Polls & Voting Management)
            </h2>
          </div>
          <p style={{ margin: 0, fontSize: '13.5px', opacity: 0.9 }}>
            បង្កើតការបោះឆ្នោតជ្រើសរើសបុគ្គលិកឆ្នើម ស្ទង់មតិផ្ទៃក្នុង និងតាមដានលទ្ធផលបោះឆ្នោតផ្ទាល់
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            onClick={() => setActiveTab('manage')}
            style={{
              background: activeTab === 'manage' ? '#fff' : 'rgba(255,255,255,0.2)',
              color: activeTab === 'manage' ? '#4f46e5' : '#fff',
              border: 'none',
              padding: '10px 20px',
              borderRadius: '12px',
              fontWeight: 700,
              fontSize: '13px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <Vote size={15} />
            <span>បញ្ជីការបោះឆ្នោត</span>
          </button>

          <button
            onClick={() => setActiveTab('results')}
            style={{
              background: activeTab === 'results' ? '#fff' : 'rgba(255,255,255,0.2)',
              color: activeTab === 'results' ? '#4f46e5' : '#fff',
              border: 'none',
              padding: '10px 20px',
              borderRadius: '12px',
              fontWeight: 700,
              fontSize: '13px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <BarChart3 size={15} />
            <span>លទ្ធផលការបោះឆ្នោត</span>
          </button>
        </div>
      </div>

      {/* StatCards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
        <div className="stat-card" style={{ background: '#fff', padding: '18px 22px', borderRadius: '16px', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)', fontWeight: 600 }}>ការបោះឆ្នោតសរុប</div>
              <div style={{ fontSize: '24px', fontWeight: 800, color: 'var(--text-primary)', marginTop: '4px' }}>{totalPolls} កម្មវិធី</div>
            </div>
            <div style={{ width: '44px', height: '44px', borderRadius: '12px', background: 'rgba(99, 102, 241, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#6366f1' }}>
              <Vote size={22} />
            </div>
          </div>
        </div>

        <div className="stat-card" style={{ background: '#fff', padding: '18px 22px', borderRadius: '16px', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)', fontWeight: 600 }}>ការបោះឆ្នោតសកម្ម</div>
              <div style={{ fontSize: '24px', fontWeight: 800, color: '#10b981', marginTop: '4px' }}>{activePollsCount} កម្មវិធី</div>
            </div>
            <div style={{ width: '44px', height: '44px', borderRadius: '12px', background: 'rgba(16, 185, 129, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#10b981' }}>
              <CheckCircle2 size={22} />
            </div>
          </div>
        </div>

        <div className="stat-card" style={{ background: '#fff', padding: '18px 22px', borderRadius: '16px', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)', fontWeight: 600 }}>បេក្ខជនសរុប</div>
              <div style={{ fontSize: '24px', fontWeight: 800, color: 'var(--text-primary)', marginTop: '4px' }}>{totalCandidatesSum} នាក់</div>
            </div>
            <div style={{ width: '44px', height: '44px', borderRadius: '12px', background: 'rgba(245, 158, 11, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#f59e0b' }}>
              <Users size={22} />
            </div>
          </div>
        </div>

        <div className="stat-card" style={{ background: '#fff', padding: '18px 22px', borderRadius: '16px', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)', fontWeight: 600 }}>សំឡេងឆ្នោតសរុប</div>
              <div style={{ fontSize: '24px', fontWeight: 800, color: '#6366f1', marginTop: '4px' }}>{totalVotesSum} សំឡេង</div>
            </div>
            <div style={{ width: '44px', height: '44px', borderRadius: '12px', background: 'rgba(99, 102, 241, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#6366f1' }}>
              <Trophy size={22} />
            </div>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: MANAGE POLLS LIST (ដូចគ្នានឹង admin_attendance.php)                */}
      {/* ========================================================================= */}
      {activeTab === 'manage' && (
        <div className="hrm-card" style={{ padding: '24px', borderRadius: '18px' }}>
          {/* Toolbar */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', background: 'var(--surface-alt)', border: '1px solid var(--border)', borderRadius: '12px', padding: '8px 14px', width: '320px', gap: '8px' }}>
              <Search size={16} color="var(--text-muted)" />
              <input
                type="text"
                placeholder="ស្វែងរកតាមចំណងជើង ទីតាំង ត្រីមាស..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ background: 'transparent', border: 'none', outline: 'none', fontSize: '13px', width: '100%', color: 'var(--text-primary)' }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <ViewModeToggle mode={viewMode} onChange={setViewMode} />

              <button onClick={loadPolls} className="btn btn-secondary" style={{ borderRadius: '10px' }}>
                <RotateCw size={14} className={loading ? 'fa-spin' : ''} />
                <span>Refresh</span>
              </button>

              <button onClick={handleOpenCreate} className="btn btn-primary" style={{ borderRadius: '10px', fontWeight: 700 }}>
                <Plus size={16} />
                <span>បង្កើតការបោះឆ្នោតថ្មី</span>
              </button>
            </div>
          </div>

          {/* View Mode Switching: Grid Cards or Table */}
          {viewMode === 'grid' ? (
            filteredPolls.length === 0 ? (
              <div className="hrm-card" style={{ textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}>
                {loading ? 'កំពុងទាញយកទិន្នន័យការបោះឆ្នោត...' : 'មិនមានការបោះឆ្នោតនៅឡើយទេ'}
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '16px' }}>
                {filteredPolls.map((poll) => {
                  const candCount = poll.candidates ? poll.candidates.length : (poll.candidate_count || 0);
                  const isActiveBool = poll.is_active === 1 || poll.status === 'Active';

                  return (
                    <div
                      key={poll.id}
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
                          <div style={{ fontWeight: 800, fontSize: '15px', color: 'var(--text-primary)' }}>
                            {poll.title}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                            ID: #{poll.id} • <span style={{ fontWeight: 700, color: 'var(--primary)' }}>{poll.quarter || 'Q3'}</span>
                          </div>
                        </div>

                        <span className={isActiveBool ? 'badge badge-good' : 'badge badge-danger'}>
                          {isActiveBool ? 'សកម្ម' : 'មិនសកម្ម'}
                        </span>
                      </div>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', background: 'var(--surface-alt)', padding: '12px', borderRadius: '12px', fontSize: '12px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                          <span style={{ color: 'var(--text-muted)' }}>ទីតាំង:</span>
                          <span style={{ fontWeight: 600 }}>{poll.location || 'ការិយាល័យកណ្តាល'}</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                          <span style={{ color: 'var(--text-muted)' }}>បេក្ខជន:</span>
                          <span style={{ fontWeight: 700, color: '#475569' }}>
                            <Users size={12} style={{ display: 'inline', marginRight: '4px' }} />
                            {candCount} នាក់
                          </span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                          <span style={{ color: 'var(--text-muted)' }}>សំឡេងឆ្នោត:</span>
                          <span style={{ fontWeight: 800, color: '#059669' }}>
                            <Vote size={12} style={{ display: 'inline', marginRight: '4px' }} />
                            {poll.total_votes || 0} សំឡេង
                          </span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderTop: '1px solid var(--border)', paddingTop: '6px', marginTop: '2px', fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                          <span>{poll.start_date || '-'}</span>
                          <span>→</span>
                          <span>{poll.end_date || poll.ends_at || '-'}</span>
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderTop: '1px solid var(--border)', paddingTop: '10px', marginTop: 'auto' }}>
                        <button
                          onClick={() => {
                            setSelectedPollForResults(poll.id);
                            setActiveTab('results');
                          }}
                          className="btn btn-sm"
                          style={{ background: '#10b981', color: '#fff', borderRadius: '8px', padding: '6px 12px', fontWeight: 700, fontSize: '12px' }}
                        >
                          <BarChart3 size={13} />
                          <span>មើលលទ្ធផល</span>
                        </button>

                        <div style={{ display: 'flex', gap: '6px' }}>
                          <button
                            onClick={() => handleOpenEdit(poll)}
                            className="btn btn-secondary btn-sm"
                            style={{ borderRadius: '8px', padding: '5px 8px' }}
                            title="កែប្រែ"
                          >
                            <Edit size={13} />
                          </button>
                          <button
                            onClick={() => handleDeletePoll(poll.id, poll.title)}
                            className="btn btn-sm"
                            style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.2)', borderRadius: '8px', padding: '5px 8px' }}
                            title="លុប"
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )
          ) : (
            /* Table matching admin_attendance.php */
            <div className="table-container" style={{ border: 'none', boxShadow: 'none' }}>
              <table className="hrm-table">
                <thead>
                  <tr>
                    <th style={{ width: '70px', textAlign: 'center' }}>ID</th>
                    <th>ចំណងជើង</th>
                    <th style={{ width: '110px' }}>ត្រីមាស</th>
                    <th style={{ width: '150px' }}>ទីតាំង/ឃ្លាំង</th>
                    <th style={{ width: '120px', textAlign: 'center' }}>បេក្ខជន</th>
                    <th style={{ width: '140px', textAlign: 'center' }}>សំឡេងឆ្នោត</th>
                    <th style={{ width: '180px' }}>កាលបរិច្ឆេទ</th>
                    <th style={{ width: '100px', textAlign: 'center' }}>ស្ថានភាព</th>
                    <th style={{ width: '160px', textAlign: 'center' }}>សកម្មភាព</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredPolls.length === 0 ? (
                    <tr>
                      <td colSpan={9} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                        {loading ? 'កំពុងទាញយកទិន្នន័យការបោះឆ្នោត...' : 'មិនមានការបោះឆ្នោតនៅឡើយទេ'}
                      </td>
                    </tr>
                  ) : (
                    filteredPolls.map((poll) => {
                      const candCount = poll.candidates ? poll.candidates.length : (poll.candidate_count || 0);
                      const isActiveBool = poll.is_active === 1 || poll.status === 'Active';

                      return (
                        <tr key={poll.id}>
                          <td style={{ textAlign: 'center', fontWeight: 800, color: 'var(--text-muted)' }}>
                            #{poll.id}
                          </td>
                          <td>
                            <div style={{ fontWeight: 800, fontSize: '14px', color: 'var(--text-primary)' }}>
                              {poll.title}
                            </div>
                            {poll.access_code && (
                              <div style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px', marginTop: '2px' }}>
                                <Lock size={11} /> កូដចូលមើល: {poll.access_code}
                              </div>
                            )}
                          </td>
                          <td>
                            <span className="badge badge-primary" style={{ fontWeight: 700 }}>
                              {poll.quarter || 'Q3'}
                            </span>
                          </td>
                          <td>
                            <span style={{ background: '#e0e7ff', color: '#3730a3', padding: '3px 8px', borderRadius: '8px', fontSize: '12px', fontWeight: 600 }}>
                              <Building2 size={12} style={{ display: 'inline', marginRight: '4px' }} />
                              {poll.location || 'ការិយាល័យកណ្តាល'}
                            </span>
                          </td>
                          <td style={{ textAlign: 'center' }}>
                            <span style={{ background: '#f1f5f9', color: '#475569', padding: '4px 10px', borderRadius: '20px', fontWeight: 800, fontSize: '12.5px' }}>
                              <Users size={13} style={{ display: 'inline', marginRight: '4px' }} />
                              {candCount} នាក់
                            </span>
                          </td>
                          <td style={{ textAlign: 'center' }}>
                            <span style={{ background: '#ecfdf5', color: '#059669', border: '1px solid #a7f3d0', padding: '4px 12px', borderRadius: '20px', fontWeight: 800, fontSize: '13px' }}>
                              <Vote size={13} style={{ display: 'inline', marginRight: '4px' }} />
                              {poll.total_votes || 0} សំឡេង
                            </span>
                          </td>
                          <td>
                            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                              <div>ចាប់ផ្ដើម: {poll.start_date || '-'}</div>
                              <div>បញ្ចប់: {poll.end_date || poll.ends_at || '-'}</div>
                            </div>
                          </td>
                          <td style={{ textAlign: 'center' }}>
                            <span className={isActiveBool ? 'badge badge-good' : 'badge badge-danger'}>
                              {isActiveBool ? 'សកម្ម' : 'មិនសកម្ម'}
                            </span>
                          </td>
                          <td style={{ textAlign: 'center' }}>
                            <div style={{ display: 'flex', gap: '6px', justifyContent: 'center' }}>
                              <button
                                onClick={() => {
                                  setSelectedPollForResults(poll.id);
                                  setActiveTab('results');
                                }}
                                className="btn btn-sm"
                                style={{ background: '#10b981', color: '#fff', borderRadius: '8px', padding: '5px 8px', fontWeight: 700, fontSize: '11.5px' }}
                                title="មើលលទ្ធផល"
                              >
                                <BarChart3 size={13} />
                                <span>លទ្ធផល</span>
                              </button>

                              <button
                                onClick={() => handleOpenEdit(poll)}
                                className="btn btn-secondary btn-sm"
                                style={{ borderRadius: '8px', padding: '5px 8px' }}
                                title="កែប្រែ"
                              >
                                <Edit size={13} />
                              </button>

                              <button
                                onClick={() => handleDeletePoll(poll.id, poll.title)}
                                className="btn btn-sm"
                                style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.2)', borderRadius: '8px', padding: '5px 8px' }}
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
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: POLL RESULTS (លទ្ធផលការបោះឆ្នោត & ស្ថិតិ)                           */}
      {/* ========================================================================= */}
      {activeTab === 'results' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Poll Switcher & Category Toolbar */}
          <div className="hrm-card" style={{ padding: '20px 24px', borderRadius: '18px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <label style={{ fontWeight: 800, fontSize: '13.5px', color: 'var(--text-secondary)' }}>
                ជ្រើសរើសការបោះឆ្នោត:
              </label>
              <select
                className="form-control"
                value={selectedPollForResults || ''}
                onChange={(e) => setSelectedPollForResults(Number(e.target.value))}
                style={{ height: '40px', borderRadius: '10px', fontWeight: 700, minWidth: '320px', background: '#fff' }}
              >
                {polls.map((p) => (
                  <option key={p.id} value={p.id}>
                    #{p.id} - {p.title} ({p.quarter || 'Q3'} - {p.location || 'ការិយាល័យកណ្តាល'})
                  </option>
                ))}
              </select>
            </div>

            {/* Filter Tabs */}
            <div style={{ display: 'flex', gap: '8px', background: 'var(--surface-alt)', padding: '4px', borderRadius: '10px' }}>
              {['all', 'ការិយាល័យកណ្តាល', 'ឃ្លាំង', 'ឃ្លាំង PRV', 'ឃ្លាំង PSP'].map((cat) => (
                <button
                  key={cat}
                  onClick={() => setCategoryFilter(cat)}
                  style={{
                    padding: '6px 14px',
                    borderRadius: '8px',
                    border: 'none',
                    background: categoryFilter === cat ? '#fff' : 'transparent',
                    color: categoryFilter === cat ? '#4f46e5' : 'var(--text-secondary)',
                    fontWeight: 700,
                    fontSize: '12px',
                    cursor: 'pointer',
                    boxShadow: categoryFilter === cat ? '0 2px 6px rgba(0,0,0,0.06)' : 'none',
                  }}
                >
                  {cat === 'all' ? 'ទាំងអស់' : cat}
                </button>
              ))}
            </div>
          </div>

          {/* Results Display */}
          <div className="hrm-card" style={{ padding: '28px', borderRadius: '18px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px', borderBottom: '1px solid var(--border)', paddingBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Trophy size={20} color="#f59e0b" />
                  <span>{currentResultBundle?.poll?.title || 'លទ្ធផលការបោះឆ្នោត'}</span>
                </h3>
                <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: 'var(--text-secondary)' }}>
                  សំឡេងឆ្នោតសរុប៖ <strong>{currentResultBundle?.total_votes || 0} សំឡេង</strong> | ទីតាំង៖ {currentResultBundle?.poll?.location || 'ការិយាល័យកណ្តាល'}
                </p>
              </div>

              <button onClick={() => loadPollResults(selectedPollForResults || undefined)} className="btn btn-secondary btn-sm" style={{ borderRadius: '10px' }}>
                <RotateCw size={13} />
                <span>Refresh លទ្ធផល</span>
              </button>
            </div>

            {filteredCandidates.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '50px', color: 'var(--text-muted)' }}>
                មិនទាន់មានទិន្នន័យសំឡេងឆ្នោតសម្រាប់បេក្ខជននៅក្នុងផ្នែកនេះនៅឡើយទេ
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: '18px' }}>
                {filteredCandidates.map((cand, idx) => {
                  const rank = idx + 1;
                  const rankColor = rank === 1 ? '#f59e0b' : rank === 2 ? '#94a3b8' : rank === 3 ? '#b45309' : '#6366f1';
                  const initials = (cand.name || cand.employee_id).substring(0, 2).toUpperCase();

                  return (
                    <div
                      key={cand.id || cand.employee_id}
                      style={{
                        background: '#fff',
                        border: rank === 1 ? '2px solid #f59e0b' : '1px solid var(--border)',
                        borderRadius: '16px',
                        padding: '18px 20px',
                        boxShadow: rank === 1 ? '0 8px 24px rgba(245, 158, 11, 0.12)' : '0 2px 8px rgba(0,0,0,0.03)',
                        position: 'relative',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '14px',
                      }}
                    >
                      {/* Rank Badge */}
                      <div
                        style={{
                          position: 'absolute',
                          top: '16px',
                          right: '16px',
                          background: rank <= 3 ? rankColor : 'rgba(99, 102, 241, 0.1)',
                          color: rank <= 3 ? '#fff' : '#6366f1',
                          width: '32px',
                          height: '32px',
                          borderRadius: '10px',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontWeight: 800,
                          fontSize: '14px',
                        }}
                      >
                        {rank === 1 ? '🥇' : rank === 2 ? '🥈' : rank === 3 ? '🥉' : `#${rank}`}
                      </div>

                      {/* Candidate Info */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                        <div
                          style={{
                            width: '52px',
                            height: '52px',
                            borderRadius: '14px',
                            background: rankColor,
                            color: '#fff',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontWeight: 800,
                            fontSize: '18px',
                            overflow: 'hidden',
                            flexShrink: 0,
                          }}
                        >
                          {cand.avatar ? (
                            <img src={cand.avatar} alt="" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                          ) : (
                            initials
                          )}
                        </div>

                        <div style={{ minWidth: 0, flex: 1, paddingRight: '40px' }}>
                          <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {cand.name}
                          </div>
                          <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                            #{cand.employee_id} • {cand.department || cand.category}
                          </div>
                        </div>
                      </div>

                      {/* Vote Progress Bar */}
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px', fontSize: '13px' }}>
                          <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>សំឡេងឆ្នោតទទួលបាន:</span>
                          <span style={{ fontWeight: 800, color: '#4f46e5' }}>
                            {cand.votes_count || 0} សំឡេង ({cand.percentage || 0}%)
                          </span>
                        </div>

                        <div style={{ width: '100%', height: '10px', background: '#f1f5f9', borderRadius: '6px', overflow: 'hidden' }}>
                          <div
                            style={{
                              width: `${cand.percentage || 0}%`,
                              height: '100%',
                              background: rank === 1 ? 'linear-gradient(90deg, #f59e0b, #fbbf24)' : 'linear-gradient(90deg, #4f46e5, #6366f1)',
                              borderRadius: '6px',
                              transition: 'width 0.5s ease',
                            }}
                          />
                        </div>
                      </div>

                      {/* Voter Audit Button */}
                      {cand.voters && cand.voters.length > 0 && (
                        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                          <button
                            type="button"
                            onClick={() => setVoterModalCandidate(cand)}
                            className="btn btn-secondary btn-sm"
                            style={{ fontSize: '11.5px', borderRadius: '8px', padding: '4px 10px' }}
                          >
                            <Eye size={12} />
                            <span>អ្នកបោះឆ្នោត ({cand.voters.length} នាក់)</span>
                          </button>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL: CREATE / EDIT POLL (ដូចគ្នានឹង pollModal ក្នុង admin_attendance.php)   */}
      {/* ========================================================================= */}
      <Modal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        title={editingPollId ? 'កែសម្រួលការបោះឆ្នោត' : 'បង្កើតការបោះឆ្នោតថ្មី'}
      >
        <form onSubmit={handleSavePoll} style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
          {/* Title */}
          <div>
            <label className="form-label" style={{ fontWeight: 700, fontSize: '13px' }}>
              ចំណងជើង <span style={{ color: '#ef4444' }}>*</span>
            </label>
            <input
              type="text"
              className="form-input"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="ឧ. ការបោះឆ្នោតជ្រើសរើសបុគ្គលិកឆ្នើមប្រចាំត្រីមាស Q3"
              required
              style={{ height: '42px', borderRadius: '10px' }}
            />
          </div>

          {/* Quarter & Location Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
            <div>
              <label className="form-label" style={{ fontWeight: 700, fontSize: '13px' }}>
                ត្រីមាស (Quarter)
              </label>
              <select
                className="form-control"
                value={quarter}
                onChange={(e) => setQuarter(e.target.value)}
                style={{ height: '42px', borderRadius: '10px' }}
              >
                <option value="Q1">ត្រីមាសទី ១ (Q1)</option>
                <option value="Q2">ត្រីមាសទី ២ (Q2)</option>
                <option value="Q3">ត្រីមាសទី ៣ (Q3)</option>
                <option value="Q4">ត្រីមាសទី ៤ (Q4)</option>
              </select>
            </div>

            <div>
              <label className="form-label" style={{ fontWeight: 700, fontSize: '13px' }}>
                Warehouse (ទីតាំង/ឃ្លាំង)
              </label>
              <select
                className="form-control"
                value={location}
                onChange={(e) => setLocation(e.target.value)}
                style={{ height: '42px', borderRadius: '10px' }}
              >
                <option value="ការិយាល័យកណ្តាល">ការិយាល័យកណ្តាល</option>
                <option value="ឃ្លាំង">ឃ្លាំង</option>
                <option value="ឃ្លាំង PRV">ឃ្លាំង PRV</option>
                <option value="ឃ្លាំង PSP">ឃ្លាំង PSP</option>
              </select>
            </div>
          </div>

          {/* Dates */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
            <div>
              <label className="form-label" style={{ fontWeight: 700, fontSize: '13px' }}>
                កាលបរិច្ឆេទចាប់ផ្ដើម <span style={{ color: '#ef4444' }}>*</span>
              </label>
              <input
                type="date"
                className="form-input"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                required
                style={{ height: '42px', borderRadius: '10px' }}
              />
            </div>

            <div>
              <label className="form-label" style={{ fontWeight: 700, fontSize: '13px' }}>
                កាលបរិច្ឆេទបញ្ចប់ <span style={{ color: '#ef4444' }}>*</span>
              </label>
              <input
                type="date"
                className="form-input"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                required
                style={{ height: '42px', borderRadius: '10px' }}
              />
            </div>
          </div>

          {/* Access Code & Status */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
            <div>
              <label className="form-label" style={{ fontWeight: 700, fontSize: '13px' }}>
                លេខកូដប្រើចូលមើល (ទុកទទេបើមិនប្រើ)
              </label>
              <input
                type="text"
                className="form-input"
                value={accessCode}
                onChange={(e) => setAccessCode(e.target.value)}
                placeholder="ឧ. 123456"
                style={{ height: '42px', borderRadius: '10px' }}
              />
            </div>

            <div>
              <label className="form-label" style={{ fontWeight: 700, fontSize: '13px' }}>
                ស្ថានភាព (Status)
              </label>
              <div style={{ display: 'flex', gap: '20px', alignItems: 'center', height: '42px' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', fontWeight: 600, fontSize: '13px' }}>
                  <input
                    type="radio"
                    name="is_active"
                    value="1"
                    checked={isActive === 1}
                    onChange={() => setIsActive(1)}
                  />
                  <span>សកម្ម</span>
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', fontWeight: 600, fontSize: '13px' }}>
                  <input
                    type="radio"
                    name="is_active"
                    value="0"
                    checked={isActive === 0}
                    onChange={() => setIsActive(0)}
                  />
                  <span>មិនសកម្ម</span>
                </label>
              </div>
            </div>
          </div>

          {/* Candidate Selection List */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <label className="form-label" style={{ fontWeight: 700, fontSize: '13px', margin: 0 }}>
                ជ្រើសរើសបេក្ខជន ({selectedCandidateIds.length} នាក់)
              </label>

              <div style={{ width: '220px' }}>
                <input
                  type="text"
                  placeholder="ស្វែងរកឈ្មោះ ឬ ID..."
                  value={candidateSearch}
                  onChange={(e) => setCandidateSearch(e.target.value)}
                  style={{
                    height: '32px',
                    borderRadius: '8px',
                    fontSize: '12px',
                    padding: '0 10px',
                    border: '1px solid var(--border)',
                    width: '100%',
                  }}
                />
              </div>
            </div>

            <div
              style={{
                border: '1px solid var(--border)',
                borderRadius: '12px',
                padding: '12px',
                maxHeight: '220px',
                overflowY: 'auto',
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
                gap: '8px',
                background: 'var(--surface-alt)',
              }}
            >
              {filteredEmployees.length === 0 ? (
                <div style={{ gridColumn: '1/-1', textAlign: 'center', padding: '20px', color: 'var(--text-muted)', fontSize: '12.5px' }}>
                  រកមិនឃើញបុគ្គលិកឡើយ
                </div>
              ) : (
                filteredEmployees.map((emp) => {
                  const isChecked = selectedCandidateIds.includes(emp.employee_id);

                  return (
                    <label
                      key={emp.employee_id}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        padding: '6px 10px',
                        borderRadius: '8px',
                        background: isChecked ? 'var(--primary-light)' : '#fff',
                        border: isChecked ? '1px solid var(--primary)' : '1px solid var(--border)',
                        cursor: 'pointer',
                        userSelect: 'none',
                        fontSize: '12.5px',
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => toggleCandidateSelection(emp.employee_id)}
                        style={{ cursor: 'pointer' }}
                      />
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div style={{ fontWeight: 700, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {emp.name}
                        </div>
                        <div style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>
                          #{emp.employee_id}
                        </div>
                      </div>
                    </label>
                  );
                })
              )}
            </div>
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '10px' }}>
            <button
              type="button"
              onClick={() => setModalOpen(false)}
              className="btn btn-secondary"
              style={{ borderRadius: '10px', padding: '10px 20px' }}
            >
              បោះបង់
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              style={{ borderRadius: '10px', padding: '10px 24px', fontWeight: 700 }}
            >
              <Check size={16} />
              <span>{editingPollId ? 'រក្សាទុកការកែប្រែ' : 'បង្កើតការបោះឆ្នោត'}</span>
            </button>
          </div>
        </form>
      </Modal>

      {/* ========================================================================= */}
      {/* MODAL: VOTER AUDIT (មើលបញ្ជីអ្នកដែលបានបោះឆ្នោត)                            */}
      {/* ========================================================================= */}
      {voterModalCandidate && (
        <Modal
          isOpen={true}
          onClose={() => setVoterModalCandidate(null)}
          title={`បញ្ជីអ្នកបោះឆ្នោតជូន៖ ${voterModalCandidate.name}`}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-secondary)' }}>
              ទទួលបានសរុប៖ <strong>{voterModalCandidate.votes_count || 0} សំឡេង</strong>
            </p>

            <div style={{ maxHeight: '320px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {voterModalCandidate.voters && voterModalCandidate.voters.length > 0 ? (
                voterModalCandidate.voters.map((v, i) => (
                  <div
                    key={i}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '10px',
                      padding: '8px 12px',
                      borderRadius: '10px',
                      background: 'var(--surface-alt)',
                      border: '1px solid var(--border)',
                    }}
                  >
                    <div
                      style={{
                        width: '32px',
                        height: '32px',
                        borderRadius: '8px',
                        background: '#6366f1',
                        color: '#fff',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontWeight: 800,
                        fontSize: '12px',
                      }}
                    >
                      {v.name.substring(0, 2).toUpperCase()}
                    </div>
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div style={{ fontWeight: 700, fontSize: '13px', color: 'var(--text-primary)' }}>
                        {v.name}
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                        ID: #{v.employee_id} {v.voted_at ? `• ${v.voted_at}` : ''}
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ textAlign: 'center', padding: '20px', color: 'var(--text-muted)' }}>
                  មិនមានព័ត៌មានលម្អិតអ្នកបោះឆ្នោតឡើយ
                </div>
              )}
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
