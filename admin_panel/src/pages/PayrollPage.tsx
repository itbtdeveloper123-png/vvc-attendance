import React, { useState, useEffect } from 'react';
import {
  DollarSign,
  Download,
  Plus,
  Search,
  CheckCircle,
  RotateCw,
  Check,
  Calendar,
  CreditCard,
  QrCode,
  FileSpreadsheet,
  History,
  TrendingDown,
  Clock,
  Printer,
  X,
  AlertCircle,
  MinusCircle,
  PlusCircle,
  HelpCircle,
  Eye,
} from 'lucide-react';
import { StatCard } from '../components/common/StatCard';
import { Modal } from '../components/common/Modal';
import { adminApi, PayrollItem } from '../api/adminApi';

export const PayrollPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'payroll_dashboard' | 'manage_salaries' | 'adjustments' | 'payroll_history'>('payroll_dashboard');

  // Month & Year Filter
  const [selectedMonth, setSelectedMonth] = useState(new Date().getMonth() + 1);
  const [selectedYear, setSelectedYear] = useState(new Date().getFullYear());

  // Dashboard Data
  const [salaries, setSalaries] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [calculating, setCalculating] = useState(false);

  // Bank Configs Data
  const [configs, setConfigs] = useState<any[]>([]);
  const [loadingConfigs, setLoadingConfigs] = useState(false);
  const [editingConfigId, setEditingConfigId] = useState<string | null>(null);
  const [configForm, setConfigForm] = useState({
    employee_id: '',
    base_salary: 0,
    bank_name: '',
    bank_account_number: '',
  });
  const [qrFile, setQrFile] = useState<File | null>(null);
  const [previewQrUrl, setPreviewQrUrl] = useState<string | null>(null);

  // Adjustments Data
  const [adjustSubTab, setAdjustSubTab] = useState<'deduction' | 'ot' | 'loan'>('deduction');
  const [usersList, setUsersList] = useState<any[]>([]);
  const [deductions, setDeductions] = useState<any[]>([]);
  const [ots, setOts] = useState<any[]>([]);
  const [loans, setLoans] = useState<any[]>([]);

  // Adjustment Forms
  const [deductForm, setDeductForm] = useState({ emp_id: '', amount: 0, reason: '', deduction_date: new Date().toISOString().split('T')[0] });
  const [otForm, setOtForm] = useState({ emp_id: '', ot_hours: 0, ot_rate: 3.5, reason: '', ot_date: new Date().toISOString().split('T')[0] });
  const [loanForm, setLoanForm] = useState({ emp_id: '', total_loan: 0, monthly_installment: 0, reason: '' });

  // History Data
  const [historyList, setHistoryList] = useState<any[]>([]);

  // Payslip Modal
  const [payslipItem, setPayslipItem] = useState<any | null>(null);

  // Banner
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const showBanner = (type: 'success' | 'error', text: string) => {
    setBanner({ type, text });
    setTimeout(() => setBanner(null), 3500);
  };

  const loadPayroll = async () => {
    setLoading(true);
    try {
      const res = await adminApi.fetchPayroll(selectedMonth, selectedYear);
      if (res && res.success && Array.isArray(res.salaries)) {
        setSalaries(res.salaries);
      }
    } catch (err) {
      console.error('Error fetching payroll:', err);
    }
    setLoading(false);
  };

  const loadConfigs = async () => {
    setLoadingConfigs(true);
    try {
      const res = await adminApi.fetchPayrollConfigs();
      if (res && res.success && Array.isArray(res.configs)) {
        setConfigs(res.configs);
      }
    } catch (err) {
      console.error('Error loading payroll configs:', err);
    }
    setLoadingConfigs(false);
  };

  const loadAdjustments = async () => {
    try {
      const res = await adminApi.fetchPayrollAdjustments();
      if (res && res.success) {
        if (res.deductions) setDeductions(res.deductions);
        if (res.ots) setOts(res.ots);
        if (res.loans) setLoans(res.loans);
      }
      const uRes = await adminApi.fetchUsers();
      if (uRes && uRes.success && Array.isArray(uRes.users)) {
        setUsersList(uRes.users);
      }
    } catch (err) {
      console.error('Error loading adjustments:', err);
    }
  };

  const loadHistory = async () => {
    try {
      const res = await adminApi.fetchPayrollHistory();
      if (res && res.success && Array.isArray(res.history)) {
        setHistoryList(res.history);
      }
    } catch (err) {
      console.error('Error loading history:', err);
    }
  };

  useEffect(() => {
    if (activeTab === 'payroll_dashboard') loadPayroll();
    if (activeTab === 'manage_salaries') loadConfigs();
    if (activeTab === 'adjustments') loadAdjustments();
    if (activeTab === 'payroll_history') loadHistory();
  }, [activeTab, selectedMonth, selectedYear]);

  const handleCalculate = async () => {
    setCalculating(true);
    try {
      const res = await adminApi.calculatePayroll(selectedMonth, selectedYear);
      if (res && res.success) {
        showBanner('success', res.message || 'បានគណនាប្រាក់បៀវត្សជោគជ័យ!');
        await loadPayroll();
      } else {
        showBanner('error', res?.message || 'Error calculating payroll');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការគណនាប្រាក់បៀវត្ស');
    }
    setCalculating(false);
  };

  const handleToggleStatus = async (item: any) => {
    const newStatus = item.status === 'Paid' ? 'Pending' : 'Paid';
    try {
      await adminApi.savePayroll({
        id: item.id,
        employee_id: item.employee_id,
        name: item.name,
        base_salary: item.base_salary,
        days_present: item.days_present,
        ot_hours: item.ot_hours,
        ot_amount: item.ot_amount,
        deductions: item.deductions,
        loans: item.loans,
        net_salary: item.net_salary,
        status: newStatus,
        month: selectedMonth,
        year: selectedYear,
      });
      showBanner('success', `បានកែប្រែស្ថានភាព ${item.name} ទៅជា ${newStatus}`);
      loadPayroll();
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការកែប្រែស្ថានភាព');
    }
  };

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!configForm.employee_id) return;
    try {
      const fd = new FormData();
      fd.append('employee_id', configForm.employee_id);
      fd.append('base_salary', String(configForm.base_salary));
      fd.append('bank_name', configForm.bank_name);
      fd.append('bank_account_number', configForm.bank_account_number);
      if (qrFile) fd.append('bank_qr', qrFile);

      const res = await adminApi.savePayrollConfig(fd);
      if (res && res.success) {
        showBanner('success', res.message || 'បានរក្សាទុកព័ត៌មានធនាគារជោគជ័យ!');
        setEditingConfigId(null);
        setQrFile(null);
        loadConfigs();
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការរក្សាទុក');
    }
  };

  const handleSaveDeduction = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!deductForm.emp_id || deductForm.amount <= 0) return;
    try {
      const res = await adminApi.savePayrollDeduction(deductForm);
      if (res && res.success) {
        showBanner('success', 'បានរក្សាទុកការកាត់ប្រាក់ជោគជ័យ!');
        setDeductForm({ emp_id: '', amount: 0, reason: '', deduction_date: new Date().toISOString().split('T')[0] });
        loadAdjustments();
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការរក្សាទុក');
    }
  };

  const handleSaveOt = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!otForm.emp_id || otForm.ot_hours <= 0) return;
    try {
      const res = await adminApi.savePayrollOt(otForm);
      if (res && res.success) {
        showBanner('success', 'បានរក្សាទុកប្រាក់ថែមម៉ោងជោគជ័យ!');
        setOtForm({ emp_id: '', ot_hours: 0, ot_rate: 3.5, reason: '', ot_date: new Date().toISOString().split('T')[0] });
        loadAdjustments();
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការរក្សាទុក');
    }
  };

  const handleSaveLoan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!loanForm.emp_id || loanForm.total_loan <= 0) return;
    try {
      const res = await adminApi.savePayrollLoan(loanForm);
      if (res && res.success) {
        showBanner('success', 'បានរក្សាទុកបំណុលជោគជ័យ!');
        setLoanForm({ emp_id: '', total_loan: 0, monthly_installment: 0, reason: '' });
        loadAdjustments();
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការរក្សាទុក');
    }
  };

  const totalPayroll = salaries.reduce((acc, s) => acc + (Number(s.net_salary) || 0), 0);
  const totalOt = salaries.reduce((acc, s) => acc + (Number(s.ot_amount) || 0), 0);
  const totalDeductions = salaries.reduce((acc, s) => acc + (Number(s.deductions) || 0), 0);
  const paidCount = salaries.filter((s) => s.status === 'Paid').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '1200px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h2 style={{ fontSize: '22px', fontWeight: 800, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
            <DollarSign size={24} color="#6366f1" />
            ប្រព័ន្ធគ្រប់គ្រងប្រាក់បៀវត្ស (Payroll Management)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: '4px 0 0' }}>
            គណនាប្រាក់បៀវត្សគោល ថែមម៉ោង (OT) កាត់កង បំណុល ធនាគារ Bank QR និងចេញប័ណ្ណបើកប្រាក់ខែ (Payslip)
          </p>
        </div>

        {activeTab === 'payroll_dashboard' && (
          <button onClick={handleCalculate} disabled={calculating} className="btn btn-gold" style={{ padding: '10px 22px' }}>
            <DollarSign size={16} />
            <span>{calculating ? 'កំពុងគណនា...' : 'គណនាប្រាក់ខែ (Calculate)'}</span>
          </button>
        )}
      </div>

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
          <CheckCircle size={16} />
          <span>{banner.text}</span>
        </div>
      )}

      {/* Main Tabs */}
      <div
        className="hrm-card"
        style={{
          padding: '10px 14px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          overflowX: 'auto',
          borderRadius: '16px',
        }}
      >
        {[
          { id: 'payroll_dashboard', label: '📊 ផ្ទាំងគណនា & បើកប្រាក់ខែ (Dashboard)', icon: DollarSign },
          { id: 'manage_salaries', label: '💳 ប្រាក់ខែគោល & គណនីធនាគារ (Bank & QR)', icon: CreditCard },
          { id: 'adjustments', label: '⚙️ កាត់ប្រាក់ / OT / បំណុល (Adjustments)', icon: TrendingDown },
          { id: 'payroll_history', label: '🕒 ប្រវត្តិទូទាត់ប្រាក់ (Payment History)', icon: History },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`btn btn-sm ${isActive ? 'btn-primary' : 'btn-secondary'}`}
              style={{
                borderRadius: '12px',
                padding: '8px 16px',
                fontWeight: isActive ? 800 : 500,
                whiteSpace: 'nowrap',
              }}
            >
              <Icon size={14} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* ========================================================================= */}
      {/* 1. PAYROLL DASHBOARD */}
      {/* ========================================================================= */}
      {activeTab === 'payroll_dashboard' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Month / Year Filter Toolbar */}
          <div className="hrm-card" style={{ padding: '16px 20px', display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-secondary)' }}>ខែ (Month):</span>
              <select
                className="form-input"
                style={{ width: '130px', height: '38px' }}
                value={selectedMonth}
                onChange={(e) => setSelectedMonth(Number(e.target.value))}
              >
                {Array.from({ length: 12 }, (_, i) => i + 1).map((m) => (
                  <option key={m} value={m}>ខែ {m}</option>
                ))}
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-secondary)' }}>ឆ្នាំ (Year):</span>
              <select
                className="form-input"
                style={{ width: '130px', height: '38px' }}
                value={selectedYear}
                onChange={(e) => setSelectedYear(Number(e.target.value))}
              >
                {[2024, 2025, 2026, 2027, 2028].map((y) => (
                  <option key={y} value={y}>{y}</option>
                ))}
              </select>
            </div>

            <button type="button" onClick={loadPayroll} className="btn btn-secondary btn-sm" style={{ height: '38px' }}>
              <RotateCw size={14} className={loading ? 'animate-spin' : ''} />
              <span>បង្ហាញ</span>
            </button>
          </div>

          {/* KPI Stat Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
            <div className="hrm-card" style={{ padding: '18px 22px', borderTop: '4px solid #6366f1' }}>
              <div style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 800, color: 'var(--text-muted)' }}>ប្រាក់បៀវត្សសរុបខែនេះ</div>
              <div style={{ fontSize: '24px', fontWeight: 900, color: '#6366f1', margin: '4px 0' }}>${totalPayroll.toFixed(2)}</div>
              <div style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>Net Salary សម្រាប់បុគ្គលិកទាំងអស់</div>
            </div>

            <div className="hrm-card" style={{ padding: '18px 22px', borderTop: '4px solid #10b981' }}>
              <div style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 800, color: 'var(--text-muted)' }}>ប្រាក់ថែមម៉ោងសរុប (OT)</div>
              <div style={{ fontSize: '24px', fontWeight: 900, color: '#10b981', margin: '4px 0' }}>${totalOt.toFixed(2)}</div>
              <div style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>បូកបន្ថែមសម្រាប់ម៉ោងការងារបន្ថែម</div>
            </div>

            <div className="hrm-card" style={{ padding: '18px 22px', borderTop: '4px solid #ef4444' }}>
              <div style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 800, color: 'var(--text-muted)' }}>កាត់កងសរុប (Deductions)</div>
              <div style={{ fontSize: '24px', fontWeight: 900, color: '#ef4444', margin: '4px 0' }}>-${totalDeductions.toFixed(2)}</div>
              <div style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>មកយឺត អវត្តមាន & បំណុល</div>
            </div>

            <div className="hrm-card" style={{ padding: '18px 22px', borderTop: '4px solid #f59e0b' }}>
              <div style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 800, color: 'var(--text-muted)' }}>ស្ថានភាពបើកប្រាក់ខែ</div>
              <div style={{ fontSize: '24px', fontWeight: 900, color: '#f59e0b', margin: '4px 0' }}>{paidCount} / {salaries.length}</div>
              <div style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>បុគ្គលិកបានទទួលប្រាក់ខែ</div>
            </div>
          </div>

          {/* Payroll Results Table */}
          <div className="table-container">
            <table className="hrm-table">
              <thead>
                <tr>
                  <th>បុគ្គលិក (Employee)</th>
                  <th>ប្រាក់ខែគោល</th>
                  <th style={{ textAlign: 'center' }}>វត្តមាន (Days)</th>
                  <th style={{ color: '#ef4444' }}>កាត់ (Deduct)</th>
                  <th style={{ color: '#10b981' }}>ថែម (OT)</th>
                  <th style={{ color: '#f59e0b' }}>បំណុល (Loan)</th>
                  <th style={{ fontWeight: 800 }}>ប្រាក់ខែសុទ្ធ (Net)</th>
                  <th>ស្ថានភាព</th>
                  <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
                </tr>
              </thead>
              <tbody>
                {salaries.length === 0 ? (
                  <tr>
                    <td colSpan={9} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                      {loading ? 'កំពុងទាញយកទិន្នន័យប្រាក់បៀវត្ស...' : 'មិនទាន់មានទិន្នន័យសម្រាប់ខែនេះឡើយ សូមចុចប៊ូតុង "គណនាប្រាក់ខែ"'}
                    </td>
                  </tr>
                ) : (
                  salaries.map((s) => (
                    <tr key={s.id}>
                      <td>
                        <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{s.name || s.user_name}</div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{s.employee_id} • {s.department || 'Staff'}</div>
                      </td>
                      <td>${Number(s.base_salary).toFixed(2)}</td>
                      <td style={{ textAlign: 'center' }}>{s.days_present || 26} ថ្ងៃ</td>
                      <td style={{ color: '#ef4444', fontWeight: 600 }}>-${Number(s.deductions).toFixed(2)}</td>
                      <td style={{ color: '#10b981', fontWeight: 600 }}>+${Number(s.ot_amount).toFixed(2)}</td>
                      <td style={{ color: '#f59e0b', fontWeight: 600 }}>-${Number(s.loans || 0).toFixed(2)}</td>
                      <td style={{ fontWeight: 900, fontSize: '14.5px', color: '#6366f1' }}>${Number(s.net_salary).toFixed(2)}</td>
                      <td>
                        <span className={`badge ${s.status === 'Paid' ? 'badge-good' : 'badge-late'}`}>
                          {s.status === 'Paid' ? '✅ បានបើករួច' : '⏳ រង់ចាំបើក'}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: '6px' }}>
                          <button
                            type="button"
                            onClick={() => setPayslipItem(s)}
                            className="btn btn-secondary btn-sm"
                            title="មើលប័ណ្ណបើកប្រាក់ខែ (Payslip)"
                            style={{ padding: '4px 8px' }}
                          >
                            <Eye size={13} />
                            <span>Slip</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => handleToggleStatus(s)}
                            className={`btn btn-sm ${s.status === 'Paid' ? 'btn-secondary' : 'btn-primary'}`}
                            style={{ padding: '4px 10px' }}
                          >
                            <span>{s.status === 'Paid' ? 'កែជា Pending' : 'បើកប្រាក់ខែ'}</span>
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
      )}

      {/* ========================================================================= */}
      {/* 2. MANAGE SALARIES & BANK QR */}
      {/* ========================================================================= */}
      {activeTab === 'manage_salaries' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div className="table-container">
            <table className="hrm-table">
              <thead>
                <tr>
                  <th>អត្តលេខ</th>
                  <th>ឈ្មោះបុគ្គលិក</th>
                  <th>ប្រាក់ខែគោល ($)</th>
                  <th>ធនាគារ (Bank Name/Acc)</th>
                  <th style={{ textAlign: 'center' }}>Bank QR Code</th>
                  <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
                </tr>
              </thead>
              <tbody>
                {configs.length === 0 ? (
                  <tr><td colSpan={6} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>{loadingConfigs ? 'កំពុងទាញយក...' : 'មិនមានទិន្នន័យឡើយ'}</td></tr>
                ) : (
                  configs.map((c) => (
                    <tr key={c.employee_id}>
                      <td style={{ fontWeight: 800, color: 'var(--primary)' }}>{c.employee_id}</td>
                      <td style={{ fontWeight: 700 }}>{c.name}</td>
                      <td style={{ fontWeight: 700, color: '#10b981' }}>${Number(c.base_salary).toFixed(2)}</td>
                      <td>
                        {c.bank_name ? `${c.bank_name} - ${c.bank_account_number || ''}` : <span style={{ color: 'var(--text-muted)' }}>មិនទាន់កំណត់</span>}
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        {c.bank_qr_url ? (
                          <img
                            src={c.bank_qr_url}
                            alt="QR"
                            onClick={() => setPreviewQrUrl(c.bank_qr_url)}
                            style={{ width: '42px', height: '42px', objectFit: 'cover', borderRadius: '8px', cursor: 'pointer', border: '2px solid #6366f1' }}
                          />
                        ) : (
                          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>គ្មាន QR</span>
                        )}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          type="button"
                          onClick={() => {
                            setEditingConfigId(c.employee_id);
                            setConfigForm({
                              employee_id: c.employee_id,
                              base_salary: Number(c.base_salary) || 0,
                              bank_name: c.bank_name || 'ABA Bank',
                              bank_account_number: c.bank_account_number || '',
                            });
                          }}
                          className="btn btn-secondary btn-sm"
                        >
                          <span>កែសម្រួល / QR</span>
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 3. ADJUSTMENTS (DEDUCTIONS / OT / LOANS) */}
      {/* ========================================================================= */}
      {activeTab === 'adjustments' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Sub-tabs */}
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              onClick={() => setAdjustSubTab('deduction')}
              className={`btn btn-sm ${adjustSubTab === 'deduction' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ borderRadius: '10px' }}
            >
              <MinusCircle size={14} />
              <span>កាត់ប្រាក់ (Deductions)</span>
            </button>
            <button
              onClick={() => setAdjustSubTab('ot')}
              className={`btn btn-sm ${adjustSubTab === 'ot' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ borderRadius: '10px' }}
            >
              <PlusCircle size={14} />
              <span>ប្រាក់ថែមម៉ោង (OT Bonus)</span>
            </button>
            <button
              onClick={() => setAdjustSubTab('loan')}
              className={`btn btn-sm ${adjustSubTab === 'loan' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ borderRadius: '10px' }}
            >
              <CreditCard size={14} />
              <span>បំណុល / កម្ចី (Loan)</span>
            </button>
          </div>

          {/* DEDUCTION SUBTAB */}
          {adjustSubTab === 'deduction' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(300px, 380px) 1fr', gap: '20px', alignItems: 'start' }}>
              <form onSubmit={handleSaveDeduction} className="hrm-card" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 800, color: '#ef4444' }}>បញ្ចូលការកាត់ប្រាក់</h4>
                <div className="form-group">
                  <label className="form-label">ជ្រើសរើសបុគ្គលិក *</label>
                  <select
                    className="form-input"
                    value={deductForm.emp_id}
                    onChange={(e) => setDeductForm({ ...deductForm, emp_id: e.target.value })}
                    required
                  >
                    <option value="">-- ជ្រើសរើសបុគ្គលិក --</option>
                    {usersList.map((u) => (
                      <option key={u.employee_id} value={u.employee_id}>{u.name} ({u.employee_id})</option>
                    ))}
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">ចំនួនទឹកប្រាក់ ($) *</label>
                  <input
                    type="number"
                    step="0.01"
                    className="form-input"
                    value={deductForm.amount}
                    onChange={(e) => setDeductForm({ ...deductForm, amount: Number(e.target.value) })}
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">មូលហេតុ *</label>
                  <input
                    type="text"
                    className="form-input"
                    value={deductForm.reason}
                    onChange={(e) => setDeductForm({ ...deductForm, reason: e.target.value })}
                    placeholder="ឧ. មកយឺតលើសពី ៣ ដង"
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">កាលបរិច្ឆេទ</label>
                  <input
                    type="date"
                    className="form-input"
                    value={deductForm.deduction_date}
                    onChange={(e) => setDeductForm({ ...deductForm, deduction_date: e.target.value })}
                  />
                </div>
                <button type="submit" className="btn btn-primary" style={{ background: '#ef4444', borderColor: '#ef4444', marginTop: '6px' }}>
                  <span>រក្សាទុកកាត់ប្រាក់</span>
                </button>
              </form>

              <div className="hrm-card" style={{ padding: '20px' }}>
                <h4 style={{ margin: '0 0 14px', fontSize: '15px', fontWeight: 800 }}>ប្រវត្តិការកាត់ប្រាក់ ({deductions.length})</h4>
                <div className="table-container" style={{ margin: 0 }}>
                  <table className="hrm-table">
                    <thead>
                      <tr><th>បុគ្គលិក</th><th>ចំនួនទឹកប្រាក់</th><th>មូលហេតុ</th><th>កាលបរិច្ឆេទ</th></tr>
                    </thead>
                    <tbody>
                      {deductions.length === 0 ? (
                        <tr><td colSpan={4} style={{ textAlign: 'center', padding: '20px', color: 'var(--text-muted)' }}>មិនទាន់មានទិន្នន័យ</td></tr>
                      ) : (
                        deductions.map((d: any) => (
                          <tr key={d.id}>
                            <td style={{ fontWeight: 700 }}>{d.emp_name} <br/><small style={{ color: 'var(--text-muted)' }}>{d.employee_id}</small></td>
                            <td style={{ color: '#ef4444', fontWeight: 800 }}>-${Number(d.amount).toFixed(2)}</td>
                            <td>{d.reason}</td>
                            <td style={{ fontSize: '12px' }}>{d.deduction_date}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* OT SUBTAB */}
          {adjustSubTab === 'ot' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(300px, 380px) 1fr', gap: '20px', alignItems: 'start' }}>
              <form onSubmit={handleSaveOt} className="hrm-card" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 800, color: '#10b981' }}>បញ្ចូលប្រាក់ថែមម៉ោង</h4>
                <div className="form-group">
                  <label className="form-label">ជ្រើសរើសបុគ្គលិក *</label>
                  <select
                    className="form-input"
                    value={otForm.emp_id}
                    onChange={(e) => setOtForm({ ...otForm, emp_id: e.target.value })}
                    required
                  >
                    <option value="">-- ជ្រើសរើសបុគ្គលិក --</option>
                    {usersList.map((u) => (
                      <option key={u.employee_id} value={u.employee_id}>{u.name} ({u.employee_id})</option>
                    ))}
                  </select>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                  <div className="form-group">
                    <label className="form-label">ចំនួនម៉ោង OT *</label>
                    <input
                      type="number"
                      step="0.5"
                      className="form-input"
                      value={otForm.ot_hours}
                      onChange={(e) => setOtForm({ ...otForm, ot_hours: Number(e.target.value) })}
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">តម្លៃក្នុង ១ ម៉ោង ($)</label>
                    <input
                      type="number"
                      step="0.1"
                      className="form-input"
                      value={otForm.ot_rate}
                      onChange={(e) => setOtForm({ ...otForm, ot_rate: Number(e.target.value) })}
                      required
                    />
                  </div>
                </div>
                <div className="form-group">
                  <label className="form-label">មូលហេតុ</label>
                  <input
                    type="text"
                    className="form-input"
                    value={otForm.reason}
                    onChange={(e) => setOtForm({ ...otForm, reason: e.target.value })}
                    placeholder="ឧ. រៀបចំស្តុកចុងសប្តាហ៍"
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">កាលបរិច្ឆេទ</label>
                  <input
                    type="date"
                    className="form-input"
                    value={otForm.ot_date}
                    onChange={(e) => setOtForm({ ...otForm, ot_date: e.target.value })}
                  />
                </div>
                <button type="submit" className="btn btn-primary" style={{ background: '#10b981', borderColor: '#10b981', marginTop: '6px' }}>
                  <span>រក្សាទុកប្រាក់ថែមម៉ោង</span>
                </button>
              </form>

              <div className="hrm-card" style={{ padding: '20px' }}>
                <h4 style={{ margin: '0 0 14px', fontSize: '15px', fontWeight: 800 }}>ប្រវត្តិប្រាក់ថែមម៉ោង ({ots.length})</h4>
                <div className="table-container" style={{ margin: 0 }}>
                  <table className="hrm-table">
                    <thead>
                      <tr><th>បុគ្គលិក</th><th>ម៉ោង OT</th><th>សរុប ($)</th><th>មូលហេតុ</th><th>កាលបរិច្ឆេទ</th></tr>
                    </thead>
                    <tbody>
                      {ots.length === 0 ? (
                        <tr><td colSpan={5} style={{ textAlign: 'center', padding: '20px', color: 'var(--text-muted)' }}>មិនទាន់មានទិន្នន័យ</td></tr>
                      ) : (
                        ots.map((o: any) => (
                          <tr key={o.id}>
                            <td style={{ fontWeight: 700 }}>{o.emp_name} <br/><small style={{ color: 'var(--text-muted)' }}>{o.employee_id}</small></td>
                            <td>{o.ot_hours} ម៉ោង</td>
                            <td style={{ color: '#10b981', fontWeight: 800 }}>+${Number(o.total_ot_amount).toFixed(2)}</td>
                            <td>{o.reason}</td>
                            <td style={{ fontSize: '12px' }}>{o.ot_date}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* LOAN SUBTAB */}
          {adjustSubTab === 'loan' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(300px, 380px) 1fr', gap: '20px', alignItems: 'start' }}>
              <form onSubmit={handleSaveLoan} className="hrm-card" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 800, color: '#f59e0b' }}>បញ្ចូលបំណុល / ប្រាក់កម្ចី</h4>
                <div className="form-group">
                  <label className="form-label">ជ្រើសរើសបុគ្គលិក *</label>
                  <select
                    className="form-input"
                    value={loanForm.emp_id}
                    onChange={(e) => setLoanForm({ ...loanForm, emp_id: e.target.value })}
                    required
                  >
                    <option value="">-- ជ្រើសរើសបុគ្គលិក --</option>
                    {usersList.map((u) => (
                      <option key={u.employee_id} value={u.employee_id}>{u.name} ({u.employee_id})</option>
                    ))}
                  </select>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                  <div className="form-group">
                    <label className="form-label">បំណុលសរុប ($) *</label>
                    <input
                      type="number"
                      step="0.01"
                      className="form-input"
                      value={loanForm.total_loan}
                      onChange={(e) => setLoanForm({ ...loanForm, total_loan: Number(e.target.value) })}
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">កាត់ក្នុង ១ ខែ ($)</label>
                    <input
                      type="number"
                      step="0.01"
                      className="form-input"
                      value={loanForm.monthly_installment}
                      onChange={(e) => setLoanForm({ ...loanForm, monthly_installment: Number(e.target.value) })}
                      required
                    />
                  </div>
                </div>
                <div className="form-group">
                  <label className="form-label">មូលហេតុ</label>
                  <input
                    type="text"
                    className="form-input"
                    value={loanForm.reason}
                    onChange={(e) => setLoanForm({ ...loanForm, reason: e.target.value })}
                    placeholder="ឧ. បុរេប្រទានទិញសម្ភារៈ"
                  />
                </div>
                <button type="submit" className="btn btn-primary" style={{ background: '#f59e0b', borderColor: '#f59e0b', marginTop: '6px' }}>
                  <span>រក្សាទុកបំណុល</span>
                </button>
              </form>

              <div className="hrm-card" style={{ padding: '20px' }}>
                <h4 style={{ margin: '0 0 14px', fontSize: '15px', fontWeight: 800 }}>ប្រវត្តិកម្ចី & បំណុល ({loans.length})</h4>
                <div className="table-container" style={{ margin: 0 }}>
                  <table className="hrm-table">
                    <thead>
                      <tr><th>បុគ្គលិក</th><th>បំណុលសរុប</th><th>កាត់ប្រចាំខែ</th><th>មូលហេតុ</th></tr>
                    </thead>
                    <tbody>
                      {loans.length === 0 ? (
                        <tr><td colSpan={4} style={{ textAlign: 'center', padding: '20px', color: 'var(--text-muted)' }}>មិនទាន់មានទិន្នន័យ</td></tr>
                      ) : (
                        loans.map((l: any) => (
                          <tr key={l.id}>
                            <td style={{ fontWeight: 700 }}>{l.emp_name} <br/><small style={{ color: 'var(--text-muted)' }}>{l.employee_id}</small></td>
                            <td style={{ fontWeight: 800, color: '#f59e0b' }}>${Number(l.total_loan).toFixed(2)}</td>
                            <td style={{ fontWeight: 700, color: '#ef4444' }}>-${Number(l.monthly_installment).toFixed(2)} /ខែ</td>
                            <td>{l.reason}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* 4. PAYMENT HISTORY */}
      {/* ========================================================================= */}
      {activeTab === 'payroll_history' && (
        <div className="table-container">
          <table className="hrm-table">
            <thead>
              <tr>
                <th>បុគ្គលិក (Employee)</th>
                <th>ខែ-ឆ្នាំ (Month-Year)</th>
                <th>ប្រាក់ខែសរុប (Net Salary)</th>
                <th>ថ្ងៃបើកប្រាក់ (Payment Date)</th>
                <th>ស្ថានភាព</th>
              </tr>
            </thead>
            <tbody>
              {historyList.length === 0 ? (
                <tr><td colSpan={5} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>មិនទាន់មានប្រវត្តិទូទាត់ប្រាក់នៅឡើយទេ</td></tr>
              ) : (
                historyList.map((h: any) => (
                  <tr key={h.id}>
                    <td style={{ fontWeight: 700 }}>{h.emp_name} <br/><small style={{ color: 'var(--text-muted)' }}>{h.employee_id}</small></td>
                    <td style={{ fontWeight: 600 }}>{h.payroll_month}/{h.payroll_year}</td>
                    <td style={{ color: '#10b981', fontWeight: 900 }}>${Number(h.calculated_salary).toFixed(2)}</td>
                    <td style={{ fontSize: '12px' }}>{h.payment_date}</td>
                    <td><span className="badge badge-good">{h.status || 'Paid'}</span></td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Bank Config Modal */}
      {editingConfigId && (
        <Modal
          isOpen={!!editingConfigId}
          onClose={() => setEditingConfigId(null)}
          title={`កំណត់ប្រាក់ខែ & ធនាគារ (${configForm.employee_id})`}
          maxWidth="500px"
        >
          <form onSubmit={handleSaveConfig}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div className="form-group">
                <label className="form-label">ប្រាក់ខែគោល (Base Salary $)</label>
                <input
                  type="number"
                  step="0.01"
                  className="form-input"
                  value={configForm.base_salary}
                  onChange={(e) => setConfigForm({ ...configForm, base_salary: Number(e.target.value) })}
                  required
                />
              </div>
              <div className="form-group">
                <label className="form-label">ឈ្មោះធនាគារ (Bank Name)</label>
                <input
                  type="text"
                  className="form-input"
                  value={configForm.bank_name}
                  onChange={(e) => setConfigForm({ ...configForm, bank_name: e.target.value })}
                  placeholder="ឧ. ABA Bank, ACLEDA, Wing..."
                />
              </div>
              <div className="form-group">
                <label className="form-label">លេខគណនី (Account Number)</label>
                <input
                  type="text"
                  className="form-input"
                  value={configForm.bank_account_number}
                  onChange={(e) => setConfigForm({ ...configForm, bank_account_number: e.target.value })}
                  placeholder="ឧ. 001 234 567"
                />
              </div>
              <div className="form-group">
                <label className="form-label">រូបភាព Bank QR Code (Upload Image)</label>
                <input
                  type="file"
                  accept="image/*"
                  className="form-input"
                  onChange={(e) => setQrFile(e.target.files ? e.target.files[0] : null)}
                />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px', borderTop: '1px solid var(--border)', paddingTop: '14px' }}>
              <button type="button" onClick={() => setEditingConfigId(null)} className="btn btn-secondary">បោះបង់</button>
              <button type="submit" className="btn btn-primary"><Check size={16} /><span>រក្សាទុក</span></button>
            </div>
          </form>
        </Modal>
      )}

      {/* QR Preview Modal */}
      {previewQrUrl && (
        <Modal isOpen={!!previewQrUrl} onClose={() => setPreviewQrUrl(null)} title="Bank QR Code">
          <div style={{ textAlign: 'center', padding: '20px' }}>
            <img src={previewQrUrl} alt="Bank QR" style={{ maxWidth: '100%', maxHeight: '450px', borderRadius: '16px', border: '2px solid #6366f1' }} />
          </div>
        </Modal>
      )}

      {/* Payslip Modal */}
      {payslipItem && (
        <Modal isOpen={!!payslipItem} onClose={() => setPayslipItem(null)} title={`ប័ណ្ណបើកប្រាក់ខែ (Payslip) - ${payslipItem.name || payslipItem.user_name}`} maxWidth="520px">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '18px', padding: '10px' }}>
            <div style={{ textAlign: 'center', borderBottom: '2px dashed var(--border)', paddingBottom: '16px' }}>
              <h3 style={{ margin: 0, fontWeight: 900, color: 'var(--text-primary)' }}>VVC CO., LTD.</h3>
              <p style={{ margin: '4px 0 0', fontSize: '13px', color: 'var(--text-muted)' }}>
                ប័ណ្ណបើកប្រាក់ខែប្រចាំខែ {selectedMonth}/{selectedYear}
              </p>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', color: 'var(--text-secondary)' }}>
              <div><strong>ឈ្មោះ:</strong> {payslipItem.name || payslipItem.user_name}</div>
              <div><strong>អត្តលេខ:</strong> {payslipItem.employee_id}</div>
            </div>

            <div style={{ background: 'var(--surface-hover)', padding: '16px', borderRadius: '12px', display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '13.5px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>ប្រាក់ខែគោល (Base Salary):</span>
                <strong>${Number(payslipItem.base_salary).toFixed(2)}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', color: '#10b981' }}>
                <span>ប្រាក់ថែមម៉ោង ({payslipItem.ot_hours || 0} hrs OT):</span>
                <strong>+${Number(payslipItem.ot_amount || 0).toFixed(2)}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', color: '#ef4444' }}>
                <span>កាត់កង (Deductions):</span>
                <strong>-${Number(payslipItem.deductions || 0).toFixed(2)}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', color: '#f59e0b' }}>
                <span>កាត់បំណុល (Loans):</span>
                <strong>-${Number(payslipItem.loans || 0).toFixed(2)}</strong>
              </div>
              <div style={{ height: '1px', background: 'var(--border)', margin: '4px 0' }} />
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '16px', fontWeight: 900, color: '#6366f1' }}>
                <span>ប្រាក់ខែសុទ្ធ (Net Payable):</span>
                <span>${Number(payslipItem.net_salary).toFixed(2)}</span>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button type="button" onClick={() => window.print()} className="btn btn-primary" style={{ padding: '8px 24px' }}>
                <Printer size={15} />
                <span>បោះពុម្ព (Print Payslip)</span>
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
