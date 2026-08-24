import React, { useState, useEffect } from 'react';
import {
  DollarSign,
  Calculator,
  Plus,
  Search,
  CheckCircle2,
  RotateCw,
  CreditCard,
  History,
  TrendingDown,
  Printer,
  Eye,
  Building2,
  Coins,
  Layers,
  FileSpreadsheet,
  Check,
  X,
  Upload,
  User,
} from 'lucide-react';
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
  const [configSearch, setConfigSearch] = useState('');
  const [editingSalaries, setEditingSalaries] = useState<Record<string, number>>({});
  const [editingBanks, setEditingBanks] = useState<Record<string, string>>({});
  const [qrFile, setQrFile] = useState<File | null>(null);
  const [previewQrUrl, setPreviewQrUrl] = useState<string | null>(null);
  const [qrUploadEmpId, setQrUploadEmpId] = useState<string | null>(null);

  // Adjustments Data
  const [adjustSubTab, setAdjustSubTab] = useState<'deduction' | 'ot' | 'loan' | 'policy'>('deduction');
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
      if (res && (res.success || res.status === 'success')) {
        const list = Array.isArray(res.salaries)
          ? res.salaries
          : Array.isArray(res.data)
          ? res.data
          : [];
        setSalaries(list);
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
      if (res && (res.success || res.status === 'success')) {
        const list = Array.isArray(res.configs) ? res.configs : Array.isArray(res.data) ? res.data : [];
        setConfigs(list);

        const salMap: Record<string, number> = {};
        const bnkMap: Record<string, string> = {};
        list.forEach((c: any) => {
          salMap[c.employee_id] = Number(c.base_salary) || 0;
          bnkMap[c.employee_id] = c.bank_name ? `${c.bank_name}${c.bank_account_number ? ' - ' + c.bank_account_number : ''}` : '';
        });
        setEditingSalaries(salMap);
        setEditingBanks(bnkMap);
      }
    } catch (err) {
      console.error('Error loading payroll configs:', err);
    }
    setLoadingConfigs(false);
  };

  const loadAdjustments = async () => {
    try {
      const res = await adminApi.fetchPayrollAdjustments();
      if (res && (res.success || res.status === 'success')) {
        if (res.deductions) setDeductions(res.deductions);
        if (res.ots) setOts(res.ots);
        if (res.loans) setLoans(res.loans);
      }
      const catRes = await adminApi.fetchCategories();
      if (catRes && Array.isArray(catRes.users)) {
        setUsersList(catRes.users);
      }
    } catch (err) {
      console.error('Error loading adjustments:', err);
    }
  };

  const loadHistory = async () => {
    try {
      const res = await adminApi.fetchPayrollHistory();
      if (res && (res.success || res.status === 'success')) {
        const list = Array.isArray(res.history) ? res.history : Array.isArray(res.data) ? res.data : [];
        setHistoryList(list);
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

  // Calculate Payroll Action
  const handleCalculate = async () => {
    setCalculating(true);
    try {
      const res = await adminApi.calculatePayroll(selectedMonth, selectedYear);
      if (res && (res.success || res.status === 'success')) {
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

  // Pay Single Salary Action (matching admin_attendance.php paySalary)
  const handlePaySalarySingle = async (item: any) => {
    try {
      const res = await adminApi.paySalarySingle({
        employee_id: item.employee_id,
        base_salary: Number(item.base_salary) || 0,
        present_days: Number(item.present_days || item.days_present) || 0,
        calculated_salary: Number(item.calculated_salary || item.net_salary) || 0,
        month: selectedMonth,
        year: selectedYear,
      });

      if (res && (res.success || res.status === 'success')) {
        showBanner('success', res.message || `បានបើកប្រាក់បៀវត្សជូន ${item.name} ជោគជ័យ!`);
        loadPayroll();
      } else {
        showBanner('error', res?.message || 'Error paying salary');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការទូទាត់ប្រាក់បៀវត្ស');
    }
  };

  // Save Config Inline per row (matching admin_attendance.php savePayrollConfig)
  const handleSaveConfigInline = async (empId: string) => {
    const baseSal = editingSalaries[empId] ?? 0;
    const bankVal = (editingBanks[empId] ?? '').split('-');
    const bankName = bankVal[0] ? bankVal[0].trim() : '';
    const bankAcc = bankVal[1] ? bankVal[1].trim() : '';

    try {
      const fd = new FormData();
      fd.append('employee_id', empId);
      fd.append('base_salary', String(baseSal));
      fd.append('bank_name', bankName);
      fd.append('bank_account_number', bankAcc);
      fd.append('payment_type', 'Monthly');

      if (qrUploadEmpId === empId && qrFile) {
        fd.append('bank_qr', qrFile);
      }

      const res = await adminApi.savePayrollConfig(fd);
      if (res && (res.success || res.status === 'success')) {
        showBanner('success', res.message || 'បានរក្សាទុកព័ត៌មានប្រាក់បៀវត្ស និងធនាគារជោគជ័យ!');
        setQrUploadEmpId(null);
        setQrFile(null);
        loadConfigs();
      } else {
        showBanner('error', res?.message || 'Error saving config');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការរក្សាទុក');
    }
  };

  // Save Adjustments
  const handleSaveDeduction = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!deductForm.emp_id || deductForm.amount <= 0) {
      alert('សូមជ្រើសរើសបុគ្គលិក និងបញ្ចូលចំនួនទឹកប្រាក់!');
      return;
    }
    try {
      const res = await adminApi.savePayrollDeduction(deductForm);
      if (res && (res.success || res.status === 'success')) {
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
    if (!otForm.emp_id || otForm.ot_hours <= 0) {
      alert('សូមជ្រើសរើសបុគ្គលិក និងបញ្ចូលម៉ោងថែម!');
      return;
    }
    try {
      const res = await adminApi.savePayrollOt(otForm);
      if (res && (res.success || res.status === 'success')) {
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
    if (!loanForm.emp_id || loanForm.total_loan <= 0) {
      alert('សូមជ្រើសរើសបុគ្គលិក និងបញ្ចូលចំនួនប្រាក់កម្ចី!');
      return;
    }
    try {
      const res = await adminApi.savePayrollLoan(loanForm);
      if (res && (res.success || res.status === 'success')) {
        showBanner('success', 'បានរក្សាទុកបំណុល/ប្រាក់កម្ចីជោគជ័យ!');
        setLoanForm({ emp_id: '', total_loan: 0, monthly_installment: 0, reason: '' });
        loadAdjustments();
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការរក្សាទុក');
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '22px', maxWidth: '1280px', margin: '0 auto', width: '100%' }}>
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

      {/* Top Sub-Navigation Bar matching admin_attendance.php */}
      <div
        className="hrm-card"
        style={{
          padding: '14px 20px',
          borderRadius: '16px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px',
          background: '#fff',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              background: 'var(--surface-alt)',
              padding: '6px 14px',
              borderRadius: '10px',
              fontWeight: 700,
              fontSize: '13px',
              color: 'var(--text-secondary)',
            }}
          >
            <Layers size={15} color="var(--primary)" />
            <span>Payroll</span>
          </span>

          <select
            className="form-control"
            value={activeTab}
            onChange={(e) => setActiveTab(e.target.value as any)}
            style={{ height: '38px', borderRadius: '10px', fontWeight: 700, fontSize: '13px', minWidth: '220px', background: '#fff' }}
          >
            <option value="payroll_dashboard">Overview</option>
            <option value="manage_salaries">Manage Salaries</option>
            <option value="payroll_history">Payroll History</option>
            <option value="adjustments">Payroll Settings</option>
          </select>
        </div>

        {/* Tab Buttons Quick Switcher */}
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          {[
            { id: 'payroll_dashboard', label: 'ទិដ្ឋភាពទូទៅ (Dashboard)', icon: DollarSign },
            { id: 'manage_salaries', label: 'គ្រប់គ្រងប្រាក់បៀវត្ស', icon: CreditCard },
            { id: 'adjustments', label: 'ការកំណត់ (Deduct/OT/Loan)', icon: TrendingDown },
            { id: 'payroll_history', label: 'ប្រវត្តិបើកប្រាក់បៀវត្ស', icon: History },
          ].map((tab) => {
            const Icon = tab.icon;
            const isTabActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '7px 14px',
                  borderRadius: '10px',
                  fontWeight: 700,
                  fontSize: '12.5px',
                  border: 'none',
                  cursor: 'pointer',
                  background: isTabActive ? 'var(--primary)' : 'transparent',
                  color: isTabActive ? '#fff' : 'var(--text-secondary)',
                  transition: 'all 0.15s ease',
                }}
              >
                <Icon size={13} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 1. TAB: OVERVIEW (ទិដ្ឋភាពទូទៅនៃប្រាក់បៀវត្ស ដូច admin_attendance.php)      */}
      {/* ========================================================================= */}
      {activeTab === 'payroll_dashboard' && (
        <div className="hrm-card" style={{ padding: '26px', borderRadius: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', flexWrap: 'wrap', gap: '10px' }}>
            <h2 style={{ fontWeight: 800, fontSize: '1.4rem', color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Coins size={24} color="var(--primary)" />
              <span>ប្រព័ន្ធគ្រប់គ្រងប្រាក់បៀវត្ស (Payroll)</span>
            </h2>
          </div>

          {/* Filter Toolbar matching admin_attendance.php */}
          <div
            style={{
              background: 'var(--surface-alt)',
              padding: '18px 22px',
              borderRadius: '16px',
              display: 'flex',
              gap: '16px',
              marginBottom: '24px',
              alignItems: 'flex-end',
              flexWrap: 'wrap',
            }}
          >
            <div style={{ flex: 1, minWidth: '180px' }}>
              <label style={{ fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px', display: 'block', fontSize: '13px' }}>
                ខែ (Month)
              </label>
              <select
                id="payroll-month"
                className="form-control"
                value={selectedMonth}
                onChange={(e) => setSelectedMonth(Number(e.target.value))}
                style={{ height: '42px', borderRadius: '10px', background: '#fff', fontSize: '13.5px' }}
              >
                {Array.from({ length: 12 }, (_, i) => i + 1).map((m) => (
                  <option key={m} value={m}>
                    ខែ {m}
                  </option>
                ))}
              </select>
            </div>

            <div style={{ flex: 1, minWidth: '180px' }}>
              <label style={{ fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px', display: 'block', fontSize: '13px' }}>
                ឆ្នាំ (Year)
              </label>
              <select
                id="payroll-year"
                className="form-control"
                value={selectedYear}
                onChange={(e) => setSelectedYear(Number(e.target.value))}
                style={{ height: '42px', borderRadius: '10px', background: '#fff', fontSize: '13.5px' }}
              >
                {[2024, 2025, 2026, 2027, 2028].map((y) => (
                  <option key={y} value={y}>
                    {y}
                  </option>
                ))}
              </select>
            </div>

            <button
              type="button"
              onClick={handleCalculate}
              disabled={calculating}
              className="btn btn-primary"
              style={{ height: '42px', padding: '0 24px', borderRadius: '10px', fontWeight: 700 }}
            >
              <Calculator size={16} />
              <span>{calculating ? 'កំពុងគណនា...' : 'គណនា (Calculate)'}</span>
            </button>
          </div>

          {/* Table matching admin_attendance.php */}
          <div className="table-container" style={{ border: 'none', boxShadow: 'none' }}>
            <table className="hrm-table">
              <thead>
                <tr>
                  <th>បុគ្គលិក (EMPLOYEE)</th>
                  <th>ប្រាក់ខែគោល (BASE SALARY)</th>
                  <th style={{ textAlign: 'center' }}>ថ្ងៃបង្ហាញខ្លួន (DAYS)</th>
                  <th style={{ color: '#ef4444' }}>កាត់ (DEDUCT)</th>
                  <th style={{ color: '#22c55e' }}>ថែម (OT)</th>
                  <th style={{ color: '#f59e0b' }}>បំណុល (LOAN)</th>
                  <th style={{ color: '#6366f1', fontWeight: 800 }}>ប្រាក់ខែសរុប (NET)</th>
                  <th style={{ textAlign: 'center' }}>ស្ថានភាព (STATUS)</th>
                </tr>
              </thead>
              <tbody id="payroll-results-body">
                {salaries.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                      {loading ? 'កំពុងទាញយកទិន្នន័យប្រាក់បៀវត្ស...' : 'សូមចុចប៊ូតុង "គណនា" ដើម្បីមើលទិន្នន័យ។'}
                    </td>
                  </tr>
                ) : (
                  salaries.map((row) => {
                    const isPaid = row.is_paid || row.status === 'Paid';

                    return (
                      <tr key={row.employee_id}>
                        <td>
                          <div style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '13.5px' }}>
                            {row.name}
                          </div>
                          <small style={{ color: '#94a3b8', fontFamily: 'monospace' }}>
                            ID: {row.employee_id}
                          </small>
                        </td>

                        <td style={{ fontWeight: 700 }}>
                          ${Number(row.base_salary || 0).toLocaleString()}
                        </td>

                        <td style={{ textAlign: 'center', fontWeight: 600 }}>
                          {row.present_days ?? row.days_present ?? 0}
                        </td>

                        <td style={{ color: '#ef4444', fontWeight: 600 }}>
                          -${Number(row.deductions || 0).toLocaleString()}
                        </td>

                        <td style={{ color: '#22c55e', fontWeight: 600 }}>
                          +${Number(row.ot_bonus || row.ot_amount || 0).toLocaleString()}
                        </td>

                        <td style={{ color: '#f59e0b', fontWeight: 600 }}>
                          -${Number(row.loan_deduct || row.loans || 0).toLocaleString()}
                        </td>

                        <td style={{ color: '#6366f1', fontWeight: 800, fontSize: '15px' }}>
                          ${Number(row.calculated_salary ?? row.net_salary ?? 0).toLocaleString()}
                        </td>

                        <td style={{ textAlign: 'center' }}>
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                            {isPaid ? (
                              <span
                                style={{
                                  background: '#22c55e',
                                  color: '#fff',
                                  padding: '5px 12px',
                                  borderRadius: '10px',
                                  fontSize: '12px',
                                  fontWeight: 700,
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '4px',
                                }}
                              >
                                <CheckCircle2 size={13} />
                                <span>Paid</span>
                              </span>
                            ) : (
                              <button
                                type="button"
                                onClick={() => handlePaySalarySingle(row)}
                                className="btn btn-primary btn-sm"
                                style={{ padding: '6px 14px', borderRadius: '8px', fontWeight: 700, fontSize: '12px' }}
                              >
                                <Coins size={13} />
                                <span>បើកប្រាក់</span>
                              </button>
                            )}

                            <button
                              type="button"
                              onClick={() => setPayslipItem(row)}
                              className="btn btn-secondary btn-sm"
                              title="ប័ណ្ណបើកប្រាក់ (Payslip)"
                              style={{ padding: '5px 8px', borderRadius: '8px' }}
                            >
                              <Eye size={13} />
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

      {/* ========================================================================= */}
      {/* 2. TAB: MANAGE SALARIES (គ្រប់គ្រងប្រាក់បៀវត្ស & BANK QR)                   */}
      {/* ========================================================================= */}
      {activeTab === 'manage_salaries' && (
        <div className="hrm-card" style={{ padding: '26px', borderRadius: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
            <h3 style={{ fontSize: '18px', fontWeight: 800, margin: 0, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <CreditCard size={20} color="var(--primary)" />
              <span>គ្រប់គ្រងប្រាក់បៀវត្ស និងគណនីធនាគារ (Manage Salaries)</span>
            </h3>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', background: 'var(--surface-alt)', border: '1px solid var(--border)', borderRadius: '10px', padding: '6px 12px', width: '220px', gap: '6px' }}>
                <Search size={14} color="var(--text-muted)" />
                <input
                  type="text"
                  placeholder="ស្វែងរកឈ្មោះ ឬ ID..."
                  value={configSearch}
                  onChange={(e) => setConfigSearch(e.target.value)}
                  style={{ background: 'transparent', border: 'none', outline: 'none', fontSize: '12.5px', width: '100%' }}
                />
              </div>

              <button onClick={loadConfigs} className="btn btn-secondary btn-sm" style={{ borderRadius: '10px' }}>
                <RotateCw size={13} className={loadingConfigs ? 'fa-spin' : ''} />
                <span>Refresh</span>
              </button>
            </div>
          </div>

          <div className="table-responsive" style={{ border: 'none', boxShadow: 'none' }}>
            <table className="hrm-table">
              <thead>
                <tr>
                  <th style={{ width: '100px' }}>អត្តលេខ (ID)</th>
                  <th>ឈ្មោះបុគ្គលិក (NAME)</th>
                  <th style={{ width: '160px' }}>ប្រាក់ខែគោល (BASE SALARY)</th>
                  <th style={{ width: '240px' }}>ធនាគារ (BANK NAME/ACC)</th>
                  <th style={{ width: '140px', textAlign: 'center' }}>BANK QR CODE</th>
                  <th style={{ width: '120px', textAlign: 'center' }}>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {configs
                  .filter((c) => (c.name || '').toLowerCase().includes(configSearch.toLowerCase()) || (c.employee_id || '').toLowerCase().includes(configSearch.toLowerCase()))
                  .map((c) => {
                    const eid = c.employee_id;
                    const baseSal = editingSalaries[eid] ?? Number(c.base_salary) ?? 0;
                    const bankVal = editingBanks[eid] ?? '';

                    return (
                      <tr key={eid}>
                        <td style={{ fontWeight: 800, color: 'var(--text-muted)' }}>
                          {eid}
                        </td>

                        <td>
                          <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{c.name}</div>
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{c.department || 'Staff'}</div>
                        </td>

                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                            <span style={{ color: '#a0aec0', fontWeight: 700 }}>$</span>
                            <input
                              type="number"
                              step="0.01"
                              value={baseSal}
                              onChange={(e) => setEditingSalaries({ ...editingSalaries, [eid]: Number(e.target.value) })}
                              className="form-control"
                              style={{ width: '120px', height: '36px', fontWeight: 700, color: '#22c55e', borderRadius: '8px' }}
                            />
                          </div>
                        </td>

                        <td>
                          <input
                            type="text"
                            value={bankVal}
                            onChange={(e) => setEditingBanks({ ...editingBanks, [eid]: e.target.value })}
                            placeholder="ABA - 123456789"
                            className="form-control"
                            style={{ height: '36px', borderRadius: '8px', fontSize: '12.5px' }}
                          />
                        </td>

                        <td style={{ textAlign: 'center' }}>
                          {c.bank_qr_url ? (
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
                              <img
                                src={c.bank_qr_url}
                                alt="QR"
                                onClick={() => setPreviewQrUrl(c.bank_qr_url)}
                                style={{ width: '38px', height: '38px', objectFit: 'cover', borderRadius: '8px', border: '2px solid #6366f1', cursor: 'pointer' }}
                              />
                            </div>
                          ) : (
                            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>គ្មាន QR</span>
                          )}
                        </td>

                        <td style={{ textAlign: 'center' }}>
                          <button
                            type="button"
                            onClick={() => handleSaveConfigInline(eid)}
                            className="btn btn-primary btn-sm"
                            style={{ padding: '6px 15px', borderRadius: '8px', fontWeight: 700 }}
                          >
                            <Check size={13} />
                            <span>រក្សាទុក</span>
                          </button>
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 3. TAB: PAYROLL SETTINGS & ADJUSTMENTS (DEDUCT, OT, LOAN, POLICY)          */}
      {/* ========================================================================= */}
      {activeTab === 'adjustments' && (
        <div className="hrm-card" style={{ padding: '26px', borderRadius: '20px' }}>
          {/* Sub-tabs */}
          <div style={{ display: 'flex', gap: '8px', marginBottom: '22px', borderBottom: '1px solid var(--border)', paddingBottom: '12px', flexWrap: 'wrap' }}>
            {[
              { id: 'deduction', label: 'កាត់ប្រាក់ (Deductions)', color: '#ef4444' },
              { id: 'ot', label: 'ប្រាក់ថែមម៉ោង (OT Bonus)', color: '#22c55e' },
              { id: 'loan', label: 'បំណុល (Loan)', color: '#f59e0b' },
              { id: 'policy', label: 'ប្រព័ន្ធគោលការណ៍ (Policies)', color: '#6366f1' },
            ].map((sub) => (
              <button
                key={sub.id}
                onClick={() => setAdjustSubTab(sub.id as any)}
                style={{
                  padding: '8px 18px',
                  borderRadius: '10px',
                  border: 'none',
                  background: adjustSubTab === sub.id ? 'var(--surface-alt)' : 'transparent',
                  color: adjustSubTab === sub.id ? sub.color : 'var(--text-secondary)',
                  fontWeight: 700,
                  fontSize: '13px',
                  cursor: 'pointer',
                  borderBottom: adjustSubTab === sub.id ? `3px solid ${sub.color}` : '3px solid transparent',
                }}
              >
                {sub.label}
              </button>
            ))}
          </div>

          {/* DEDUCTION SUBTAB */}
          {adjustSubTab === 'deduction' && (
            <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: '24px', alignItems: 'start' }}>
              <form onSubmit={handleSaveDeduction} style={{ background: 'var(--surface-alt)', padding: '20px', borderRadius: '16px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <h4 style={{ margin: 0, color: '#ef4444', fontWeight: 800, fontSize: '14.5px' }}>បញ្ចូលការកាត់ប្រាក់</h4>
                <div>
                  <label className="form-label">ជ្រើសរើសបុគ្គលិក *</label>
                  <select
                    className="form-control"
                    value={deductForm.emp_id}
                    onChange={(e) => setDeductForm({ ...deductForm, emp_id: e.target.value })}
                    required
                    style={{ height: '40px', borderRadius: '8px' }}
                  >
                    <option value="">-- ជ្រើសរើសបុគ្គលិក --</option>
                    {usersList.map((u) => (
                      <option key={u.employee_id} value={u.employee_id}>
                        {u.name} (#{u.employee_id})
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="form-label">ចំនួនទឹកប្រាក់ ($) *</label>
                  <input
                    type="number"
                    step="0.01"
                    className="form-input"
                    value={deductForm.amount || ''}
                    onChange={(e) => setDeductForm({ ...deductForm, amount: Number(e.target.value) })}
                    placeholder="0.00"
                    required
                    style={{ height: '40px', borderRadius: '8px' }}
                  />
                </div>

                <div>
                  <label className="form-label">មូលហេតុ</label>
                  <input
                    type="text"
                    className="form-input"
                    value={deductForm.reason}
                    onChange={(e) => setDeductForm({ ...deductForm, reason: e.target.value })}
                    placeholder="ឧ. មកយឺត ៣ លើក"
                    style={{ height: '40px', borderRadius: '8px' }}
                  />
                </div>

                <div>
                  <label className="form-label">កាលបរិច្ឆេទ</label>
                  <input
                    type="date"
                    className="form-input"
                    value={deductForm.deduction_date}
                    onChange={(e) => setDeductForm({ ...deductForm, deduction_date: e.target.value })}
                    style={{ height: '40px', borderRadius: '8px' }}
                  />
                </div>

                <button type="submit" className="btn btn-danger" style={{ height: '40px', borderRadius: '8px', fontWeight: 700 }}>
                  <Plus size={15} />
                  <span>រក្សាទុកការកាត់ប្រាក់</span>
                </button>
              </form>

              {/* Deductions Table */}
              <div className="table-container" style={{ border: 'none', boxShadow: 'none' }}>
                <table className="hrm-table">
                  <thead>
                    <tr>
                      <th>បុគ្គលិក</th>
                      <th>ចំនួនទឹកប្រាក់</th>
                      <th>មូលហេតុ</th>
                      <th>កាលបរិច្ឆេទ</th>
                    </tr>
                  </thead>
                  <tbody>
                    {deductions.length === 0 ? (
                      <tr><td colSpan={4} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>មិនទាន់មានទិន្នន័យកាត់ប្រាក់ឡើយ</td></tr>
                    ) : (
                      deductions.map((d) => (
                        <tr key={d.id}>
                          <td><strong>{d.emp_name || d.employee_id}</strong></td>
                          <td style={{ color: '#ef4444', fontWeight: 700 }}>-${Number(d.amount).toFixed(2)}</td>
                          <td>{d.reason || '-'}</td>
                          <td>{d.deduction_date}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* OT SUBTAB */}
          {adjustSubTab === 'ot' && (
            <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: '24px', alignItems: 'start' }}>
              <form onSubmit={handleSaveOt} style={{ background: 'var(--surface-alt)', padding: '20px', borderRadius: '16px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <h4 style={{ margin: 0, color: '#22c55e', fontWeight: 800, fontSize: '14.5px' }}>បញ្ចូលប្រាក់ថែមម៉ោង (OT)</h4>
                <div>
                  <label className="form-label">ជ្រើសរើសបុគ្គលិក *</label>
                  <select
                    className="form-control"
                    value={otForm.emp_id}
                    onChange={(e) => setOtForm({ ...otForm, emp_id: e.target.value })}
                    required
                    style={{ height: '40px', borderRadius: '8px' }}
                  >
                    <option value="">-- ជ្រើសរើសបុគ្គលិក --</option>
                    {usersList.map((u) => (
                      <option key={u.employee_id} value={u.employee_id}>
                        {u.name} (#{u.employee_id})
                      </option>
                    ))}
                  </select>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                  <div>
                    <label className="form-label">ម៉ោងថែម (Hrs) *</label>
                    <input
                      type="number"
                      step="0.5"
                      className="form-input"
                      value={otForm.ot_hours || ''}
                      onChange={(e) => setOtForm({ ...otForm, ot_hours: Number(e.target.value) })}
                      placeholder="2"
                      required
                      style={{ height: '40px', borderRadius: '8px' }}
                    />
                  </div>
                  <div>
                    <label className="form-label">អត្រា ($/hr)</label>
                    <input
                      type="number"
                      step="0.1"
                      className="form-input"
                      value={otForm.ot_rate}
                      onChange={(e) => setOtForm({ ...otForm, ot_rate: Number(e.target.value) })}
                      style={{ height: '40px', borderRadius: '8px' }}
                    />
                  </div>
                </div>

                <div>
                  <label className="form-label">មូលហេតុ</label>
                  <input
                    type="text"
                    className="form-input"
                    value={otForm.reason}
                    onChange={(e) => setOtForm({ ...otForm, reason: e.target.value })}
                    placeholder="ឧ. ជួយរៀបចំស្តុកយប់"
                    style={{ height: '40px', borderRadius: '8px' }}
                  />
                </div>

                <div>
                  <label className="form-label">កាលបរិច្ឆេទ</label>
                  <input
                    type="date"
                    className="form-input"
                    value={otForm.ot_date}
                    onChange={(e) => setOtForm({ ...otForm, ot_date: e.target.value })}
                    style={{ height: '40px', borderRadius: '8px' }}
                  />
                </div>

                <button type="submit" className="btn btn-primary" style={{ height: '40px', borderRadius: '8px', fontWeight: 700 }}>
                  <Plus size={15} />
                  <span>រក្សាទុកប្រាក់ថែមម៉ោង</span>
                </button>
              </form>

              {/* OT Table */}
              <div className="table-container" style={{ border: 'none', boxShadow: 'none' }}>
                <table className="hrm-table">
                  <thead>
                    <tr>
                      <th>បុគ្គលិក</th>
                      <th>ម៉ោងថែម</th>
                      <th>ទឹកប្រាក់</th>
                      <th>មូលហេតុ</th>
                      <th>កាលបរិច្ឆេទ</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ots.length === 0 ? (
                      <tr><td colSpan={5} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>មិនទាន់មានទិន្នន័យ OT ឡើយ</td></tr>
                    ) : (
                      ots.map((o) => (
                        <tr key={o.id}>
                          <td><strong>{o.emp_name || o.employee_id}</strong></td>
                          <td>{o.ot_hours} ម៉ោង</td>
                          <td style={{ color: '#22c55e', fontWeight: 700 }}>+${Number(o.total_ot_amount || o.amount || 0).toFixed(2)}</td>
                          <td>{o.reason || '-'}</td>
                          <td>{o.ot_date || '-'}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* LOAN SUBTAB */}
          {adjustSubTab === 'loan' && (
            <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: '24px', alignItems: 'start' }}>
              <form onSubmit={handleSaveLoan} style={{ background: 'var(--surface-alt)', padding: '20px', borderRadius: '16px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <h4 style={{ margin: 0, color: '#f59e0b', fontWeight: 800, fontSize: '14.5px' }}>បញ្ចូលបំណុល/ប្រាក់កម្ចី</h4>
                <div>
                  <label className="form-label">ជ្រើសរើសបុគ្គលិក *</label>
                  <select
                    className="form-control"
                    value={loanForm.emp_id}
                    onChange={(e) => setLoanForm({ ...loanForm, emp_id: e.target.value })}
                    required
                    style={{ height: '40px', borderRadius: '8px' }}
                  >
                    <option value="">-- ជ្រើសរើសបុគ្គលិក --</option>
                    {usersList.map((u) => (
                      <option key={u.employee_id} value={u.employee_id}>
                        {u.name} (#{u.employee_id})
                      </option>
                    ))}
                  </select>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                  <div>
                    <label className="form-label">កម្ចីសរុប ($) *</label>
                    <input
                      type="number"
                      step="0.01"
                      className="form-input"
                      value={loanForm.total_loan || ''}
                      onChange={(e) => setLoanForm({ ...loanForm, total_loan: Number(e.target.value) })}
                      placeholder="500"
                      required
                      style={{ height: '40px', borderRadius: '8px' }}
                    />
                  </div>
                  <div>
                    <label className="form-label">កាត់ប្រចាំខែ ($)</label>
                    <input
                      type="number"
                      step="0.01"
                      className="form-input"
                      value={loanForm.monthly_installment || ''}
                      onChange={(e) => setLoanForm({ ...loanForm, monthly_installment: Number(e.target.value) })}
                      placeholder="50"
                      style={{ height: '40px', borderRadius: '8px' }}
                    />
                  </div>
                </div>

                <div>
                  <label className="form-label">មូលហេតុ</label>
                  <input
                    type="text"
                    className="form-input"
                    value={loanForm.reason}
                    onChange={(e) => setLoanForm({ ...loanForm, reason: e.target.value })}
                    placeholder="ឧ. កម្ចីទិញម៉ូតូ"
                    style={{ height: '40px', borderRadius: '8px' }}
                  />
                </div>

                <button type="submit" className="btn btn-primary" style={{ height: '40px', borderRadius: '8px', fontWeight: 700 }}>
                  <Plus size={15} />
                  <span>រក្សាទុកបំណុល/កម្ចី</span>
                </button>
              </form>

              {/* Loan Table */}
              <div className="table-container" style={{ border: 'none', boxShadow: 'none' }}>
                <table className="hrm-table">
                  <thead>
                    <tr>
                      <th>បុគ្គលិក</th>
                      <th>កម្ចីសរុប</th>
                      <th>កាត់ប្រចាំខែ</th>
                      <th>មូលហេតុ</th>
                    </tr>
                  </thead>
                  <tbody>
                    {loans.length === 0 ? (
                      <tr><td colSpan={4} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>មិនទាន់មានទិន្នន័យប្រាក់កម្ចីឡើយ</td></tr>
                    ) : (
                      loans.map((l) => (
                        <tr key={l.id}>
                          <td><strong>{l.emp_name || l.employee_id}</strong></td>
                          <td>${Number(l.total_loan).toFixed(2)}</td>
                          <td style={{ color: '#f59e0b', fontWeight: 700 }}>-${Number(l.monthly_installment || l.monthly_deduction || 0).toFixed(2)}/ខែ</td>
                          <td>{l.reason || '-'}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* POLICY SUBTAB */}
          {adjustSubTab === 'policy' && (
            <div style={{ maxWidth: '600px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
              <div style={{ background: 'var(--surface-alt)', padding: '20px', borderRadius: '16px', border: '1px solid var(--border)' }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)' }}>
                  គោលការណ៍កាត់ប្រាក់ភ្លេចស្កេន និង OT
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div>
                    <label className="form-label">អត្រាកាត់ភ្លេចស្កេន ($/លើក)</label>
                    <input type="number" defaultValue={5.00} className="form-input" style={{ height: '40px', borderRadius: '8px' }} />
                  </div>
                  <div>
                    <label className="form-label">មេគុណ OT Multiplier (Standard)</label>
                    <input type="number" defaultValue={1.5} step={0.1} className="form-input" style={{ height: '40px', borderRadius: '8px' }} />
                  </div>
                  <button type="button" onClick={() => showBanner('success', 'បានរក្សាទុកគោលការណ៍ជោគជ័យ!')} className="btn btn-primary" style={{ height: '40px', borderRadius: '8px', fontWeight: 700, marginTop: '8px' }}>
                    <Check size={15} />
                    <span>រក្សាទុកគោលការណ៍</span>
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* 4. TAB: PAYROLL HISTORY (ប្រវត្តិបើកប្រាក់បៀវត្ស)                            */}
      {/* ========================================================================= */}
      {activeTab === 'payroll_history' && (
        <div className="hrm-card" style={{ padding: '26px', borderRadius: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
            <h3 style={{ fontSize: '18px', fontWeight: 800, margin: 0, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <History size={20} color="var(--primary)" />
              <span>ប្រវត្តិបើកប្រាក់បៀវត្ស (Payroll History)</span>
            </h3>

            <button onClick={loadHistory} className="btn btn-secondary btn-sm" style={{ borderRadius: '10px' }}>
              <RotateCw size={13} />
              <span>Refresh</span>
            </button>
          </div>

          <div className="table-container" style={{ border: 'none', boxShadow: 'none' }}>
            <table className="hrm-table">
              <thead>
                <tr>
                  <th>បុគ្គលិក (EMPLOYEE)</th>
                  <th>ខែ-ឆ្នាំ (MONTH-YEAR)</th>
                  <th>ប្រាក់ខែសរុប (NET SALARY)</th>
                  <th>ថ្ងៃបើកប្រាក់ (PAYMENT DATE)</th>
                  <th style={{ textAlign: 'center' }}>ស្ថានភាព (STATUS)</th>
                </tr>
              </thead>
              <tbody>
                {historyList.length === 0 ? (
                  <tr><td colSpan={5} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>មិនទាន់មានប្រវត្តិទូទាត់ប្រាក់នៅឡើយទេ។</td></tr>
                ) : (
                  historyList.map((h) => (
                    <tr key={h.id}>
                      <td>
                        <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{h.emp_name || h.name || h.employee_id}</div>
                        <small style={{ color: '#94a3b8' }}>ID: {h.employee_id}</small>
                      </td>
                      <td style={{ fontWeight: 700 }}>{h.payroll_month}/{h.payroll_year}</td>
                      <td style={{ color: '#22c55e', fontWeight: 800, fontSize: '14.5px' }}>${Number(h.calculated_salary).toFixed(2)}</td>
                      <td>{h.payment_date ? new Date(h.payment_date).toLocaleString() : '-'}</td>
                      <td style={{ textAlign: 'center' }}>
                        <span style={{ background: '#22c55e', color: '#fff', padding: '4px 12px', borderRadius: '10px', fontSize: '12px', fontWeight: 700 }}>
                          {h.status || 'Paid'}
                        </span>
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
      {/* MODAL: PAYSLIP (ប័ណ្ណបើកប្រាក់បៀវត្ស & PRINT)                               */}
      {/* ========================================================================= */}
      {payslipItem && (
        <Modal isOpen={true} onClose={() => setPayslipItem(null)} title="ប័ណ្ណបើកប្រាក់ខែ (Official Payslip)">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '18px', padding: '10px' }} id="printablePayslip">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '2px solid var(--border)', paddingBottom: '12px' }}>
              <div>
                <h3 style={{ margin: 0, fontWeight: 900, color: 'var(--primary)' }}>VVC Asia Co., Ltd.</h3>
                <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: 'var(--text-muted)' }}>វិក្កយបត្រប្រាក់បៀវត្សបុគ្គលិកប្រចាំខែ {selectedMonth}/{selectedYear}</p>
              </div>
              <button onClick={() => window.print()} className="btn btn-secondary btn-sm" style={{ borderRadius: '8px' }}>
                <Printer size={14} />
                <span>Print</span>
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px', background: 'var(--surface-alt)', padding: '14px', borderRadius: '12px' }}>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>ឈ្មោះបុគ្គលិក (Employee Name):</div>
                <div style={{ fontWeight: 800, fontSize: '14px' }}>{payslipItem.name}</div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>អត្តលេខ (Employee ID):</div>
                <div style={{ fontWeight: 800, fontSize: '14px' }}>#{payslipItem.employee_id}</div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>ផ្នែក (Department):</div>
                <div style={{ fontWeight: 700 }}>{payslipItem.department || 'Staff'}</div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>វត្តមានជាក់ស្តែង (Days):</div>
                <div style={{ fontWeight: 700 }}>{payslipItem.present_days ?? payslipItem.days_present ?? 0} ថ្ងៃ</div>
              </div>
            </div>

            <div style={{ border: '1px solid var(--border)', borderRadius: '12px', overflow: 'hidden' }}>
              <table className="hrm-table" style={{ margin: 0 }}>
                <tbody>
                  <tr>
                    <td>ប្រាក់ខែគោល (Base Salary)</td>
                    <td style={{ textAlign: 'right', fontWeight: 700 }}>${Number(payslipItem.base_salary || 0).toFixed(2)}</td>
                  </tr>
                  <tr>
                    <td>ប្រាក់ថែមម៉ោង (OT Bonus)</td>
                    <td style={{ textAlign: 'right', fontWeight: 700, color: '#22c55e' }}>+${Number(payslipItem.ot_bonus || payslipItem.ot_amount || 0).toFixed(2)}</td>
                  </tr>
                  <tr>
                    <td>កាត់កងទូទៅ (Deductions)</td>
                    <td style={{ textAlign: 'right', fontWeight: 700, color: '#ef4444' }}>-${Number(payslipItem.deductions || 0).toFixed(2)}</td>
                  </tr>
                  <tr>
                    <td>កាត់ប្រាក់កម្ចី (Loan Repayment)</td>
                    <td style={{ textAlign: 'right', fontWeight: 700, color: '#f59e0b' }}>-${Number(payslipItem.loan_deduct || payslipItem.loans || 0).toFixed(2)}</td>
                  </tr>
                  <tr style={{ background: 'var(--surface-alt)' }}>
                    <td style={{ fontWeight: 900, fontSize: '15px' }}>ប្រាក់ខែសុទ្ធត្រូវបើក (Net Payable)</td>
                    <td style={{ textAlign: 'right', fontWeight: 900, fontSize: '17px', color: 'var(--primary)' }}>
                      ${Number(payslipItem.calculated_salary ?? payslipItem.net_salary ?? 0).toFixed(2)}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '10px' }}>
              <button onClick={() => setPayslipItem(null)} className="btn btn-secondary" style={{ borderRadius: '8px', padding: '8px 20px' }}>
                បិទ
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* QR Preview Modal */}
      {previewQrUrl && (
        <Modal isOpen={true} onClose={() => setPreviewQrUrl(null)} title="Bank QR Code">
          <div style={{ textAlign: 'center', padding: '20px' }}>
            <img src={previewQrUrl} alt="Bank QR" style={{ maxWidth: '300px', maxHeight: '300px', borderRadius: '12px' }} />
          </div>
        </Modal>
      )}
    </div>
  );
};
