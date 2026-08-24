import React, { useState, useEffect } from 'react';
import { DollarSign, Download, Plus, Search, CheckCircle, RotateCw, Check } from 'lucide-react';
import { StatCard } from '../components/common/StatCard';
import { adminApi, PayrollItem } from '../api/adminApi';

export const PayrollPage: React.FC = () => {
  const [salaries, setSalaries] = useState<PayrollItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [calculating, setCalculating] = useState(false);

  const loadPayroll = async () => {
    setLoading(true);
    try {
      const res = await adminApi.fetchPayroll();
      if (res && res.success && Array.isArray(res.salaries)) {
        setSalaries(res.salaries);
      }
    } catch (err) {
      console.error('Error fetching payroll:', err);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadPayroll();
  }, []);

  const handleCalculate = async () => {
    if (window.confirm('តើអ្នកចង់គណនាប្រាក់បៀវត្សសម្រាប់ខែនេះមែនទេ?')) {
      setCalculating(true);
      try {
        await adminApi.calculatePayroll();
        await loadPayroll();
      } catch (err) {
        alert('កំហុសក្នុងការគណនាប្រាក់បៀវត្ស');
      }
      setCalculating(false);
    }
  };

  const handleToggleStatus = async (item: PayrollItem) => {
    const newStatus = item.status === 'Paid' ? 'Pending' : 'Paid';
    try {
      await adminApi.savePayroll({
        id: item.id,
        employee_id: item.employee_id,
        name: item.name,
        base_salary: item.base_salary,
        ot_hours: item.ot_hours,
        ot_amount: item.ot_amount,
        deductions: item.deductions,
        net_salary: item.net_salary,
        status: newStatus,
      });
      loadPayroll();
    } catch (err) {
      alert('កំហុសក្នុងការកែប្រែស្ថានភាព');
    }
  };

  const totalPayroll = salaries.reduce((acc, s) => acc + (Number(s.net_salary) || 0), 0);
  const totalOt = salaries.reduce((acc, s) => acc + (Number(s.ot_amount) || 0), 0);
  const paidCount = salaries.filter((s) => s.status === 'Paid').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
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
            ប្រព័ន្ធគ្រប់គ្រងប្រាក់បៀវត្ស (Payroll Management)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            គណនាប្រាក់បៀវត្សគោល ថែមម៉ោង (OT) កាត់កង និងចេញប័ណ្ណបើកប្រាក់ខែ (Payslip)
          </p>
        </div>

        <button
          onClick={handleCalculate}
          disabled={calculating}
          className="btn btn-gold"
        >
          <DollarSign size={16} />
          <span>{calculating ? 'កំពុងគណនា...' : 'គណនាប្រាក់ខែខែនេះ (Calculate)'}</span>
        </button>
      </div>

      {/* Summary KPI Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '20px',
        }}
      >
        <StatCard
          title="ប្រាក់បៀវត្សសរុប (Total Payroll)"
          value={`$${totalPayroll.toFixed(2)}`}
          subtitle="ចំណាយប្រាក់ខែសរុបខែនេះ"
          icon={<DollarSign size={22} />}
          variant="gold"
        />
        <StatCard
          title="ប្រាក់ថែមម៉ោងសរុប (Total OT)"
          value={`$${totalOt.toFixed(2)}`}
          subtitle="ប្រាក់ថែមម៉ោងខែនេះ"
          icon={<DollarSign size={22} />}
          variant="success"
        />
        <StatCard
          title="បានបើកប្រាក់ខែ (Paid)"
          value={`${paidCount} / ${salaries.length}`}
          subtitle="បុគ្គលិកបានទទួលប្រាក់ខែ"
          icon={<CheckCircle size={22} />}
          variant="primary"
        />
      </div>

      {/* Table */}
      <div className="table-container">
        <table className="hrm-table">
          <thead>
            <tr>
              <th>អត្តលេខ</th>
              <th>ឈ្មោះបុគ្គលិក</th>
              <th>ប្រាក់ខែគោល</th>
              <th>ម៉ោង OT (Hours)</th>
              <th>ប្រាក់ OT ($)</th>
              <th>កាត់កង ($)</th>
              <th>ប្រាក់ខែសុទ្ធ (Net Salary)</th>
              <th>ស្ថានភាព</th>
              <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
            </tr>
          </thead>
          <tbody>
            {salaries.length === 0 ? (
              <tr>
                <td colSpan={9} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                  {loading ? 'កំពុងទាញយកទិន្នន័យប្រាក់បៀវត្ស...' : 'មិនទាន់មានទិន្នន័យប្រាក់បៀវត្សឡើយ សូមចុចគណនាប្រាក់ខែ'}
                </td>
              </tr>
            ) : (
              salaries.map((s) => (
                <tr key={s.id}>
                  <td style={{ fontFamily: "'Outfit', monospace", fontWeight: 700, color: 'var(--primary)' }}>
                    {s.employee_id}
                  </td>
                  <td style={{ fontWeight: 600 }}>{s.name || 'បុគ្គលិក'}</td>
                  <td>${Number(s.base_salary).toFixed(2)}</td>
                  <td>{s.ot_hours} ម៉ោង</td>
                  <td style={{ color: '#10b981', fontWeight: 600 }}>+${Number(s.ot_amount).toFixed(2)}</td>
                  <td style={{ color: '#ef4444' }}>-${Number(s.deductions).toFixed(2)}</td>
                  <td style={{ fontWeight: 800, fontSize: '14px', color: 'var(--accent-gold)' }}>
                    ${Number(s.net_salary).toFixed(2)}
                  </td>
                  <td>
                    <span className={`badge ${s.status === 'Paid' ? 'badge-good' : 'badge-late'}`}>
                      {s.status === 'Paid' ? '✅ បានបើករួច' : '⏳ រង់ចាំបើក'}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      onClick={() => handleToggleStatus(s)}
                      className={`btn btn-sm ${s.status === 'Paid' ? 'btn-secondary' : 'btn-primary'}`}
                    >
                      <span>{s.status === 'Paid' ? 'សម្គាល់មិនទាន់បើក' : 'សម្គាល់បានបើក'}</span>
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

