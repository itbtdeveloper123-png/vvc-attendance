import React, { useState } from 'react';
import { DollarSign, Download, Plus, Search, CheckCircle } from 'lucide-react';
import { StatCard } from '../components/common/StatCard';

export const PayrollPage: React.FC = () => {
  const [salaries] = useState([
    {
      id: 1,
      employee_id: 'VVC-101',
      name: 'សុខ គឹមហុង',
      base_salary: 350,
      ot_hours: 12,
      ot_amount: 35,
      deductions: 5,
      net_salary: 380,
      status: 'Paid',
    },
    {
      id: 2,
      employee_id: 'VVC-102',
      name: 'កែវ សុភា',
      base_salary: 600,
      ot_hours: 0,
      ot_amount: 0,
      deductions: 0,
      net_salary: 600,
      status: 'Paid',
    },
    {
      id: 3,
      employee_id: 'VVC-103',
      name: 'ជា វណ្ណៈ',
      base_salary: 500,
      ot_hours: 8,
      ot_amount: 25,
      deductions: 10,
      net_salary: 515,
      status: 'Pending',
    },
  ]);

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

        <button className="btn btn-gold">
          <DollarSign size={16} />
          <span>គណនាប្រាក់ខែខែនេះ (Calculate)</span>
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
          value="$1,495.00"
          subtitle="ចំណាយប្រាក់ខែសរុបខែនេះ"
          icon={<DollarSign size={22} />}
          variant="gold"
        />
        <StatCard
          title="ប្រាក់ថែមម៉ោងសរុប (Total OT)"
          value="$60.00"
          subtitle="20 ម៉ោងថែមម៉ោង"
          icon={<DollarSign size={22} />}
          variant="success"
        />
        <StatCard
          title="បានបើកប្រាក់ខែ (Paid)"
          value="2 / 3"
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
            </tr>
          </thead>
          <tbody>
            {salaries.map((s) => (
              <tr key={s.id}>
                <td style={{ fontFamily: "'Outfit', monospace", fontWeight: 700, color: 'var(--primary)' }}>
                  {s.employee_id}
                </td>
                <td style={{ fontWeight: 600 }}>{s.name}</td>
                <td>${s.base_salary}.00</td>
                <td>{s.ot_hours} ម៉ោង</td>
                <td style={{ color: '#10b981', fontWeight: 600 }}>+${s.ot_amount}.00</td>
                <td style={{ color: '#ef4444' }}>-${s.deductions}.00</td>
                <td style={{ fontWeight: 800, fontSize: '14px', color: 'var(--accent-gold)' }}>
                  ${s.net_salary}.00
                </td>
                <td>
                  <span className={`badge ${s.status === 'Paid' ? 'badge-good' : 'badge-late'}`}>
                    {s.status === 'Paid' ? '✅ បានបើករួច' : '⏳ រង់ចាំបើក'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
