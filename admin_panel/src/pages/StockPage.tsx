import React, { useState } from 'react';
import {
  Package,
  ShoppingCart,
  ArrowRightLeft,
  FileSpreadsheet,
  Plus,
  Search,
  CheckCircle,
  AlertTriangle,
} from 'lucide-react';
import { StatCard } from '../components/common/StatCard';

export const StockPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'control' | 'requests' | 'purchase' | 'transfer' | 'reports'>('control');

  const [stockItems] = useState([
    {
      id: 1,
      code: 'STK-001',
      name: 'កាហ្វេគូលែន KouPrey Coffee (250g)',
      category: 'Coffee Beans',
      quantity: 140,
      unit: 'កញ្ចប់',
      price: 6.5,
      location: 'Store 318',
      status: 'In Stock',
    },
    {
      id: 2,
      code: 'STK-002',
      name: 'តែបៃតង Green Tea Premium (500g)',
      category: 'Tea & Beverages',
      quantity: 8,
      unit: 'កញ្ចប់',
      price: 8.0,
      location: 'Store SKKS2',
      status: 'Low Stock',
    },
    {
      id: 3,
      code: 'STK-003',
      name: 'កែវជ័រ VVC Eco Cup (500ml)',
      category: 'Packaging',
      quantity: 2500,
      unit: 'កែវ',
      price: 0.12,
      location: 'Warehouse PSP',
      status: 'In Stock',
    },
    {
      id: 4,
      code: 'STK-004',
      name: 'ទឹកស៊ីរ៉ូវ៉ានីឡា Vanilla Syrup (1L)',
      category: 'Ingredients',
      quantity: 0,
      unit: 'ដប',
      price: 12.0,
      location: 'Warehouse PSP',
      status: 'Out of Stock',
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
            គ្រប់គ្រងស្តុក & សម្ភារៈ (Stock Control)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            គ្រប់គ្រងទំនិញក្នុងស្តុក ទិញចូល សំណើរសុំទំនិញ ផ្ទេរស្តុក និងរបាយការណ៍ស្តុក
          </p>
        </div>

        <button className="btn btn-primary">
          <Plus size={16} />
          <span>បញ្ចូលទំនិញថ្មី</span>
        </button>
      </div>

      {/* KPI Stats */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '20px',
        }}
      >
        <StatCard
          title="មុខទំនិញសរុប (Total Items)"
          value="45 មុខ"
          subtitle="ទំនិញសកម្មក្នុងប្រព័ន្ធ"
          icon={<Package size={22} />}
          variant="primary"
        />
        <StatCard
          title="ទំនិញជិតអស់ (Low Stock)"
          value="3 មុខ"
          subtitle="ទាបជាងកម្រិតស្តង់ដារ"
          icon={<AlertTriangle size={22} />}
          variant="warning"
        />
        <StatCard
          title="សំណើរសុំទំនិញ (Requests)"
          value="5 សំណើរ"
          subtitle="រង់ចាំអនុម័តពីប្រធានឃ្លាំង"
          icon={<ShoppingCart size={22} />}
          variant="gold"
        />
      </div>

      {/* Tabs */}
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
        {[
          { id: 'control', label: '📦 បញ្ជីស្តុកទំនិញ (Stock List)' },
          { id: 'requests', label: '🛒 សំណើរសុំទំនិញ (Stock Requests)' },
          { id: 'purchase', label: '📥 ទិញចូលស្តុក (Purchase)' },
          { id: 'transfer', label: '🔄 ផ្ទេរទំនិញរវាងសាខា (Transfer)' },
          { id: 'reports', label: '📊 របាយការណ៍ស្តុក (Reports)' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`btn btn-sm ${activeTab === tab.id ? 'btn-primary' : 'btn-secondary'}`}
          >
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Stock Table */}
      <div className="table-container">
        <table className="hrm-table">
          <thead>
            <tr>
              <th>កូដទំនិញ</th>
              <th>ឈ្មោះទំនិញ</th>
              <th>ប្រភេទទំនិញ</th>
              <th>បរិមាណក្នុងស្តុក</th>
              <th>ឯកតា</th>
              <th>តម្លៃរាយ ($)</th>
              <th>ទីតាំង / ឃ្លាំង</th>
              <th>ស្ថានភាព</th>
            </tr>
          </thead>
          <tbody>
            {stockItems.map((item) => (
              <tr key={item.id}>
                <td style={{ fontFamily: "'Outfit', monospace", fontWeight: 700, color: 'var(--primary)' }}>
                  {item.code}
                </td>
                <td style={{ fontWeight: 600 }}>{item.name}</td>
                <td style={{ color: 'var(--text-secondary)' }}>{item.category}</td>
                <td style={{ fontWeight: 700, fontSize: '14px' }}>{item.quantity}</td>
                <td>{item.unit}</td>
                <td style={{ fontWeight: 700, color: 'var(--accent-gold)' }}>${item.price.toFixed(2)}</td>
                <td>{item.location}</td>
                <td>
                  <span
                    className={`badge ${
                      item.status === 'In Stock'
                        ? 'badge-good'
                        : item.status === 'Low Stock'
                        ? 'badge-late'
                        : 'badge-absent'
                    }`}
                  >
                    {item.status === 'In Stock'
                      ? '✅ មានក្នុងស្តុក'
                      : item.status === 'Low Stock'
                      ? '⚠️ ជិតអស់'
                      : '❌ អស់ពីស្តុក'}
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
