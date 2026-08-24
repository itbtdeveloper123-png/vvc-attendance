import React, { useState, useEffect } from 'react';
import {
  Package,
  ShoppingCart,
  ArrowRightLeft,
  FileSpreadsheet,
  Plus,
  Search,
  CheckCircle,
  AlertTriangle,
  Edit2,
  Trash2,
  Check,
  RotateCw,
} from 'lucide-react';
import { StatCard } from '../components/common/StatCard';
import { Modal } from '../components/common/Modal';
import { adminApi, StockItem } from '../api/adminApi';

export const StockPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'control' | 'requests' | 'purchase' | 'transfer' | 'reports'>('control');
  const [stockItems, setStockItems] = useState<StockItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  const [editingItem, setEditingItem] = useState<StockItem | null>(null);
  const [formData, setFormData] = useState({
    code: '',
    name: '',
    category: 'General',
    quantity: 0,
    unit: 'កញ្ចប់',
    price: 0,
    location: 'Store 318',
  });

  const loadStock = async () => {
    setLoading(true);
    try {
      const res = await adminApi.fetchStockItems();
      if (res && res.success && Array.isArray(res.items)) {
        setStockItems(res.items);
      }
    } catch (err) {
      console.error('Error fetching stock:', err);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadStock();
  }, []);

  const filtered = stockItems.filter((item) => {
    const q = (search || '').toLowerCase();
    const name = (item.name || '').toLowerCase();
    const code = (item.code || '').toLowerCase();
    const category = (item.category || '').toLowerCase();
    return name.includes(q) || code.includes(q) || category.includes(q);
  });

  const totalItemsCount = stockItems.length;
  const lowStockCount = stockItems.filter((i) => {
    const qty = Number(i.quantity) || 0;
    return qty > 0 && qty < 10;
  }).length;
  const outOfStockCount = stockItems.filter((i) => (Number(i.quantity) || 0) <= 0).length;

  const handleOpenCreate = () => {
    setEditingItem(null);
    setFormData({
      code: `STK-${Math.floor(100 + Math.random() * 900)}`,
      name: '',
      category: 'General',
      quantity: 10,
      unit: 'កញ្ចប់',
      price: 5.0,
      location: 'Store 318',
    });
    setModalOpen(true);
  };

  const handleOpenEdit = (item: StockItem) => {
    setEditingItem(item);
    setFormData({
      code: item.code,
      name: item.name,
      category: item.category || 'General',
      quantity: Number(item.quantity) || 0,
      unit: item.unit || 'កញ្ចប់',
      price: Number(item.price) || 0,
      location: item.location || 'Store 318',
    });
    setModalOpen(true);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name) return;
    try {
      if (editingItem) {
        await adminApi.saveStockItem({ id: editingItem.id, ...formData });
      } else {
        await adminApi.saveStockItem(formData);
      }
      setModalOpen(false);
      loadStock();
    } catch (err) {
      alert('កំហុសក្នុងការរក្សាទុកទំនិញ');
    }
  };

  const handleDelete = async (id: number) => {
    if (window.confirm('តើអ្នកពិតជាចង់លុបទំនិញនេះមែនទេ?')) {
      try {
        await adminApi.deleteStockItem(id);
        loadStock();
      } catch (err) {
        alert('កំហុសក្នុងការលុប');
      }
    }
  };

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

        <button onClick={handleOpenCreate} className="btn btn-primary">
          <Plus size={16} />
          <span>បញ្ចូលទំនិញថ្មី (Add Stock Item)</span>
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
          value={`${totalItemsCount} មុខ`}
          subtitle="ទំនិញសកម្មក្នុងប្រព័ន្ធ"
          icon={<Package size={22} />}
          variant="primary"
        />
        <StatCard
          title="ទំនិញជិតអស់ (Low Stock)"
          value={`${lowStockCount} មុខ`}
          subtitle="ទាបជាងកម្រិតស្តង់ដារ"
          icon={<AlertTriangle size={22} />}
          variant="warning"
        />
        <StatCard
          title="អស់ពីស្តុក (Out of Stock)"
          value={`${outOfStockCount} មុខ`}
          subtitle="ត្រូវបញ្ជាទិញបន្ថែម"
          icon={<ShoppingCart size={22} />}
          variant="danger"
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
              <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={9} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                  {loading ? 'កំពុងទាញយកទិន្នន័យស្តុក...' : 'មិនមានទំនិញក្នុងស្តុកឡើយ'}
                </td>
              </tr>
            ) : (
              filtered.map((item) => (
                <tr key={item.id}>
                  <td style={{ fontFamily: "'Outfit', monospace", fontWeight: 700, color: 'var(--primary)' }}>
                    {item.code}
                  </td>
                  <td style={{ fontWeight: 600 }}>{item.name}</td>
                  <td style={{ color: 'var(--text-secondary)' }}>{item.category}</td>
                  <td style={{ fontWeight: 700, fontSize: '14px' }}>{item.quantity}</td>
                  <td>{item.unit}</td>
                  <td style={{ fontWeight: 700, color: 'var(--accent-gold)' }}>${Number(item.price).toFixed(2)}</td>
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
                  <td style={{ textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: '6px' }}>
                      <button
                        type="button"
                        onClick={() => handleOpenEdit(item)}
                        className="btn btn-secondary btn-sm"
                        title="កែប្រែ"
                      >
                        <Edit2 size={13} />
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDelete(item.id)}
                        className="btn btn-danger btn-sm"
                        title="លុប"
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Add / Edit Stock Modal */}
      {modalOpen && (
        <Modal
          isOpen={modalOpen}
          onClose={() => setModalOpen(false)}
          title={editingItem ? 'កែប្រែទំនិញក្នុងស្តុក' : 'បញ្ចូលទំនិញថ្មី'}
          maxWidth="520px"
        >
          <form onSubmit={handleSave}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">កូដទំនិញ *</label>
                  <input
                    type="text"
                    className="form-input"
                    value={formData.code}
                    onChange={(e) => setFormData({ ...formData, code: e.target.value })}
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">ឈ្មោះទំនិញ *</label>
                  <input
                    type="text"
                    className="form-input"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="ឧ. កាហ្វេគូលែន KouPrey"
                    required
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">ប្រភេទទំនិញ</label>
                  <input
                    type="text"
                    className="form-input"
                    value={formData.category}
                    onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">ទីតាំង / ឃ្លាំង</label>
                  <select
                    className="form-select"
                    value={formData.location}
                    onChange={(e) => setFormData({ ...formData, location: e.target.value })}
                  >
                    <option value="Store 318">Store 318</option>
                    <option value="Store SKKS2">Store SKKS2</option>
                    <option value="Warehouse PSP">Warehouse PSP</option>
                  </select>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">ចំនួនស្តុក *</label>
                  <input
                    type="number"
                    className="form-input"
                    value={formData.quantity}
                    onChange={(e) => setFormData({ ...formData, quantity: Number(e.target.value) })}
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">ឯកតា</label>
                  <input
                    type="text"
                    className="form-input"
                    value={formData.unit}
                    onChange={(e) => setFormData({ ...formData, unit: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">តម្លៃរាយ ($)</label>
                  <input
                    type="number"
                    step="0.01"
                    className="form-input"
                    value={formData.price}
                    onChange={(e) => setFormData({ ...formData, price: Number(e.target.value) })}
                  />
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px', borderTop: '1px solid var(--border)', paddingTop: '14px' }}>
              <button type="button" onClick={() => setModalOpen(false)} className="btn btn-secondary">
                បោះបង់
              </button>
              <button type="submit" className="btn btn-primary">
                <Check size={16} />
                <span>រក្សាទុកទំនិញ</span>
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
};

