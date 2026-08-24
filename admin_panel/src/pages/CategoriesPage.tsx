import React, { useState, useEffect } from 'react';
import {
  Folder,
  Plus,
  Search,
  Edit2,
  Trash2,
  Check,
  Layers,
  Tag,
  RotateCw,
  CheckCircle2,
  Package,
} from 'lucide-react';
import { Modal } from '../components/common/Modal';
import { StatCard } from '../components/common/StatCard';
import { adminApi, CategoryItem } from '../api/adminApi';

export const CategoriesPage: React.FC = () => {
  const [categories, setCategories] = useState<CategoryItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  const [editingCat, setEditingCat] = useState<CategoryItem | null>(null);
  const [formData, setFormData] = useState({ name: '', code: '', description: '' });
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const showBanner = (type: 'success' | 'error', text: string) => {
    setBanner({ type, text });
    setTimeout(() => setBanner(null), 3500);
  };

  const loadCategories = async () => {
    setLoading(true);
    try {
      const res = await adminApi.fetchCategories();
      if (res && (res.success || res.status === 'success')) {
        const list = Array.isArray(res.categories) ? res.categories : (Array.isArray(res.data) ? res.data : []);
        setCategories(list);
      }
    } catch (err) {
      console.error('Error fetching categories:', err);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadCategories();
  }, []);

  const filtered = categories.filter((c) => {
    const q = (search || '').toLowerCase();
    const name = (c.name || '').toLowerCase();
    const code = (c.code || '').toLowerCase();
    const desc = (c.description || '').toLowerCase();
    return name.includes(q) || code.includes(q) || desc.includes(q);
  });

  const totalItemsCount = categories.reduce((sum, c) => sum + Number(c.item_count || 0), 0);

  const handleOpenCreate = () => {
    setEditingCat(null);
    setFormData({ name: '', code: `CAT-${Math.floor(100 + Math.random() * 900)}`, description: '' });
    setModalOpen(true);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name.trim()) {
      alert('សូមបញ្ចូលឈ្មោះប្រភេទ!');
      return;
    }
    try {
      const payload: any = {
        name: formData.name,
        category_name: formData.name,
        code: formData.code,
        description: formData.description,
      };
      if (editingCat) {
        payload.id = editingCat.id;
        payload.category_id = editingCat.id;
      }
      const res = await adminApi.saveCategory(payload);
      if (res && (res.success || res.status === 'success')) {
        showBanner('success', res.message || 'បានរក្សាទុកប្រភេទជោគជ័យ!');
        setModalOpen(false);
        loadCategories();
      } else {
        showBanner('error', res?.message || 'Error saving category');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការរក្សាទុកប្រភេទ');
    }
  };

  const handleDelete = async (id: number, name: string) => {
    if (window.confirm(`តើអ្នកពិតជាចង់លុបប្រភេទ "${name}" នេះមែនទេ?`)) {
      try {
        const res = await adminApi.deleteCategory(id);
        if (res && (res.success || res.status === 'success')) {
          showBanner('success', res.message || 'បានលុបប្រភេទជោគជ័យ!');
          loadCategories();
        } else {
          showBanner('error', res?.message || 'Error deleting category');
        }
      } catch (err) {
        showBanner('error', 'កំហុសក្នុងការលុប');
      }
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '22px', maxWidth: '1200px', margin: '0 auto', width: '100%' }}>
      {/* Header Banner */}
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
              <Folder size={20} />
            </span>
            <h2 style={{ fontSize: '22px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              គ្រប់គ្រងប្រភេទ (Category Management)
            </h2>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0 }}>
            គ្រប់គ្រងប្រភេទមុខទំនិញ សម្ភារៈ និងផ្នែកចាត់ថ្នាក់ទូទៅក្នុងប្រព័ន្ធស្តុក និងក្រុមហ៊ុន
          </p>
        </div>

        <button
          onClick={handleOpenCreate}
          className="btn btn-primary"
          style={{ borderRadius: '12px', padding: '11px 20px', fontWeight: 700 }}
        >
          <Plus size={16} />
          <span>+ បន្ថែមប្រភេទថ្មី</span>
        </button>
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
          <CheckCircle2 size={16} />
          <span>{banner.text}</span>
        </div>
      )}

      {/* KPI Stats */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '16px',
        }}
      >
        <StatCard
          title="ប្រភេទសរុប"
          value={`${categories.length} ប្រភេទ`}
          subtitle="ប្រភេទមុខទំនិញ និងសម្ភារៈ"
          icon={<Folder size={22} />}
          variant="primary"
        />
        <StatCard
          title="មុខទំនិញក្នុងប្រភេទ"
          value={`${totalItemsCount} មុខ`}
          subtitle="មុខទំនិញបានចាត់ថ្នាក់"
          icon={<Package size={22} />}
          variant="success"
        />
        <StatCard
          title="ស្ថានភាពប្រព័ន្ធ"
          value="សកម្ម (Active)"
          subtitle="ទិន្នន័យបានធ្វើសមកាលកម្ម"
          icon={<Layers size={22} />}
          variant="gold"
        />
      </div>

      {/* Toolbar */}
      <div
        className="hrm-card"
        style={{
          padding: '16px 20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '14px',
          borderRadius: '16px',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            background: 'var(--surface-alt)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            padding: '8px 14px',
            width: '320px',
            gap: '8px',
          }}
        >
          <Search size={16} color="var(--text-muted)" />
          <input
            type="text"
            placeholder="ស្វែងរកតាមឈ្មោះ ឬកូដប្រភេទ..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              background: 'transparent',
              border: 'none',
              outline: 'none',
              fontSize: '13.5px',
              color: 'var(--text-primary)',
              fontFamily: 'inherit',
              width: '100%',
            }}
          />
        </div>

        <button onClick={loadCategories} className="btn btn-secondary btn-sm" style={{ borderRadius: '10px' }}>
          <RotateCw size={14} className={loading ? 'fa-spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Categories Table */}
      <div className="table-container">
        <table className="hrm-table">
          <thead>
            <tr>
              <th style={{ width: '80px' }}>#</th>
              <th>កូដប្រភេទ (Code)</th>
              <th>ឈ្មោះប្រភេទ</th>
              <th>ការពិពណ៌នា</th>
              <th>ចំនួនទំនិញ</th>
              <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                  {loading ? 'កំពុងទាញយកទិន្នន័យ...' : 'រកមិនឃើញប្រភេទឡើយ'}
                </td>
              </tr>
            ) : (
              filtered.map((cat, idx) => (
                <tr key={cat.id}>
                  <td>{idx + 1}</td>
                  <td>
                    <span className="badge badge-primary" style={{ fontFamily: 'monospace', fontWeight: 700 }}>
                      {cat.code}
                    </span>
                  </td>
                  <td>
                    <div style={{ fontWeight: 800, color: 'var(--text-primary)', fontSize: '13.5px' }}>{cat.name}</div>
                  </td>
                  <td style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>{cat.description || '—'}</td>
                  <td>
                    <span className="badge badge-good">{cat.item_count || 0} មុខ</span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: '6px' }}>
                      <button
                        type="button"
                        onClick={() => {
                          setEditingCat(cat);
                          setFormData({ name: cat.name, code: cat.code, description: cat.description || '' });
                          setModalOpen(true);
                        }}
                        className="btn btn-secondary btn-sm"
                        style={{ borderRadius: '8px' }}
                      >
                        <Edit2 size={13} />
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDelete(cat.id, cat.name)}
                        className="btn btn-danger btn-sm"
                        style={{ borderRadius: '8px' }}
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

      <Modal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        title={editingCat ? `កែសម្រួលប្រភេទ - ${editingCat.name}` : 'បន្ថែមប្រភេទថ្មី'}
      >
        <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div className="form-group">
            <label className="form-label">កូដប្រភេទ (Category Code) *</label>
            <input
              type="text"
              className="form-input"
              value={formData.code}
              onChange={(e) => setFormData({ ...formData, code: e.target.value })}
              required
            />
          </div>
          <div className="form-group">
            <label className="form-label">ឈ្មោះប្រភេទ (Category Name) *</label>
            <input
              type="text"
              className="form-input"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              placeholder="ឧ. សម្ភារៈការិយាល័យ ឬ Coffee Beans"
              required
            />
          </div>
          <div className="form-group">
            <label className="form-label">ការពិពណ៌នា (Description)</label>
            <textarea
              className="form-input"
              rows={3}
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="ព័ត៌មានលម្អិតបន្ថែមអំពីប្រភេទនេះ..."
            />
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
            <button type="button" onClick={() => setModalOpen(false)} className="btn btn-secondary">
              បោះបង់
            </button>
            <button type="submit" className="btn btn-primary">
              <Check size={16} />
              <span>រក្សាទុក</span>
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
