import React, { useState } from 'react';
import {
  Folder,
  Plus,
  Search,
  Edit2,
  Trash2,
  Check,
  Layers,
  Tag,
} from 'lucide-react';
import { Modal } from '../components/common/Modal';

export const CategoriesPage: React.FC = () => {
  const [categories, setCategories] = useState([
    { id: 1, name: 'សម្ភារៈការិយាល័យ (Office Supplies)', code: 'CAT-OFFICE', itemCount: 34, description: 'សម្ភារៈប្រើប្រាស់ទូទៅ' },
    { id: 2, name: 'គ្រឿងអេឡិចត្រូនិច (Electronics)', code: 'CAT-ELEC', itemCount: 18, description: 'កុំព្យូទ័រ ម៉ាស៊ីនព្រីន ឧបករណ៍បច្ចេកវិទ្យា' },
    { id: 3, name: 'ទំនិញស្តុកហាង 318 (Store 318 Goods)', code: 'CAT-S318', itemCount: 120, description: 'ទំនិញលក់រាយនៅហាង 318' },
    { id: 4, name: 'ទំនិញស្តុកឃ្លាំង PSP (Warehouse PSP Goods)', code: 'CAT-PSP', itemCount: 250, description: 'ទំនិញស្តុកធំនៅឃ្លាំង PSP' },
  ]);

  const [search, setSearch] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  const [editingCat, setEditingCat] = useState<any>(null);
  const [formData, setFormData] = useState({ name: '', code: '', description: '' });

  const filtered = categories.filter(
    (c) =>
      c.name.toLowerCase().includes(search.toLowerCase()) ||
      c.code.toLowerCase().includes(search.toLowerCase())
  );

  const handleOpenCreate = () => {
    setEditingCat(null);
    setFormData({ name: '', code: `CAT-${Math.floor(100 + Math.random() * 900)}`, description: '' });
    setModalOpen(true);
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name) return;
    if (editingCat) {
      setCategories((prev) =>
        prev.map((c) => (c.id === editingCat.id ? { ...c, ...formData } : c))
      );
    } else {
      setCategories((prev) => [
        { id: Date.now(), ...formData, itemCount: 0 },
        ...prev,
      ]);
    }
    setModalOpen(false);
  };

  const handleDelete = (id: number) => {
    if (window.confirm('តើអ្នកពិតជាចង់លុបប្រភេទនេះមែនទេ?')) {
      setCategories((prev) => prev.filter((c) => c.id !== id));
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-primary)' }}>
            គ្រប់គ្រងប្រភេទ (Category Management)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            គ្រប់គ្រងប្រភេទមុខទំនិញ សម្ភារៈ និងផ្នែកចាត់ថ្នាក់ទូទៅក្នុងប្រព័ន្ធ
          </p>
        </div>

        <button onClick={handleOpenCreate} className="btn btn-primary">
          <Plus size={16} />
          <span>បន្ថែមប្រភេទថ្មី (Add Category)</span>
        </button>
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
      </div>

      {/* Categories Table */}
      <div className="table-container">
        <table className="hrm-table">
          <thead>
            <tr>
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
                <td colSpan={5} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                  រកមិនឃើញប្រភេទឡើយ
                </td>
              </tr>
            ) : (
              filtered.map((cat) => (
                <tr key={cat.id}>
                  <td>
                    <span className="badge badge-primary" style={{ fontFamily: 'monospace' }}>
                      {cat.code}
                    </span>
                  </td>
                  <td>
                    <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{cat.name}</div>
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }}>{cat.description || '-'}</td>
                  <td>
                    <span className="badge badge-good">{cat.itemCount} មុខ</span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: '6px' }}>
                      <button
                        onClick={() => {
                          setEditingCat(cat);
                          setFormData({ name: cat.name, code: cat.code, description: cat.description });
                          setModalOpen(true);
                        }}
                        className="btn btn-secondary btn-sm"
                      >
                        <Edit2 size={13} />
                      </button>
                      <button
                        onClick={() => handleDelete(cat.id)}
                        className="btn btn-danger btn-sm"
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
        title={editingCat ? 'កែសម្រួលប្រភេទ' : 'បន្ថែមប្រភេទថ្មី'}
      >
        <form onSubmit={handleSave}>
          <div className="form-group">
            <label className="form-label">កូដប្រភេទ (Category Code)</label>
            <input
              type="text"
              className="form-input"
              value={formData.code}
              onChange={(e) => setFormData({ ...formData, code: e.target.value })}
              required
            />
          </div>
          <div className="form-group">
            <label className="form-label">ឈ្មោះប្រភេទ (Category Name)</label>
            <input
              type="text"
              className="form-input"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              placeholder="ឧ. សម្ភារៈការិយាល័យ"
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
            />
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px' }}>
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
