import React, { useState } from 'react';
import {
  Settings,
  Save,
  Shield,
  Palette,
  Smartphone,
  Check,
  LayoutGrid,
  FileCode,
  Menu,
} from 'lucide-react';
import { adminApi } from '../api/adminApi';

export const SettingsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'panel' | 'scan_rules' | 'fields' | 'menu' | 'theme'>('panel');

  const [panelTitle, setPanelTitle] = useState('VVC ATTENDANCE');
  const [companyName, setCompanyName] = useState('VVC Asia Co., Ltd.');
  const [lateThreshold, setLateThreshold] = useState('15');
  const [requireFaceScan, setRequireFaceScan] = useState(true);
  const [allowOutsideScan, setAllowOutsideScan] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);

  const [userFields] = useState([
    { key: 'department', label: 'នាយកដ្ឋាន / ផ្នែក', type: 'text', required: true },
    { key: 'position', label: 'តួនាទី / មុខតំណែង', type: 'text', required: true },
    { key: 'workplace', label: 'កន្លែងធ្វើការ', type: 'text', required: false },
    { key: 'branch', label: 'សាខា', type: 'text', required: false },
  ]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await adminApi.saveSettings({
        panel_title: panelTitle,
        company_name: companyName,
        late_threshold_minutes: lateThreshold,
        require_face_scan: requireFaceScan ? '1' : '0',
        allow_outside_scan: allowOutsideScan ? '1' : '0',
      });
      setSavedSuccess(true);
      setTimeout(() => setSavedSuccess(false), 3000);
    } catch {}
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '900px' }}>
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-primary)' }}>
          ការកំណត់ប្រព័ន្ធទាំងមូល (System & Panel Settings)
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
          កំណត់ព័ត៌មាន Branding, ច្បាប់ស្កេនវត្តមាន App, គ្រប់គ្រង Fields ទិន្នន័យ និង Themes
        </p>
      </div>

      {/* Sub-Tabs */}
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
          { id: 'panel', label: '🏢 ការកំណត់ Panel (Branding)', icon: LayoutGrid },
          { id: 'scan_rules', label: '📱 ច្បាប់ស្កេន App (App Scan)', icon: Smartphone },
          { id: 'fields', label: '📑 គ្រប់គ្រង Fields (Form Fields)', icon: FileCode },
          { id: 'menu', label: '🗂️ ការកំណត់ Menu (Sidebar Settings)', icon: Menu },
          { id: 'theme', label: '🎨 Theme & ពណ៌ (Themes)', icon: Palette },
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`btn btn-sm ${activeTab === tab.id ? 'btn-primary' : 'btn-secondary'}`}
            >
              <Icon size={14} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {savedSuccess && (
        <div
          style={{
            padding: '14px 20px',
            borderRadius: '12px',
            background: 'var(--success-light)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            color: 'var(--success)',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            fontSize: '14px',
            fontWeight: 600,
          }}
        >
          <Check size={18} />
          <span>ការកំណត់ត្រូវបានរក្សាទុកដោយជោគជ័យ!</span>
        </div>
      )}

      {activeTab === 'panel' && (
        <form onSubmit={handleSave} className="hrm-card" style={{ padding: '28px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
            <LayoutGrid size={20} color="var(--primary)" />
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
              ព័ត៌មានទូទៅ & Logo Panel
            </h3>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '18px' }}>
            <div className="form-group">
              <label className="form-label">ឈ្មោះ Panel (Panel Title)</label>
              <input
                type="text"
                className="form-input"
                value={panelTitle}
                onChange={(e) => setPanelTitle(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">ឈ្មោះក្រុមហ៊ុន (Company Name)</label>
              <input
                type="text"
                className="form-input"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                required
              />
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '16px' }}>
            <button type="submit" className="btn btn-primary">
              <Save size={16} />
              <span>រក្សាទុក (Save)</span>
            </button>
          </div>
        </form>
      )}

      {activeTab === 'scan_rules' && (
        <form onSubmit={handleSave} className="hrm-card" style={{ padding: '28px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
            <Smartphone size={20} color="var(--accent-gold)" />
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
              ច្បាប់ស្កេនវត្តមានលើ App (App Scan Rules)
            </h3>
          </div>

          <div className="form-group">
            <label className="form-label">
              កម្រិតកំណត់មកយឺត (Late Threshold Minutes)
            </label>
            <input
              type="number"
              className="form-input"
              value={lateThreshold}
              onChange={(e) => setLateThreshold(e.target.value)}
              style={{ maxWidth: '200px' }}
            />
            <span style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px', display: 'block' }}>
              ប្រសិនបើស្កេនលើសម៉ោងកំណត់នេះ ប្រព័ន្ធនឹងទាមទារឱ្យបុគ្គលិកបញ្ជាក់មូលហេតុ។
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', marginTop: '16px' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={requireFaceScan}
                onChange={(e) => setRequireFaceScan(e.target.checked)}
                style={{ width: '18px', height: '18px', accentColor: 'var(--primary)' }}
              />
              <span style={{ fontSize: '14px', color: 'var(--text-primary)', fontWeight: 500 }}>
                ទាមទារការស្កេនផ្ទៃមុខ (Face Recognition Required)
              </span>
            </label>

            <label style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={allowOutsideScan}
                onChange={(e) => setAllowOutsideScan(e.target.checked)}
                style={{ width: '18px', height: '18px', accentColor: 'var(--primary)' }}
              />
              <span style={{ fontSize: '14px', color: 'var(--text-primary)', fontWeight: 500 }}>
                អនុញ្ញាតឱ្យស្កេនក្រៅទីតាំង (Allow Outside Scan)
              </span>
            </label>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '24px' }}>
            <button type="submit" className="btn btn-primary">
              <Save size={16} />
              <span>រក្សាទុក (Save)</span>
            </button>
          </div>
        </form>
      )}

      {activeTab === 'fields' && (
        <div className="hrm-card" style={{ padding: '24px' }}>
          <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '16px' }}>
            គ្រប់គ្រង Dynamic Form Fields
          </h3>
          <div className="table-container">
            <table className="hrm-table">
              <thead>
                <tr>
                  <th>Key</th>
                  <th>ឈ្មោះ Field (Label)</th>
                  <th>ប្រភេទ Field</th>
                  <th>តម្រូវការ (Required)</th>
                </tr>
              </thead>
              <tbody>
                {userFields.map((f, idx) => (
                  <tr key={idx}>
                    <td><code>{f.key}</code></td>
                    <td style={{ fontWeight: 600 }}>{f.label}</td>
                    <td>{f.type}</td>
                    <td>
                      <span className={`badge ${f.required ? 'badge-good' : 'badge-primary'}`}>
                        {f.required ? 'ចាំបាច់ (Required)' : 'ស្រេចចិត្ត (Optional)'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'menu' && (
        <div className="hrm-card" style={{ padding: '24px' }}>
          <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '12px' }}>
            ការកំណត់ Sidebar Menu Visibility
          </h3>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            គ្រប់ម៉ឺនុយទាំងអស់ត្រូវបានគ្រប់គ្រងដោយស្វ័យប្រវត្តតាមរយៈ System Role Permission (Super Admin, HR, Manager, Staff)។
          </p>
        </div>
      )}

      {activeTab === 'theme' && (
        <div className="hrm-card" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <Palette size={20} color="var(--primary)" />
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
              ការគ្រប់គ្រង Seasonal Themes & Colors
            </h3>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '20px' }}>
            ជ្រើសរើស Theme សម្រាប់ដំណើរការទូទាំងប្រព័ន្ធ Panel និង Mobile App
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
            {[
              { id: 'vvc_royal_gold', name: 'VVC Royal Luxury', color: '#1e1b4b', accent: '#d4af37' },
              { id: 'khmer_new_year', name: 'ចូលឆ្នាំខ្មែរ (Khmer New Year)', color: '#991b1b', accent: '#fbbf24' },
              { id: 'pchum_ben', name: 'ភ្ជុំបិណ្ឌ (Pchum Ben Festival)', color: '#312e81', accent: '#f59e0b' },
              { id: 'water_festival', name: 'បុណ្យអុំទូក (Water Festival)', color: '#0369a1', accent: '#38bdf8' },
            ].map((t) => (
              <div
                key={t.id}
                style={{
                  border: '1px solid var(--border)',
                  borderRadius: '12px',
                  padding: '16px',
                  background: 'var(--surface-alt)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '12px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div style={{ width: '18px', height: '18px', borderRadius: '50%', background: t.color }} />
                  <div style={{ width: '18px', height: '18px', borderRadius: '50%', background: t.accent }} />
                  <span style={{ fontSize: '13.5px', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {t.name}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={async () => {
                    try {
                      await adminApi.setActiveTheme(t.id);
                      alert(`បានប្តូរ Theme ទៅ «${t.name}» ជោគជ័យ!`);
                    } catch (err) {
                      alert('កំហុសក្នុងការប្តូរ Theme');
                    }
                  }}
                  className="btn btn-secondary btn-sm"
                  style={{ width: '100%', justifyContent: 'center' }}
                >
                  <Check size={14} />
                  <span>ជ្រើសរើស Theme នេះ</span>
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
