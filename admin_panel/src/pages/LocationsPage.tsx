import React, { useState, useEffect } from 'react';
import { MapPin, QrCode, Plus, Download, Edit2, Trash2, Check, RotateCw } from 'lucide-react';
import { Modal } from '../components/common/Modal';
import { adminApi, LocationItem } from '../api/adminApi';

export const LocationsPage: React.FC = () => {
  const [locations, setLocations] = useState<LocationItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [qrModal, setQrModal] = useState<LocationItem | null>(null);
  const [editModal, setEditModal] = useState(false);
  const [editingLoc, setEditingLoc] = useState<LocationItem | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    address: '',
    latitude: 11.5683,
    longitude: 104.9125,
    radius_meters: 100,
    qr_secret: '',
  });

  const loadLocations = async () => {
    setLoading(true);
    try {
      const res = await adminApi.fetchLocations();
      if (res && res.success && Array.isArray(res.locations)) {
        setLocations(res.locations);
      }
    } catch (err) {
      console.error('Error fetching locations:', err);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadLocations();
  }, []);

  const handleOpenCreate = () => {
    setEditingLoc(null);
    setFormData({
      name: '',
      address: '',
      latitude: 11.5564,
      longitude: 104.9282,
      radius_meters: 100,
      qr_secret: `vvc_${Math.floor(100 + Math.random() * 900)}_secure_qr`,
    });
    setEditModal(true);
  };

  const handleOpenEdit = (loc: LocationItem) => {
    setEditingLoc(loc);
    setFormData({
      name: loc.name,
      address: loc.address || '',
      latitude: Number(loc.latitude) || 11.5564,
      longitude: Number(loc.longitude) || 104.9282,
      radius_meters: Number(loc.radius_meters) || 100,
      qr_secret: loc.qr_secret || '',
    });
    setEditModal(true);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name) return;
    try {
      if (editingLoc) {
        await adminApi.saveLocation({ id: editingLoc.id, ...formData });
      } else {
        await adminApi.saveLocation(formData);
      }
      setEditModal(false);
      loadLocations();
    } catch (err) {
      alert('កំហុសក្នុងការរក្សាទុកទីតាំង');
    }
  };

  const handleDelete = async (id: number) => {
    if (window.confirm('តើអ្នកពិតជាចង់លុបទីតាំងនេះមែនទេ?')) {
      try {
        await adminApi.deleteLocation(id);
        loadLocations();
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
            ទីតាំង & QR Codes (Locations Management)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            កំណត់កូអរដោនេ GPS កាំស្កេន (Radius) និងទាញយក QR Code សម្រាប់បិទនៅតាមសាខា
          </p>
        </div>

        <button onClick={handleOpenCreate} className="btn btn-primary">
          <Plus size={16} />
          <span>បង្កើតទីតាំងថ្មី (Add Location)</span>
        </button>
      </div>

      {/* Locations Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: '20px',
        }}
      >
        {locations.map((loc) => (
          <div key={loc.id} className="hrm-card hover-lift" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
                <div
                  style={{
                    width: '44px',
                    height: '44px',
                    borderRadius: '12px',
                    background: 'var(--primary-light)',
                    color: 'var(--primary)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                  }}
                >
                  <MapPin size={22} />
                </div>
                <div>
                  <h3 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {loc.name}
                  </h3>
                  <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>
                    {loc.address || 'មិនមានអាសយដ្ឋាន'}
                  </p>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '4px' }}>
                <button
                  type="button"
                  onClick={() => handleOpenEdit(loc)}
                  className="btn btn-secondary btn-sm"
                  title="កែប្រែ"
                >
                  <Edit2 size={13} />
                </button>
                <button
                  type="button"
                  onClick={() => handleDelete(loc.id)}
                  className="btn btn-danger btn-sm"
                  title="លុប"
                >
                  <Trash2 size={13} />
                </button>
              </div>
            </div>

            <div
              style={{
                background: 'var(--surface-alt)',
                border: '1px solid var(--border)',
                borderRadius: '10px',
                padding: '12px 16px',
                fontSize: '12.5px',
                color: 'var(--text-secondary)',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
                marginBottom: '16px',
              }}
            >
              <div>• GPS: <code>{loc.latitude}, {loc.longitude}</code></div>
              <div>• កាំស្កេនអនុញ្ញាត: <strong>{loc.radius_meters} ម៉ែត្រ</strong></div>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <button
                onClick={() => setQrModal(loc)}
                className="btn btn-gold btn-sm"
                style={{ flex: 1 }}
              >
                <QrCode size={15} />
                <span>មើល & បោះពុម្ព QR</span>
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Edit / Create Location Modal */}
      {editModal && (
        <Modal
          isOpen={editModal}
          onClose={() => setEditModal(false)}
          title={editingLoc ? 'កែប្រែព័ត៌មានទីតាំង' : 'បង្កើតទីតាំងសាខាថ្មី'}
          maxWidth="500px"
        >
          <form onSubmit={handleSave}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div className="form-group">
                <label className="form-label">ឈ្មោះទីតាំង / សាខា *</label>
                <input
                  type="text"
                  className="form-input"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="ឧ. សាខា Store 318"
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">អាសយដ្ឋាន</label>
                <input
                  type="text"
                  className="form-input"
                  value={formData.address}
                  onChange={(e) => setFormData({ ...formData, address: e.target.value })}
                  placeholder="ឧ. ផ្លូវកម្ពុជាក្រោម រាជធានីភ្នំពេញ"
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">Latitude</label>
                  <input
                    type="number"
                    step="any"
                    className="form-input"
                    value={formData.latitude}
                    onChange={(e) => setFormData({ ...formData, latitude: Number(e.target.value) })}
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Longitude</label>
                  <input
                    type="number"
                    step="any"
                    className="form-input"
                    value={formData.longitude}
                    onChange={(e) => setFormData({ ...formData, longitude: Number(e.target.value) })}
                    required
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">កាំស្កេនអនុញ្ញាត (Radius Meters)</label>
                <input
                  type="number"
                  className="form-input"
                  value={formData.radius_meters}
                  onChange={(e) => setFormData({ ...formData, radius_meters: Number(e.target.value) })}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">QR Secret Key</label>
                <input
                  type="text"
                  className="form-input"
                  value={formData.qr_secret}
                  onChange={(e) => setFormData({ ...formData, qr_secret: e.target.value })}
                  placeholder="ស្វ័យប្រវត្ត"
                />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px', borderTop: '1px solid var(--border)', paddingTop: '14px' }}>
              <button type="button" onClick={() => setEditModal(false)} className="btn btn-secondary">
                បោះបង់
              </button>
              <button type="submit" className="btn btn-primary">
                <Check size={16} />
                <span>រក្សាទុកទីតាំង</span>
              </button>
            </div>
          </form>
        </Modal>
      )}

      {/* QR Code Modal */}
      {qrModal && (
        <Modal
          isOpen={!!qrModal}
          onClose={() => setQrModal(null)}
          title={`QR Code វត្តមាន - ${qrModal.name}`}
        >
          <div style={{ textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '20px' }}>
            <div
              style={{
                background: '#ffffff',
                padding: '24px',
                borderRadius: '20px',
                boxShadow: 'var(--shadow)',
                border: '2px dashed var(--accent-gold)',
              }}
            >
              <img
                src={`https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(
                  JSON.stringify({ location_id: qrModal.id, secret: qrModal.qr_secret })
                )}`}
                alt="QR Code"
                style={{ width: '220px', height: '220px', display: 'block' }}
              />
              <div style={{ marginTop: '12px', fontWeight: 800, fontSize: '15px', color: '#0f172a' }}>
                {qrModal.name}
              </div>
              <div style={{ fontSize: '11px', color: '#64748b' }}>
                ស្កេនដើម្បីកត់ត្រាវត្តមាន (Check-In / Out)
              </div>
            </div>

            <button
              onClick={() => window.print()}
              className="btn btn-primary"
            >
              <Download size={16} />
              <span>បោះពុម្ព QR Code (Print)</span>
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
};
