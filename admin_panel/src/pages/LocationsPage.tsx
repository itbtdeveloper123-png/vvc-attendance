import React, { useState } from 'react';
import { MapPin, QrCode, Plus, Download, ShieldCheck } from 'lucide-react';
import { Modal } from '../components/common/Modal';

export const LocationsPage: React.FC = () => {
  const [locations] = useState([
    {
      id: 1,
      name: 'ការិយាល័យកណ្តាល (Store 318)',
      address: 'ផ្ទះលេខ 318 ផ្លូវកម្ពុជាក្រោម រាជធានីភ្នំពេញ',
      latitude: 11.5683,
      longitude: 104.9125,
      radius_meters: 100,
      qr_secret: 'vvc_318_secure_qr_2026',
    },
    {
      id: 2,
      name: 'សាខា SKKS2',
      address: 'ផ្លូវ 271 រាជធានីភ្នំពេញ',
      latitude: 11.5421,
      longitude: 104.9012,
      radius_meters: 100,
      qr_secret: 'vvc_skks2_secure_qr_2026',
    },
    {
      id: 3,
      name: 'ឃ្លាំងទំនិញ PSP (Warehouse)',
      address: 'ផ្លូវជាតិលេខ ៤ រាជធានីភ្នំពេញ',
      latitude: 11.5124,
      longitude: 104.8211,
      radius_meters: 150,
      qr_secret: 'vvc_psp_warehouse_qr_2026',
    },
  ]);

  const [qrModal, setQrModal] = useState<any | null>(null);

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

        <button className="btn btn-primary">
          <Plus size={16} />
          <span>បង្កើតទីតាំងថ្មី</span>
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
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px', marginBottom: '16px' }}>
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
                  {loc.address}
                </p>
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
