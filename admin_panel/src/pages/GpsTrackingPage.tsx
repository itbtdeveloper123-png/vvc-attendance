import React, { useState, useEffect } from 'react';
import { Navigation, MapPin, Users, Activity, Play, CheckCircle2, Plus, Check, RotateCw } from 'lucide-react';
import { StatCard } from '../components/common/StatCard';
import { Modal } from '../components/common/Modal';
import { adminApi, GpsTripItem } from '../api/adminApi';

export const GpsTrackingPage: React.FC = () => {
  const [activeTrips, setActiveTrips] = useState<GpsTripItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [formData, setFormData] = useState({
    driver_name: '',
    employee_id: '',
    vehicle: 'ឡានដឹកទំនិញ (Truck 2.5T)',
    destination: '',
    current_location: '',
    speed: '40 km/h',
    status: 'In Transit',
  });

  const loadTrips = async () => {
    setLoading(true);
    try {
      const res = await adminApi.fetchGpsTrips();
      if (res && res.success && Array.isArray(res.trips)) {
        setActiveTrips(res.trips);
      }
    } catch (err) {
      console.error('Error fetching GPS trips:', err);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadTrips();
  }, []);

  const handleOpenCreate = () => {
    setFormData({
      driver_name: '',
      employee_id: `VVC-${Math.floor(100 + Math.random() * 900)}`,
      vehicle: 'ឡានដឹកទំនិញ (Truck 2.5T)',
      destination: '',
      current_location: 'Store 318',
      speed: '0 km/h',
      status: 'In Transit',
    });
    setModalOpen(true);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.driver_name || !formData.destination) {
      alert('សូមបញ្ចូលឈ្មោះអ្នកបើកបរ និងទិសដៅ!');
      return;
    }
    try {
      await adminApi.saveGpsTrip(formData);
      setModalOpen(false);
      loadTrips();
    } catch (err) {
      alert('កំហុសក្នុងការកត់ត្រាដំណើរ');
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
            តាមដានការធ្វើដំណើរ & GPS (Live GPS Tracking)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            តាមដានទីតាំងបុគ្គលិកចុះបេសកកម្ម ដឹកជញ្ជូនទំនិញ និងទស្សនាទីតាំងផ្ទាល់លើផែនទី
          </p>
        </div>

        <button onClick={handleOpenCreate} className="btn btn-primary">
          <Plus size={16} />
          <span>បង្កើតដំណើរបេសកកម្ម (New Trip)</span>
        </button>
      </div>

      {/* KPI Stats */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '20px',
        }}
      >
        <StatCard
          title="ដំណើរកំពុងសកម្ម (Active Trips)"
          value={`${activeTrips.length} នាក់`}
          subtitle="កំពុងធ្វើដំណើរក្នុងពេលនេះ"
          icon={<Navigation size={22} />}
          variant="primary"
        />
        <StatCard
          title="បានបញ្ចប់ថ្ងៃនេះ (Completed)"
          value="6 ជើង"
          subtitle="ការដឹកជញ្ជូនជោគជ័យ"
          icon={<CheckCircle2 size={22} />}
          variant="success"
        />
        <StatCard
          title="អតិថិជនបានចុះឈ្មោះ (Customers)"
          value="38 ទីតាំង"
          subtitle="ទីតាំងហាង & ដៃគូអាជីវកម្ម"
          icon={<MapPin size={22} />}
          variant="gold"
        />
      </div>

      {/* Map Simulated Container */}
      <div
        className="hrm-card"
        style={{
          height: '300px',
          background: 'radial-gradient(circle at 50% 50%, #1e293b 0%, #0f172a 100%)',
          borderRadius: 'var(--radius-lg)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          position: 'relative',
          overflow: 'hidden',
          border: '1px solid var(--border)',
        }}
      >
        <div style={{ textAlign: 'center', color: '#94a3b8' }}>
          <Navigation size={48} color="var(--primary)" style={{ animation: 'bounce 2s infinite', margin: '0 auto 12px' }} />
          <div style={{ fontSize: '16px', fontWeight: 700, color: '#ffffff' }}>
            ផ្ទាំងផែនទីផ្ទាល់ (Live OpenStreetMap / Google Maps)
          </div>
          <div style={{ fontSize: '12.5px', marginTop: '4px' }}>
            កំពុងតាមដានកូអរដោនេ GPS នៃអ្នកដឹកជញ្ជូន {activeTrips.length} នាក់ក្នុងពេលវេលាជាក់ស្តែង
          </div>
        </div>
      </div>

      {/* Active Trips Table */}
      <div className="table-container">
        <table className="hrm-table">
          <thead>
            <tr>
              <th>អ្នកបើកបរ / បុគ្គលិក</th>
              <th>មធ្យោបាយធ្វើដំណើរ</th>
              <th>ទិសដៅគោលដៅ</th>
              <th>ទីតាំងបច្ចុប្បន្ន</th>
              <th>ល្បឿន</th>
              <th>ម៉ោងចេញដំណើរ</th>
              <th>ស្ថានភាព</th>
            </tr>
          </thead>
          <tbody>
            {activeTrips.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                  {loading ? 'កំពុងទាញយកទិន្នន័យ GPS...' : 'មិនមានដំណើរបេសកកម្មសកម្មឡើយ'}
                </td>
              </tr>
            ) : (
              activeTrips.map((trip) => (
                <tr key={trip.id}>
                  <td>
                    <div style={{ fontWeight: 600 }}>{trip.driver_name}</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      {trip.employee_id}
                    </div>
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }}>{trip.vehicle}</td>
                  <td style={{ fontWeight: 600 }}>{trip.destination}</td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--primary)' }}>
                      <MapPin size={13} />
                      <span>{trip.current_location}</span>
                    </div>
                  </td>
                  <td style={{ fontFamily: "'Outfit', monospace", fontWeight: 700 }}>{trip.speed}</td>
                  <td>{trip.started_at || '08:00 AM'}</td>
                  <td>
                    <span className="badge badge-good">{trip.status || 'In Transit'}</span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Create Trip Modal */}
      {modalOpen && (
        <Modal
          isOpen={modalOpen}
          onClose={() => setModalOpen(false)}
          title="បង្កើតដំណើរបេសកកម្មថ្មី"
          maxWidth="520px"
        >
          <form onSubmit={handleSave}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label">ឈ្មោះអ្នកបើកបរ *</label>
                  <input
                    type="text"
                    className="form-input"
                    value={formData.driver_name}
                    onChange={(e) => setFormData({ ...formData, driver_name: e.target.value })}
                    placeholder="ឧ. ជា វណ្ណៈ"
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">អត្តលេខ</label>
                  <input
                    type="text"
                    className="form-input"
                    value={formData.employee_id}
                    onChange={(e) => setFormData({ ...formData, employee_id: e.target.value })}
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">មធ្យោបាយធ្វើដំណើរ</label>
                <input
                  type="text"
                  className="form-input"
                  value={formData.vehicle}
                  onChange={(e) => setFormData({ ...formData, vehicle: e.target.value })}
                />
              </div>

              <div className="form-group">
                <label className="form-label">ទិសដៅគោលដៅ *</label>
                <input
                  type="text"
                  className="form-input"
                  value={formData.destination}
                  onChange={(e) => setFormData({ ...formData, destination: e.target.value })}
                  placeholder="ឧ. សាខាកំពង់សោម"
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">ទីតាំងបច្ចុប្បន្ន</label>
                <input
                  type="text"
                  className="form-input"
                  value={formData.current_location}
                  onChange={(e) => setFormData({ ...formData, current_location: e.target.value })}
                  placeholder="ឧ. ផ្លូវជាតិលេខ ៤"
                />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px', borderTop: '1px solid var(--border)', paddingTop: '14px' }}>
              <button type="button" onClick={() => setModalOpen(false)} className="btn btn-secondary">
                បោះបង់
              </button>
              <button type="submit" className="btn btn-primary">
                <Check size={16} />
                <span>បង្កើតដំណើរបេសកកម្ម</span>
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
};

