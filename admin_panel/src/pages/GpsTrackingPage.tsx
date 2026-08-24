import React, { useState } from 'react';
import { Navigation, MapPin, Users, Activity, Play, CheckCircle2 } from 'lucide-react';
import { StatCard } from '../components/common/StatCard';

export const GpsTrackingPage: React.FC = () => {
  const [activeTrips] = useState([
    {
      id: 1,
      driver_name: 'ជា វណ្ណៈ',
      employee_id: 'VVC-103',
      vehicle: 'ឡានដឹកទំនិញ (Truck 2.5T)',
      destination: 'សាខាកំពង់សោម (Sihanoukville Store)',
      current_location: 'ផ្លូវល្បឿនលឿន គ.ម ៧៤',
      speed: '75 km/h',
      status: 'In Transit',
      started_at: '06:30 AM',
    },
    {
      id: 2,
      driver_name: 'លឹម គឹមសាន',
      employee_id: 'VVC-104',
      vehicle: 'ម៉ូតូដឹកឥវ៉ាន់ (Delivery Moto)',
      destination: 'អតិថិជន KouPrey Coffee (ទួលគោក)',
      current_location: 'ផ្លូវ 598 រាជធានីភ្នំពេញ',
      speed: '35 km/h',
      status: 'Delivering',
      started_at: '08:45 AM',
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
            តាមដានការធ្វើដំណើរ & GPS (Live GPS Tracking)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            តាមដានទីតាំងបុគ្គលិកចុះបេសកកម្ម ដឹកជញ្ជូនទំនិញ និងទស្សនាទីតាំងផ្ទាល់លើផែនទី
          </p>
        </div>
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
          value="2 នាក់"
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
          height: '350px',
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
            កំពុងតាមដានកូអរដោនេ GPS នៃអ្នកដឹកជញ្ជូន ២ នាក់ក្នុងពេលវេលាជាក់ស្តែង
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
            {activeTrips.map((trip) => (
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
                <td>{trip.started_at}</td>
                <td>
                  <span className="badge badge-good">កំពុងធ្វើដំណើរ</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
