import React, { useState, useEffect, useRef } from 'react';
import {
  Navigation,
  MapPin,
  Users,
  Activity,
  CheckCircle2,
  Plus,
  RotateCw,
  Clock,
  Car,
  Search,
  ExternalLink,
  Trash2,
  Edit2,
  StopCircle,
  Compass,
  Route,
  Building,
  Phone,
  Check,
  Eye,
  Crosshair,
} from 'lucide-react';
import { StatCard } from '../components/common/StatCard';
import { Modal } from '../components/common/Modal';
import { adminApi, GpsTripItem, TrackingCustomerItem } from '../api/adminApi';

declare const L: any; // Leaflet global from CDN in index.html

export const GpsTrackingPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'live' | 'history' | 'customers'>('live');

  // Stats & Active Trips
  const [activeTrips, setActiveTrips] = useState<GpsTripItem[]>([]);
  const [stats, setStats] = useState({
    active_trips: 0,
    active_employees: 0,
    completed_today: 0,
    total_km_today: 0,
    total_customers: 0,
  });
  const [loadingLive, setLoadingLive] = useState(false);
  const [selectedTripForRoute, setSelectedTripForRoute] = useState<GpsTripItem | null>(null);
  const [tripLocations, setTripLocations] = useState<any[]>([]);
  const [activeViewedTripId, setActiveViewedTripId] = useState<number | null>(null);

  // History State
  const [historyTrips, setHistoryTrips] = useState<GpsTripItem[]>([]);
  const [dateFrom, setDateFrom] = useState(new Date().toISOString().split('T')[0]);
  const [dateTo, setDateTo] = useState(new Date().toISOString().split('T')[0]);
  const [historySearch, setHistorySearch] = useState('');
  const [historyStatusFilter, setHistoryStatusFilter] = useState('all');
  const [loadingHistory, setLoadingHistory] = useState(false);

  // Customers State
  const [customers, setCustomers] = useState<TrackingCustomerItem[]>([]);
  const [loadingCustomers, setLoadingCustomers] = useState(false);
  const [customerSearch, setCustomerSearch] = useState('');
  const [isCustomerModalOpen, setIsCustomerModalOpen] = useState(false);
  const [editingCustomer, setEditingCustomer] = useState<TrackingCustomerItem | null>(null);
  const [customerFormData, setCustomerFormData] = useState({
    name: '',
    phone: '',
    address: '',
    latitude: 11.5564,
    longitude: 104.9282,
  });

  // Map References
  const mapContainerRef = useRef<HTMLDivElement | null>(null);
  const mapInstanceRef = useRef<any>(null);
  const markersRef = useRef<Record<number, any>>({});
  const polylineRef = useRef<any>(null);

  const routeModalMapRef = useRef<HTMLDivElement | null>(null);
  const routeModalMapInstanceRef = useRef<any>(null);

  // Banner
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const showBanner = (type: 'success' | 'error', text: string) => {
    setBanner({ type, text });
    setTimeout(() => setBanner(null), 3500);
  };

  // 1. Load Live Trips & Stats
  const loadLiveTrips = async () => {
    setLoadingLive(true);
    try {
      const res = await adminApi.fetchGpsTrips();
      if (res && (res.success || res.status === 'success')) {
        const trips = Array.isArray(res.trips) ? res.trips : (Array.isArray(res.data) ? res.data : []);
        setActiveTrips(trips);
        if (res.stats) {
          setStats(res.stats);
        } else {
          setStats({
            active_trips: trips.length,
            active_employees: new Set(trips.map((t: any) => t.employee_id)).size,
            completed_today: 0,
            total_km_today: trips.reduce((sum: number, t: any) => sum + parseFloat(t.total_distance_km || 0), 0),
            total_customers: customers.length,
          });
        }
      }
    } catch (err) {
      console.error('Error fetching live GPS trips:', err);
    }
    setLoadingLive(false);
  };

  // Auto-refresh live trips every 10 seconds (matching admin_attendance.php)
  useEffect(() => {
    loadLiveTrips();
    const interval = setInterval(() => {
      if (activeTab === 'live') {
        loadLiveTrips();
      }
    }, 10000);
    return () => clearInterval(interval);
  }, [activeTab]);

  // Initialize and Update Live Leaflet Map
  useEffect(() => {
    if (activeTab !== 'live' || !mapContainerRef.current) return;

    if (typeof L === 'undefined') {
      console.warn('Leaflet L is not loaded yet');
      return;
    }

    if (!mapInstanceRef.current) {
      const map = L.map(mapContainerRef.current).setView([11.5564, 104.9282], 12);
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; OpenStreetMap contributors',
        maxZoom: 19,
      }).addTo(map);
      mapInstanceRef.current = map;
    }

    const map = mapInstanceRef.current;

    // Clear existing markers that are no longer active
    Object.keys(markersRef.current).forEach((idStr) => {
      const id = Number(idStr);
      if (!activeTrips.find((t) => t.id === id)) {
        map.removeLayer(markersRef.current[id]);
        delete markersRef.current[id];
      }
    });

    // Plot / Update markers for active trips
    const boundsPoints: any[] = [];

    activeTrips.forEach((trip) => {
      const lat = parseFloat(String(trip.current_lat || trip.start_lat || 11.5564));
      const lng = parseFloat(String(trip.current_lng || trip.start_lng || 104.9282));
      if (isNaN(lat) || isNaN(lng)) return;

      boundsPoints.push([lat, lng]);

      const driverName = trip.display_name || trip.employee_name || trip.employee_id;
      const targetName = trip.customer_target_name || trip.customer_name || 'គ្មានទិសដៅ';
      const speed = trip.current_speed || 0;
      const dist = trip.total_distance_km || 0;

      const popupContent = `
        <div style="font-family: 'Kantumruy Pro', sans-serif; font-size: 12.5px; line-height: 1.5; padding: 4px;">
          <strong style="font-size: 14px; color: #4f46e5; display: block; margin-bottom: 4px;">🚗 ${driverName}</strong>
          <div><strong>ID:</strong> ${trip.employee_id}</div>
          <div><strong>ទិសដៅ:</strong> ${targetName}</div>
          <div><strong>ល្បឿន:</strong> <span style="color: #10b981; font-weight: 700;">${speed} km/h</span></div>
          <div><strong>ចម្ងាយសរុប:</strong> ${dist} km</div>
          <div style="margin-top: 6px; font-size: 11px; color: #64748b;">ម៉ោងចាប់ផ្តើម: ${trip.started_at || '—'}</div>
        </div>
      `;

      // Custom HTML Marker Icon
      const customIcon = L.divIcon({
        className: 'custom-driver-marker',
        html: `
          <div style="position: relative; width: 38px; height: 38px; border-radius: 50%; background: #10b981; border: 3px solid #ffffff; box-shadow: 0 4px 12px rgba(0,0,0,0.3); display: flex; align-items: center; justify-content: center; color: #ffffff; font-weight: 800; font-size: 13px;">
            ${(driverName).substring(0, 2).toUpperCase()}
            <span style="position: absolute; bottom: -2px; right: -2px; width: 12px; height: 12px; background: #22c55e; border: 2px solid #fff; border-radius: 50%;"></span>
          </div>
        `,
        iconSize: [38, 38],
        iconAnchor: [19, 19],
        popupAnchor: [0, -20],
      });

      if (markersRef.current[trip.id]) {
        markersRef.current[trip.id].setLatLng([lat, lng]).setPopupContent(popupContent);
      } else {
        const marker = L.marker([lat, lng], { icon: customIcon }).addTo(map).bindPopup(popupContent);
        markersRef.current[trip.id] = marker;
      }

      // If activeViewedTripId matches, fly to this trip
      if (activeViewedTripId === trip.id) {
        map.flyTo([lat, lng], 15, { animate: true, duration: 1 });
        markersRef.current[trip.id]?.openPopup();
      }
    });

    if (boundsPoints.length > 0 && !activeViewedTripId) {
      try {
        map.fitBounds(boundsPoints, { padding: [50, 50], maxZoom: 14 });
      } catch (e) {
        // bounds error safeguard
      }
    }
  }, [activeTab, activeTrips, activeViewedTripId]);

  // 2. Load History Trips
  const loadHistory = async () => {
    setLoadingHistory(true);
    try {
      const res = await adminApi.fetchTripHistory(dateFrom, dateTo, historySearch, historyStatusFilter);
      if (res && (res.success || res.status === 'success')) {
        setHistoryTrips(Array.isArray(res.trips) ? res.trips : (Array.isArray(res.data) ? res.data : []));
      }
    } catch (err) {
      console.error('Error fetching trip history:', err);
    }
    setLoadingHistory(false);
  };

  useEffect(() => {
    if (activeTab === 'history') {
      loadHistory();
    }
  }, [activeTab, dateFrom, dateTo, historyStatusFilter]);

  // 3. Load Customers
  const loadCustomers = async () => {
    setLoadingCustomers(true);
    try {
      const res = await adminApi.fetchTrackingCustomers();
      if (res && (res.success || res.status === 'success')) {
        setCustomers(Array.isArray(res.customers) ? res.customers : (Array.isArray(res.data) ? res.data : []));
      }
    } catch (err) {
      console.error('Error fetching customers:', err);
    }
    setLoadingCustomers(false);
  };

  useEffect(() => {
    if (activeTab === 'customers') {
      loadCustomers();
    }
  }, [activeTab]);

  // End Trip
  const handleEndTrip = async (trip: GpsTripItem) => {
    if (!window.confirm(`តើអ្នកពិតជាចង់បញ្ចប់ដំណើររបស់បុគ្គលិក "${trip.display_name || trip.employee_id}" មែនទេ?`)) {
      return;
    }
    try {
      const res = await adminApi.endTrip(trip.id);
      if (res && (res.success || res.status === 'success')) {
        showBanner('success', res.message || 'បានបញ្ចប់ដំណើរជោគជ័យ!');
        loadLiveTrips();
      } else {
        showBanner('error', res?.message || 'Error ending trip');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការបញ្ចប់ដំណើរ');
    }
  };

  // View Trip Route
  const handleViewRoute = async (trip: GpsTripItem) => {
    setSelectedTripForRoute(trip);
    setActiveViewedTripId(trip.id);
    try {
      const res = await adminApi.fetchTripLocations(trip.id);
      if (res && (res.success || res.status === 'success')) {
        setTripLocations(Array.isArray(res.locations) ? res.locations : (Array.isArray(res.points) ? res.points : []));
      }
    } catch (err) {
      console.error('Error fetching trip route:', err);
    }
  };

  // Modal Map initialization for Route preview
  useEffect(() => {
    if (!selectedTripForRoute || !routeModalMapRef.current || typeof L === 'undefined') return;

    if (!routeModalMapInstanceRef.current) {
      const map = L.map(routeModalMapRef.current).setView([11.5564, 104.9282], 13);
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; OpenStreetMap',
        maxZoom: 19,
      }).addTo(map);
      routeModalMapInstanceRef.current = map;
    }

    const modalMap = routeModalMapInstanceRef.current;
    modalMap.eachLayer((layer: any) => {
      if (layer instanceof L.Marker || layer instanceof L.Polyline) {
        modalMap.removeLayer(layer);
      }
    });

    const pathPoints = tripLocations.map((loc) => [parseFloat(loc.latitude), parseFloat(loc.longitude)]).filter((p) => !isNaN(p[0]) && !isNaN(p[1]));

    if (pathPoints.length >= 2) {
      const poly = L.polyline(pathPoints, { color: '#6366f1', weight: 5, opacity: 0.8 }).addTo(modalMap);
      modalMap.fitBounds(poly.getBounds(), { padding: [30, 30] });

      // Start Marker (Blue)
      L.marker(pathPoints[0], {
        title: 'Start Location',
      }).addTo(modalMap).bindPopup('📍 ចំណុចចាប់ផ្តើម (Start)');

      // End Marker (Green/Red)
      L.marker(pathPoints[pathPoints.length - 1], {
        title: 'Current / End Location',
      }).addTo(modalMap).bindPopup('🏁 ទីតាំងបច្ចុប្បន្ន / ចុងក្រោយ');
    } else if (selectedTripForRoute.current_lat && selectedTripForRoute.current_lng) {
      const pos = [parseFloat(String(selectedTripForRoute.current_lat)), parseFloat(String(selectedTripForRoute.current_lng))];
      modalMap.setView(pos, 14);
      L.marker(pos).addTo(modalMap).bindPopup(selectedTripForRoute.display_name || selectedTripForRoute.employee_id).openPopup();
    }
  }, [selectedTripForRoute, tripLocations]);

  // Save Customer
  const handleSaveCustomer = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customerFormData.name.trim()) {
      alert('សូមបញ្ចូលឈ្មោះអតិថិជន ឬទីតាំង!');
      return;
    }
    try {
      const payload: any = {
        cust_name: customerFormData.name,
        name: customerFormData.name,
        cust_phone: customerFormData.phone,
        phone: customerFormData.phone,
        address: customerFormData.address,
        cust_lat: customerFormData.latitude,
        latitude: customerFormData.latitude,
        cust_lng: customerFormData.longitude,
        longitude: customerFormData.longitude,
      };
      if (editingCustomer) {
        payload.cust_id = editingCustomer.id;
        payload.id = editingCustomer.id;
      }
      const res = await adminApi.saveTrackingCustomer(payload);
      if (res && (res.success || res.status === 'success')) {
        showBanner('success', res.message || 'បានរក្សាទុកទីតាំងអតិថិជនជោគជ័យ!');
        setIsCustomerModalOpen(false);
        setEditingCustomer(null);
        loadCustomers();
      } else {
        showBanner('error', res?.message || 'Error saving customer');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការរក្សាទុក');
    }
  };

  // Delete Customer
  const handleDeleteCustomer = async (id: number, name: string) => {
    if (!window.confirm(`តើអ្នកពិតជាចង់លុបទីតាំង "${name}" មែនទេ?`)) return;
    try {
      const res = await adminApi.deleteTrackingCustomer(id);
      if (res && (res.success || res.status === 'success')) {
        showBanner('success', res.message || 'បានលុបទីតាំងអតិថិជនជោគជ័យ!');
        loadCustomers();
      } else {
        showBanner('error', res?.message || 'Error deleting customer');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការលុប');
    }
  };

  // Helper for Time Ago
  const formatTimeAgo = (dateStr?: string) => {
    if (!dateStr) return 'N/A';
    const diffSec = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
    if (diffSec < 60) return `${Math.max(1, diffSec)}វ មុន`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)} នាទីមុន`;
    return `${Math.floor(diffSec / 3600)} ម៉ោងមុន`;
  };

  const filteredCustomers = customers.filter((c) => {
    const q = customerSearch.toLowerCase();
    return (
      (c.name || '').toLowerCase().includes(q) ||
      (c.phone || '').toLowerCase().includes(q) ||
      (c.address || '').toLowerCase().includes(q)
    );
  });

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
              <Navigation size={20} />
            </span>
            <h2 style={{ fontSize: '22px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              តាមដានការធ្វើដំណើរ & GPS (Live GPS Tracking)
            </h2>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0 }}>
            តាមដានទីតាំងបុគ្គលិកចុះបេសកកម្ម ដឹកជញ្ជូនទំនិញផ្ទាល់លើផែនទី GPS និងប្រវត្តិធ្វើដំណើរ
          </p>
        </div>

        {/* Right Area: Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {activeTab === 'customers' ? (
            <button
              onClick={() => {
                setEditingCustomer(null);
                setCustomerFormData({
                  name: '',
                  phone: '',
                  address: '',
                  latitude: 11.5564,
                  longitude: 104.9282,
                });
                setIsCustomerModalOpen(true);
              }}
              className="btn btn-primary"
              style={{ borderRadius: '12px', padding: '11px 20px', fontWeight: 700 }}
            >
              <Plus size={16} />
              <span>+ បន្ថែមអតិថិជនថ្មី</span>
            </button>
          ) : (
            <button
              onClick={activeTab === 'live' ? loadLiveTrips : loadHistory}
              className="btn btn-secondary"
              style={{ borderRadius: '12px', padding: '11px 18px', fontWeight: 700 }}
              title="ផ្ទុកឡើងវិញ"
            >
              <RotateCw size={15} className={loadingLive || loadingHistory ? 'fa-spin' : ''} />
              <span>ផ្ទុកឡើងវិញ</span>
            </button>
          )}
        </div>
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

      {/* Main Sub-Tabs Switcher */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          background: 'var(--surface-subtle, #f1f5f9)',
          padding: '6px',
          borderRadius: '14px',
          overflowX: 'auto',
        }}
      >
        {[
          { id: 'live', label: `តាមដានផ្ទាល់ (Live Map: ${activeTrips.length})`, icon: Activity },
          { id: 'history', label: 'ប្រវត្តិធ្វើដំណើរ (Trip History)', icon: Clock },
          { id: 'customers', label: `ទីតាំងអតិថិជន (Customers: ${customers.length})`, icon: Building },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                padding: '9px 16px',
                borderRadius: '10px',
                fontWeight: 700,
                fontSize: '13px',
                border: 'none',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                whiteSpace: 'nowrap',
                background: isActive ? '#fff' : 'transparent',
                color: isActive ? 'var(--primary)' : 'var(--text-secondary)',
                boxShadow: isActive ? '0 4px 12px rgba(0,0,0,0.06)' : 'none',
              }}
            >
              <Icon size={14} color={isActive ? 'var(--primary)' : undefined} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* KPI Stats Bar Matching admin_attendance.php */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '16px',
        }}
      >
        <StatCard
          title="ដំណើរកំពុងដំណើរការ"
          value={`${stats.active_trips || activeTrips.length} ជើង`}
          subtitle="កំពុងធ្វើដំណើរក្នុងពេលនេះ"
          icon={<Car size={22} />}
          variant="primary"
        />
        <StatCard
          title="បុគ្គលិកកំពុងធ្វើដំណើរ"
          value={`${stats.active_employees || activeTrips.length} នាក់`}
          subtitle="អ្នកបើកបរ & ដឹកជញ្ជូន"
          icon={<Users size={22} />}
          variant="success"
        />
        <StatCard
          title="គ.ម សរុបថ្ងៃនេះ"
          value={`${stats.total_km_today || 0} km`}
          subtitle="ចម្ងាយធ្វើដំណើរសរុប"
          icon={<Route size={22} />}
          variant="gold"
        />
        <StatCard
          title="បានបញ្ចប់ថ្ងៃនេះ"
          value={`${stats.completed_today || 0} ជើង`}
          subtitle="ការដឹកជញ្ជូនជោគជ័យ"
          icon={<CheckCircle2 size={22} />}
          variant="primary"
        />
      </div>

      {/* ========================================================================= */}
      {/* 1. LIVE GPS TRACKING TAB                                                  */}
      {/* ========================================================================= */}
      {activeTab === 'live' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Leaflet Interactive Map Container */}
          <div
            className="hrm-card"
            style={{
              padding: '20px',
              borderRadius: '16px',
              background: 'var(--surface)',
            }}
          >
            {/* Map Legend */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '18px', fontSize: '13px', color: 'var(--text-secondary)' }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ width: '12px', height: '12px', borderRadius: '50%', background: '#10b981', display: 'inline-block' }} />
                  <strong>បុគ្គលិកកំពុងធ្វើដំណើរ (Active Driver)</strong>
                </span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ width: '12px', height: '12px', borderRadius: '50%', background: '#ef4444', display: 'inline-block' }} />
                  <strong>អតិថិជន / ទិសដៅ (Target)</strong>
                </span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ width: '12px', height: '12px', borderRadius: '50%', background: '#3b82f6', display: 'inline-block' }} />
                  <strong>ចំណុចចាប់ផ្ដើម</strong>
                </span>
              </div>

              <div style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#10b981', display: 'inline-block', marginRight: '6px' }} />
                Auto-refresh រៀងរាល់ ១០ វិនាទី
              </div>
            </div>

            {/* Interactive Leaflet Map Div */}
            <div
              id="live-trip-map"
              ref={mapContainerRef}
              style={{
                width: '100%',
                height: '450px',
                borderRadius: '14px',
                overflow: 'hidden',
                border: '1px solid var(--border)',
                position: 'relative',
                zIndex: 1,
              }}
            />
          </div>

          {/* Active Trips Cards Grid */}
          <div>
            <h3 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--text-primary)', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Car size={18} color="var(--primary)" />
              <span>ដំណើរសកម្ម (Active Trips: {activeTrips.length})</span>
            </h3>

            {activeTrips.length === 0 ? (
              <div className="hrm-card" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                <Car size={36} style={{ opacity: 0.3, margin: '0 auto 10px' }} />
                <p style={{ margin: 0, fontSize: '14px', fontWeight: 600 }}>
                  ពុំមានបុគ្គលិកកំពុងធ្វើដំណើរបេសកកម្ម ឬដឹកជញ្ជូនក្នុងពេលនេះឡើយ។
                </p>
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))', gap: '16px' }}>
                {activeTrips.map((trip) => {
                  const isViewing = activeViewedTripId === trip.id;
                  const agoText = formatTimeAgo(trip.last_recorded_at || trip.latest_location?.recorded_at);

                  return (
                    <div
                      key={trip.id}
                      className="hrm-card"
                      onClick={() => {
                        setActiveViewedTripId(trip.id);
                        if (mapInstanceRef.current && trip.current_lat && trip.current_lng) {
                          mapInstanceRef.current.flyTo([Number(trip.current_lat), Number(trip.current_lng)], 15);
                          markersRef.current[trip.id]?.openPopup();
                        }
                      }}
                      style={{
                        padding: '20px',
                        borderRadius: '16px',
                        borderLeft: '4px solid #10b981',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '14px',
                        cursor: 'pointer',
                        border: isViewing ? '2px solid var(--primary)' : undefined,
                        boxShadow: isViewing ? '0 0 0 3px rgba(99, 102, 241, 0.15)' : undefined,
                      }}
                    >
                      {/* Top Row: User Avatar & Status */}
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                          <div
                            style={{
                              width: '42px',
                              height: '42px',
                              borderRadius: '12px',
                              background: 'var(--primary)',
                              color: '#fff',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              fontWeight: 800,
                              fontSize: '15px',
                              overflow: 'hidden',
                            }}
                          >
                            {trip.avatar ? (
                              <img src={trip.avatar} alt="" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                            ) : (
                              (trip.display_name || trip.employee_id).substring(0, 2).toUpperCase()
                            )}
                          </div>
                          <div>
                            <div style={{ fontSize: '14.5px', fontWeight: 800, color: 'var(--text-primary)' }}>
                              {trip.display_name || trip.employee_name || trip.employee_id}
                            </div>
                            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                              ID: {trip.employee_id} {trip.department && `• ${trip.department}`}
                            </div>
                          </div>
                        </div>

                        <span className="badge badge-good" style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                          <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10b981' }} />
                          {isViewing ? '📍 កំពុងតាមដាន' : 'Active'}
                        </span>
                      </div>

                      {/* Origin & Destination */}
                      <div style={{ background: 'var(--surface-alt)', padding: '12px', borderRadius: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
                          <MapPin size={15} color="#3b82f6" />
                          <div>
                            <span style={{ color: 'var(--text-muted)', fontSize: '11px', display: 'block' }}>ចំណុចចាប់ផ្តើម</span>
                            <strong style={{ color: 'var(--text-primary)' }}>{trip.start_address || 'ទីតាំងចាប់ផ្តើម'}</strong>
                          </div>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
                          <MapPin size={15} color="#ef4444" />
                          <div>
                            <span style={{ color: 'var(--text-muted)', fontSize: '11px', display: 'block' }}>ទិសដៅ (Destination)</span>
                            <strong style={{ color: 'var(--text-primary)' }}>
                              {trip.customer_target_name || trip.customer_name || 'អតិថិជន / ទីតាំងគោលដៅ'}
                            </strong>
                          </div>
                        </div>
                      </div>

                      {/* Trip Metrics */}
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '8px', textAlign: 'center', fontSize: '12px' }}>
                        <div style={{ background: 'var(--surface-subtle)', padding: '8px', borderRadius: '10px' }}>
                          <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '11px' }}>ល្បឿន</span>
                          <strong style={{ color: 'var(--primary)' }}>{trip.current_speed || 0} km/h</strong>
                        </div>
                        <div style={{ background: 'var(--surface-subtle)', padding: '8px', borderRadius: '10px' }}>
                          <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '11px' }}>ចម្ងាយ</span>
                          <strong>{trip.total_distance_km || 0} km</strong>
                        </div>
                        <div style={{ background: 'var(--surface-subtle)', padding: '8px', borderRadius: '10px' }}>
                          <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '11px' }}>GPS Points</span>
                          <strong>{trip.point_count || 0} pts</strong>
                        </div>
                      </div>

                      <div style={{ fontSize: '11.5px', color: '#10b981', display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <Crosshair size={12} />
                        <span>GPS Update: {agoText}</span>
                      </div>

                      {/* Action Buttons */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }} onClick={(e) => e.stopPropagation()}>
                        <button
                          type="button"
                          onClick={() => handleViewRoute(trip)}
                          className="btn btn-secondary btn-sm"
                          style={{ flex: 1, borderRadius: '10px' }}
                        >
                          <Eye size={14} />
                          <span>មើលផ្លូវ (Route)</span>
                        </button>

                        <button
                          type="button"
                          onClick={() => handleEndTrip(trip)}
                          className="btn btn-danger btn-sm"
                          style={{ borderRadius: '10px' }}
                          title="បញ្ចប់ដំណើរនេះ"
                        >
                          <StopCircle size={14} />
                          <span>បញ្ចប់ដំណើរ</span>
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 2. TRIP HISTORY TAB                                                       */}
      {/* ========================================================================= */}
      {activeTab === 'history' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* History Toolbar */}
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
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '12.5px', fontWeight: 700, color: 'var(--text-secondary)' }}>ពីថ្ងៃ៖</span>
                <input
                  type="date"
                  className="form-input"
                  value={dateFrom}
                  onChange={(e) => setDateFrom(e.target.value)}
                  style={{ width: '145px', height: '36px', fontSize: '12.5px' }}
                />
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '12.5px', fontWeight: 700, color: 'var(--text-secondary)' }}>ដល់ថ្ងៃ៖</span>
                <input
                  type="date"
                  className="form-input"
                  value={dateTo}
                  onChange={(e) => setDateTo(e.target.value)}
                  style={{ width: '145px', height: '36px', fontSize: '12.5px' }}
                />
              </div>

              <select
                className="form-control"
                value={historyStatusFilter}
                onChange={(e) => setHistoryStatusFilter(e.target.value)}
                style={{ width: '140px', height: '36px', fontSize: '12.5px' }}
              >
                <option value="all">គ្រប់ស្ថានភាព</option>
                <option value="active">Active</option>
                <option value="completed">Completed</option>
                <option value="cancelled">Cancelled</option>
              </select>

              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  background: 'var(--surface-alt)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius)',
                  padding: '6px 12px',
                  width: '240px',
                  gap: '8px',
                }}
              >
                <Search size={14} color="var(--text-muted)" />
                <input
                  type="text"
                  placeholder="ឈ្មោះ ឬ ID បុគ្គលិក..."
                  value={historySearch}
                  onChange={(e) => setHistorySearch(e.target.value)}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    outline: 'none',
                    fontSize: '12.5px',
                    color: 'var(--text-primary)',
                    width: '100%',
                  }}
                />
              </div>

              <button onClick={loadHistory} className="btn btn-primary btn-sm" style={{ borderRadius: '10px', padding: '8px 16px' }}>
                <Search size={14} />
                <span>ស្វែងរក</span>
              </button>
            </div>

            <button onClick={loadHistory} className="btn btn-secondary btn-sm" style={{ borderRadius: '10px' }}>
              <RotateCw size={14} className={loadingHistory ? 'fa-spin' : ''} />
              <span>Refresh</span>
            </button>
          </div>

          {/* History Table Matching admin_attendance.php */}
          <div className="table-container">
            <table className="hrm-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>បុគ្គលិក</th>
                  <th>អតិថិជន / ទិសដៅ</th>
                  <th>ចាប់ផ្ដើម</th>
                  <th>បញ្ចប់</th>
                  <th>ចម្ងាយ (Km)</th>
                  <th>រយៈពេល</th>
                  <th>ស្ថានភាព</th>
                  <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
                </tr>
              </thead>
              <tbody>
                {historyTrips.length === 0 ? (
                  <tr>
                    <td colSpan={9} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                      {loadingHistory ? 'កំពុងទាញយកទិន្នន័យ...' : 'មិនមានទិន្នន័យក្នុងចន្លោះពេលនេះឡើយ។'}
                    </td>
                  </tr>
                ) : (
                  historyTrips.map((t, idx) => (
                    <tr key={t.id}>
                      <td>{idx + 1}</td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <div
                            style={{
                              width: '34px',
                              height: '34px',
                              borderRadius: '8px',
                              background: 'var(--primary-light)',
                              color: 'var(--primary)',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              fontWeight: 700,
                              fontSize: '12px',
                            }}
                          >
                            {(t.display_name || t.employee_id).substring(0, 2).toUpperCase()}
                          </div>
                          <div>
                            <strong style={{ fontSize: '13.5px' }}>{t.display_name || t.employee_name || t.employee_id}</strong>
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{t.employee_id}</div>
                          </div>
                        </div>
                      </td>
                      <td>
                        <strong>{t.customer_target_name || t.customer_name || '—'}</strong>
                      </td>
                      <td style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>{t.started_at || '—'}</td>
                      <td style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>{t.ended_at || '—'}</td>
                      <td>
                        <span className="badge badge-primary">{t.total_distance_km || 0} km</span>
                      </td>
                      <td>{t.duration_minutes ? `${Math.floor(Number(t.duration_minutes) / 60)}ម៉ ${Number(t.duration_minutes) % 60}ន` : '—'}</td>
                      <td>
                        <span
                          className={`badge ${
                            t.status === 'active' ? 'badge-good' : t.status === 'completed' ? 'badge-good' : 'badge-danger'
                          }`}
                        >
                          {t.status === 'active' ? 'កំពុងដំណើរការ' : t.status === 'completed' ? 'បានបញ្ចប់' : 'បានលុបចោល'}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          type="button"
                          onClick={() => handleViewRoute(t)}
                          className="btn btn-secondary btn-sm"
                          style={{ borderRadius: '8px' }}
                        >
                          <Eye size={13} />
                          <span>មើលផ្លូវ</span>
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 3. TRACKING CUSTOMERS TAB                                                 */}
      {/* ========================================================================= */}
      {activeTab === 'customers' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Search Toolbar */}
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
                width: '300px',
                gap: '8px',
              }}
            >
              <Search size={15} color="var(--text-muted)" />
              <input
                type="text"
                placeholder="ស្វែងរកឈ្មោះអតិថិជន, លេខទូរស័ព្ទ, អាសយដ្ឋាន..."
                value={customerSearch}
                onChange={(e) => setCustomerSearch(e.target.value)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  outline: 'none',
                  fontSize: '13px',
                  color: 'var(--text-primary)',
                  width: '100%',
                }}
              />
            </div>

            <button onClick={loadCustomers} className="btn btn-secondary btn-sm" style={{ borderRadius: '10px' }}>
              <RotateCw size={14} className={loadingCustomers ? 'fa-spin' : ''} />
              <span>Refresh</span>
            </button>
          </div>

          {/* Customers Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '16px' }}>
            {filteredCustomers.length === 0 ? (
              <div className="hrm-card" style={{ gridColumn: '1/-1', padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                <Building size={36} style={{ opacity: 0.3, margin: '0 auto 10px' }} />
                <p style={{ margin: 0, fontSize: '14px' }}>ពុំទាន់មានទិន្នន័យទីតាំងអតិថិជនឡើយ។</p>
              </div>
            ) : (
              filteredCustomers.map((cust) => (
                <div
                  key={cust.id}
                  className="hrm-card"
                  style={{
                    padding: '20px',
                    borderRadius: '16px',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                    gap: '14px',
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                      <h4 style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                        {cust.name}
                      </h4>
                      <span className="badge badge-primary">#{cust.id}</span>
                    </div>

                    {cust.phone && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12.5px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                        <Phone size={13} color="var(--primary)" />
                        <span>{cust.phone}</span>
                      </div>
                    )}

                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '6px', fontSize: '12.5px', color: 'var(--text-muted)' }}>
                      <MapPin size={13} color="#ef4444" style={{ marginTop: '2px', flexShrink: 0 }} />
                      <span>{cust.address || `Lat: ${cust.latitude || '11.5564'}, Lng: ${cust.longitude || '104.9282'}`}</span>
                    </div>
                  </div>

                  <div style={{ borderTop: '1px solid var(--border)', paddingTop: '12px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <a
                      href={`https://www.google.com/maps/search/?api=1&query=${cust.latitude || 11.5564},${cust.longitude || 104.9282}`}
                      target="_blank"
                      rel="noreferrer"
                      style={{ fontSize: '11.5px', color: 'var(--primary)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '4px', fontWeight: 700 }}
                    >
                      <span>Google Maps</span>
                      <ExternalLink size={12} />
                    </a>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <button
                        type="button"
                        onClick={() => {
                          setEditingCustomer(cust);
                          setCustomerFormData({
                            name: cust.name,
                            phone: cust.phone || '',
                            address: cust.address || '',
                            latitude: Number(cust.latitude || 11.5564),
                            longitude: Number(cust.longitude || 104.9282),
                          });
                          setIsCustomerModalOpen(true);
                        }}
                        className="btn btn-secondary btn-sm"
                        style={{ padding: '4px 10px', borderRadius: '8px' }}
                      >
                        <Edit2 size={13} />
                      </button>

                      <button
                        type="button"
                        onClick={() => handleDeleteCustomer(cust.id, cust.name)}
                        className="btn btn-danger btn-sm"
                        style={{ padding: '4px 10px', borderRadius: '8px' }}
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* ROUTE DETAIL MODAL                                                        */}
      {/* ========================================================================= */}
      {selectedTripForRoute && (
        <Modal
          isOpen={!!selectedTripForRoute}
          onClose={() => {
            setSelectedTripForRoute(null);
            if (routeModalMapInstanceRef.current) {
              routeModalMapInstanceRef.current.remove();
              routeModalMapInstanceRef.current = null;
            }
          }}
          title={`ព័ត៌មានលម្អិតផ្លូវធ្វើដំណើរ - ${selectedTripForRoute.display_name || selectedTripForRoute.employee_id}`}
          maxWidth="750px"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '13px' }}>
              <div style={{ background: 'var(--surface-alt)', padding: '12px', borderRadius: '10px' }}>
                <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>បុគ្គលិក</span>
                <strong style={{ display: 'block' }}>{selectedTripForRoute.display_name || selectedTripForRoute.employee_id}</strong>
              </div>
              <div style={{ background: 'var(--surface-alt)', padding: '12px', borderRadius: '10px' }}>
                <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>ទិសដៅ</span>
                <strong style={{ display: 'block' }}>
                  {selectedTripForRoute.customer_target_name || selectedTripForRoute.customer_name || '—'}
                </strong>
              </div>
            </div>

            {/* Modal Leaflet Map */}
            <div
              ref={routeModalMapRef}
              style={{ width: '100%', height: '320px', borderRadius: '12px', overflow: 'hidden', border: '1px solid var(--border)', zIndex: 1 }}
            />

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
              <div style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
                ចំនួនកូអរដោនេបានកត់ត្រា៖ <strong>{tripLocations.length} Points</strong>
                {selectedTripForRoute.total_distance_km && ` • ចម្ងាយសរុប៖ ${selectedTripForRoute.total_distance_km} km`}
              </div>

              <a
                href={`https://www.google.com/maps/dir/?api=1&origin=${selectedTripForRoute.start_lat || 11.5564},${selectedTripForRoute.start_lng || 104.9282}&destination=${selectedTripForRoute.current_lat || 11.5564},${selectedTripForRoute.current_lng || 104.9282}`}
                target="_blank"
                rel="noreferrer"
                className="btn btn-primary btn-sm"
                style={{ borderRadius: '8px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
              >
                <span>បើកក្នុង Google Maps</span>
                <ExternalLink size={13} />
              </a>
            </div>
          </div>
        </Modal>
      )}

      {/* ========================================================================= */}
      {/* CREATE / EDIT CUSTOMER MODAL                                              */}
      {/* ========================================================================= */}
      {isCustomerModalOpen && (
        <Modal
          isOpen={isCustomerModalOpen}
          onClose={() => setIsCustomerModalOpen(false)}
          title={editingCustomer ? `កែប្រែទីតាំង - ${editingCustomer.name}` : 'បន្ថែមអតិថិជន / ទិសដៅថ្មី'}
          maxWidth="550px"
        >
          <form onSubmit={handleSaveCustomer} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div className="form-group">
              <label className="form-label">ឈ្មោះអតិថិជន ឬ ទីតាំង *</label>
              <input
                type="text"
                className="form-input"
                value={customerFormData.name}
                onChange={(e) => setCustomerFormData({ ...customerFormData, name: e.target.value })}
                required
                placeholder="ឧ. KouPrey Coffee (ទួលគោក)"
              />
            </div>

            <div className="form-group">
              <label className="form-label">លេខទូរស័ព្ទ</label>
              <input
                type="text"
                className="form-input"
                value={customerFormData.phone}
                onChange={(e) => setCustomerFormData({ ...customerFormData, phone: e.target.value })}
                placeholder="ឧ. 012 345 678"
              />
            </div>

            <div className="form-group">
              <label className="form-label">អាសយដ្ឋាន</label>
              <input
                type="text"
                className="form-input"
                value={customerFormData.address}
                onChange={(e) => setCustomerFormData({ ...customerFormData, address: e.target.value })}
                placeholder="ឧ. ផ្លូវ 598 សង្កាត់បឹងកក់២ ខណ្ឌទួលគោក រាជធានីភ្នំពេញ"
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div className="form-group">
                <label className="form-label">Latitude</label>
                <input
                  type="number"
                  step="any"
                  className="form-input"
                  value={customerFormData.latitude}
                  onChange={(e) => setCustomerFormData({ ...customerFormData, latitude: Number(e.target.value) })}
                />
              </div>

              <div className="form-group">
                <label className="form-label">Longitude</label>
                <input
                  type="number"
                  step="any"
                  className="form-input"
                  value={customerFormData.longitude}
                  onChange={(e) => setCustomerFormData({ ...customerFormData, longitude: Number(e.target.value) })}
                />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
              <button type="button" onClick={() => setIsCustomerModalOpen(false)} className="btn btn-secondary">
                បោះបង់
              </button>
              <button type="submit" className="btn btn-primary">
                <Check size={16} />
                <span>រក្សាទុក</span>
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
};
