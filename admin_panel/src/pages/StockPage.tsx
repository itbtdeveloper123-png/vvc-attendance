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
  Minus,
  Truck,
  ClipboardList,
  History,
  TrendingDown,
  Layers,
  FileText,
  DollarSign,
  Calendar,
  Send,
  X,
  Eye,
  Filter,
  RefreshCw,
  Image as ImageIcon,
} from 'lucide-react';
import { Modal } from '../components/common/Modal';
import { adminApi, StockItem } from '../api/adminApi';

export const StockPage: React.FC = () => {
  // Main Sub-page / Dropdown switcher
  const [activePage, setActivePage] = useState<
    'stock_control' | 'stock_purchase' | 'stock_reports' | 'stock_counting' | 'stock_requests' | 'direct_transfer'
  >('stock_control');

  // ==========================================
  // 1. STOCK CONTROL STATE
  // ==========================================
  const [stockItems, setStockItems] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  const [editingItem, setEditingItem] = useState<any | null>(null);
  const [formData, setFormData] = useState({
    code: '',
    name: '',
    category: 'General',
    quantity: 0,
    unit: 'កញ្ចប់',
    price: 0,
    location: 'Store 318',
  });
  const [itemImageFile, setItemImageFile] = useState<File | null>(null);

  // ==========================================
  // 2. STOCK PURCHASE STATE
  // ==========================================
  const [purchaseSupplier, setPurchaseSupplier] = useState('');
  const [purchaseInvoiceNo, setPurchaseInvoiceNo] = useState('');
  const [purchaseNotes, setPurchaseNotes] = useState('');
  const [purchaseInvoiceImage, setPurchaseInvoiceImage] = useState<File | null>(null);
  const [purchaseRows, setPurchaseRows] = useState<Array<{ item_id: string; quantity: number; price: number }>>([
    { item_id: '', quantity: 1, price: 0 },
  ]);
  const [savingPurchase, setSavingPurchase] = useState(false);

  // ==========================================
  // 3. STOCK REPORTS STATE
  // ==========================================
  const [reportTab, setReportTab] = useState<'all_stock' | 'low_stock' | 'requests' | 'history' | 'ledger'>('all_stock');
  const [reportStats, setReportStats] = useState({
    total_items: 0,
    total_qty: 0,
    total_value: 0,
    low_stock: 0,
  });
  const [reportData, setReportData] = useState<any[]>([]);
  const [loadingReport, setLoadingReport] = useState(false);

  // ==========================================
  // 4. STOCK COUNTING STATE
  // ==========================================
  const [countingSubTab, setCountingSubTab] = useState<'new_count' | 'count_history'>('new_count');
  const [countingPhase, setCountingPhase] = useState('Morning');
  const [countSearchQuery, setCountSearchQuery] = useState('');
  const [physicalCounts, setPhysicalCounts] = useState<Record<string, number | string>>({});
  const [countingSearchDate, setCountingSearchDate] = useState(new Date().toISOString().split('T')[0]);
  const [countHistory, setCountHistory] = useState<any[]>([]);
  const [savingCount, setSavingCount] = useState(false);

  // ==========================================
  // 5. STOCK REQUESTS STATE
  // ==========================================
  const [stockRequests, setStockRequests] = useState<any[]>([]);
  const [requestStatusFilter, setRequestStatusFilter] = useState('');
  const [loadingRequests, setLoadingRequests] = useState(false);

  // ==========================================
  // 6. DIRECT TRANSFER STATE
  // ==========================================
  const [transferTitle, setTransferTitle] = useState('');
  const [transferReqNo, setTransferReqNo] = useState('');
  const [transferLocation, setTransferLocation] = useState('Store SKKS2');
  const [selectedPickerItemId, setSelectedPickerItemId] = useState('');
  const [transferItems, setTransferItems] = useState<Array<{ id: number; name: string; current_stock: number; qty: number; note: string }>>([]);
  const [savingTransfer, setSavingTransfer] = useState(false);

  // Feedback banner
  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);

  const showBanner = (type: 'success' | 'error' | 'info', text: string) => {
    setActionMessage({ type, text });
    setTimeout(() => setActionMessage(null), 3500);
  };

  // Loaders
  const loadStock = async () => {
    setLoading(true);
    try {
      const res = await adminApi.fetchStockItems(search);
      if (res && res.success && Array.isArray(res.items)) {
        setStockItems(res.items);
      }
    } catch (err) {
      console.error('Error fetching stock:', err);
    }
    setLoading(false);
  };

  const loadReports = async (tab: string = reportTab) => {
    setLoadingReport(true);
    try {
      const res = await adminApi.fetchStockReports(tab);
      if (res && res.success) {
        if (res.stats) setReportStats(res.stats);
        if (res.data && Array.isArray(res.data)) setReportData(res.data);
      }
    } catch (err) {
      console.error('Error fetching stock reports:', err);
    }
    setLoadingReport(false);
  };

  const loadCounting = async (date: string = countingSearchDate) => {
    try {
      const res = await adminApi.fetchStockCounting(date);
      if (res && res.success) {
        if (res.items && Array.isArray(res.items) && stockItems.length === 0) {
          setStockItems(res.items);
        }
        if (res.history && Array.isArray(res.history)) {
          setCountHistory(res.history);
        }
      }
    } catch (err) {
      console.error('Error loading stock count:', err);
    }
  };

  const loadRequests = async (status: string = requestStatusFilter) => {
    setLoadingRequests(true);
    try {
      const res = await adminApi.fetchStockRequests(status);
      if (res && res.success && Array.isArray(res.requests)) {
        setStockRequests(res.requests);
      }
    } catch (err) {
      console.error('Error loading stock requests:', err);
    }
    setLoadingRequests(false);
  };

  useEffect(() => {
    loadStock();
  }, []);

  useEffect(() => {
    if (activePage === 'stock_control') loadStock();
    if (activePage === 'stock_reports') loadReports(reportTab);
    if (activePage === 'stock_counting') loadCounting(countingSearchDate);
    if (activePage === 'stock_requests') loadRequests(requestStatusFilter);
    if (activePage === 'direct_transfer' || activePage === 'stock_purchase') {
      if (stockItems.length === 0) loadStock();
    }
  }, [activePage, reportTab, countingSearchDate, requestStatusFilter]);

  // Handle Create / Edit Stock
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
    setItemImageFile(null);
    setModalOpen(true);
  };

  const handleOpenEdit = (item: any) => {
    setEditingItem(item);
    setFormData({
      code: item.code || `STK-${item.id}`,
      name: item.name || item.item_name || '',
      category: item.category || 'General',
      quantity: Number(item.quantity) || 0,
      unit: item.unit || 'កញ្ចប់',
      price: Number(item.price) || 0,
      location: item.location || 'Store 318',
    });
    setItemImageFile(null);
    setModalOpen(true);
  };

  const handleSaveStock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name) return;

    try {
      const fd = new FormData();
      if (editingItem) fd.append('id', String(editingItem.id));
      fd.append('code', formData.code);
      fd.append('name', formData.name);
      fd.append('category', formData.category);
      fd.append('quantity', String(formData.quantity));
      fd.append('unit', formData.unit);
      fd.append('price', String(formData.price));
      fd.append('location', formData.location);
      if (itemImageFile) fd.append('item_image', itemImageFile);

      await adminApi.saveStockItem(fd);
      setModalOpen(false);
      showBanner('success', editingItem ? 'បានកែប្រែទំនិញជោគជ័យ!' : 'បានបញ្ចូលទំនិញថ្មីជោគជ័យ!');
      loadStock();
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការរក្សាទុកទំនិញ');
    }
  };

  const handleDeductStock = async (item: any) => {
    const qtyStr = prompt(`កាត់បន្ថយស្តុកសម្រាប់ '${item.name || item.item_name}'\nបរិមាណបច្ចុប្បន្ន: ${item.quantity}\nសូមបញ្ចូលចំនួនដែលត្រូវដកចេញ:`);
    if (!qtyStr) return;
    const qty = parseInt(qtyStr);
    if (isNaN(qty) || qty <= 0) {
      alert('សូមបញ្ចូលចំនួនដែលត្រឹមត្រូវ!');
      return;
    }
    if (qty > item.quantity) {
      alert('បរិមាណដែលដកចេញ មិនអាចធំជាងបរិមាណក្នុងស្តុកឡើយ!');
      return;
    }

    try {
      const res = await adminApi.deductStock(item.id, qty);
      if (res && res.success) {
        showBanner('success', res.message || 'បានកាត់បន្ថយស្តុកជោគជ័យ');
        loadStock();
      } else {
        showBanner('error', res?.message || 'Error occurred');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការកាត់បន្ថយស្តុក');
    }
  };

  const handleDeleteStock = async (id: number) => {
    if (window.confirm('តើអ្នកប្រាកដថាចង់លុបទំនិញនេះ? ប្រវត្តិដែលពាក់ព័ន្ធទាំងអស់នឹងត្រូវលុបចេញជារៀងរហូត។')) {
      try {
        await adminApi.deleteStockItem(id);
        showBanner('success', 'បានលុបទំនិញជោគជ័យ!');
        loadStock();
      } catch (err) {
        showBanner('error', 'កំហុសក្នុងការលុប');
      }
    }
  };

  // Purchase Actions
  const handleAddPurchaseRow = () => {
    setPurchaseRows([...purchaseRows, { item_id: '', quantity: 1, price: 0 }]);
  };

  const handleRemovePurchaseRow = (idx: number) => {
    const updated = [...purchaseRows];
    updated.splice(idx, 1);
    setPurchaseRows(updated);
  };

  const handlePurchaseRowChange = (idx: number, field: string, value: any) => {
    const updated = [...purchaseRows];
    updated[idx] = { ...updated[idx], [field]: value };
    setPurchaseRows(updated);
  };

  const handleSavePurchase = async (e: React.FormEvent) => {
    e.preventDefault();
    const validItems = purchaseRows.filter((r) => r.item_id && r.quantity > 0);
    if (validItems.length === 0) {
      showBanner('error', 'សូមបន្ថែមទំនិញយ៉ាងហោចណាស់មួយ!');
      return;
    }

    setSavingPurchase(true);
    try {
      const fd = new FormData();
      fd.append('supplier', purchaseSupplier);
      fd.append('invoice_number', purchaseInvoiceNo || `INV-${Date.now()}`);
      fd.append('notes', purchaseNotes);
      if (purchaseInvoiceImage) fd.append('invoice_image', purchaseInvoiceImage);
      fd.append('items', JSON.stringify(validItems));

      const res = await adminApi.saveStockPurchase(fd);
      if (res && res.success) {
        showBanner('success', res.message || 'បានទិញចូលស្តុកជោគជ័យ!');
        setPurchaseSupplier('');
        setPurchaseInvoiceNo('');
        setPurchaseNotes('');
        setPurchaseInvoiceImage(null);
        setPurchaseRows([{ item_id: '', quantity: 1, price: 0 }]);
        setActivePage('stock_control');
      } else {
        showBanner('error', res?.message || 'កំហុសក្នុងការរក្សាទុក');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការបញ្ជូនទិន្នន័យ');
    }
    setSavingPurchase(false);
  };

  // Counting Actions
  const handleStepCountQty = (itemId: string, step: number, sysQty: number) => {
    const curVal = physicalCounts[itemId] !== undefined && physicalCounts[itemId] !== '' ? Number(physicalCounts[itemId]) : 0;
    const newVal = Math.max(0, curVal + step);
    setPhysicalCounts({ ...physicalCounts, [itemId]: newVal });
  };

  const handleSetMatchQty = (itemId: string, sysQty: number) => {
    setPhysicalCounts({ ...physicalCounts, [itemId]: sysQty });
  };

  const handleSaveCount = async (e: React.FormEvent) => {
    e.preventDefault();
    const countsToSend: Record<string, number> = {};
    let hasCount = false;
    Object.entries(physicalCounts).forEach(([k, v]) => {
      if (v !== '' && v !== undefined && !isNaN(Number(v))) {
        countsToSend[k] = Number(v);
        hasCount = true;
      }
    });

    if (!hasCount) {
      showBanner('info', 'សូមបញ្ចូលចំនួនដែលបានរាប់យ៉ាងហោចណាស់មួយទំនិញ!');
      return;
    }

    if (!window.confirm('តើអ្នកប្រាកដថាចង់រក្សាទុកលទ្ធផលការរាប់ស្តុកនេះ?')) return;

    setSavingCount(true);
    try {
      const res = await adminApi.saveStockCount(countingPhase, countsToSend);
      if (res && res.success) {
        showBanner('success', res.message || 'បានរក្សាទុកលទ្ធផលការរាប់ស្តុកជោគជ័យ!');
        setCountingSubTab('count_history');
        loadCounting();
      } else {
        showBanner('error', res?.message || 'Error occurred');
      }
    } catch (err) {
      showBanner('error', 'System Error');
    }
    setSavingCount(false);
  };

  // Direct Transfer Actions
  const handleAddTransferItem = () => {
    if (!selectedPickerItemId) return;
    const it = stockItems.find((s) => String(s.id) === String(selectedPickerItemId));
    if (!it) return;
    if (transferItems.some((t) => t.id === it.id)) return;

    setTransferItems([
      ...transferItems,
      {
        id: it.id,
        name: it.name || it.item_name,
        current_stock: it.quantity,
        qty: 1,
        note: '',
      },
    ]);
    setSelectedPickerItemId('');
  };

  const handleRemoveTransferItem = (id: number) => {
    setTransferItems(transferItems.filter((t) => t.id !== id));
  };

  const handleSaveTransfer = async (e: React.FormEvent) => {
    e.preventDefault();
    if (transferItems.length === 0) {
      showBanner('error', 'សូមជ្រើសរើសទំនិញយ៉ាងហោចណាស់មួយដើម្បីផ្ទេរ!');
      return;
    }
    if (!transferTitle) {
      showBanner('error', 'សូមបញ្ចូលចំណងជើងការផ្ទេរ!');
      return;
    }

    setSavingTransfer(true);
    try {
      const res = await adminApi.saveDirectTransfer({
        transfer_title: transferTitle,
        request_no: transferReqNo || `TRF-${Date.now()}`,
        location: transferLocation,
        items: transferItems,
      });

      if (res && res.success) {
        showBanner('success', res.message || 'បានផ្ទេរទំនិញដោយផ្ទាល់ជោគជ័យ!');
        setTransferTitle('');
        setTransferReqNo('');
        setTransferItems([]);
        setActivePage('stock_control');
      } else {
        showBanner('error', res?.message || 'Error occurred');
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការផ្ទេរទំនិញ');
    }
    setSavingTransfer(false);
  };

  // Request Status Update
  const handleUpdateRequest = async (reqId: number, status: 'approved' | 'rejected') => {
    const comment = prompt(`បញ្ចូលចំណាំសម្រាប់សំណើនេះ (${status === 'approved' ? 'យល់ព្រម' : 'បដិសេធ'}):`, '');
    try {
      const res = await adminApi.updateStockRequestStatus(reqId, status, comment || undefined);
      if (res && res.success) {
        showBanner('success', res.message);
        loadRequests();
      }
    } catch (err) {
      showBanner('error', 'កំហុសក្នុងការកែប្រែស្ថានភាពសំណើ');
    }
  };

  // Dropdown Sub-pages
  const STOCK_SUBPAGES = [
    { id: 'stock_control', label: 'បញ្ជីស្តុក (Stock Control)', icon: Package },
    { id: 'stock_purchase', label: 'ទិញចូល (Purchase)', icon: ShoppingCart },
    { id: 'stock_reports', label: 'របាយការណ៍ (Reports)', icon: FileSpreadsheet },
    { id: 'stock_counting', label: 'ការរាប់ស្តុក (Count)', icon: ClipboardList },
    { id: 'stock_requests', label: 'សំណើសម្ភារៈ (Requests)', icon: FileText },
    { id: 'direct_transfer', label: 'ផ្ទេរទំនិញ (Transfers)', icon: Truck },
  ];

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
              <Package size={20} />
            </span>
            <h2 style={{ fontSize: '22px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              គ្រប់គ្រងស្តុក & សម្ភារៈ (Stock Management)
            </h2>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0 }}>
            គ្រប់គ្រងទំនិញក្នុងស្តុក ប័ណ្ណទិញចូល សំណើសម្ភារៈ ផ្ទេរទំនិញ និងរបាយការណ៍សវនកម្មស្តុក
          </p>
        </div>

        {activePage === 'stock_control' ? (
          <button
            onClick={handleOpenCreate}
            className="btn btn-primary"
            style={{ borderRadius: '12px', padding: '11px 20px', fontWeight: 700 }}
          >
            <Plus size={16} />
            <span>+ បន្ថែមទំនិញថ្មី</span>
          </button>
        ) : (
          <button
            onClick={() => setActivePage('stock_control')}
            className="btn btn-secondary"
            style={{ borderRadius: '12px', padding: '11px 20px', fontWeight: 700 }}
          >
            <Package size={16} />
            <span>← ត្រឡប់ទៅបញ្ជីស្តុក</span>
          </button>
        )}
      </div>

      {/* Action Banner */}
      {actionMessage && (
        <div
          style={{
            padding: '12px 18px',
            borderRadius: '12px',
            background:
              actionMessage.type === 'success'
                ? 'rgba(16, 185, 129, 0.12)'
                : actionMessage.type === 'error'
                ? 'rgba(239, 68, 68, 0.12)'
                : 'rgba(59, 130, 246, 0.12)',
            border: `1px solid ${
              actionMessage.type === 'success' ? '#10b981' : actionMessage.type === 'error' ? '#ef4444' : '#3b82f6'
            }`,
            color: actionMessage.type === 'success' ? '#10b981' : actionMessage.type === 'error' ? '#ef4444' : '#3b82f6',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '13.5px',
            fontWeight: 600,
          }}
        >
          <CheckCircle size={16} />
          <span>{actionMessage.text}</span>
        </div>
      )}

      {/* Subpage Segmented Controls */}
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
        {STOCK_SUBPAGES.map((tab) => {
          const Icon = tab.icon;
          const isActive = activePage === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActivePage(tab.id as any)}
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
              <Icon size={14} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* ========================================================================= */}
      {/* 1. STOCK CONTROL (គ្រប់គ្រងស្តុក) */}
      {/* ========================================================================= */}
      {activePage === 'stock_control' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Search bar */}
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            <div style={{ position: 'relative', flex: 1 }}>
              <Search size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                type="text"
                className="form-input"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && loadStock()}
                placeholder="ស្វែងរកតាមឈ្មោះទំនិញ ឬកូដ..."
                style={{ paddingLeft: '40px' }}
              />
            </div>
            <button type="button" onClick={loadStock} className="btn btn-secondary">
              <Search size={15} />
              <span>ស្វែងរក</span>
            </button>
          </div>

          {/* Items Table */}
          <div className="table-container">
            <table className="hrm-table">
              <thead>
                <tr>
                  <th style={{ width: '60px' }}>ID</th>
                  <th style={{ width: '80px' }}>រូបភាព</th>
                  <th>ឈ្មោះទំនិញ</th>
                  <th style={{ width: '140px' }}>បរិមាណ</th>
                  <th style={{ width: '130px' }}>តម្លៃ ($)</th>
                  <th style={{ width: '150px' }}>ប្រភេទ</th>
                  <th style={{ width: '140px' }}>ទីតាំង</th>
                  <th style={{ textAlign: 'right', width: '160px' }}>សកម្មភាព</th>
                </tr>
              </thead>
              <tbody>
                {stockItems.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                      {loading ? 'កំពុងទាញយកទិន្នន័យទំនិញ...' : 'មិនមានទិន្នន័យទំនិញឡើយ'}
                    </td>
                  </tr>
                ) : (
                  stockItems.map((item) => {
                    const isLow = Number(item.quantity) <= 10;
                    return (
                      <tr key={item.id}>
                        <td>#{item.id}</td>
                        <td>
                          {item.image_path ? (
                            <img
                              src={item.image_path}
                              alt={item.name || item.item_name}
                              style={{ width: '48px', height: '48px', objectFit: 'cover', borderRadius: '10px', border: '1px solid var(--border)' }}
                              onError={(e) => {
                                (e.target as HTMLElement).style.display = 'none';
                              }}
                            />
                          ) : (
                            <div
                              style={{
                                width: '48px',
                                height: '48px',
                                borderRadius: '10px',
                                background: 'var(--surface-hover)',
                                border: '1px dashed var(--border)',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                color: 'var(--text-muted)',
                              }}
                            >
                              <ImageIcon size={18} />
                            </div>
                          )}
                        </td>
                        <td>
                          <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{item.name || item.item_name}</div>
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>កូដ: {item.code || `STK-${item.id}`}</div>
                        </td>
                        <td>
                          {isLow ? (
                            <span style={{ color: '#ef4444', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '4px' }}>
                              <AlertTriangle size={14} />
                              {item.quantity} (ទាប)
                            </span>
                          ) : (
                            <span style={{ fontWeight: 700 }}>{item.quantity} {item.unit || ''}</span>
                          )}
                        </td>
                        <td style={{ fontWeight: 700, color: '#10b981' }}>${Number(item.price).toFixed(2)}</td>
                        <td>
                          <span className="badge" style={{ background: 'var(--surface-hover)', color: 'var(--text-secondary)' }}>
                            {item.category || 'General'}
                          </span>
                        </td>
                        <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{item.location || 'Store 318'}</td>
                        <td style={{ textAlign: 'right' }}>
                          <div style={{ display: 'inline-flex', gap: '6px' }}>
                            <button
                              type="button"
                              onClick={() => handleDeductStock(item)}
                              className="btn btn-secondary btn-sm"
                              style={{ color: '#f59e0b', borderColor: '#f59e0b', padding: '4px 8px' }}
                              title="Deduct (កាត់ស្តុក)"
                            >
                              <Minus size={12} />
                              <span>ដក</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => handleOpenEdit(item)}
                              className="btn btn-secondary btn-sm"
                              style={{ padding: '4px 8px' }}
                              title="កែប្រែ"
                            >
                              <Edit2 size={12} />
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDeleteStock(item.id)}
                              className="btn btn-secondary btn-sm"
                              style={{ color: '#ef4444', padding: '4px 8px' }}
                              title="លុប"
                            >
                              <Trash2 size={12} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 2. STOCK PURCHASE (ទិញចូលស្តុក) */}
      {/* ========================================================================= */}
      {activePage === 'stock_purchase' && (
        <form onSubmit={handleSavePurchase} className="hrm-card" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div>
            <h4 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              ទិញសម្ភារៈចូលស្តុក (Stock Purchase)
            </h4>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0' }}>
              បង្កើតប័ណ្ណទិញចូលថ្មី បន្ថែមទំនិញច្រើនមុខក្នុងវិក្កយបត្រតែមួយ និងកត់ត្រាចូលស្តុកស្វ័យប្រវត្តិ
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            <div className="form-group">
              <label className="form-label">ឈ្មោះអ្នកផ្គត់ផ្គង់ (Supplier)</label>
              <input
                type="text"
                className="form-input"
                value={purchaseSupplier}
                onChange={(e) => setPurchaseSupplier(e.target.value)}
                placeholder="ឧ. ហាងលក់សម្ភារៈ ABC"
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">លេខវិក្កយបត្រ (Invoice No.)</label>
              <input
                type="text"
                className="form-input"
                value={purchaseInvoiceNo}
                onChange={(e) => setPurchaseInvoiceNo(e.target.value)}
                placeholder="ឧ. INV-00123"
              />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            <div className="form-group">
              <label className="form-label">រូបភាពវិក្កយបត្រ (Invoice Image / Scan)</label>
              <input
                type="file"
                className="form-input"
                accept="image/*,.pdf"
                onChange={(e) => setPurchaseInvoiceImage(e.target.files ? e.target.files[0] : null)}
              />
            </div>

            <div className="form-group">
              <label className="form-label">ចំណាំ (Notes)</label>
              <input
                type="text"
                className="form-input"
                value={purchaseNotes}
                onChange={(e) => setPurchaseNotes(e.target.value)}
                placeholder="ព័ត៌មានបន្ថែម..."
              />
            </div>
          </div>

          {/* Dynamic Items Purchase Table */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
              <h5 style={{ margin: 0, fontSize: '13.5px', fontWeight: 700, color: 'var(--text-primary)' }}>
                បញ្ជីទំនិញទិញចូល (Purchase Items)
              </h5>
              <button type="button" onClick={handleAddPurchaseRow} className="btn btn-secondary btn-sm">
                <Plus size={13} />
                <span>+ បន្ថែមមុខទំនិញ</span>
              </button>
            </div>

            <div className="table-container" style={{ margin: 0 }}>
              <table className="hrm-table">
                <thead>
                  <tr>
                    <th>ទំនិញ / សម្ភារៈ</th>
                    <th style={{ width: '160px', textAlign: 'center' }}>ចំនួនទិញចូល</th>
                    <th style={{ width: '180px', textAlign: 'center' }}>តម្លៃទិញចូល ($)</th>
                    <th style={{ width: '160px', textAlign: 'center' }}>សរុប ($)</th>
                    <th style={{ width: '60px' }}></th>
                  </tr>
                </thead>
                <tbody>
                  {purchaseRows.map((row, idx) => (
                    <tr key={idx}>
                      <td>
                        <select
                          className="form-input"
                          value={row.item_id}
                          onChange={(e) => handlePurchaseRowChange(idx, 'item_id', e.target.value)}
                          required
                        >
                          <option value="">-- ជ្រើសរើសទំនិញ --</option>
                          {stockItems.map((it) => (
                            <option key={it.id} value={it.id}>
                              {it.name || it.item_name} (ស្តុក: {it.quantity})
                            </option>
                          ))}
                        </select>
                      </td>
                      <td>
                        <input
                          type="number"
                          className="form-input"
                          min="1"
                          value={row.quantity}
                          onChange={(e) => handlePurchaseRowChange(idx, 'quantity', Number(e.target.value))}
                          style={{ textAlign: 'center' }}
                          required
                        />
                      </td>
                      <td>
                        <input
                          type="number"
                          step="0.01"
                          className="form-input"
                          value={row.price}
                          onChange={(e) => handlePurchaseRowChange(idx, 'price', Number(e.target.value))}
                          style={{ textAlign: 'center' }}
                          required
                        />
                      </td>
                      <td style={{ textAlign: 'center', fontWeight: 700, color: '#10b981' }}>
                        ${(row.quantity * row.price).toFixed(2)}
                      </td>
                      <td>
                        {purchaseRows.length > 1 && (
                          <button
                            type="button"
                            onClick={() => handleRemovePurchaseRow(idx)}
                            className="btn btn-secondary btn-sm"
                            style={{ color: '#ef4444' }}
                          >
                            <Trash2 size={12} />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '14px' }}>
            <button type="submit" disabled={savingPurchase} className="btn btn-primary" style={{ padding: '10px 28px' }}>
              <Check size={16} />
              <span>{savingPurchase ? 'កំពុងរក្សាទុក...' : 'រក្សាទុកការទិញចូល'}</span>
            </button>
          </div>
        </form>
      )}

      {/* ========================================================================= */}
      {/* 3. STOCK REPORTS (របាយការណ៍ស្តុក) */}
      {/* ========================================================================= */}
      {activePage === 'stock_reports' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Stat Cards Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
            <div className="hrm-card" style={{ padding: '18px 22px', borderTop: '4px solid #7c3aed' }}>
              <div style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 800, color: 'var(--text-muted)' }}>ប្រភេទទំនិញសរុប</div>
              <div style={{ fontSize: '24px', fontWeight: 900, color: 'var(--text-primary)', margin: '4px 0' }}>{reportStats.total_items}</div>
              <div style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>SKUs ក្នុងប្រព័ន្ធ</div>
            </div>

            <div className="hrm-card" style={{ padding: '18px 22px', borderTop: '4px solid #10b981' }}>
              <div style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 800, color: 'var(--text-muted)' }}>បរិមាណក្នុងស្តុកសរុប</div>
              <div style={{ fontSize: '24px', fontWeight: 900, color: 'var(--text-primary)', margin: '4px 0' }}>{reportStats.total_qty}</div>
              <div style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>Units ដែលនៅសល់</div>
            </div>

            <div className="hrm-card" style={{ padding: '18px 22px', borderTop: '4px solid #3b82f6' }}>
              <div style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 800, color: 'var(--text-muted)' }}>តម្លៃស្តុកសរុប</div>
              <div style={{ fontSize: '24px', fontWeight: 900, color: '#3b82f6', margin: '4px 0' }}>${Number(reportStats.total_value).toFixed(2)}</div>
              <div style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>គិតតាមតម្លៃឯកតាបច្ចុប្បន្ន</div>
            </div>

            <div className="hrm-card" style={{ padding: '18px 22px', borderTop: '4px solid #ef4444' }}>
              <div style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 800, color: 'var(--text-muted)' }}>ទំនិញជិតអស់ពីស្តុក</div>
              <div style={{ fontSize: '24px', fontWeight: 900, color: '#ef4444', margin: '4px 0' }}>{reportStats.low_stock}</div>
              <div style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>ត្រូវពិនិត្យទិញបន្ថែម</div>
            </div>
          </div>

          {/* Report Sub-tabs */}
          <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border)', paddingBottom: '10px' }}>
            {[
              { id: 'all_stock', label: 'ស្តុកទាំងអស់' },
              { id: 'low_stock', label: 'ស្តុកទាប (Low Stock)' },
              { id: 'requests', label: 'សំណើប្រើប្រាស់' },
              { id: 'history', label: 'ប្រវត្តិផ្ទេរ (Transfer History)' },
              { id: 'ledger', label: 'Stock Ledger' },
            ].map((t) => (
              <button
                key={t.id}
                onClick={() => setReportTab(t.id as any)}
                className={`btn btn-sm ${reportTab === t.id ? 'btn-primary' : 'btn-secondary'}`}
                style={{ borderRadius: '10px' }}
              >
                <span>{t.label}</span>
              </button>
            ))}
          </div>

          {/* Report Table */}
          <div className="table-container">
            <table className="hrm-table">
              {reportTab === 'all_stock' && (
                <>
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>ឈ្មោះទំនិញ</th>
                      <th>បរិមាណ</th>
                      <th>តម្លៃឯកតា</th>
                      <th>តម្លៃសរុប ($)</th>
                      <th>ទីតាំង</th>
                    </tr>
                  </thead>
                  <tbody>
                    {reportData.map((r: any) => (
                      <tr key={r.id}>
                        <td>#{r.id}</td>
                        <td style={{ fontWeight: 700 }}>{r.name || r.item_name}</td>
                        <td>{r.quantity} {r.unit || ''}</td>
                        <td>${Number(r.price).toFixed(2)}</td>
                        <td style={{ fontWeight: 700, color: '#10b981' }}>${Number(r.total_value || r.quantity * r.price).toFixed(2)}</td>
                        <td>{r.location || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </>
              )}

              {reportTab === 'low_stock' && (
                <>
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>ឈ្មោះទំនិញ</th>
                      <th>បរិមាណដែលនៅសល់</th>
                      <th>តម្លៃឯកតា</th>
                    </tr>
                  </thead>
                  <tbody>
                    {reportData.length === 0 ? (
                      <tr><td colSpan={4} style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>មិនមានទំនិញស្តុកទាបឡើយ</td></tr>
                    ) : (
                      reportData.map((r: any) => (
                        <tr key={r.id} style={{ background: 'rgba(239, 68, 68, 0.04)' }}>
                          <td>#{r.id}</td>
                          <td style={{ fontWeight: 700, color: '#ef4444' }}>{r.name || r.item_name}</td>
                          <td style={{ fontWeight: 800, color: '#ef4444' }}>{r.quantity}</td>
                          <td>${Number(r.price).toFixed(2)}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </>
              )}

              {reportTab === 'requests' && (
                <>
                  <thead>
                    <tr>
                      <th>លេខសំណើ</th>
                      <th>ចំណងជើង</th>
                      <th>ស្ថានភាព</th>
                      <th>ថ្ងៃដាក់ស្នើ</th>
                    </tr>
                  </thead>
                  <tbody>
                    {reportData.length === 0 ? (
                      <tr><td colSpan={4} style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>មិនទាន់មានសំណើនៅឡើយទេ</td></tr>
                    ) : (
                      reportData.map((r: any) => (
                        <tr key={r.id}>
                          <td style={{ fontWeight: 700 }}>{r.request_no}</td>
                          <td>{r.title}</td>
                          <td>
                            <span className={`badge ${r.status === 'approved' ? 'badge-good' : r.status === 'rejected' ? 'badge-absent' : 'badge-late'}`}>
                              {r.status}
                            </span>
                          </td>
                          <td style={{ fontSize: '12px' }}>{r.created_at}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </>
              )}

              {reportTab === 'history' && (
                <>
                  <thead>
                    <tr>
                      <th>ទំនិញ</th>
                      <th>ចំនួនផ្ទេរ</th>
                      <th>ទៅទីតាំង</th>
                      <th>ថ្ងៃផ្ទេរ</th>
                    </tr>
                  </thead>
                  <tbody>
                    {reportData.length === 0 ? (
                      <tr><td colSpan={4} style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>មិនទាន់មានប្រវត្តិផ្ទេរនៅឡើយទេ</td></tr>
                    ) : (
                      reportData.map((r: any) => (
                        <tr key={r.id}>
                          <td style={{ fontWeight: 700 }}>{r.item_name}</td>
                          <td style={{ fontWeight: 700 }}>{r.quantity_transferred}</td>
                          <td><span className="badge" style={{ background: '#e0f2fe', color: '#0369a1' }}>{r.to_location}</span></td>
                          <td style={{ fontSize: '12px' }}>{r.transfer_date}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </>
              )}

              {reportTab === 'ledger' && (
                <>
                  <thead>
                    <tr>
                      <th>ថ្ងៃ/ម៉ោង</th>
                      <th>ទំនិញ</th>
                      <th>ប្រភេទចលនា</th>
                      <th>Qty Change</th>
                      <th>Before</th>
                      <th>After</th>
                      <th>Reference</th>
                      <th>Actor</th>
                      <th>Notes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {reportData.length === 0 ? (
                      <tr><td colSpan={9} style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>មិនទាន់មានប្រវត្តិ stock movement នៅឡើយទេ</td></tr>
                    ) : (
                      reportData.map((m: any) => (
                        <tr key={m.id}>
                          <td style={{ fontSize: '12px' }}>{m.created_at}</td>
                          <td style={{ fontWeight: 700 }}>{m.item_name}</td>
                          <td>
                            <span className="badge" style={{ background: '#eef2ff', color: '#4338ca' }}>
                              {m.movement_type}
                            </span>
                          </td>
                          <td style={{ fontWeight: 800, color: Number(m.quantity_change) >= 0 ? '#10b981' : '#ef4444' }}>
                            {Number(m.quantity_change) > 0 ? `+${m.quantity_change}` : m.quantity_change}
                          </td>
                          <td>{m.quantity_before}</td>
                          <td>{m.quantity_after}</td>
                          <td style={{ fontSize: '12px', fontWeight: 600 }}>{m.reference_no}</td>
                          <td>{m.actor_name || 'Admin'}</td>
                          <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{m.notes}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </>
              )}
            </table>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 4. STOCK COUNTING (ការរាប់ស្តុក) */}
      {/* ========================================================================= */}
      {activePage === 'stock_counting' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Sub-tabs: New Count vs History */}
          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              type="button"
              onClick={() => setCountingSubTab('new_count')}
              className={`btn btn-sm ${countingSubTab === 'new_count' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ borderRadius: '12px' }}
            >
              <Plus size={14} />
              <span>រាប់ស្តុកថ្មី (New Count)</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setCountingSubTab('count_history');
                loadCounting();
              }}
              className={`btn btn-sm ${countingSubTab === 'count_history' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ borderRadius: '12px' }}
            >
              <History size={14} />
              <span>ប្រវត្តិរាប់ស្តុក (Count History)</span>
            </button>
          </div>

          {countingSubTab === 'new_count' && (
            <form onSubmit={handleSaveCount} className="hrm-card" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '16px' }}>
                <div className="form-group">
                  <label className="form-label">វេនរាប់ស្តុក (Phase)</label>
                  <select
                    className="form-input"
                    value={countingPhase}
                    onChange={(e) => setCountingPhase(e.target.value)}
                  >
                    <option value="Morning">ពេលព្រឹក (Morning)</option>
                    <option value="Afternoon">ពេលរសៀល (Afternoon)</option>
                    <option value="Night">ពេលយប់ (Night)</option>
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">ស្វែងរកទំនិញដើម្បីចោះរាប់</label>
                  <input
                    type="text"
                    className="form-input"
                    value={countSearchQuery}
                    onChange={(e) => setCountSearchQuery(e.target.value)}
                    placeholder="វាយឈ្មោះទំនិញ..."
                  />
                </div>
              </div>

              <div className="table-container" style={{ maxHeight: '450px', overflowY: 'auto' }}>
                <table className="hrm-table">
                  <thead>
                    <tr>
                      <th>ឈ្មោះទំនិញ</th>
                      <th style={{ textAlign: 'center', width: '130px' }}>ក្នុងប្រព័ន្ធ</th>
                      <th style={{ textAlign: 'center', width: '240px' }}>ចំនួនរាប់ជាក់ស្តែង</th>
                      <th style={{ textAlign: 'center', width: '140px' }}>ភាពខុសគ្នា</th>
                    </tr>
                  </thead>
                  <tbody>
                    {stockItems
                      .filter((it) => (it.name || it.item_name || '').toLowerCase().includes(countSearchQuery.toLowerCase()))
                      .map((it) => {
                        const sys = Number(it.quantity) || 0;
                        const physVal = physicalCounts[it.id];
                        const hasVal = physVal !== undefined && physVal !== '';
                        const phys = hasVal ? Number(physVal) : null;
                        const diff = phys !== null ? phys - sys : null;

                        return (
                          <tr key={it.id} style={{ background: diff !== null && diff !== 0 ? 'rgba(239, 68, 68, 0.04)' : undefined }}>
                            <td style={{ fontWeight: 700 }}>{it.name || it.item_name}</td>
                            <td style={{ textAlign: 'center', fontWeight: 800 }}>
                              <span className="badge" style={{ background: 'var(--surface-hover)' }}>{sys}</span>
                            </td>
                            <td>
                              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
                                <button
                                  type="button"
                                  onClick={() => handleStepCountQty(String(it.id), -1, sys)}
                                  className="btn btn-secondary btn-sm"
                                  style={{ padding: '4px 8px', color: '#ef4444' }}
                                >
                                  <Minus size={12} />
                                </button>
                                <input
                                  type="number"
                                  min="0"
                                  className="form-input"
                                  style={{ width: '80px', textAlign: 'center', height: '34px', fontWeight: 800 }}
                                  value={physVal !== undefined ? physVal : ''}
                                  placeholder="0"
                                  onChange={(e) => setPhysicalCounts({ ...physicalCounts, [it.id]: e.target.value })}
                                />
                                <button
                                  type="button"
                                  onClick={() => handleStepCountQty(String(it.id), 1, sys)}
                                  className="btn btn-secondary btn-sm"
                                  style={{ padding: '4px 8px', color: '#10b981' }}
                                >
                                  <Plus size={12} />
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleSetMatchQty(String(it.id), sys)}
                                  className="btn btn-secondary btn-sm"
                                  style={{ padding: '4px 8px', color: '#0369a1' }}
                                  title="គ្រប់"
                                >
                                  <Check size={12} />
                                </button>
                              </div>
                            </td>
                            <td style={{ textAlign: 'center', fontWeight: 900 }}>
                              {diff === null ? (
                                <span style={{ color: 'var(--text-muted)' }}>-</span>
                              ) : diff === 0 ? (
                                <span style={{ color: '#10b981' }}>✅ គ្រប់</span>
                              ) : (
                                <span style={{ color: diff > 0 ? '#10b981' : '#ef4444' }}>
                                  {diff > 0 ? `+${diff}` : diff}
                                </span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                  </tbody>
                </table>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '10px' }}>
                <button type="submit" disabled={savingCount} className="btn btn-primary" style={{ padding: '12px 36px' }}>
                  <Check size={16} />
                  <span>{savingCount ? 'កំពុងរក្សាទុក...' : 'រក្សាទុកលទ្ធផលការរាប់'}</span>
                </button>
              </div>
            </form>
          )}

          {countingSubTab === 'count_history' && (
            <div className="hrm-card" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <input
                  type="date"
                  className="form-input"
                  value={countingSearchDate}
                  onChange={(e) => setCountingSearchDate(e.target.value)}
                  style={{ width: '200px' }}
                />
                <button type="button" onClick={() => loadCounting(countingSearchDate)} className="btn btn-secondary">
                  <Filter size={14} />
                  <span>បង្ហាញតាមថ្ងៃនេះ</span>
                </button>
              </div>

              <div className="table-container">
                <table className="hrm-table">
                  <thead>
                    <tr>
                      <th>ទំនិញ</th>
                      <th style={{ textAlign: 'center' }}>ក្នុងប្រព័ន្ធ</th>
                      <th style={{ textAlign: 'center' }}>ជាក់ស្តែង</th>
                      <th style={{ textAlign: 'center' }}>ខុសគ្នា</th>
                      <th style={{ textAlign: 'center' }}>វេន</th>
                      <th>ថ្ងៃ-ម៉ោង</th>
                    </tr>
                  </thead>
                  <tbody>
                    {countHistory.length === 0 ? (
                      <tr><td colSpan={6} style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>មិនមានទិន្នន័យរាប់ស្តុកសម្រាប់ថ្ងៃនេះទេ</td></tr>
                    ) : (
                      countHistory.map((h: any) => (
                        <tr key={h.id}>
                          <td style={{ fontWeight: 700 }}>{h.item_name}</td>
                          <td style={{ textAlign: 'center' }}>{h.system_qty}</td>
                          <td style={{ textAlign: 'center', fontWeight: 800, color: 'var(--primary)' }}>{h.physical_qty}</td>
                          <td style={{ textAlign: 'center', fontWeight: 900, color: h.difference < 0 ? '#ef4444' : h.difference > 0 ? '#10b981' : '#64748b' }}>
                            {h.difference === 0 ? 'គ្រប់' : (h.difference > 0 ? `+${h.difference}` : h.difference)}
                          </td>
                          <td style={{ textAlign: 'center' }}><span className="badge" style={{ background: 'var(--surface-hover)' }}>{h.phase}</span></td>
                          <td style={{ fontSize: '12px' }}>{h.count_date}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* 5. STOCK REQUESTS (ពិនិត្យសំណើរ) */}
      {/* ========================================================================= */}
      {activePage === 'stock_requests' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', gap: '8px' }}>
              {['', 'pending', 'approved', 'rejected'].map((st) => (
                <button
                  key={st}
                  onClick={() => setRequestStatusFilter(st)}
                  className={`btn btn-sm ${requestStatusFilter === st ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ borderRadius: '10px' }}
                >
                  <span>{st === '' ? 'ទាំងអស់ (All)' : st.toUpperCase()}</span>
                </button>
              ))}
            </div>
            <button onClick={() => loadRequests()} className="btn btn-secondary btn-sm">
              <RefreshCw size={13} className={loadingRequests ? 'animate-spin' : ''} />
              <span>ផ្ទុកឡើងវិញ</span>
            </button>
          </div>

          <div className="table-container">
            <table className="hrm-table">
              <thead>
                <tr>
                  <th>លេខសំណើ</th>
                  <th>អ្នកស្នើសុំ</th>
                  <th>ចំណងជើងសំណើ</th>
                  <th>មន្ទីរ / ទីតាំង</th>
                  <th>ស្ថានភាព</th>
                  <th>កាលបរិច្ឆេទ</th>
                  <th style={{ textAlign: 'right' }}>សកម្មភាព</th>
                </tr>
              </thead>
              <tbody>
                {stockRequests.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                      {loadingRequests ? 'កំពុងទាញយកសំណើ...' : 'មិនមានសំណើសម្ភារៈឡើយ'}
                    </td>
                  </tr>
                ) : (
                  stockRequests.map((r: any) => (
                    <tr key={r.id}>
                      <td style={{ fontWeight: 800, color: 'var(--primary)' }}>{r.request_no}</td>
                      <td>{r.user_name || r.user_id || 'បុគ្គលិក'}</td>
                      <td style={{ fontWeight: 600 }}>{r.title}</td>
                      <td>{r.department || r.location || '-'}</td>
                      <td>
                        <span className={`badge ${r.status === 'approved' ? 'badge-good' : r.status === 'rejected' ? 'badge-absent' : 'badge-late'}`}>
                          {r.status}
                        </span>
                      </td>
                      <td style={{ fontSize: '12px' }}>{r.created_at}</td>
                      <td style={{ textAlign: 'right' }}>
                        {r.status === 'pending' && (
                          <div style={{ display: 'inline-flex', gap: '6px' }}>
                            <button
                              type="button"
                              onClick={() => handleUpdateRequest(r.id, 'approved')}
                              className="btn btn-primary btn-sm"
                              style={{ padding: '4px 10px' }}
                            >
                              <Check size={12} />
                              <span>យល់ព្រម</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => handleUpdateRequest(r.id, 'rejected')}
                              className="btn btn-secondary btn-sm"
                              style={{ color: '#ef4444', padding: '4px 10px' }}
                            >
                              <X size={12} />
                              <span>បដិសេធ</span>
                            </button>
                          </div>
                        )}
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
      {/* 6. DIRECT TRANSFER (ផ្ទេរដោយផ្ទាល់) */}
      {/* ========================================================================= */}
      {activePage === 'direct_transfer' && (
        <form onSubmit={handleSaveTransfer} className="hrm-card" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div>
            <h4 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              ផ្ទេរទំនិញដោយផ្ទាល់ (Direct Stock Transfer)
            </h4>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0' }}>
              បង្កើតប័ណ្ណផ្ទេរទំនិញទៅទីតាំងផ្សេងៗភ្លាមៗ ដោយកំណត់ចំនួនផ្ទេរ និងកាត់ចេញពីស្តុកដើម
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px' }}>
            <div className="form-group">
              <label className="form-label">ចំណងជើងការផ្ទេរ (Transfer Title)</label>
              <input
                type="text"
                className="form-input"
                value={transferTitle}
                onChange={(e) => setTransferTitle(e.target.value)}
                placeholder="ឧ. ផ្ទេរទៅសាខា NR3"
                required
              />
            </div>
            <div className="form-group">
              <label className="form-label">លេខប័ណ្ណផ្ទេរ (Request No.)</label>
              <input
                type="text"
                className="form-input"
                value={transferReqNo}
                onChange={(e) => setTransferReqNo(e.target.value)}
                placeholder="ទុកឱ្យទំនេរដើម្បីបង្កើតស្វ័យប្រវត្តិ..."
              />
            </div>
            <div className="form-group">
              <label className="form-label">ទីតាំងគោលដៅ (Target Location)</label>
              <select
                className="form-input"
                value={transferLocation}
                onChange={(e) => setTransferLocation(e.target.value)}
              >
                <option value="Store 318">Store 318</option>
                <option value="Store SKKS2">Store SKKS2</option>
                <option value="Store NR3">Store NR3</option>
                <option value="Warehouse PSP">Warehouse PSP</option>
                <option value="Warehouse PRV">Warehouse PRV</option>
              </select>
            </div>
          </div>

          {/* Item Picker */}
          <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-end', background: 'var(--surface-hover)', padding: '16px', borderRadius: '12px', border: '1px solid var(--border)' }}>
            <div className="form-group" style={{ flex: 1, margin: 0 }}>
              <label className="form-label">ជ្រើសរើសទំនិញដើម្បីបន្ថែម</label>
              <select
                className="form-input"
                value={selectedPickerItemId}
                onChange={(e) => setSelectedPickerItemId(e.target.value)}
              >
                <option value="">-- ជ្រើសរើសទំនិញដើម្បីបន្ថែម --</option>
                {stockItems.map((it) => (
                  <option key={it.id} value={it.id}>
                    {it.name || it.item_name} (ស្តុក: {it.quantity})
                  </option>
                ))}
              </select>
            </div>
            <button type="button" onClick={handleAddTransferItem} className="btn btn-primary">
              <Plus size={14} />
              <span>បន្ថែមចូលបញ្ជី</span>
            </button>
          </div>

          {/* Transfer Items List */}
          <div>
            <h5 style={{ margin: '0 0 10px', fontSize: '13.5px', fontWeight: 700, color: 'var(--text-primary)' }}>
              បញ្ជីទំនិញត្រូវផ្ទេរ ({transferItems.length})
            </h5>
            <div className="table-container" style={{ margin: 0 }}>
              <table className="hrm-table">
                <thead>
                  <tr>
                    <th>ឈ្មោះទំនិញ</th>
                    <th style={{ textAlign: 'center', width: '130px' }}>ស្តុកបច្ចុប្បន្ន</th>
                    <th style={{ textAlign: 'center', width: '160px' }}>ចំនួនផ្ទេរ</th>
                    <th>ចំណាំ</th>
                    <th style={{ width: '60px' }}></th>
                  </tr>
                </thead>
                <tbody>
                  {transferItems.length === 0 ? (
                    <tr><td colSpan={5} style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>មិនទាន់មានទំនិញត្រូវបានបន្ថែមនៅឡើយទេ</td></tr>
                  ) : (
                    transferItems.map((it, idx) => (
                      <tr key={it.id}>
                        <td style={{ fontWeight: 700 }}>{it.name}</td>
                        <td style={{ textAlign: 'center', fontWeight: 800 }}>{it.current_stock}</td>
                        <td>
                          <input
                            type="number"
                            min="1"
                            max={it.current_stock}
                            className="form-input"
                            value={it.qty}
                            onChange={(e) => {
                              const updated = [...transferItems];
                              updated[idx].qty = Math.min(it.current_stock, Math.max(1, Number(e.target.value)));
                              setTransferItems(updated);
                            }}
                            style={{ textAlign: 'center', fontWeight: 700, color: 'var(--primary)' }}
                            required
                          />
                        </td>
                        <td>
                          <input
                            type="text"
                            className="form-input"
                            value={it.note}
                            onChange={(e) => {
                              const updated = [...transferItems];
                              updated[idx].note = e.target.value;
                              setTransferItems(updated);
                            }}
                            placeholder="ចំណាំ..."
                          />
                        </td>
                        <td>
                          <button
                            type="button"
                            onClick={() => handleRemoveTransferItem(it.id)}
                            className="btn btn-secondary btn-sm"
                            style={{ color: '#ef4444' }}
                          >
                            <Trash2 size={12} />
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '10px' }}>
            <button type="submit" disabled={savingTransfer || transferItems.length === 0} className="btn btn-primary" style={{ padding: '12px 36px' }}>
              <Truck size={16} />
              <span>{savingTransfer ? 'កំពុងផ្ទេរ...' : 'បញ្ជាក់ការផ្ទេរភ្លាមៗ'}</span>
            </button>
          </div>
        </form>
      )}

      {/* ========================================================================= */}
      {/* ADD / EDIT STOCK MODAL */}
      {/* ========================================================================= */}
      {modalOpen && (
        <Modal
          isOpen={modalOpen}
          onClose={() => setModalOpen(false)}
          title={editingItem ? 'កែប្រែទំនិញក្នុងស្តុក' : 'បញ្ចូលទំនិញថ្មី'}
          maxWidth="540px"
        >
          <form onSubmit={handleSaveStock}>
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
                    className="form-input"
                    value={formData.location}
                    onChange={(e) => setFormData({ ...formData, location: e.target.value })}
                  >
                    <option value="Store 318">Store 318</option>
                    <option value="Store SKKS2">Store SKKS2</option>
                    <option value="Store NR3">Store NR3</option>
                    <option value="Warehouse PSP">Warehouse PSP</option>
                    <option value="Warehouse PRV">Warehouse PRV</option>
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

              <div className="form-group">
                <label className="form-label">រូបភាពទំនិញ (Item Image)</label>
                <input
                  type="file"
                  className="form-input"
                  accept="image/*"
                  onChange={(e) => setItemImageFile(e.target.files ? e.target.files[0] : null)}
                />
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
