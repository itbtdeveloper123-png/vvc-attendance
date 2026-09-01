import { apiClient } from './client';

export interface AdminUser {
  id: string | number;
  employee_id: string;
  name: string;
  latin_name?: string;
  username?: string;
  password?: string;
  email?: string;
  phone?: string;
  user_role: string;
  system_role?: string;
  system_role_label?: string;
  position?: string;
  department?: string;
  branch?: string;
  current_address?: string;
  avatar?: string;
  is_active?: boolean | number;
  is_verified?: boolean | number;
  sort_order?: number;
  group_id?: number;
  joined_at?: string;
  marital_status?: string;
  contract_start?: string;
  contract_end?: string;
  contract_type?: string;
  manager_id?: string;
  al_total?: number;
  al_remaining?: number;
  base_salary?: string | number;
  nssf_id?: string;
  bank_data_str?: string;
  custom_data?: any;
}

export interface DashboardStats {
  total_employees: number;
  total_admins?: number;
  today_good: number;
  today_late: number;
  today_scans_count?: number;
  pending_requests: number;
  total_locations?: number;
  total_categories?: number;
  total_tokens?: number;
  total_notifications?: number;
  total_payroll?: number;
  total_stock?: number;
  low_stock?: number;
  total_meetings?: number;
  active_trips?: number;
  total_training?: number;
  total_polls?: number;
  total_audit_logs?: number;
  today_threats?: number;
  today_scans?: any[];
  success?: boolean;
}

export type DashboardSummary = DashboardStats;

export interface AttendanceRecord {
  id: number | string;
  employee_id: string;
  name: string;
  action: string;
  status: 'Good' | 'Late' | 'Absent' | string;
  log_time: string;
  workplace: string;
  late_reason?: string;
  location_raw?: string;
  photo?: string;
  photo_path?: string;
  geo_address?: string;
  department?: string;
  position?: string;
  distance_m?: number;
  noted?: string;
}

export interface RequestItem {
  id: number | string;
  user_id: number | string;
  employee_id?: string;
  requester_name: string;
  request_type: string;
  department?: string;
  position?: string;
  request_date?: string;
  return_date?: string;
  reason?: string;
  status: 'Pending' | 'Approved' | 'Rejected';
  approved_by?: string;
  created_at?: string;
}

export interface LocationItem {
  id: number;
  name: string;
  location_name?: string;
  address?: string;
  latitude: number | string;
  longitude: number | string;
  radius_meters: number;
  qr_secret: string;
  assigned_employees_count?: number;
  created_at?: string;
}

export interface UserLocationAssignment {
  assign_id: number;
  id?: number;
  employee_id: string;
  user_name: string;
  department?: string;
  system_role?: string;
  avatar?: string;
  location_id: number;
  location_name: string;
  latitude?: number | string;
  longitude?: number | string;
  custom_radius_meters: number;
  created_at?: string;
}

export interface CategoryItem {
  id: number;
  name: string;
  group_name?: string;
  code?: string;
  sort_order?: number;
  description?: string;
  item_count?: number;
  user_count?: number;
}

export interface GroupUserItem {
  id: number;
  employee_id: string;
  name: string;
  avatar?: string;
  department?: string;
  phone?: string;
  role?: string;
  group_id?: number | null;
}

export interface StockItem {
  id: number;
  code: string;
  name: string;
  category: string;
  quantity: number;
  unit: string;
  price: number;
  location: string;
  status: 'In Stock' | 'Low Stock' | 'Out of Stock';
}

export interface MeetingItem {
  id: number;
  topic: string;
  title?: string;
  department: string;
  category?: string;
  date?: string;
  meeting_date?: string;
  duration?: string;
  summary?: string;
  description?: string;
  external_url?: string;
  audio_url?: string;
  audio_file_path?: string;
  mp3_url?: string;
  hasAudio?: boolean;
  photo_url?: string;
  photos?: string[];
  related_photos?: string[];
  transcript_text?: string;
  transcript?: string;
  summary_json?: string;
  summary_generated_at?: string;
  created_at?: string;
}

export interface NotificationItem {
  id: number;
  admin_id?: string;
  title: string;
  message: string;
  recipient_type?: 'all' | 'role' | 'user' | 'specific' | string;
  recipient_info?: string;
  target_roles?: string;
  target_users?: string;
  expiry_date?: string;
  image_url?: string;
  sent_at?: string;
  created_at?: string;
}

export interface NotificationTemplate {
  id: number;
  admin_id?: string;
  template_key?: string;
  template_name: string;
  title_template: string;
  message_template: string;
  target_type: 'all' | 'role' | 'user' | string;
  target_roles_json?: string;
  target_users_json?: string;
  image_url?: string;
  is_active: number | boolean;
  created_at?: string;
  updated_at?: string;
}

export interface NotificationSchedule {
  id: number;
  admin_id?: string;
  template_id?: number | null;
  template_name?: string;
  schedule_name: string;
  title_override?: string;
  message_override?: string;
  target_type?: 'all' | 'role' | 'user' | string;
  target_roles_json?: string;
  target_users_json?: string;
  image_url?: string;
  frequency: 'once' | 'daily' | 'weekly' | 'monthly' | string;
  scheduled_at?: string;
  time_of_day?: string;
  day_of_week?: number | null;
  day_of_month?: number | null;
  next_run_at?: string;
  last_run_at?: string;
  last_result?: string;
  last_message?: string;
  is_active: number | boolean;
  created_at?: string;
  updated_at?: string;
}

export interface NotificationRecipientUser {
  employee_id: string;
  name: string;
  department?: string;
  system_role?: string;
  avatar?: string;
}

export interface PollCandidate {
  id: number;
  poll_id?: number;
  employee_id: string;
  name: string;
  department?: string;
  position?: string;
  category?: string;
  avatar?: string;
  votes_count?: number;
  percentage?: number;
  voters?: Array<{
    employee_id: string;
    name: string;
    avatar?: string;
    voted_at?: string;
  }>;
}

export interface PollOption {
  text: string;
  votes: number;
  percentage: number;
}

export interface PollItem {
  id: number;
  title: string;
  quarter?: string;
  location?: string;
  creator?: string;
  start_date?: string;
  end_date?: string;
  access_code?: string;
  is_active?: number;
  status: 'Active' | 'Closed';
  candidate_count?: number;
  total_votes: number;
  ends_at?: string;
  allowed_employee_ids?: string;
  excluded_employee_ids?: string;
  candidates?: PollCandidate[];
  options?: PollOption[];
}

export interface SessionGroup {
  id: number;
  group_name: string;
  sort_order: number;
}

export interface SessionItem {
  id: number;
  employee_id: string;
  user_name?: string;
  name?: string;
  auth_token: string;
  user_role?: string;
  department?: string;
  position?: string;
  custom_data?: string;
  avatar?: string;
  created_at: string;
  last_used: string;
}

export interface QuizItem {
  id: number;
  question: string;
  department: string;
  correct_answer: string;
  options: string[];
  points: number;
}

export interface GpsTripItem {
  id: number;
  employee_id: string;
  employee_name?: string;
  display_name?: string;
  avatar?: string;
  department?: string;
  employee_phone?: string;
  customer_id?: number | null;
  customer_name?: string;
  customer_target_name?: string;
  target_lat?: number | string | null;
  target_lng?: number | string | null;
  target_address?: string;
  status: 'active' | 'completed' | 'cancelled';
  start_lat?: number | string | null;
  start_lng?: number | string | null;
  start_address?: string;
  end_lat?: number | string | null;
  end_lng?: number | string | null;
  end_address?: string;
  current_lat?: number | string | null;
  current_lng?: number | string | null;
  current_speed?: number | string;
  total_distance_km?: number | string;
  duration_minutes?: number | string;
  started_at?: string;
  ended_at?: string;
  point_count?: number;
  last_recorded_at?: string;
  latest_location?: {
    latitude: number | string;
    longitude: number | string;
    speed: number | string;
    accuracy: number | string;
    recorded_at: string;
  } | null;
}

export interface TrackingCustomerItem {
  id: number;
  name: string;
  phone?: string;
  address?: string;
  latitude?: number | string;
  longitude?: number | string;
  profile_image?: string;
  created_at?: string;
}

export interface PayrollItem {
  id: number;
  employee_id: string;
  name: string;
  base_salary: number;
  days_present?: number;
  ot_hours: number;
  ot_amount: number;
  deductions: number;
  loans?: number;
  net_salary: number;
  status: 'Paid' | 'Pending';
  month?: number;
  year?: number;
  department?: string;
  position?: string;
}

export interface ThemeItem {
  id: number;
  theme_id: string;
  theme_name: string;
  theme_name_kh?: string;
  primary_color: string;
  secondary_color: string;
  accent_color: string;
  is_active: number | boolean;
}

export const adminApi = {
  // Authentication & 2FA
  login: async (adminId: string, password: string, skip2fa = false) => {
    const params = new URLSearchParams();
    params.append('action', 'admin_login');
    params.append('admin_id', adminId);
    params.append('password', password);
    if (skip2fa) params.append('skip_2fa', '1');
    const res = await apiClient.post('', params);
    return res.data;
  },

  verify2FA: async (adminId: string, otpCode: string, tempToken?: string) => {
    const params = new URLSearchParams();
    params.append('action', 'verify_2fa_login');
    params.append('admin_id', adminId);
    params.append('otp_code', otpCode);
    if (tempToken) params.append('temp_token', tempToken);
    const res = await apiClient.post('', params);
    return res.data;
  },

  get2FASetup: async (adminId: string) => {
    const params = new URLSearchParams();
    params.append('action', 'get_2fa_setup');
    params.append('admin_id', adminId);
    const res = await apiClient.post('', params);
    return res.data;
  },

  createQrLoginSession: async (adminId: string, tempToken?: string) => {
    const params = new URLSearchParams();
    params.append('action', 'create_qr_login_session');
    params.append('admin_id', adminId);
    if (tempToken) params.append('temp_token', tempToken);
    const res = await apiClient.post('', params);
    return res.data;
  },

  checkQrLoginStatus: async (qrToken: string) => {
    const params = new URLSearchParams();
    params.append('action', 'check_qr_login_status');
    params.append('qr_token', qrToken);
    const res = await apiClient.post('', params);
    return res.data;
  },

  approveQrLogin: async (qrToken: string, adminId: string, totpCode?: string, deviceInfo?: string) => {
    const params = new URLSearchParams();
    params.append('action', 'approve_qr_login');
    params.append('qr_token', qrToken);
    params.append('admin_id', adminId);
    if (totpCode) params.append('totp_code', totpCode);
    if (deviceInfo) params.append('device_info', deviceInfo);
    const res = await apiClient.post('', params);
    return res.data;
  },

  getProfile: async () => {
    const params = new URLSearchParams();
    params.append('action', 'get_admin_profile');
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Dashboard Stats
  fetchDashboard: async () => {
    const params = new URLSearchParams();
    params.append('action', 'get_dashboard_summary');
    const res = await apiClient.post('', params);
    return res.data;
  },

  getDashboardSummary: async () => {
    const params = new URLSearchParams();
    params.append('action', 'get_dashboard_summary');
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Users Management
  fetchUsers: async (department?: string, search?: string) => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_users');
    if (department) params.append('department', department);
    if (search) params.append('search', search);
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveUser: async (userData: Partial<AdminUser>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_user');
    Object.entries(userData).forEach(([k, v]) => {
      if (v !== undefined && v !== null) params.append(k, String(v));
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  deleteUser: async (employeeId: string) => {
    const params = new URLSearchParams();
    params.append('action', 'delete_user');
    params.append('employee_id', employeeId);
    const res = await apiClient.post('', params);
    return res.data;
  },

  toggleVerification: async (employeeId: string) => {
    const params = new URLSearchParams();
    params.append('action', 'toggle_verification');
    params.append('employee_id', employeeId);
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveUserSortOrder: async (orders: { employee_id: string; sort_order: number; department?: string }[]) => {
    const params = new URLSearchParams();
    params.append('action', 'save_user_sort_order');
    params.append('orders', JSON.stringify(orders));
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveGroupSortOrder: async (orders: { id: number | string; sort_order: number }[]) => {
    const params = new URLSearchParams();
    params.append('action', 'save_group_sort_order');
    params.append('orders', JSON.stringify(orders));
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Attendance Records
  fetchAttendance: async (page = 1, limit = 100, filters?: { date?: string; department?: string; dept_category?: string; status?: string; search?: string; tab?: string }) => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_attendance_records');
    params.append('page', String(page));
    params.append('limit', String(limit));
    if (filters?.date) params.append('date', filters.date);
    if (filters?.department) params.append('department', filters.department);
    if (filters?.dept_category) params.append('dept_category', filters.dept_category);
    if (filters?.status) params.append('status', filters.status);
    if (filters?.search) params.append('search', filters.search);
    if (filters?.tab) params.append('tab', filters.tab);
    const res = await apiClient.post('', params);
    return res.data;
  },

  updateAttendanceNoted: async (logId: number | string, noted: string) => {
    const params = new URLSearchParams();
    params.append('action', 'update_attendance_noted');
    params.append('log_id', String(logId));
    params.append('noted', noted);
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Leave & Deo / Consolidated Reports
  fetchLeaveDeoReport: async (store: string, date: string) => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_leave_deo_report');
    params.append('store', store);
    params.append('date', date);
    const res = await apiClient.post('', params);
    return res.data;
  },

  createLeaveDeoRow: async (store: string, date: string) => {
    const params = new URLSearchParams();
    params.append('action', 'create_leave_deo_row');
    params.append('store', store);
    params.append('date', date);
    const res = await apiClient.post('', params);
    return res.data;
  },

  updateLeaveDeoRow: async (store: string, id: number | string, column: string, value: string) => {
    const params = new URLSearchParams();
    params.append('action', 'update_leave_deo_row');
    params.append('store', store);
    params.append('id', String(id));
    params.append('column', column);
    params.append('value', value);
    const res = await apiClient.post('', params);
    return res.data;
  },

  deleteLeaveDeoRow: async (store: string, id: number | string, date?: string) => {
    const params = new URLSearchParams();
    params.append('action', 'delete_leave_deo_row');
    params.append('ajax_action', 'delete_leave_deo_ajax');
    params.append('store', store);
    params.append('id', String(id));
    if (date) params.append('date', date);
    const res = await apiClient.post('', params);
    return res.data;
  },

  clearAllLeaveDeoRows: async (store: string, date: string) => {
    const params = new URLSearchParams();
    params.append('action', 'clear_all_leave_deo_rows');
    params.append('store', store);
    params.append('date', date);
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchConsolidatedReport: async (store: string, date: string) => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_consolidated_report');
    params.append('store', store);
    params.append('date', date);
    const res = await apiClient.post('', params);
    return res.data;
  },

  updateSingleAttendance: async (store: string, date: string, column: string, value: number) => {
    const params = new URLSearchParams();
    params.append('action', 'update_single_attendance');
    params.append('store', store);
    params.append('date', date);
    params.append('column', column);
    params.append('value', String(value));
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchLateSummaryReport: async (filters?: { start_date?: string; end_date?: string; department?: string; dept_category?: string }) => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_late_summary_report');
    if (filters?.start_date) params.append('start_date', filters.start_date);
    if (filters?.end_date) params.append('end_date', filters.end_date);
    if (filters?.department) params.append('department', filters.department);
    if (filters?.dept_category) params.append('dept_category', filters.dept_category);
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchForgottenScanReport: async (filters?: { start_date?: string; end_date?: string; department?: string; dept_category?: string }) => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_forgotten_scan_report');
    if (filters?.start_date) params.append('start_date', filters.start_date);
    if (filters?.end_date) params.append('end_date', filters.end_date);
    if (filters?.department) params.append('department', filters.department);
    if (filters?.dept_category) params.append('dept_category', filters.dept_category);
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Requests Management
  fetchRequests: async (status?: string, type?: string) => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_all_requests');
    if (status) params.append('status', status);
    if (type) params.append('type', type);
    const res = await apiClient.post('', params);
    return res.data;
  },

  createRequest: async (data: Partial<RequestItem>) => {
    const params = new URLSearchParams();
    params.append('action', 'create_request');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) params.append(k, String(v));
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  updateRequestStatus: async (requestId: string | number, status: 'Approved' | 'Rejected', comment?: string) => {
    const params = new URLSearchParams();
    params.append('action', 'update_request_status');
    params.append('request_id', String(requestId));
    params.append('status', status);
    if (comment) params.append('admin_comment', comment);
    const res = await apiClient.post('', params);
    return res.data;
  },

  deleteRequest: async (requestId: string | number) => {
    const params = new URLSearchParams();
    params.append('action', 'delete_request');
    params.append('request_id', String(requestId));
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Locations & User Assignments
  fetchLocations: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_locations');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveLocation: async (data: Partial<LocationItem> | Record<string, any>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_location');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) params.append(k, String(v));
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  deleteLocation: async (id: number | string) => {
    const params = new URLSearchParams();
    params.append('action', 'delete_location');
    params.append('id', String(id));
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchUserLocations: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_user_locations');
    const res = await apiClient.post('', params);
    return res.data;
  },

  assignUserLocation: async (data: { employee_ids: string[]; location_ids: (number | string)[]; custom_radius_meters?: number }) => {
    const params = new URLSearchParams();
    params.append('action', 'assign_user_location');
    params.append('employee_ids', JSON.stringify(data.employee_ids));
    params.append('location_ids', JSON.stringify(data.location_ids));
    if (data.custom_radius_meters) params.append('custom_radius_meters', String(data.custom_radius_meters));
    const res = await apiClient.post('', params);
    return res.data;
  },

  unassignUserLocation: async (assignId: number | string) => {
    const params = new URLSearchParams();
    params.append('action', 'unassign_user_location');
    params.append('assign_id', String(assignId));
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchLocationsMeta: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_locations_meta');
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Categories & Skill Groups
  fetchCategories: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_categories');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveCategory: async (data: Partial<CategoryItem>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_category');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) params.append(k, String(v));
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  deleteCategory: async (id: number | string) => {
    const params = new URLSearchParams();
    params.append('action', 'delete_category');
    params.append('id', String(id));
    const res = await apiClient.post('', params);
    return res.data;
  },

  updateGroupSort: async (orders: Array<{ id: number; sort: number }>) => {
    const params = new URLSearchParams();
    params.append('action', 'update_groups_sort');
    params.append('orders', JSON.stringify(orders));
    const res = await apiClient.post('', params);
    return res.data;
  },

  assignUsersToGroup: async (employeeIds: string[], groupId: number | null) => {
    const params = new URLSearchParams();
    params.append('action', 'assign_user_group');
    params.append('employee_ids', JSON.stringify(employeeIds));
    if (groupId !== null) {
      params.append('group_id', String(groupId));
    }
    const res = await apiClient.post('', params);
    return res.data;
  },

  removeUsersFromGroup: async (employeeIds: string[]) => {
    const params = new URLSearchParams();
    params.append('action', 'remove_user_group');
    params.append('employee_ids', JSON.stringify(employeeIds));
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Stock Management (All Sub-Pages & Features)
  fetchStockItems: async (search?: string) => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_stock_items');
    if (search) params.append('search', search);
    const res = await apiClient.post('', params);
    return res.data;
  },

  getStockItem: async (id: number | string) => {
    const params = new URLSearchParams();
    params.append('action', 'get_stock_item');
    params.append('id', String(id));
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveStockItem: async (data: FormData | Partial<StockItem> | Record<string, any>) => {
    if (data instanceof FormData) {
      data.append('action', 'save_stock_item');
      const res = await apiClient.post('', data, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      return res.data;
    }
    const params = new URLSearchParams();
    params.append('action', 'save_stock_item');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) params.append(k, String(v));
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  deductStock: async (itemId: number | string, deductQuantity: number) => {
    const params = new URLSearchParams();
    params.append('action', 'deduct_stock');
    params.append('item_id', String(itemId));
    params.append('deduct_quantity', String(deductQuantity));
    const res = await apiClient.post('', params);
    return res.data;
  },

  deleteStockItem: async (id: number | string) => {
    const params = new URLSearchParams();
    params.append('action', 'delete_stock_item');
    params.append('id', String(id));
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchStockPurchases: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_stock_purchases');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveStockPurchase: async (data: FormData | Record<string, any>) => {
    if (data instanceof FormData) {
      data.append('action', 'save_stock_purchase');
      const res = await apiClient.post('', data, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      return res.data;
    }
    const params = new URLSearchParams();
    params.append('action', 'save_stock_purchase');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) {
        if (typeof v === 'object') params.append(k, JSON.stringify(v));
        else params.append(k, String(v));
      }
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchStockReports: async (tab: string = 'all_stock') => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_stock_reports');
    params.append('tab', tab);
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchStockCounting: async (searchDate?: string) => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_stock_counting');
    if (searchDate) params.append('search_date', searchDate);
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveStockCount: async (phase: string, counts: Record<string, number | string>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_stock_count');
    params.append('phase', phase);
    params.append('counts', JSON.stringify(counts));
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchStockRequests: async (status?: string) => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_stock_requests');
    if (status) params.append('status', status);
    const res = await apiClient.post('', params);
    return res.data;
  },

  updateStockRequestStatus: async (requestId: number | string, status: string, adminComment?: string) => {
    const params = new URLSearchParams();
    params.append('action', 'update_stock_request_status');
    params.append('request_id', String(requestId));
    params.append('status', status);
    if (adminComment) params.append('admin_comment', adminComment);
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchDirectTransfers: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_direct_transfers');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveDirectTransfer: async (data: { transfer_title: string; request_no?: string; location: string; items: any[] }) => {
    const params = new URLSearchParams();
    params.append('action', 'save_direct_transfer');
    params.append('transfer_title', data.transfer_title);
    if (data.request_no) params.append('request_no', data.request_no);
    params.append('location', data.location);
    params.append('items', JSON.stringify(data.items));
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Meetings
  fetchMeetings: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_meetings');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveMeeting: async (data: FormData | Partial<MeetingItem> | Record<string, any>) => {
    if (data instanceof FormData) {
      data.append('action', 'save_meeting');
      const res = await apiClient.post('', data, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      return res.data;
    }
    const params = new URLSearchParams();
    params.append('action', 'save_meeting');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) {
        if (typeof v === 'object') params.append(k, JSON.stringify(v));
        else params.append(k, String(v));
      }
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  deleteMeeting: async (id: number | string) => {
    const params = new URLSearchParams();
    params.append('action', 'delete_meeting');
    params.append('id', String(id));
    const res = await apiClient.post('', params);
    return res.data;
  },

  summarizeMeeting: async (meetingId: number | string, force: boolean = false) => {
    const params = new URLSearchParams();
    params.append('action', 'summarize_meeting');
    params.append('meeting_id', String(meetingId));
    if (force) params.append('force', '1');
    const res = await apiClient.post('', params, { timeout: 300000 });
    return res.data;
  },

  // Polls
  fetchPolls: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_polls');
    const res = await apiClient.post('', params);
    return res.data;
  },

  savePoll: async (data: Partial<PollItem>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_poll');
    Object.entries(data).forEach(([k, v]) => {
      if (k === 'options') {
        params.append('options', JSON.stringify(v));
      } else if (v !== undefined && v !== null) {
        params.append(k, String(v));
      }
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  deletePoll: async (id: number | string) => {
    const params = new URLSearchParams();
    params.append('action', 'delete_poll');
    params.append('id', String(id));
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchPollResults: async (pollId?: number | string) => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_poll_results');
    if (pollId) params.append('poll_id', String(pollId));
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Sessions & Tokens
  fetchActiveSessions: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_active_sessions');
    const res = await apiClient.post('', params);
    return res.data;
  },

  revokeSession: async (tokenOrId: number | string) => {
    const params = new URLSearchParams();
    params.append('action', 'revoke_session');
    if (typeof tokenOrId === 'number' || !isNaN(Number(tokenOrId))) {
      params.append('id', String(tokenOrId));
    } else {
      params.append('token', String(tokenOrId));
    }
    const res = await apiClient.post('', params);
    return res.data;
  },

  revokeBulkTokens: async (tokens: string[]) => {
    const params = new URLSearchParams();
    params.append('action', 'revoke_bulk_tokens');
    params.append('tokens', JSON.stringify(tokens));
    const res = await apiClient.post('', params);
    return res.data;
  },

  revokeAllSessions: async () => {
    const params = new URLSearchParams();
    params.append('action', 'revoke_all_sessions');
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchGlobalTokenSettings: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_global_token_settings');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveGlobalTokenSettings: async (maxTokens: number) => {
    const params = new URLSearchParams();
    params.append('action', 'save_global_token_settings');
    params.append('global_max_tokens', String(maxTokens));
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Training & Quizzes
  fetchQuizzes: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_quizzes');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveQuiz: async (data: Partial<QuizItem>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_quiz');
    Object.entries(data).forEach(([k, v]) => {
      if (k === 'options') {
        params.append('options', JSON.stringify(v));
      } else if (v !== undefined && v !== null) {
        params.append(k, String(v));
      }
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  deleteQuiz: async (id: number | string) => {
    const params = new URLSearchParams();
    params.append('action', 'delete_quiz');
    params.append('id', String(id));
    const res = await apiClient.post('', params);
    return res.data;
  },

  // GPS Tracking & Trips (Matching admin_attendance.php)
  fetchGpsTrips: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_gps_trips');
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchTripHistory: async (dateFrom?: string, dateTo?: string, search?: string, status?: string) => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_trip_history');
    if (dateFrom) params.append('date_from', dateFrom);
    if (dateTo) params.append('date_to', dateTo);
    if (search) params.append('employee_filter', search);
    if (status) params.append('status', status);
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchTripLocations: async (tripId: number) => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_trip_locations');
    params.append('trip_id', String(tripId));
    const res = await apiClient.post('', params);
    return res.data;
  },

  endTrip: async (tripId: number) => {
    const params = new URLSearchParams();
    params.append('action', 'admin_end_trip');
    params.append('trip_id', String(tripId));
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchTrackingCustomers: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_tracking_customers');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveTrackingCustomer: async (data: Partial<TrackingCustomerItem>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_tracking_customer');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) params.append(k, String(v));
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  deleteTrackingCustomer: async (id: number) => {
    const params = new URLSearchParams();
    params.append('action', 'delete_tracking_customer');
    params.append('id', String(id));
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Payroll
  fetchPayroll: async (month?: number, year?: number) => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_payroll_records');
    if (month) params.append('month', String(month));
    if (year) params.append('year', String(year));
    const res = await apiClient.post('', params);
    return res.data;
  },

  savePayroll: async (data: Partial<PayrollItem>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_payroll_record');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) params.append(k, String(v));
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  calculatePayroll: async (month?: number, year?: number) => {
    const params = new URLSearchParams();
    params.append('action', 'calculate_payroll');
    if (month) params.append('month', String(month));
    if (year) params.append('year', String(year));
    const res = await apiClient.post('', params);
    return res.data;
  },

  paySalarySingle: async (data: { employee_id: string; base_salary: number; present_days: number; calculated_salary: number; month: number; year: number }) => {
    const params = new URLSearchParams();
    params.append('action', 'pay_salary');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) params.append(k, String(v));
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchPayrollConfigs: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_payroll_configs');
    const res = await apiClient.post('', params);
    return res.data;
  },

  savePayrollConfig: async (data: FormData | Record<string, any>) => {
    if (data instanceof FormData) {
      data.append('action', 'save_payroll_config');
      const res = await apiClient.post('', data, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      return res.data;
    }
    const params = new URLSearchParams();
    params.append('action', 'save_payroll_config');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) params.append(k, String(v));
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchPayrollAdjustments: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_payroll_adjustments');
    const res = await apiClient.post('', params);
    return res.data;
  },

  savePayrollDeduction: async (data: any) => {
    const params = new URLSearchParams();
    params.append('action', 'save_payroll_deduction');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) params.append(k, String(v));
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  savePayrollOt: async (data: any) => {
    const params = new URLSearchParams();
    params.append('action', 'save_payroll_ot');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) params.append(k, String(v));
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  savePayrollLoan: async (data: any) => {
    const params = new URLSearchParams();
    params.append('action', 'save_payroll_loan');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) params.append(k, String(v));
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchPayrollHistory: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_payroll_history');
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Notifications & Schedules & Templates
  fetchNotifications: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_notifications');
    const res = await apiClient.post('', params);
    return res.data;
  },

  sendNotification: async (data: FormData | { title: string; message: string; target_type?: string; target_roles?: string[] | string; target_users?: string[] | string; expiry_date?: string; image_url?: string; [key: string]: any }) => {
    if (data instanceof FormData) {
      data.append('action', 'send_notification');
      const res = await apiClient.post('', data, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      return res.data;
    }
    const params = new URLSearchParams();
    params.append('action', 'send_notification');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) {
        if (Array.isArray(v) || typeof v === 'object') params.append(k, JSON.stringify(v));
        else params.append(k, String(v));
      }
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  deleteNotification: async (id: number | string) => {
    const params = new URLSearchParams();
    params.append('action', 'delete_notification');
    params.append('id', String(id));
    const res = await apiClient.post('', params);
    return res.data;
  },

  bulkDeleteNotifications: async (ids: number[]) => {
    const params = new URLSearchParams();
    params.append('action', 'bulk_delete_notifications');
    params.append('ids', JSON.stringify(ids));
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Notification Templates
  fetchNotificationTemplates: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_notification_templates');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveNotificationTemplate: async (data: Partial<NotificationTemplate> | Record<string, any>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_notification_template');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) {
        if (Array.isArray(v) || typeof v === 'object') params.append(k, JSON.stringify(v));
        else params.append(k, String(v));
      }
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  deleteNotificationTemplate: async (id: number | string) => {
    const params = new URLSearchParams();
    params.append('action', 'delete_notification_template');
    params.append('id', String(id));
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Notification Schedules
  fetchNotificationSchedules: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_notification_schedules');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveNotificationSchedule: async (data: Partial<NotificationSchedule> | Record<string, any>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_notification_schedule');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) {
        if (Array.isArray(v) || typeof v === 'object') params.append(k, JSON.stringify(v));
        else params.append(k, String(v));
      }
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  toggleNotificationSchedule: async (id: number | string) => {
    const params = new URLSearchParams();
    params.append('action', 'toggle_notification_schedule');
    params.append('id', String(id));
    const res = await apiClient.post('', params);
    return res.data;
  },

  deleteNotificationSchedule: async (id: number | string) => {
    const params = new URLSearchParams();
    params.append('action', 'delete_notification_schedule');
    params.append('id', String(id));
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchNotificationRecipients: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_notification_recipients');
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Work Rules / Shift Schedule
  getTimeRules: async (userId: string) => {
    const params = new URLSearchParams();
    params.append('action', 'get_time_rules');
    params.append('user_id', userId);
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveTimeRules: async (employeeId: string, rules: any[]) => {
    const params = new URLSearchParams();
    params.append('action', 'save_time_rules');
    params.append('rule_employee_id', employeeId);
    params.append('rules_json', JSON.stringify(rules));
    const res = await apiClient.post('', params);
    return res.data;
  },

  copyTimeRules: async (fromUserId: string, toUserId: string) => {
    const params = new URLSearchParams();
    params.append('action', 'copy_time_rules');
    params.append('from_user_id', fromUserId);
    params.append('to_user_id', toUserId);
    const res = await apiClient.post('', params);
    return res.data;
  },


  // Themes
  fetchThemes: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_themes');
    const res = await apiClient.post('', params);
    return res.data;
  },

  setActiveTheme: async (themeId: string) => {
    const params = new URLSearchParams();
    params.append('action', 'set_active_theme');
    params.append('theme_id', themeId);
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveTheme: async (themeData: Record<string, any>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_theme');
    Object.entries(themeData).forEach(([k, v]) => params.append(k, String(v)));
    const res = await apiClient.post('', params);
    return res.data;
  },

  deleteTheme: async (themeId: string) => {
    const params = new URLSearchParams();
    params.append('action', 'delete_theme');
    params.append('theme_id', themeId);
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Panel & General Settings
  fetchSettings: async () => {
    const params = new URLSearchParams();
    params.append('action', 'get_panel_settings');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveSettings: async (settings: Record<string, string>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_panel_settings');
    Object.entries(settings).forEach(([k, v]) => params.append(k, v));
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Login Page Settings
  fetchLoginPageSettings: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_login_page_settings');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveLoginPageSettings: async (settings: Record<string, string>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_login_page_settings');
    Object.entries(settings).forEach(([k, v]) => params.append(k, v));
    const res = await apiClient.post('', params);
    return res.data;
  },

  // App Scan & Mobile Settings
  fetchAppScanSettings: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_app_scan_settings');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveAppScanSettings: async (settings: Record<string, string>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_app_scan_settings');
    Object.entries(settings).forEach(([k, v]) => params.append(k, v));
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchScanHistory: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_scan_history');
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchPayrollBiometricRecords: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_payroll_biometric_records');
    const res = await apiClient.post('', params);
    return res.data;
  },

  deletePayrollBiometricRecord: async (recordId: number) => {
    const params = new URLSearchParams();
    params.append('action', 'delete_payroll_biometric_record');
    params.append('record_id', String(recordId));
    const res = await apiClient.post('', params);
    return res.data;
  },

  clearPayrollBiometricRecords: async () => {
    const params = new URLSearchParams();
    params.append('action', 'clear_payroll_biometric_records');
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Menu Settings
  fetchMenuSettings: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_menu_settings');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveMenuSettings: async (menuText: Record<string, string>, menuOrder: Record<string, number>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_menu_settings');
    Object.entries(menuText).forEach(([k, v]) => params.append(`menu_text[${k}]`, v));
    Object.entries(menuOrder).forEach(([k, v]) => params.append(`menu_order[${k}]`, String(v)));
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Audit Logs
  fetchAuditLogs: async (filterParams?: {
    search?: string;
    module?: string;
    severity?: string;
    action_filter?: string;
    start_date?: string;
    end_date?: string;
    page?: number;
    limit?: number;
  }) => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_audit_logs');
    if (filterParams?.search) params.append('search', filterParams.search);
    if (filterParams?.module) params.append('module', filterParams.module);
    if (filterParams?.severity) params.append('severity', filterParams.severity);
    if (filterParams?.action_filter) params.append('action_filter', filterParams.action_filter);
    if (filterParams?.start_date) params.append('start_date', filterParams.start_date);
    if (filterParams?.end_date) params.append('end_date', filterParams.end_date);
    if (filterParams?.page) params.append('page', String(filterParams.page));
    if (filterParams?.limit) params.append('limit', String(filterParams.limit));
    const res = await apiClient.post('', params);
    return res.data;
  },

  clearAuditLogs: async (olderThanDays = 90, adminName = 'Admin') => {
    const params = new URLSearchParams();
    params.append('action', 'clear_audit_logs');
    params.append('older_than_days', String(olderThanDays));
    params.append('admin_name', adminName);
    const res = await apiClient.post('', params);
    return res.data;
  },

  logCustomAudit: async (data: {
    log_action: string;
    module: string;
    target_name?: string;
    details?: any;
    severity?: 'info' | 'warning' | 'danger' | 'critical';
    actor_name?: string;
    actor_id?: string;
    actor_role?: string;
  }) => {
    const params = new URLSearchParams();
    params.append('action', 'log_custom_audit');
    params.append('log_action', data.log_action);
    params.append('module', data.module);
    if (data.target_name) params.append('target_name', data.target_name);
    if (data.details) params.append('details', typeof data.details === 'object' ? JSON.stringify(data.details) : String(data.details));
    if (data.severity) params.append('severity', data.severity);
    if (data.actor_name) params.append('actor_name', data.actor_name);
    if (data.actor_id) params.append('actor_id', data.actor_id);
    if (data.actor_role) params.append('actor_role', data.actor_role);
    const res = await apiClient.post('', params);
    return res.data;
  },

  // IP Blocklist Management
  blockIp: async (ip: string, reason = 'Suspicious Activity', adminName = 'Super Admin') => {
    const params = new URLSearchParams();
    params.append('action', 'block_ip');
    params.append('ip_address', ip);
    params.append('reason', reason);
    params.append('admin_name', adminName);
    const res = await apiClient.post('', params);
    return res.data;
  },

  unblockIp: async (ip: string, adminName = 'Super Admin') => {
    const params = new URLSearchParams();
    params.append('action', 'unblock_ip');
    params.append('ip_address', ip);
    params.append('admin_name', adminName);
    const res = await apiClient.post('', params);
    return res.data;
  },

  fetchBlockedIps: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_blocked_ips');
    const res = await apiClient.post('', params);
    return res.data;
  },
};

export interface AuditLog {
  id: number;
  actor_id?: string;
  actor_name: string;
  actor_role?: string;
  action: string;
  module: string;
  target_id?: string;
  target_name?: string;
  details?: string;
  severity: 'info' | 'warning' | 'danger' | 'critical';
  ip_address?: string;
  user_agent?: string;
  created_at: string;
}

export interface BlockedIp {
  id: number;
  ip_address: string;
  reason?: string;
  blocked_by?: string;
  created_at: string;
}

export interface AuditLogStats {
  total_logs: number;
  today_count: number;
  warning_count: number;
  danger_count: number;
  top_actors: { actor_name: string; count: number }[];
  module_breakdown: { module: string; count: number }[];
}



