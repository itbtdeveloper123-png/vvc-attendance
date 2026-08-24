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
  today_good: number;
  today_late: number;
  pending_requests: number;
  today_scans?: any[];
}

export type DashboardSummary = DashboardStats;

export interface AttendanceRecord {
  id: number | string;
  employee_id: string;
  name: string;
  action: string;
  status: 'Good' | 'Late' | 'Absent';
  log_time: string;
  workplace: string;
  late_reason?: string;
  location_raw?: string;
  photo?: string;
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
  address: string;
  latitude: number;
  longitude: number;
  radius_meters: number;
  qr_secret: string;
}

export interface CategoryItem {
  id: number;
  name: string;
  code: string;
  description?: string;
  item_count?: number;
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
  date: string;
  duration: string;
  summary: string;
  hasAudio?: boolean;
  audio_url?: string;
}

export interface PollOption {
  text: string;
  votes: number;
  percentage: number;
}

export interface PollItem {
  id: number;
  title: string;
  creator?: string;
  status: 'Active' | 'Closed';
  total_votes: number;
  ends_at: string;
  options: PollOption[];
}

export interface SessionItem {
  id: number;
  employee_id: string;
  name: string;
  device: string;
  ip_address: string;
  last_used: string;
  status: string;
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
  driver_name: string;
  employee_id: string;
  vehicle: string;
  destination: string;
  current_location: string;
  speed: string;
  status: string;
  started_at: string;
}

export interface PayrollItem {
  id: number;
  employee_id: string;
  name: string;
  base_salary: number;
  ot_hours: number;
  ot_amount: number;
  deductions: number;
  net_salary: number;
  status: 'Paid' | 'Pending';
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
  // Authentication
  login: async (adminId: string, password: string) => {
    const params = new URLSearchParams();
    params.append('action', 'admin_login');
    params.append('admin_id', adminId);
    params.append('password', password);
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

  // Attendance Records
  fetchAttendance: async (page = 1, limit = 50, filters?: { date?: string; department?: string; status?: string; search?: string }) => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_attendance_records');
    params.append('page', String(page));
    params.append('limit', String(limit));
    if (filters?.date) params.append('date', filters.date);
    if (filters?.department) params.append('department', filters.department);
    if (filters?.status) params.append('status', filters.status);
    if (filters?.search) params.append('search', filters.search);
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

  // Locations
  fetchLocations: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_locations');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveLocation: async (data: Partial<LocationItem>) => {
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

  // Categories
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

  // Stock Items
  fetchStockItems: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_stock_items');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveStockItem: async (data: Partial<StockItem>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_stock_item');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) params.append(k, String(v));
    });
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

  // Meetings
  fetchMeetings: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_meetings');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveMeeting: async (data: Partial<MeetingItem>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_meeting');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) params.append(k, String(v));
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

  // Sessions & Tokens
  fetchActiveSessions: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_active_sessions');
    const res = await apiClient.post('', params);
    return res.data;
  },

  revokeSession: async (id: number | string) => {
    const params = new URLSearchParams();
    params.append('action', 'revoke_session');
    params.append('id', String(id));
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

  // GPS Tracking
  fetchGpsTrips: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_gps_trips');
    const res = await apiClient.post('', params);
    return res.data;
  },

  saveGpsTrip: async (data: Partial<GpsTripItem>) => {
    const params = new URLSearchParams();
    params.append('action', 'save_gps_trip');
    Object.entries(data).forEach(([k, v]) => {
      if (v !== undefined && v !== null) params.append(k, String(v));
    });
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Payroll
  fetchPayroll: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_payroll_records');
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

  calculatePayroll: async () => {
    const params = new URLSearchParams();
    params.append('action', 'calculate_payroll');
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Notifications & Banners
  fetchNotifications: async () => {
    const params = new URLSearchParams();
    params.append('action', 'fetch_notifications');
    const res = await apiClient.post('', params);
    return res.data;
  },

  sendNotification: async (title: string, message: string, targetType: string, targetInfo?: string, imageUrl?: string) => {
    const params = new URLSearchParams();
    params.append('action', 'send_admin_notification');
    params.append('title', title);
    params.append('message', message);
    params.append('recipient_type', targetType);
    if (targetInfo) params.append('recipient_info', targetInfo);
    if (imageUrl) params.append('image_url', imageUrl);
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

  // Global Token Settings
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
};


