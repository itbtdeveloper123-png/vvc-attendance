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

  updateRequestStatus: async (requestId: string | number, status: 'Approved' | 'Rejected', comment?: string) => {
    const params = new URLSearchParams();
    params.append('action', 'update_request_status');
    params.append('request_id', String(requestId));
    params.append('status', status);
    if (comment) params.append('admin_comment', comment);
    const res = await apiClient.post('', params);
    return res.data;
  },

  // Notifications & Banners
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

  // Settings
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
};

