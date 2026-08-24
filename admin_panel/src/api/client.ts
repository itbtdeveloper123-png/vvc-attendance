import axios from 'axios';

// Get base URL for live PHP API gateway
const API_URL = import.meta.env.VITE_API_URL || 'https://app.vvc.asia/flutter/admin_api.php';

export const apiClient = axios.create({
  baseURL: API_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Accept': 'application/json',
  },
});

// Request Interceptor: Attach Bearer token and CSRF header
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('admin_token');
  if (token) {
    config.headers['Authorization'] = `Bearer ${token}`;
  }
  const csrf = localStorage.getItem('csrf_token');
  if (csrf) {
    config.headers['X-CSRF-Token'] = csrf;
  }
  return config;
});

// Response Interceptor: Global error & auth handling
apiClient.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('admin_token');
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);
