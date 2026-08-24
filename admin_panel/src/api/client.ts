import axios from 'axios';

// Live PHP API Gateway endpoint
const LIVE_API_URL = 'https://app.vvc.asia/flutter/admin_api.php';

// In development, prefer Vite proxy '/admin_api.php' to avoid CORS issues, or use direct live URL
const BASE_URL = import.meta.env.DEV ? '/admin_api.php' : (import.meta.env.VITE_API_URL || LIVE_API_URL);

export const apiClient = axios.create({
  baseURL: BASE_URL,
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

// Response Interceptor: Global error & auth handling with automatic live fallback
apiClient.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    // If proxy failed, retry directly with live URL
    const originalRequest = error.config;
    if (originalRequest && !originalRequest._retry && (error.code === 'ERR_NETWORK' || error.response?.status === 404)) {
      originalRequest._retry = true;
      originalRequest.baseURL = LIVE_API_URL;
      return axios(originalRequest);
    }

    if (error.response && error.response.status === 401) {
      localStorage.removeItem('admin_token');
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);
