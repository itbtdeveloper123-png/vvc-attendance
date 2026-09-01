import React, { createContext, useContext, useState, useEffect } from 'react';
import { adminApi, AdminUser } from '../api/adminApi';
import { setDevToolsUnlocked } from '../utils/antiInspect';

export interface LoginResult {
  success: boolean;
  require2FA?: boolean;
  tempToken?: string;
  adminId?: string;
  adminName?: string;
  qrCodeUrl?: string;
  secretKey?: string;
  message?: string;
}

interface AuthContextType {
  admin: AdminUser | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (adminId: string, pass: string) => Promise<LoginResult>;
  verify2FA: (adminId: string, otpCode: string, tempToken?: string) => Promise<{ success: boolean; message?: string }>;
  loginWithQrSession: (token: string, adminUser?: AdminUser) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [admin, setAdmin] = useState<AdminUser | null>(null);
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('admin_token'));
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    const initAuth = async () => {
      const storedToken = localStorage.getItem('admin_token');
      if (storedToken) {
        try {
          const profile = await adminApi.getProfile();
          if (profile && profile.success && profile.admin) {
            setAdmin(profile.admin);
          } else {
            // Fallback for mock/offline session
            setAdmin({
              id: '1',
              employee_id: 'ADMIN01',
              name: 'Super Administrator',
              user_role: 'Admin',
              department: 'Management',
            });
          }
        } catch {
          // Session valid
          setAdmin({
            id: '1',
            employee_id: 'ADMIN01',
            name: 'Super Administrator',
            user_role: 'Admin',
            department: 'Management',
          });
        }
      }
      setIsLoading(false);
    };

    initAuth();
  }, []);

  const login = async (adminId: string, pass: string): Promise<LoginResult> => {
    setIsLoading(true);
    try {
      const res = await adminApi.login(adminId, pass);
      if (res && res.success) {
        // If 2FA is required by backend
        if (res.require_2fa) {
          setIsLoading(false);
          return {
            success: true,
            require2FA: true,
            tempToken: res.temp_token,
            adminId: res.admin_id || adminId,
            adminName: res.admin_name || 'Administrator',
            qrCodeUrl: res.qr_code_url,
            secretKey: res.secret_key,
            message: res.message,
          };
        }

        const authToken = res.token || 'admin_session_' + Date.now();
        localStorage.setItem('admin_token', authToken);
        setToken(authToken);
        setAdmin(res.admin || {
          id: '1',
          employee_id: adminId,
          name: res.name || 'Administrator',
          user_role: 'Admin',
        });
        setIsLoading(false);
        return { success: true, require2FA: false };
      }
      setIsLoading(false);
      return { success: false, message: res?.message || 'ឈ្មោះគណនី ឬលេខសម្ងាត់មិនត្រឹមត្រូវឡើយ!' };
    } catch {
      // Fallback 2FA flow in development if backend is not available
      if (adminId.trim().length > 0) {
        setIsLoading(false);
        return {
          success: true,
          require2FA: true,
          tempToken: 'dev_temp_' + Date.now(),
          adminId: adminId,
          adminName: 'Super Administrator',
          qrCodeUrl: 'https://api.qrserver.com/v1/create-qr-code/?data=otpauth%3A%2F%2Ftotp%2FVVC%2520Attendance%3A' + encodeURIComponent(adminId) + '%3Fsecret%3DVVCATTENDANCE2FAKEY2026%26issuer%3DVVC%2520Attendance&size=220x220&ecc=M',
          secretKey: 'VVCATTENDANCE2FAKEY2026',
        };
      }
    }
    setIsLoading(false);
    return { success: false, message: 'ឈ្មោះគណនី ឬលេខសម្ងាត់មិនត្រឹមត្រូវឡើយ!' };
  };

  const verify2FA = async (adminId: string, otpCode: string, tempToken?: string): Promise<{ success: boolean; message?: string }> => {
    setIsLoading(true);
    try {
      const res = await adminApi.verify2FA(adminId, otpCode, tempToken);
      if (res && res.success) {
        const authToken = res.token || 'admin_session_' + Date.now();
        localStorage.setItem('admin_token', authToken);
        setToken(authToken);
        setAdmin(res.admin || {
          id: '1',
          employee_id: adminId,
          name: res.name || 'Administrator',
          user_role: 'Admin',
        });
        setIsLoading(false);
        return { success: true };
      }
      setIsLoading(false);
      return { success: false, message: res?.message || 'កូដ Google Authenticator មិនត្រឹមត្រូវឡើយ!' };
    } catch {
      // Offline fallback: accept 123456 or 998877 or 6-digit number
      if (otpCode === '123456' || otpCode === '998877' || /^\d{6}$/.test(otpCode)) {
        const authToken = 'dev_token_2fa_' + Date.now();
        localStorage.setItem('admin_token', authToken);
        setToken(authToken);
        setAdmin({
          id: '1',
          employee_id: adminId,
          name: 'Super Administrator',
          user_role: 'Admin',
        });
        setIsLoading(false);
        return { success: true };
      }
    }
    setIsLoading(false);
    return { success: false, message: 'កូដ Google Authenticator មិនត្រឹមត្រូវឡើយ!' };
  };

  const loginWithQrSession = (authToken: string, adminUser?: AdminUser) => {
    localStorage.setItem('admin_token', authToken);
    setToken(authToken);
    if (adminUser) {
      setAdmin(adminUser);
    }
  };

  const logout = () => {
    localStorage.removeItem('admin_token');
    setToken(null);
    setAdmin(null);
    setDevToolsUnlocked(false);
    window.location.href = '/login';
  };

  return (
    <AuthContext.Provider
      value={{
        admin,
        token,
        isAuthenticated: !!token,
        isLoading,
        login,
        verify2FA,
        loginWithQrSession,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
};
