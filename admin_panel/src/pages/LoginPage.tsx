import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Lock,
  User,
  ShieldCheck,
  ArrowRight,
  ArrowLeft,
  Eye,
  EyeOff,
  AlertCircle,
  Server,
  Zap,
  Smartphone,
  QrCode,
  Copy,
  Check,
  X,
  KeyRound,
  RefreshCw,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { adminApi } from '../api/adminApi';

export const LoginPage: React.FC = () => {
  // Step: 'credentials' | '2fa'
  const [step, setStep] = useState<'credentials' | '2fa'>('credentials');

  // Step 1 Form States
  const [adminId, setAdminId] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [inputFocused, setInputFocused] = useState<'admin' | 'pass' | null>(null);

  // Step 2 2FA States
  const [otpDigits, setOtpDigits] = useState<string[]>(['', '', '', '', '', '']);
  const [tempToken, setTempToken] = useState('');
  const [adminName, setAdminName] = useState('');
  const [qrCodeUrl, setQrCodeUrl] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [showQrModal, setShowQrModal] = useState(false);
  const [copiedKey, setCopiedKey] = useState(false);
  const [totpSecondsLeft, setTotpSecondsLeft] = useState(30);

  // Common States
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const { login, verify2FA } = useAuth();
  const navigate = useNavigate();
  const otpInputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // 30-Second TOTP Window Countdown Timer
  useEffect(() => {
    const updateCountdown = () => {
      const now = Math.floor(Date.now() / 1000);
      const remaining = 30 - (now % 30);
      setTotpSecondsLeft(remaining);
    };
    updateCountdown();
    const timer = setInterval(updateCountdown, 1000);
    return () => clearInterval(timer);
  }, []);

  // Step 1: Submit Credentials
  const handleCredentialsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!adminId.trim() || !password.trim()) {
      setError('សូមបញ្ចូលឈ្មោះគណនី និងលេខសម្ងាត់!');
      return;
    }
    setError('');
    setLoading(true);
    const result = await login(adminId.trim(), password);
    setLoading(false);

    if (result.success) {
      if (result.require2FA) {
        setTempToken(result.tempToken || '');
        setAdminName(result.adminName || 'Admin');
        setQrCodeUrl(result.qrCodeUrl || '');
        setSecretKey(result.secretKey || 'VVCATTENDANCE2FAKEY2026');
        setStep('2fa');
        setError('');
        setOtpDigits(['', '', '', '', '', '']);
        setTimeout(() => {
          otpInputRefs.current[0]?.focus();
        }, 150);
      } else {
        navigate('/dashboard');
      }
    } else {
      setError(result.message || 'ឈ្មោះគណនី ឬលេខសម្ងាត់មិនត្រឹមត្រូវឡើយ!');
    }
  };

  // Step 2: Handle 2FA OTP Input Changes
  const handleOtpChange = (index: number, value: string) => {
    const cleaned = value.replace(/\D/g, '');
    if (!cleaned) {
      const newDigits = [...otpDigits];
      newDigits[index] = '';
      setOtpDigits(newDigits);
      return;
    }

    const digit = cleaned.slice(-1);
    const newDigits = [...otpDigits];
    newDigits[index] = digit;
    setOtpDigits(newDigits);

    // Auto advance to next box
    if (index < 5 && digit) {
      otpInputRefs.current[index + 1]?.focus();
    }

    // Auto submit if all 6 digits are entered
    const fullCode = newDigits.join('');
    if (fullCode.length === 6 && !newDigits.includes('')) {
      handleVerifyOtp(fullCode);
    }
  };

  const handleOtpKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !otpDigits[index] && index > 0) {
      otpInputRefs.current[index - 1]?.focus();
    }
  };

  const handleOtpPaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
    if (pastedData.length > 0) {
      const newDigits = ['', '', '', '', '', ''];
      for (let i = 0; i < pastedData.length; i++) {
        newDigits[i] = pastedData[i];
      }
      setOtpDigits(newDigits);
      const nextIndex = Math.min(pastedData.length, 5);
      otpInputRefs.current[nextIndex]?.focus();

      if (pastedData.length === 6) {
        handleVerifyOtp(pastedData);
      }
    }
  };

  // Verify OTP
  const handleVerifyOtp = async (codeToVerify?: string) => {
    const code = codeToVerify || otpDigits.join('');
    if (code.length !== 6) {
      setError('សូមបញ្ចូលកូដ ៦ ខ្ទង់ឱ្យបានពេញលេញ!');
      return;
    }
    setError('');
    setLoading(true);
    const res = await verify2FA(adminId.trim() || 'ADMIN01', code, tempToken);
    setLoading(false);

    if (res.success) {
      navigate('/dashboard');
    } else {
      setError(res.message || 'កូដ Google Authenticator មិនត្រឹមត្រូវឡើយ!');
      setOtpDigits(['', '', '', '', '', '']);
      otpInputRefs.current[0]?.focus();
    }
  };

  const [loadingQr, setLoadingQr] = useState(false);

  const handleOpenQrModal = async () => {
    setShowQrModal(true);
    if (!secretKey || !qrCodeUrl) {
      setLoadingQr(true);
      try {
        const res = await adminApi.get2FASetup(adminId.trim() || 'ADMIN01');
        if (res && res.success) {
          if (res.secret_key) setSecretKey(res.secret_key);
          if (res.qr_code_url) setQrCodeUrl(res.qr_code_url);
        }
      } catch (err) {
        console.warn('Failed to load 2FA setup details from server:', err);
      } finally {
        setLoadingQr(false);
      }
    }
  };

  const handleCopySecretKey = () => {
    const keyToCopy = secretKey || 'VVCATTENDANCE2FAKEY2026';
    navigator.clipboard.writeText(keyToCopy);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2500);
  };

  const currentSecret = secretKey || 'VVCATTENDANCE2FAKEY2026';
  const currentIssuer = 'VVC Attendance';
  const currentAccount = adminName || adminId || 'Super Administrator';
  const otpauthUri = `otpauth://totp/${encodeURIComponent(currentIssuer)}:${encodeURIComponent(currentAccount)}?secret=${currentSecret}&issuer=${encodeURIComponent(currentIssuer)}`;
  const displayQrUrl = qrCodeUrl || `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(otpauthUri)}&size=240x240&ecc=M`;
  const fallbackQrUrl = `https://chart.googleapis.com/chart?chs=240x240&chld=M|0&cht=qr&chl=${encodeURIComponent(otpauthUri)}`;

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'radial-gradient(ellipse at 50% -20%, #1e1b4b 0%, #090d16 55%, #040711 100%)',
        padding: '24px 16px',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Background Grid Pattern */}
      <div
        className="login-bg-grid"
        style={{
          position: 'absolute',
          inset: 0,
          pointerEvents: 'none',
          zIndex: 1,
        }}
      />

      {/* Dynamic Ambient Glowing Orbs */}
      <div
        style={{
          position: 'absolute',
          top: '12%',
          left: '18%',
          width: '420px',
          height: '420px',
          background: 'radial-gradient(circle, rgba(79, 70, 229, 0.22) 0%, rgba(99, 102, 241, 0.05) 60%, transparent 80%)',
          borderRadius: '50%',
          filter: 'blur(70px)',
          animation: 'floatSlow1 12s ease-in-out infinite',
          pointerEvents: 'none',
          zIndex: 1,
        }}
      />
      <div
        style={{
          position: 'absolute',
          bottom: '10%',
          right: '16%',
          width: '380px',
          height: '380px',
          background: 'radial-gradient(circle, rgba(212, 175, 55, 0.18) 0%, rgba(245, 158, 11, 0.04) 60%, transparent 80%)',
          borderRadius: '50%',
          filter: 'blur(65px)',
          animation: 'floatSlow2 14s ease-in-out infinite',
          pointerEvents: 'none',
          zIndex: 1,
        }}
      />
      <div
        style={{
          position: 'absolute',
          top: '45%',
          right: '25%',
          width: '280px',
          height: '280px',
          background: 'radial-gradient(circle, rgba(6, 182, 212, 0.12) 0%, transparent 75%)',
          borderRadius: '50%',
          filter: 'blur(60px)',
          animation: 'floatSlow3 10s ease-in-out infinite',
          pointerEvents: 'none',
          zIndex: 1,
        }}
      />

      {/* Main Glassmorphic Card Container */}
      <div
        className="login-glass-card"
        style={{
          maxWidth: step === '2fa' ? '480px' : '460px',
          width: '100%',
          borderRadius: '26px',
          padding: '42px 36px 36px',
          position: 'relative',
          zIndex: 10,
          transition: 'all 0.3s ease',
        }}
      >
        {/* Top Status Pill */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            marginBottom: '24px',
          }}
        >
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '7px',
              padding: '5px 14px',
              borderRadius: '9999px',
              background: 'rgba(255, 255, 255, 0.06)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              fontSize: '11px',
              fontWeight: 600,
              color: '#94a3b8',
              letterSpacing: '0.4px',
            }}
          >
            <span
              style={{
                width: '7px',
                height: '7px',
                borderRadius: '50%',
                background: step === '2fa' ? '#06b6d4' : '#10b981',
                boxShadow: step === '2fa' ? '0 0 8px #06b6d4' : '0 0 8px #10b981',
                display: 'inline-block',
              }}
            />
            <span>
              {step === '2fa'
                ? '🔒 2FA AUTHENTICATION REQUIRED'
                : 'ប្រព័ន្ធដំណើរការសុវត្ថិភាព • VVC HRM 2.6'}
            </span>
          </div>
        </div>

        {/* Header Icon & Title */}
        {step === 'credentials' ? (
          <div style={{ textAlign: 'center', marginBottom: '28px' }}>
            <div
              style={{
                width: '72px',
                height: '72px',
                borderRadius: '20px',
                background: 'linear-gradient(145deg, #fce074 0%, #d4af37 50%, #996515 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 16px',
                boxShadow: '0 8px 25px rgba(212, 175, 55, 0.4), inset 0 2px 4px rgba(255, 255, 255, 0.6)',
                animation: 'pulseGlowRing 3.5s infinite',
                position: 'relative',
              }}
            >
              <ShieldCheck size={40} color="#151100" strokeWidth={2.4} />
            </div>

            <h1
              style={{
                fontSize: '24px',
                fontWeight: 800,
                letterSpacing: '0.8px',
                marginBottom: '6px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '6px',
              }}
            >
              <span className="gold-text-gradient">VVC</span>
              <span style={{ color: '#ffffff' }}>ATTENDANCE</span>
            </h1>
            <p style={{ fontSize: '13px', color: '#94a3b8', lineHeight: 1.5, fontWeight: 400 }}>
              ផ្ទាំងគ្រប់គ្រងប្រព័ន្ធធនធានមនុស្ស & វត្តមានបុគ្គលិក
            </p>
          </div>
        ) : (
          <div style={{ textAlign: 'center', marginBottom: '24px' }}>
            <div
              style={{
                width: '70px',
                height: '70px',
                borderRadius: '20px',
                background: 'linear-gradient(135deg, #06b6d4 0%, #3b82f6 50%, #6366f1 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 16px',
                boxShadow: '0 8px 25px rgba(6, 182, 212, 0.4), inset 0 2px 4px rgba(255, 255, 255, 0.5)',
              }}
            >
              <Smartphone size={36} color="#ffffff" strokeWidth={2.2} />
            </div>

            <h1
              style={{
                fontSize: '21px',
                fontWeight: 800,
                color: '#ffffff',
                marginBottom: '6px',
                letterSpacing: '0.3px',
              }}
            >
              ផ្ទៀងផ្ទាត់សុវត្ថិភាព ២ ជាន់ (2FA)
            </h1>
            <p style={{ fontSize: '12.5px', color: '#94a3b8', lineHeight: 1.5 }}>
              សូមបញ្ចូលកូដ ៦ ខ្ទង់ពីកម្មវិធី <strong style={{ color: '#38bdf8' }}>Google Authenticator</strong>
            </p>
          </div>
        )}

        {/* Error Alert Box */}
        {error && (
          <div
            style={{
              padding: '12px 16px',
              borderRadius: '14px',
              background: 'rgba(239, 68, 68, 0.12)',
              border: '1px solid rgba(239, 68, 68, 0.35)',
              color: '#fca5a5',
              fontSize: '13px',
              marginBottom: '22px',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              animation: 'shakeError 0.4s ease',
              boxShadow: '0 4px 14px rgba(239, 68, 68, 0.1)',
            }}
          >
            <AlertCircle size={18} color="#ef4444" style={{ flexShrink: 0 }} />
            <span style={{ fontWeight: 500 }}>{error}</span>
          </div>
        )}

        {/* STEP 1: CREDENTIALS FORM */}
        {step === 'credentials' ? (
          <form onSubmit={handleCredentialsSubmit}>
            {/* Admin ID / Email */}
            <div style={{ marginBottom: '18px' }}>
              <label
                style={{
                  display: 'block',
                  fontSize: '12.5px',
                  fontWeight: 600,
                  color: inputFocused === 'admin' ? '#d4af37' : '#cbd5e1',
                  marginBottom: '7px',
                  transition: 'color 0.2s ease',
                }}
              >
                ឈ្មោះគណនី (Admin ID / Email)
              </label>
              <div className="login-input-wrapper">
                <User
                  size={18}
                  style={{
                    position: 'absolute',
                    top: '14px',
                    left: '15px',
                    color: inputFocused === 'admin' ? '#d4af37' : '#64748b',
                    transition: 'color 0.2s ease',
                  }}
                />
                <input
                  type="text"
                  className="login-input-field"
                  placeholder="ឧ. admin ឬ អ៊ីមែលអ្នកគ្រប់គ្រង"
                  value={adminId}
                  onChange={(e) => setAdminId(e.target.value)}
                  onFocus={() => setInputFocused('admin')}
                  onBlur={() => setInputFocused(null)}
                  autoComplete="username"
                />
              </div>
            </div>

            {/* Password */}
            <div style={{ marginBottom: '18px' }}>
              <label
                style={{
                  display: 'block',
                  fontSize: '12.5px',
                  fontWeight: 600,
                  color: inputFocused === 'pass' ? '#d4af37' : '#cbd5e1',
                  marginBottom: '7px',
                  transition: 'color 0.2s ease',
                }}
              >
                លេខសម្ងាត់ (Password)
              </label>
              <div className="login-input-wrapper">
                <Lock
                  size={18}
                  style={{
                    position: 'absolute',
                    top: '14px',
                    left: '15px',
                    color: inputFocused === 'pass' ? '#d4af37' : '#64748b',
                    transition: 'color 0.2s ease',
                  }}
                />
                <input
                  type={showPassword ? 'text' : 'password'}
                  className="login-input-field"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onFocus={() => setInputFocused('pass')}
                  onBlur={() => setInputFocused(null)}
                  autoComplete="current-password"
                  style={{ paddingRight: '46px' }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{
                    position: 'absolute',
                    top: '12px',
                    right: '14px',
                    background: 'none',
                    border: 'none',
                    color: showPassword ? '#d4af37' : '#64748b',
                    cursor: 'pointer',
                    padding: '2px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    transition: 'color 0.2s ease',
                  }}
                  title={showPassword ? 'លាក់លេខសម្ងាត់' : 'បង្ហាញលេខសម្ងាត់'}
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            {/* Remember Me */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'flex-start',
                marginBottom: '26px',
                fontSize: '12.5px',
              }}
            >
              <label
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  cursor: 'pointer',
                  color: '#94a3b8',
                  userSelect: 'none',
                }}
              >
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  style={{
                    accentColor: '#d4af37',
                    width: '15px',
                    height: '15px',
                    borderRadius: '4px',
                    cursor: 'pointer',
                  }}
                />
                <span>ចងចាំការចូលប្រើ</span>
              </label>
            </div>

            {/* Submit Button */}
            <button type="submit" disabled={loading} className="btn-login-gold">
              {loading ? (
                <>
                  <div
                    style={{
                      width: '18px',
                      height: '18px',
                      border: '2.5px solid rgba(21, 17, 0, 0.3)',
                      borderTopColor: '#151100',
                      borderRadius: '50%',
                      animation: 'spinSlow 0.8s linear infinite',
                    }}
                  />
                  <span>កំពុងផ្ទៀងផ្ទាត់សុវត្ថិភាព...</span>
                </>
              ) : (
                <>
                  <span>បន្តទៅផ្ទៀងផ្ទាត់ 2FA</span>
                  <ArrowRight size={19} strokeWidth={2.5} />
                </>
              )}
            </button>
          </form>
        ) : (
          /* STEP 2: 2FA GOOGLE AUTHENTICATOR STEP */
          <div>
            {/* 6-Digit OTP Box Grid */}
            <div className="otp-input-group">
              {otpDigits.map((digit, idx) => (
                <input
                  key={idx}
                  ref={(el) => (otpInputRefs.current[idx] = el)}
                  type="text"
                  inputMode="numeric"
                  maxLength={1}
                  value={digit}
                  className={`otp-box ${digit ? 'filled' : ''}`}
                  onChange={(e) => handleOtpChange(idx, e.target.value)}
                  onKeyDown={(e) => handleOtpKeyDown(idx, e)}
                  onPaste={handleOtpPaste}
                />
              ))}
            </div>

            {/* 30-Second Countdown Indicator */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                fontSize: '11.5px',
                color: totpSecondsLeft <= 5 ? '#f87171' : '#94a3b8',
                marginBottom: '22px',
                fontWeight: 500,
              }}
            >
              <RefreshCw
                size={13}
                style={{
                  animation: 'spinSlow 4s linear infinite',
                  color: totpSecondsLeft <= 5 ? '#ef4444' : '#38bdf8',
                }}
              />
              <span>
                កូដនឹងផ្លាស់ប្តូរក្នុងរយៈពេល៖ <strong>{totpSecondsLeft} វិនាទី</strong>
              </span>
            </div>

            {/* Verify 2FA Button */}
            <button
              type="button"
              disabled={loading}
              onClick={() => handleVerifyOtp()}
              className="btn-login-gold"
              style={{
                background: 'linear-gradient(135deg, #38bdf8 0%, #0284c7 50%, #0369a1 100%)',
                color: '#ffffff',
                boxShadow: '0 4px 20px rgba(2, 132, 199, 0.35)',
                marginBottom: '16px',
              }}
            >
              {loading ? (
                <>
                  <div
                    style={{
                      width: '18px',
                      height: '18px',
                      border: '2.5px solid rgba(255, 255, 255, 0.3)',
                      borderTopColor: '#ffffff',
                      borderRadius: '50%',
                      animation: 'spinSlow 0.8s linear infinite',
                    }}
                  />
                  <span>កំពុងផ្ទៀងផ្ទាត់ 2FA...</span>
                </>
              ) : (
                <>
                  <ShieldCheck size={19} strokeWidth={2.4} />
                  <span>ផ្ទៀងផ្ទាត់ និងចូលប្រើប្រាស់</span>
                </>
              )}
            </button>

            {/* Actions: Setup QR Code & Back */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '12.5px',
                paddingTop: '6px',
              }}
            >
              <button
                type="button"
                onClick={() => {
                  setStep('credentials');
                  setError('');
                }}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#94a3b8',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '5px',
                  padding: '4px 0',
                  transition: 'color 0.2s ease',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.color = '#ffffff')}
                onMouseLeave={(e) => (e.currentTarget.style.color = '#94a3b8')}
              >
                <ArrowLeft size={15} />
                <span>ត្រឡប់ក្រោយ</span>
              </button>

              <button
                type="button"
                onClick={handleOpenQrModal}
                style={{
                  background: 'rgba(56, 189, 248, 0.12)',
                  border: '1px solid rgba(56, 189, 248, 0.35)',
                  borderRadius: '10px',
                  color: '#38bdf8',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '7px 14px',
                  fontSize: '12px',
                  fontWeight: 600,
                  transition: 'all 0.2s ease',
                  boxShadow: '0 2px 8px rgba(56, 189, 248, 0.15)',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = 'rgba(56, 189, 248, 0.25)';
                  e.currentTarget.style.borderColor = '#38bdf8';
                  e.currentTarget.style.transform = 'translateY(-1px)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = 'rgba(56, 189, 248, 0.12)';
                  e.currentTarget.style.borderColor = 'rgba(56, 189, 248, 0.35)';
                  e.currentTarget.style.transform = 'translateY(0)';
                }}
              >
                <QrCode size={15} />
                <span>ស្កេន QR Code រៀបចំ 2FA</span>
              </button>
            </div>
          </div>
        )}

        {/* Security Badges */}
        <div
          style={{
            marginTop: '28px',
            paddingTop: '20px',
            borderTop: '1px solid rgba(255, 255, 255, 0.07)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-around',
            fontSize: '11px',
            color: '#64748b',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
            <Zap size={13} color="#eab308" />
            <span>2FA TOTP RFC 6238</span>
          </div>
          <div style={{ width: '3px', height: '3px', borderRadius: '50%', background: '#334155' }} />
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
            <ShieldCheck size={13} color="#10b981" />
            <span>256-Bit SSL</span>
          </div>
          <div style={{ width: '3px', height: '3px', borderRadius: '50%', background: '#334155' }} />
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
            <Server size={13} color="#6366f1" />
            <span>Cloud Guard</span>
          </div>
        </div>

        {/* Copyright */}
        <div
          style={{
            marginTop: '16px',
            textAlign: 'center',
            fontSize: '11px',
            color: '#475569',
            letterSpacing: '0.2px',
          }}
        >
          © 2026 VVC Asia. All rights reserved. Ultra-Fast React Admin.
        </div>
      </div>

      {/* QR Code Setup Modal (High z-index fixed overlay) */}
      {showQrModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 999999,
            backgroundColor: 'rgba(2, 6, 23, 0.88)',
            backdropFilter: 'blur(12px)',
            WebkitBackdropFilter: 'blur(12px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '20px',
            animation: 'fadeIn 0.2s ease',
          }}
          onClick={() => setShowQrModal(false)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              maxWidth: '440px',
              width: '100%',
              maxHeight: '92vh',
              overflowY: 'auto',
              padding: '28px',
              background: '#0f172a',
              border: '1px solid rgba(56, 189, 248, 0.35)',
              borderRadius: '24px',
              boxShadow: '0 25px 65px rgba(0, 0, 0, 0.85), 0 0 35px rgba(56, 189, 248, 0.15)',
              color: '#ffffff',
            }}
          >
            {/* Modal Header */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '18px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div
                  style={{
                    width: '40px',
                    height: '40px',
                    borderRadius: '12px',
                    background: 'rgba(6, 182, 212, 0.18)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    border: '1px solid rgba(56, 189, 248, 0.3)',
                  }}
                >
                  <QrCode size={22} color="#38bdf8" />
                </div>
                <div>
                  <h3 style={{ fontSize: '16.5px', fontWeight: 700, color: '#ffffff', margin: 0 }}>
                    រៀបចំ Google Authenticator / 2FA
                  </h3>
                  <p style={{ fontSize: '11.5px', color: '#94a3b8', margin: '2px 0 0' }}>
                    ស្កេនជាមួយ App VVC ឬ Google Authenticator
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowQrModal(false)}
                style={{
                  background: 'rgba(255, 255, 255, 0.08)',
                  border: 'none',
                  borderRadius: '50%',
                  width: '32px',
                  height: '32px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#94a3b8',
                  cursor: 'pointer',
                  transition: 'background 0.2s ease',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(255, 255, 255, 0.15)')}
                onMouseLeave={(e) => (e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)')}
              >
                <X size={17} />
              </button>
            </div>

            {/* QR Code Container */}
            <div
              style={{
                background: '#ffffff',
                borderRadius: '18px',
                padding: '16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 18px',
                width: '220px',
                height: '220px',
                boxShadow: '0 10px 30px rgba(0, 0, 0, 0.4)',
                position: 'relative',
              }}
            >
              {loadingQr ? (
                <div style={{ textAlign: 'center', color: '#0f172a', fontSize: '12px' }}>
                  <RefreshCw size={24} className="spin-animation" style={{ color: '#0284c7', margin: '0 auto 8px' }} />
                  <div>កំពុងផ្ទុក QR Code...</div>
                </div>
              ) : (
                <img
                  src={displayQrUrl}
                  alt="2FA QR Code"
                  onError={(e) => {
                    if (e.currentTarget.src !== fallbackQrUrl) {
                      e.currentTarget.src = fallbackQrUrl;
                    }
                  }}
                  style={{ width: '100%', height: '100%', objectFit: 'contain' }}
                />
              )}
            </div>

            {/* Secret Key Box */}
            <div style={{ marginBottom: '18px' }}>
              <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '6px' }}>
                ឬវាយបញ្ចូលកូដ Secret Key ដោយផ្ទាល់៖
              </label>
              <div
                style={{
                  background: 'rgba(30, 41, 59, 0.9)',
                  border: '1px solid rgba(56, 189, 248, 0.25)',
                  borderRadius: '12px',
                  padding: '10px 14px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '8px',
                }}
              >
                <span
                  style={{
                    fontFamily: 'monospace',
                    fontSize: '13px',
                    letterSpacing: '1.2px',
                    color: '#38bdf8',
                    fontWeight: 700,
                    wordBreak: 'break-all',
                  }}
                >
                  {currentSecret}
                </span>
                <button
                  type="button"
                  onClick={handleCopySecretKey}
                  style={{
                    background: copiedKey ? '#10b981' : 'rgba(56, 189, 248, 0.15)',
                    border: '1px solid rgba(56, 189, 248, 0.3)',
                    borderRadius: '8px',
                    padding: '6px 10px',
                    color: '#ffffff',
                    cursor: 'pointer',
                    fontSize: '11.5px',
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    flexShrink: 0,
                    transition: 'all 0.2s ease',
                  }}
                >
                  {copiedKey ? <Check size={13} color="#ffffff" /> : <Copy size={13} color="#38bdf8" />}
                  <span>{copiedKey ? 'ចម្លងរួច' : 'Copy'}</span>
                </button>
              </div>
            </div>

            {/* Steps Instructions */}
            <div
              style={{
                fontSize: '12px',
                color: '#cbd5e1',
                lineHeight: 1.65,
                background: 'rgba(15, 23, 42, 0.7)',
                borderRadius: '14px',
                padding: '12px 16px',
                border: '1px solid rgba(255, 255, 255, 0.07)',
                marginBottom: '20px',
              }}
            >
              <ol style={{ paddingLeft: '18px', margin: 0 }}>
                <li>បើក <strong>VVC Attendance App</strong> (មុខងារ 2FA) ឬ <strong>Google Authenticator</strong></li>
                <li>ចុចសញ្ញា <strong style={{ color: '#38bdf8' }}>+</strong> រួចជ្រើសរើស <strong>ស្កេន QR Code</strong></li>
                <li>ស្កេនរូប QR ខាងលើ រួចយកកូដ ៦ ខ្ទង់មកបំពេញដើម្បី Login ភ្លាមៗ</li>
              </ol>
            </div>

            <button
              type="button"
              onClick={() => setShowQrModal(false)}
              style={{
                width: '100%',
                borderRadius: '12px',
                padding: '12px',
                background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
                border: 'none',
                color: '#ffffff',
                fontWeight: 700,
                fontSize: '13.5px',
                cursor: 'pointer',
                boxShadow: '0 4px 15px rgba(2, 132, 199, 0.3)',
                transition: 'all 0.2s ease',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.filter = 'brightness(1.1)')}
              onMouseLeave={(e) => (e.currentTarget.style.filter = 'brightness(1)')}
            >
              យល់ព្រម និងបន្ត Login
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
