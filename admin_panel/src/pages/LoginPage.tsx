import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lock, User, ShieldCheck, ArrowRight, Sparkles } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const LoginPage: React.FC = () => {
  const [adminId, setAdminId] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!adminId.trim() || !password.trim()) {
      setError('សូមបញ្ចូលឈ្មោះគណនី និងលេខសម្ងាត់!');
      return;
    }
    setError('');
    setLoading(true);
    const ok = await login(adminId, password);
    setLoading(false);
    if (ok) {
      navigate('/dashboard');
    } else {
      setError('ឈ្មោះគណនី ឬលេខសម្ងាត់មិនត្រឹមត្រូវឡើយ!');
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'radial-gradient(circle at 50% 20%, #1e1b4b 0%, #090d16 100%)',
        padding: '20px',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Glow Orbs */}
      <div
        style={{
          position: 'absolute',
          top: '20%',
          left: '15%',
          width: '350px',
          height: '350px',
          background: 'rgba(79, 70, 229, 0.15)',
          borderRadius: '50%',
          filter: 'blur(90px)',
          pointerEvents: 'none',
        }}
      />
      <div
        style={{
          position: 'absolute',
          bottom: '15%',
          right: '15%',
          width: '300px',
          height: '300px',
          background: 'rgba(212, 175, 55, 0.12)',
          borderRadius: '50%',
          filter: 'blur(80px)',
          pointerEvents: 'none',
        }}
      />

      <div
        style={{
          maxWidth: '440px',
          width: '100%',
          background: 'rgba(15, 23, 42, 0.85)',
          backdropFilter: 'blur(16px)',
          WebkitBackdropFilter: 'blur(16px)',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          borderRadius: '24px',
          padding: '40px 36px',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
          position: 'relative',
          zIndex: 10,
        }}
      >
        {/* Logo & Header */}
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <div
            style={{
              width: '64px',
              height: '64px',
              borderRadius: '16px',
              background: 'linear-gradient(135deg, #d4af37 0%, #b8860b 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 18px',
              boxShadow: '0 4px 20px rgba(212, 175, 55, 0.35)',
            }}
          >
            <ShieldCheck size={36} color="#1a1500" />
          </div>
          <h1
            style={{
              fontSize: '22px',
              fontWeight: 800,
              color: '#ffffff',
              letterSpacing: '0.3px',
              marginBottom: '6px',
            }}
          >
            VVC ATTENDANCE
          </h1>
          <p style={{ fontSize: '13px', color: '#94a3b8' }}>
            ផ្ទាំងគ្រប់គ្រងប្រព័ន្ធធនធានមនុស្ស & វត្តមាន
          </p>
        </div>

        {error && (
          <div
            style={{
              padding: '12px 16px',
              borderRadius: '10px',
              background: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              color: '#f87171',
              fontSize: '13px',
              marginBottom: '20px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
            }}
          >
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label" style={{ color: '#cbd5e1' }}>
              ឈ្មោះគណនី (Admin ID / Email)
            </label>
            <div style={{ position: 'relative' }}>
              <User
                size={18}
                style={{
                  position: 'absolute',
                  top: '12px',
                  left: '14px',
                  color: '#64748b',
                }}
              />
              <input
                type="text"
                className="form-input"
                placeholder="ឧ. admin"
                value={adminId}
                onChange={(e) => setAdminId(e.target.value)}
                style={{
                  paddingLeft: '44px',
                  background: 'rgba(30, 41, 59, 0.7)',
                  borderColor: '#334155',
                  color: '#ffffff',
                }}
              />
            </div>
          </div>

          <div className="form-group" style={{ marginBottom: '28px' }}>
            <label className="form-label" style={{ color: '#cbd5e1' }}>
              លេខសម្ងាត់ (Password)
            </label>
            <div style={{ position: 'relative' }}>
              <Lock
                size={18}
                style={{
                  position: 'absolute',
                  top: '12px',
                  left: '14px',
                  color: '#64748b',
                }}
              />
              <input
                type="password"
                className="form-input"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                style={{
                  paddingLeft: '44px',
                  background: 'rgba(30, 41, 59, 0.7)',
                  borderColor: '#334155',
                  color: '#ffffff',
                }}
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn btn-gold"
            style={{ width: '100%', padding: '13px', fontSize: '15px' }}
          >
            {loading ? (
              <span>កំពុងផ្ទៀងផ្ទាត់...</span>
            ) : (
              <>
                <span>ចូលប្រើប្រាស់</span>
                <ArrowRight size={18} />
              </>
            )}
          </button>
        </form>

        <div
          style={{
            marginTop: '28px',
            textAlign: 'center',
            fontSize: '11.5px',
            color: '#64748b',
          }}
        >
          © 2026 VVC Asia. All rights reserved. Ultra-Fast React Admin.
        </div>
      </div>
    </div>
  );
};
