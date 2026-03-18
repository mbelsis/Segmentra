import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { api } from '../lib/api';
import { getToken, setToken } from '../lib/auth';

export function LoginPage() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const token = getToken();
    if (!token) return;
    api
      .me()
      .then(() => navigate('/', { replace: true }))
      .catch(() => undefined);
  }, [navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const r = await api.login(username, password);
      setToken(r.token);
      navigate('/', { replace: true });
    } catch (e: any) {
      setError(String(e?.message ?? e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'linear-gradient(145deg, #3d2e1e 0%, #5c4633 40%, #78644e 100%)',
      padding: '20px',
      position: 'relative',
      overflow: 'hidden'
    }}>
      {/* Subtle texture overlay */}
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: 'radial-gradient(ellipse at 30% 20%, rgba(139, 105, 20, 0.15) 0%, transparent 60%), radial-gradient(ellipse at 70% 80%, rgba(90, 122, 58, 0.1) 0%, transparent 50%)',
        pointerEvents: 'none'
      }} />

      <div style={{
        width: '100%',
        maxWidth: '440px',
        background: '#fdfcf9',
        borderRadius: '16px',
        boxShadow: '0 24px 80px rgba(41, 32, 24, 0.5), 0 8px 24px rgba(41, 32, 24, 0.3)',
        padding: '48px',
        position: 'relative',
        zIndex: 1,
        border: '1px solid rgba(232, 224, 212, 0.5)'
      }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <img
            src="/segmentra.png"
            alt="Segmentra"
            style={{
              maxWidth: '240px',
              height: 'auto',
              marginBottom: '8px'
            }}
          />
          <h1 style={{
            margin: '16px 0 8px 0',
            fontSize: '26px',
            fontWeight: '700',
            color: '#292018',
            letterSpacing: '-0.5px'
          }}>
            Welcome Back
          </h1>
          <p style={{
            margin: 0,
            fontSize: '14px',
            color: '#78644e',
            fontWeight: '400'
          }}>
            Sign in to continue to Segmentra
          </p>
        </div>

        {/* Login Form */}
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div>
            <label style={{
              display: 'block',
              marginBottom: '8px',
              fontSize: '13px',
              fontWeight: '600',
              color: '#5c4633',
              letterSpacing: '0.01em'
            }}>
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter your username"
              required
              disabled={loading}
              style={{
                width: '100%',
                padding: '12px 16px',
                fontSize: '14px',
                border: '1.5px solid #d4c9b8',
                borderRadius: '10px',
                transition: 'all 0.15s',
                boxSizing: 'border-box',
                outline: 'none',
                fontFamily: 'inherit',
                background: '#fff',
                color: '#3d2e1e'
              }}
              onFocus={(e) => {
                e.target.style.borderColor = '#8b6914';
                e.target.style.boxShadow = '0 0 0 3px rgba(139, 105, 20, 0.12)';
              }}
              onBlur={(e) => {
                e.target.style.borderColor = '#d4c9b8';
                e.target.style.boxShadow = 'none';
              }}
            />
          </div>

          <div>
            <label style={{
              display: 'block',
              marginBottom: '8px',
              fontSize: '13px',
              fontWeight: '600',
              color: '#5c4633',
              letterSpacing: '0.01em'
            }}>
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
              required
              disabled={loading}
              style={{
                width: '100%',
                padding: '12px 16px',
                fontSize: '14px',
                border: '1.5px solid #d4c9b8',
                borderRadius: '10px',
                transition: 'all 0.15s',
                boxSizing: 'border-box',
                outline: 'none',
                fontFamily: 'inherit',
                background: '#fff',
                color: '#3d2e1e'
              }}
              onFocus={(e) => {
                e.target.style.borderColor = '#8b6914';
                e.target.style.boxShadow = '0 0 0 3px rgba(139, 105, 20, 0.12)';
              }}
              onBlur={(e) => {
                e.target.style.borderColor = '#d4c9b8';
                e.target.style.boxShadow = 'none';
              }}
            />
          </div>

          {error && (
            <div style={{
              padding: '12px 16px',
              background: '#faf0ee',
              border: '1px solid #e8c4bf',
              borderRadius: '8px',
              color: '#a63d2f',
              fontSize: '13.5px',
              borderLeft: '4px solid #a63d2f'
            }}>
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading || !username || !password}
            style={{
              width: '100%',
              padding: '13px',
              fontSize: '15px',
              fontWeight: '600',
              color: '#fdfcf9',
              background: loading ? '#b8a890' : '#8b6914',
              border: 'none',
              borderRadius: '10px',
              cursor: loading || !username || !password ? 'not-allowed' : 'pointer',
              transition: 'all 0.15s',
              boxShadow: loading || !username || !password ? 'none' : '0 4px 12px rgba(139, 105, 20, 0.3)',
              opacity: loading || !username || !password ? 0.6 : 1,
              fontFamily: 'inherit',
              letterSpacing: '0.01em'
            }}
            onMouseEnter={(e) => {
              if (!loading && username && password) {
                e.currentTarget.style.background = '#725710';
                e.currentTarget.style.boxShadow = '0 6px 20px rgba(139, 105, 20, 0.4)';
              }
            }}
            onMouseLeave={(e) => {
              if (!loading && username && password) {
                e.currentTarget.style.background = '#8b6914';
                e.currentTarget.style.boxShadow = '0 4px 12px rgba(139, 105, 20, 0.3)';
              }
            }}
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>

        {/* Footer */}
        <div style={{
          marginTop: '28px',
          paddingTop: '20px',
          borderTop: '1px solid #e8e0d4',
          fontSize: '12px',
          color: '#97846c',
          textAlign: 'center'
        }}>
          <div style={{ marginBottom: '8px' }}>
            Already have a token?{' '}
            <a
              href="/"
              onClick={(e) => {
                e.preventDefault();
                navigate('/');
              }}
              style={{
                color: '#8b6914',
                textDecoration: 'none',
                fontWeight: '600'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.textDecoration = 'underline';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.textDecoration = 'none';
              }}
            >
              Go to Dashboard
            </a>
          </div>
          <div style={{ fontSize: '11px', color: '#b8a890' }}>
            Segmentra Fleet Firewall Management
          </div>
        </div>
      </div>
    </div>
  );
}
