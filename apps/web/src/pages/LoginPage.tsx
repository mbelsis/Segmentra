import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { api } from '../lib/api';
import { setToken } from '../lib/auth';

export function LoginPage() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  return (
    <div className="card" style={{ maxWidth: 420, margin: '40px auto' }}>
      <h2>Login</h2>
      <div style={{ display: 'grid', gap: 8 }}>
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label>
          Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <button
          onClick={async () => {
            setError(null);
            try {
              const r = await api.login(username, password);
              setToken(r.token);
              navigate('/');
            } catch (e: any) {
              setError(String(e?.message ?? e));
            }
          }}
        >
          Login
        </button>
        {error ? <div style={{ color: 'crimson' }}>{error}</div> : null}
        <div style={{ fontSize: 12, opacity: 0.75 }}>
          API base: <code>{(import.meta as any).env?.VITE_API_URL ?? 'http://localhost:8080/api'}</code>
        </div>
      </div>
    </div>
  );
}


