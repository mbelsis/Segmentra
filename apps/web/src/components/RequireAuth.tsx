import { useCallback, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';

import { api, errorMessage, isApiError } from '../lib/api';
import { clearToken, getToken } from '../lib/auth';

type SessionState = { status: 'checking' } | { status: 'ok' } | { status: 'invalid' } | { status: 'error'; message: string };

export function RequireAuth(props: { children: ReactNode }) {
  const token = getToken();
  const location = useLocation();
  const [state, setState] = useState<SessionState>({ status: 'checking' });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    api
      .me()
      .then(() => { if (!cancelled) setState({ status: 'ok' }); })
      .catch((e) => {
        if (cancelled) return;
        // A 401 means the session is invalid (request() normally clears the
        // token already). Anything else (network error, 5xx) says nothing about the
        // session, so keep the token and let the user retry.
        if (isApiError(e) && e.status === 401) {
          clearToken();
          setState({ status: 'invalid' });
        } else {
          setState({ status: 'error', message: errorMessage(e) });
        }
      });
    return () => { cancelled = true; };
  }, [token, attempt]);

  const retry = useCallback(() => {
    setState({ status: 'checking' });
    setAttempt((n) => n + 1);
  }, []);

  const next = `${location.pathname}${location.search}${location.hash}`;
  const loginPath = next && next !== '/' ? `/login?next=${encodeURIComponent(next)}` : '/login';

  if (!token) return <Navigate to={loginPath} replace />;
  if (state.status === 'checking') return <div className="card">Checking session…</div>;
  if (state.status === 'invalid') return <Navigate to={loginPath} replace />;
  if (state.status === 'error') {
    return (
      <div className="card" style={{ maxWidth: 560, margin: '40px auto' }}>
        <h3 style={{ marginTop: 0 }}>Could not reach the Segmentra API</h3>
        <p style={{ color: '#78644e' }}>Your session was not checked: {state.message}</p>
        <button className="btn-primary" onClick={retry}>Retry</button>
      </div>
    );
  }
  return <>{props.children}</>;
}
