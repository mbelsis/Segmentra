import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';

import { api } from '../lib/api';
import { clearToken, getToken } from '../lib/auth';

export function RequireAuth(props: { children: ReactNode }) {
  const token = getToken();
  const location = useLocation();
  const [ok, setOk] = useState<boolean | null>(null);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    api
      .me()
      .then(() => { if (!cancelled) setOk(true); })
      .catch(() => {
        // Invalid/expired session: drop the token so we don't loop with a stale one.
        clearToken();
        if (!cancelled) setOk(false);
      });
    return () => { cancelled = true; };
  }, [token]);

  const next = `${location.pathname}${location.search}${location.hash}`;
  const loginPath = next && next !== '/' ? `/login?next=${encodeURIComponent(next)}` : '/login';

  if (!token) return <Navigate to={loginPath} replace />;
  if (ok === null) return <div className="card">Checking session…</div>;
  if (ok === false) return <Navigate to={loginPath} replace />;
  return <>{props.children}</>;
}
