import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';

import { api } from '../lib/api';
import { getToken } from '../lib/auth';

export function RequireAuth(props: { children: ReactNode }) {
  const token = getToken();
  const [ok, setOk] = useState<boolean | null>(null);

  useEffect(() => {
    if (!token) return;
    api
      .me()
      .then(() => setOk(true))
      .catch(() => setOk(false));
  }, [token]);

  if (!token) return <Navigate to="/login" replace />;
  if (ok === null) return <div className="card">Checking session…</div>;
  if (ok === false) return <Navigate to="/login" replace />;
  return <>{props.children}</>;
}


