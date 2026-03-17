import { createContext, useContext, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { api } from './api';
import { getToken } from './auth';

interface AuthState {
  username: string;
  roles: string[];
  loading: boolean;
}

const AuthContext = createContext<AuthState>({ username: '', roles: [], loading: true });

export function useAuth() {
  return useContext(AuthContext);
}

export function hasRole(roles: string[], ...required: string[]): boolean {
  return required.some(r => roles.includes(r));
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ username: '', roles: [], loading: true });

  useEffect(() => {
    const token = getToken();
    if (!token) {
      setState({ username: '', roles: [], loading: false });
      return;
    }
    api.me()
      .then(res => {
        setState({
          username: res.user?.username || '',
          roles: res.roles || [],
          loading: false,
        });
      })
      .catch(() => {
        setState({ username: '', roles: [], loading: false });
      });
  }, []);

  return <AuthContext.Provider value={state}>{children}</AuthContext.Provider>;
}
