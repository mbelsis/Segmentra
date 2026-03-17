import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { api } from './api';
import { getToken } from './auth';

interface AuthState {
  username: string;
  roles: string[];
  loading: boolean;
  refresh: () => void;
}

const AuthContext = createContext<AuthState>({ username: '', roles: [], loading: true, refresh: () => {} });

export function useAuth() {
  return useContext(AuthContext);
}

export function hasRole(roles: string[], ...required: string[]): boolean {
  return required.some(r => roles.includes(r));
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{ username: string; roles: string[]; loading: boolean }>({ username: '', roles: [], loading: true });
  const [refreshCounter, setRefreshCounter] = useState(0);

  const refresh = useCallback(() => {
    setRefreshCounter(c => c + 1);
  }, []);

  useEffect(() => {
    const token = getToken();
    if (!token) {
      setState({ username: '', roles: [], loading: false });
      return;
    }
    setState(prev => ({ ...prev, loading: true }));
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
  }, [refreshCounter]);

  // Also listen for storage changes (in case token is set by another tab or by login)
  useEffect(() => {
    const onStorage = () => refresh();
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, [refresh]);

  // Poll for token changes (catches same-tab login since storage event doesn't fire for same tab)
  useEffect(() => {
    let lastToken = getToken();
    const interval = setInterval(() => {
      const currentToken = getToken();
      if (currentToken !== lastToken) {
        lastToken = currentToken;
        refresh();
      }
    }, 500);
    return () => clearInterval(interval);
  }, [refresh]);

  return <AuthContext.Provider value={{ ...state, refresh }}>{children}</AuthContext.Provider>;
}
