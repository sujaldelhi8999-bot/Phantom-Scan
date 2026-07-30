import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { getStoredUser, login, logout } from '../services/auth';

interface AuthContextType {
  user: { username: string; role: 'admin' | 'user' } | null;
  loginUser: (username: string, password: string) => Promise<void>;
  logoutUser: () => void;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<{ username: string; role: 'admin' | 'user' } | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const stored = getStoredUser();
    if (stored) {
      setUser({ username: stored.username || 'admin', role: stored.role as 'admin' | 'user' });
    }
    setIsLoading(false);
  }, []);

  const loginUser = async (username: string, password: string) => {
    const response = await login(username, password);
    localStorage.setItem('phantom_token', response.token);
    localStorage.setItem('phantom_user_role', response.role);
    localStorage.setItem('phantom_username', response.username);
    setUser({ username: response.username, role: response.role });
  };

  const logoutUser = () => {
    logout();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loginUser, logoutUser, isLoading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
