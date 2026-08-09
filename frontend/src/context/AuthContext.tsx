import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { getStoredUser, login, loginWithSupabase, logout, getUserProfile, register } from '../services/auth';
import { signInWithProvider, signOutOfSupabase, supabaseConfigured } from '../services/supabase';
import type { Provider } from '@supabase/supabase-js';

export interface PhantomUser {
  id: string;
  username: string;
  email: string | null;
  name: string;
  role: 'admin' | 'user';
  subscriptionTier: 'FREE' | 'PRO';
  subscriptionStatus: 'active' | 'canceled' | 'past_due';
}

interface AuthContextType {
  user: PhantomUser | null;
  loginUser: (email: string, password: string) => Promise<void>;
  registerUser: (email: string, password: string, name?: string) => Promise<void>;
  loginWithProvider: (provider: Provider) => Promise<void>;
  exchangeSupabaseLogin: (accessToken: string) => Promise<void>;
  logoutUser: () => Promise<void>;
  isLoading: boolean;
  supabaseConfigured: boolean;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<PhantomUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();

  const fetchUserProfile = async (token: string) => {
    try {
      const profile = await getUserProfile(token);
      setUser({
        id: profile.id,
        username: profile.email,
        email: profile.email,
        name: profile.name || profile.email,
        role: profile.role as 'admin' | 'user',
        subscriptionTier: profile.subscription_tier as 'FREE' | 'PRO',
        subscriptionStatus: profile.subscription_status as 'active' | 'canceled' | 'past_due',
      });
    } catch (error) {
      console.error('Failed to fetch user profile:', error);
      // On 401 (invalid/expired token), clear the session entirely
      if (axios.isAxiosError(error) && error.response?.status === 401) {
        logout();
        setUser(null);
      } else {
        // For other errors (network, etc.), fall back to stored user
        const stored = getStoredUser();
        if (stored) {
          setUser({
            id: stored.username,
            username: stored.username || 'admin',
            role: stored.role as 'admin' | 'user',
            name: stored.name || stored.username || 'Admin',
            email: stored.email ?? null,
            subscriptionTier: (stored.subscriptionTier || 'FREE') as 'FREE' | 'PRO',
            subscriptionStatus: (stored.subscriptionStatus || 'active') as 'active' | 'canceled' | 'past_due',
          });
        } else {
          setUser(null);
        }
      }
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    const stored = getStoredUser();
    if (stored) {
      const token = stored.token;
      if (token) {
        fetchUserProfile(token);
      } else {
        setUser({
          id: stored.username,
          username: stored.username || 'admin',
          role: stored.role as 'admin' | 'user',
          name: stored.name || stored.username || 'Admin',
          email: stored.email ?? null,
          subscriptionTier: (stored.subscriptionTier || 'FREE') as 'FREE' | 'PRO',
          subscriptionStatus: (stored.subscriptionStatus || 'active') as 'active' | 'canceled' | 'past_due',
        });
        setIsLoading(false);
      }
    } else {
      setIsLoading(false);
    }
  }, []);

  const applySession = (response: { token: string; role: 'admin' | 'user'; username: string; name?: string | null; email?: string | null; subscription_tier?: string; subscription_status?: string }) => {
    const name = response.name || response.username;
    localStorage.setItem('phantom_token', response.token);
    localStorage.setItem('phantom_user_role', response.role);
    localStorage.setItem('phantom_username', response.username);
    localStorage.setItem('phantom_user_name', name);
    localStorage.setItem('phantom_user_email', response.email ?? '');
    localStorage.setItem('phantom_subscription_tier', response.subscription_tier || 'FREE');
    localStorage.setItem('phantom_subscription_status', response.subscription_status || 'active');
    setUser({ 
      id: response.username, 
      username: response.username, 
      role: response.role, 
      name, 
      email: response.email ?? null,
      subscriptionTier: (response.subscription_tier || 'FREE') as 'FREE' | 'PRO',
      subscriptionStatus: (response.subscription_status || 'active') as 'active' | 'canceled' | 'past_due',
    });
  };

  const loginUser = async (email: string, password: string) => {
    const response = await login(email, password);
    applySession(response);
  };

  const registerUser = async (email: string, password: string, name?: string) => {
    const response = await register(email, password, name);
    applySession(response);
  };

  const loginWithProvider = async (provider: Provider) => {
    await signInWithProvider(provider);
  };

  const exchangeSupabaseLogin = async (accessToken: string) => {
    const response = await loginWithSupabase(accessToken);
    applySession(response);
  };

  const logoutUser = async () => {
    logout();
    await signOutOfSupabase();
    setUser(null);
    navigate('/');
  };

  const refreshUser = async () => {
    const token = localStorage.getItem('phantom_token');
    if (token) {
      await fetchUserProfile(token);
    }
  };

  return (
    <AuthContext.Provider
      value={{ user, loginUser, registerUser, loginWithProvider, exchangeSupabaseLogin, logoutUser, isLoading, supabaseConfigured, refreshUser }}
    >
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
