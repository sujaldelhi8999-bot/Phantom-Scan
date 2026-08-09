import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

export interface LoginResponse {
  token: string;
  role: 'admin' | 'user';
  username: string;
  name?: string | null;
  email?: string | null;
  subscription_tier?: string;
  subscription_status?: string;
}

interface AuthApiResponse {
  token: string;
  user: UserProfile;
}

export interface UserProfile {
  id: string;
  email: string;
  name: string | null;
  role: string;
  subscription_tier: string;
  subscription_status: string;
  created_at: string;
}

const normalizeAuthResponse = (data: AuthApiResponse): LoginResponse => ({
  token: data.token,
  role: data.user.role as 'admin' | 'user',
  username: data.user.email,
  name: data.user.name,
  email: data.user.email,
  subscription_tier: data.user.subscription_tier,
  subscription_status: data.user.subscription_status,
});

export const login = async (email: string, password: string): Promise<LoginResponse> => {
  const response = await axios.post<AuthApiResponse>(`${API_BASE}/api/auth/login`, {
    email,
    password,
  });
  return normalizeAuthResponse(response.data);
};

export const register = async (email: string, password: string, name?: string): Promise<LoginResponse> => {
  const response = await axios.post<AuthApiResponse>(`${API_BASE}/api/auth/register`, {
    email,
    password,
    name: name || undefined,
  });
  return normalizeAuthResponse(response.data);
};

export const loginWithSupabase = async (accessToken: string): Promise<LoginResponse> => {
  const response = await axios.post<AuthApiResponse>(`${API_BASE}/api/auth/supabase`, {
    access_token: accessToken,
  });
  return normalizeAuthResponse(response.data);
};

export const getUserProfile = async (token: string): Promise<UserProfile> => {
  const response = await axios.get(`${API_BASE}/api/auth/me`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  return response.data;
};

export const logout = () => {
  localStorage.removeItem('phantom_token');
  localStorage.removeItem('phantom_user_role');
  localStorage.removeItem('phantom_username');
  localStorage.removeItem('phantom_user_name');
  localStorage.removeItem('phantom_user_email');
  localStorage.removeItem('phantom_subscription_tier');
  localStorage.removeItem('phantom_subscription_status');
};

export const getStoredUser = () => {
  const token = localStorage.getItem('phantom_token');
  const role = localStorage.getItem('phantom_user_role');
  const username = localStorage.getItem('phantom_username');
  const name = localStorage.getItem('phantom_user_name');
  const email = localStorage.getItem('phantom_user_email');
  const subscriptionTier = localStorage.getItem('phantom_subscription_tier');
  const subscriptionStatus = localStorage.getItem('phantom_subscription_status');
  if (token && role) {
    return { token, role: role as 'admin' | 'user', username: username || '', name, email, subscriptionTier, subscriptionStatus };
  }
  return null;
};
