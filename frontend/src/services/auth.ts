import axios from 'axios';

const API_BASE = 'http://127.0.0.1:8000';

export interface LoginResponse {
  token: string;
  role: 'admin' | 'user';
  username: string;
}

export const login = async (username: string, password: string): Promise<LoginResponse> => {
  const response = await axios.post(`${API_BASE}/api/auth/login`, {
    username,
    password,
  });
  return response.data;
};

export const logout = () => {
  localStorage.removeItem('phantom_token');
  localStorage.removeItem('phantom_user_role');
  localStorage.removeItem('phantom_username');
};

export const getStoredUser = () => {
  const token = localStorage.getItem('phantom_token');
  const role = localStorage.getItem('phantom_user_role');
  const username = localStorage.getItem('phantom_username');
  if (token && role) {
    return { token, role: role as 'admin' | 'user', username };
  }
  return null;
};
