const API_BASE = 'http://localhost:8000';

export async function register({ email, display_name, password }) {
  const res = await fetch(`${API_BASE}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, display_name, password }),
  });
  const data = await res.json();
  if (!res.ok) throw { status: res.status, data };
  return data;
}

export async function login({ email, password }) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const data = await res.json();
  if (!res.ok) throw { status: res.status, data };
  return data;
}

export function saveSession(data) {
  localStorage.setItem('access_token', data.access_token);
  localStorage.setItem('refresh_token', data.refresh_token);
  localStorage.setItem('session_user', JSON.stringify(data.user));
  const expiresAt = Date.now() + data.expires_in * 1000;
  localStorage.setItem('expires_at', String(expiresAt));
}

export function getToken() {
  return localStorage.getItem('access_token');
}

export function getSessionUser() {
  const raw = localStorage.getItem('session_user');
  return raw ? JSON.parse(raw) : null;
}

export function getExpiresAt() {
  return Number(localStorage.getItem('expires_at') || 0);
}

export function clearTokens() {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('session_user');
  localStorage.removeItem('expires_at');
}
