const API_BASE = 'http://localhost:8000';

// Contraseña en memoria de sesión (necesaria para descifrar llave privada)
let _sessionPassword = null;

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

export function saveSession(data, password) {
  localStorage.setItem('access_token', data.access_token);
  localStorage.setItem('refresh_token', data.refresh_token);
  localStorage.setItem('session_user', JSON.stringify(data.user));
  // encrypted_private_key: salt:nonce:ciphertext — necesario para descifrar mensajes
  if (data.encrypted_private_key) {
    sessionStorage.setItem('encrypted_private_key', data.encrypted_private_key);
  }
  // encrypted_ecdsa_private_key: salt:nonce:ciphertext — necesario para firmar mensajes
  if (data.encrypted_ecdsa_private_key) {
    sessionStorage.setItem('encrypted_ecdsa_private_key', data.encrypted_ecdsa_private_key);
  }
  const expiresAt = Date.now() + data.expires_in * 1000;
  localStorage.setItem('expires_at', String(expiresAt));
  // Guardar contraseña en memoria (no en storage) para derivar llave privada
  if (password) _sessionPassword = password;
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

export function getEncryptedPrivateKey() {
  return sessionStorage.getItem('encrypted_private_key');
}

export function getEncryptedECDSAPrivateKey() {
  return sessionStorage.getItem('encrypted_ecdsa_private_key');
}

/** Retorna la contraseña en memoria (para derivar llave privada). Puede ser null. */
export function getSessionPassword() {
  return _sessionPassword;
}

export function clearTokens() {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('session_user');
  localStorage.removeItem('expires_at');
  sessionStorage.removeItem('encrypted_private_key');
  sessionStorage.removeItem('encrypted_ecdsa_private_key');
  _sessionPassword = null;
}
