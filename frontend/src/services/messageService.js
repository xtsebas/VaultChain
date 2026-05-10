/**
 * messageService.js — llamadas a la API de mensajería y grupos.
 * El cifrado/descifrado ocurre en cryptoService.js, no aquí.
 */

import { log, LOG_TYPES } from './cryptoLog';
import { getToken } from './authService';

const { NETWORK, SUCCESS, ERROR } = LOG_TYPES;
const API = 'http://localhost:8000';

function authHeaders() {
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${getToken()}`,
  };
}

/** Lista todos los usuarios registrados. */
export async function listUsers() {
  log(NETWORK, 'GET /auth/users/ — obteniendo lista de usuarios…');
  const res = await fetch(`${API}/auth/users/`);
  if (!res.ok) throw new Error('Error al obtener usuarios');
  const data = await res.json();
  log(SUCCESS, `${data.users.length} usuario(s) encontrado(s)`);
  return data.users;
}

/** Obtiene la llave pública PEM de un usuario. */
export async function getUserPublicKey(userId) {
  log(NETWORK, `GET /auth/users/${userId.slice(0, 8)}…/key`);
  const res = await fetch(`${API}/auth/users/${userId}/key`);
  if (!res.ok) throw new Error('Usuario no encontrado');
  const pem = await res.text();
  log(SUCCESS, 'Llave pública PEM recibida', `${pem.length} chars`);
  return pem;
}

/**
 * Envía un mensaje directo ya cifrado por el cliente.
 * @param {string} recipientId
 * @param {{ ciphertext, encrypted_key, nonce, auth_tag }} encryptedPayload
 */
export async function sendDirectMessage(recipientId, encryptedPayload) {
  log(NETWORK, `POST /messages/ → destinatario ${recipientId.slice(0, 8)}…`);
  const res = await fetch(`${API}/messages/`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ recipient_id: recipientId, ...encryptedPayload }),
  });
  const data = await res.json();
  if (!res.ok) throw { status: res.status, data };
  log(SUCCESS, `Mensaje almacenado en servidor — id: ${data.id?.slice(0, 8)}…`);
  return data;
}

/**
 * Envía un mensaje grupal ya cifrado por el cliente.
 * @param {string} groupId
 * @param {{ ciphertext, nonce, auth_tag, encrypted_keys }} groupPayload
 */
export async function sendGroupMessage(groupId, groupPayload) {
  log(NETWORK, `POST /messages/ → grupo ${groupId.slice(0, 8)}…`);
  const res = await fetch(`${API}/messages/`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ group_id: groupId, ...groupPayload }),
  });
  const data = await res.json();
  if (!res.ok) throw { status: res.status, data };
  log(SUCCESS, `Mensaje grupal almacenado — ${data.message_count} copias`);
  return data;
}

/** Obtiene los mensajes recibidos del usuario autenticado. */
export async function getMyMessages(userId) {
  log(NETWORK, `GET /messages/${userId.slice(0, 8)}… — obteniendo bandeja…`);
  const res = await fetch(`${API}/messages/${userId}`, { headers: authHeaders() });
  const data = await res.json();
  if (!res.ok) throw { status: res.status, data };
  log(SUCCESS, `${data.messages.length} mensaje(s) en bandeja`);
  return data.messages;
}

/** Crea un grupo con los miembros dados. */
export async function createGroup(name, memberIds) {
  log(NETWORK, `POST /groups/ — creando grupo "${name}"…`);
  const res = await fetch(`${API}/groups/`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ name, member_ids: memberIds }),
  });
  const data = await res.json();
  if (!res.ok) throw { status: res.status, data };
  log(SUCCESS, `Grupo creado — id: ${data.id?.slice(0, 8)}…, ${data.members.length} miembro(s)`);
  return data;
}

/** Obtiene info de un grupo (incluyendo public_key de cada miembro). */
export async function getGroup(groupId) {
  log(NETWORK, `GET /groups/${groupId.slice(0, 8)}…`);
  const res = await fetch(`${API}/groups/${groupId}`, { headers: authHeaders() });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Grupo no encontrado');
  return data;
}
