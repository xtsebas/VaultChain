/**
 * cryptoService.js — cifrado/descifrado E2E en el navegador usando Web Crypto API.
 *
 * Compatibilidad con el backend (Python / PyCryptodome + cryptography):
 *  - AES-256-GCM:  nonce 12 bytes, tag 16 bytes (separado del ciphertext en BD)
 *  - RSA-OAEP:     RSA-2048, hash SHA-256
 *  - Protección de llave privada: PBKDF2-SHA256 (600 000 iter) + AES-256-GCM
 */

import { log, LOG_TYPES } from './cryptoLog';

const { INFO, NETWORK, KEY, ENCRYPT, DECRYPT, CRYPTO, SUCCESS, ERROR } = LOG_TYPES;

// ─── helpers de codificación ──────────────────────────────────────────────────

function toB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function fromB64(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function hex(buf, maxBytes = 8) {
  const arr = new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer);
  const slice = Array.from(arr.slice(0, maxBytes))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return arr.length > maxBytes ? `${slice}…` : slice;
}

function stripPem(pem) {
  return pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
}

// ─── importar llave pública RSA (SPKI PEM → CryptoKey) ───────────────────────

export async function importRSAPublicKey(pem) {
  log(CRYPTO, 'Importando llave pública RSA-2048 (SPKI → CryptoKey)…');
  const der = fromB64(stripPem(pem));
  const key = await crypto.subtle.importKey(
    'spki',
    der,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['wrapKey'],
  );
  log(KEY, 'Llave pública RSA importada', `SPKI ${der.length} bytes`);
  return key;
}

// ─── importar llave privada RSA (PKCS8 DER → CryptoKey) ──────────────────────

export async function importRSAPrivateKey(pkcs8DerBytes) {
  log(CRYPTO, 'Importando llave privada RSA-2048 (PKCS8 DER → CryptoKey)…');
  const key = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8DerBytes,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['unwrapKey'],
  );
  log(KEY, 'Llave privada RSA importada');
  return key;
}

// ─── descifrar llave privada almacenada (PBKDF2 + AES-GCM) ──────────────────

/**
 * Dado el valor encrypted_private_key del backend (salt:nonce:ciphertext_b64)
 * y la contraseña del usuario, retorna los bytes DER de la llave privada.
 */
export async function decryptPrivateKey(encryptedPrivKeyStr, password) {
  log(DECRYPT, 'Derivando clave AES desde contraseña (PBKDF2-SHA256, 600 000 iter)…');

  const [saltB64, nonceB64, ctB64] = encryptedPrivKeyStr.split(':');
  const salt       = fromB64(saltB64);
  const nonce      = fromB64(nonceB64);
  const ciphertext = fromB64(ctB64);   // ciphertext || tag (16 bytes al final)

  const passwordKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits'],
  );

  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600_000 },
    passwordKey,
    256,
  );

  log(KEY, 'Clave AES derivada (PBKDF2)', hex(derivedBits));

  const aesKey = await crypto.subtle.importKey(
    'raw',
    derivedBits,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );

  log(DECRYPT, 'Descifrando llave privada con AES-256-GCM…');

  const pkcs8Der = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    aesKey,
    ciphertext,   // Web Crypto espera ciphertext || tag
  );

  log(SUCCESS, 'Llave privada descifrada', `PKCS8 ${pkcs8Der.byteLength} bytes`);
  return pkcs8Der;
}

// ─── cifrado E2E de mensaje individual ───────────────────────────────────────

/**
 * Cifra `plaintext` para un destinatario (E2E):
 *  1. Genera AES-256 efímero
 *  2. Cifra con AES-256-GCM
 *  3. Envuelve la clave AES con RSA-OAEP usando la llave pública del destinatario
 *
 * Retorna { ciphertext, encrypted_key, nonce, auth_tag } en Base64.
 */
export async function encryptMessage(plaintext, recipientPublicKeyPem) {
  log(INFO, `Iniciando cifrado E2E del mensaje (${plaintext.length} chars)…`);

  // 1. Importar llave pública del destinatario
  const rsaPublicKey = await importRSAPublicKey(recipientPublicKeyPem);

  // 2. Generar clave AES-256 efímera
  log(CRYPTO, 'Generando clave AES-256 efímera (os.urandom equivalente)…');
  const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,          // exportable para wrapKey
    ['encrypt'],
  );
  const rawAes = await crypto.subtle.exportKey('raw', aesKey);
  log(KEY, 'Clave AES-256 generada', `${hex(rawAes)} (32 bytes)`);

  // 3. Generar nonce de 12 bytes
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  log(KEY, 'Nonce generado', `${hex(nonce)} (12 bytes)`);

  // 4. Cifrar con AES-256-GCM
  log(ENCRYPT, `Cifrando con AES-256-GCM: "${plaintext.slice(0, 40)}${plaintext.length > 40 ? '…' : ''}"`);
  const enc    = new TextEncoder();
  const result = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    aesKey,
    enc.encode(plaintext),
  );
  // Web Crypto devuelve ciphertext || tag (últimos 16 bytes)
  const resultBytes  = new Uint8Array(result);
  const cipherBytes  = resultBytes.slice(0, -16);
  const authTagBytes = resultBytes.slice(-16);

  log(ENCRYPT, 'Ciphertext producido', `${hex(cipherBytes)} (${cipherBytes.length} bytes)`);
  log(ENCRYPT, 'Auth tag GCM',         `${hex(authTagBytes)} (16 bytes)`);

  // 5. Envolver clave AES con RSA-OAEP/SHA-256
  log(CRYPTO, 'Envolviendo clave AES con RSA-OAEP/SHA-256…');
  const wrappedKeyBuf = await crypto.subtle.wrapKey('raw', aesKey, rsaPublicKey, { name: 'RSA-OAEP' });
  const wrappedKeyBytes = new Uint8Array(wrappedKeyBuf);
  log(KEY, 'Clave AES envuelta con RSA-OAEP', `${hex(wrappedKeyBytes)} (${wrappedKeyBytes.length} bytes)`);

  const payload = {
    ciphertext:    toB64(cipherBytes),
    encrypted_key: toB64(wrappedKeyBytes),
    nonce:         toB64(nonce),
    auth_tag:      toB64(authTagBytes),
  };

  log(SUCCESS, 'Payload cifrado listo para enviar al servidor');
  return payload;
}

// ─── cifrado E2E de mensaje grupal ───────────────────────────────────────────

/**
 * Cifra `plaintext` para múltiples destinatarios:
 *  - Un solo AES key + ciphertext para todos
 *  - La clave AES se envuelve individualmente para cada miembro
 *
 * @param {string} plaintext
 * @param {Array<{id: string, public_key: string}>} members
 * @returns {{ ciphertext, nonce, auth_tag, encrypted_keys: [{user_id, encrypted_key}] }}
 */
export async function encryptGroupMessage(plaintext, members) {
  log(INFO, `Iniciando cifrado grupal para ${members.length} miembro(s)…`);

  // 1. Generar clave AES-256 efímera compartida
  log(CRYPTO, 'Generando clave AES-256 compartida para el grupo…');
  const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt'],
  );
  const rawAes = await crypto.subtle.exportKey('raw', aesKey);
  log(KEY, 'Clave AES grupal generada', `${hex(rawAes)} (32 bytes)`);

  // 2. Nonce
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  log(KEY, 'Nonce grupal generado', `${hex(nonce)} (12 bytes)`);

  // 3. Cifrar plaintext una sola vez
  log(ENCRYPT, `Cifrando mensaje único para el grupo (AES-256-GCM)…`);
  const result      = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    aesKey,
    new TextEncoder().encode(plaintext),
  );
  const resultBytes  = new Uint8Array(result);
  const cipherBytes  = resultBytes.slice(0, -16);
  const authTagBytes = resultBytes.slice(-16);
  log(ENCRYPT, 'Ciphertext grupal', `${hex(cipherBytes)} (${cipherBytes.length} bytes)`);

  // 4. Envolver clave AES para cada miembro con su RSA public key
  const encrypted_keys = [];
  for (const member of members) {
    log(CRYPTO, `Envolviendo clave AES para ${member.display_name || member.id} (RSA-OAEP)…`);
    const rsaKey     = await importRSAPublicKey(member.public_key);
    const wrappedBuf = await crypto.subtle.wrapKey('raw', aesKey, rsaKey, { name: 'RSA-OAEP' });
    encrypted_keys.push({
      user_id:       member.id,
      encrypted_key: toB64(new Uint8Array(wrappedBuf)),
    });
    log(KEY, `Clave envuelta para ${member.display_name || member.id}`, hex(new Uint8Array(wrappedBuf)));
  }

  log(SUCCESS, 'Payload grupal cifrado listo');
  return {
    ciphertext:    toB64(cipherBytes),
    nonce:         toB64(nonce),
    auth_tag:      toB64(authTagBytes),
    encrypted_keys,
  };
}

// ─── descifrado de mensaje recibido ──────────────────────────────────────────

/**
 * Descifra un mensaje recibido usando la llave privada del usuario.
 * @param {object} message — campos del mensaje (ciphertext, encrypted_key, nonce, auth_tag)
 * @param {CryptoKey} rsaPrivateKey — obtenida con importRSAPrivateKey()
 * @returns {string} plaintext
 */
export async function decryptMessage(message, rsaPrivateKey) {
  log(INFO, `Descifrando mensaje ${message.id?.slice(0, 8)}…`);

  const encryptedKeyBytes = fromB64(message.encrypted_key);
  const cipherBytes       = fromB64(message.ciphertext);
  const nonceBytes        = fromB64(message.nonce);
  const authTagBytes      = fromB64(message.auth_tag);

  // 1. Desenvolver clave AES con RSA-OAEP
  log(DECRYPT, 'Desenvolviendo clave AES con RSA-OAEP/SHA-256…');
  const aesKey = await crypto.subtle.unwrapKey(
    'raw',
    encryptedKeyBytes,
    rsaPrivateKey,
    { name: 'RSA-OAEP' },
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
  log(KEY, 'Clave AES recuperada');

  // 2. Descifrar con AES-256-GCM (ciphertext || tag)
  log(DECRYPT, 'Descifrando con AES-256-GCM (verificando auth tag)…');
  const combined = new Uint8Array(cipherBytes.length + authTagBytes.length);
  combined.set(cipherBytes);
  combined.set(authTagBytes, cipherBytes.length);

  const plaintextBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonceBytes, tagLength: 128 },
    aesKey,
    combined,
  );

  const plaintext = new TextDecoder().decode(plaintextBuf);
  log(SUCCESS, 'Mensaje descifrado exitosamente', `"${plaintext.slice(0, 60)}${plaintext.length > 60 ? '…' : ''}"`);
  return plaintext;
}
