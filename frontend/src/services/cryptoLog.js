/**
 * cryptoLog.js — bus de eventos para el log criptográfico.
 * Usado por cryptoService.js para emitir pasos; suscrito por CryptoLog.jsx.
 */

const listeners = new Set();

/** Tipos de entrada con colores asociados en CryptoLog.jsx */
export const LOG_TYPES = {
  INFO:    'INFO',
  NETWORK: 'NETWORK',
  KEY:     'KEY',
  ENCRYPT: 'ENCRYPT',
  DECRYPT: 'DECRYPT',
  CRYPTO:  'CRYPTO',
  SUCCESS: 'SUCCESS',
  ERROR:   'ERROR',
};

let idCounter = 0;

/**
 * Emite una entrada al log.
 * @param {string} type  — uno de LOG_TYPES
 * @param {string} message — descripción de la operación
 * @param {string} [value] — valor hexadecimal / base64 (opcional)
 */
export function log(type, message, value = '') {
  const entry = {
    id: ++idCounter,
    ts: new Date().toISOString().slice(11, 23), // HH:MM:SS.mmm
    type,
    message,
    value,
  };
  listeners.forEach((fn) => fn(entry));
}

/** Suscribe un listener. Retorna una función para desuscribir. */
export function onLog(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}
