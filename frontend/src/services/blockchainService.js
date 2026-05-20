import { log, LOG_TYPES } from './cryptoLog';
import { getToken } from './authService';

const API = import.meta.env.VITE_API_URL ?? 'http://localhost:8000';

function authHeaders() {
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${getToken()}`,
  };
}

export async function getBlockchain() {
  log(LOG_TYPES.NETWORK, 'GET /blockchain — obteniendo cadena de bloques…');
  const res = await fetch(`${API}/blockchain`, { headers: authHeaders() });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Error al obtener blockchain');
  log(LOG_TYPES.SUCCESS, `Cadena recibida — ${data.chain?.length ?? 0} bloque(s)`);
  return data;
}

export async function verifyBlockchain() {
  log(LOG_TYPES.NETWORK, 'GET /blockchain/verify — verificando integridad de la cadena…');
  const res = await fetch(`${API}/blockchain/verify`, { headers: authHeaders() });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Error al verificar blockchain');
  log(
    data.valid ? LOG_TYPES.SUCCESS : LOG_TYPES.ERROR,
    `Integridad: ${data.valid ? 'ÍNTEGRA ✓' : 'COMPROMETIDA ✗'}`,
  );
  return data;
}

export async function verifyBlockchainFrom(index) {
  log(LOG_TYPES.NETWORK, `GET /blockchain/verify/from/?from=${index} — verificando desde bloque #${index}…`);
  const res = await fetch(`${API}/blockchain/verify/from/?from=${index}`, { headers: authHeaders() });
  const data = await res.json();
  log(
    data.valid ? LOG_TYPES.SUCCESS : LOG_TYPES.ERROR,
    `Verificación parcial desde #${index}: ${data.valid ? 'ÍNTEGRA ✓' : 'COMPROMETIDA ✗'}`,
  );
  return data;
}
