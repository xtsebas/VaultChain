/**
 * Messaging.jsx — UI de mensajería E2E sin dependencias externas de UI.
 */
import { useEffect, useState } from 'react';
import {
  encryptMessage, encryptGroupMessage,
  decryptMessage, decryptPrivateKey, importRSAPrivateKey,
} from '../services/cryptoService';
import {
  listUsers, getUserPublicKey, sendDirectMessage,
  sendGroupMessage, getMyMessages, createGroup,
} from '../services/messageService';
import { getSessionUser, getEncryptedPrivateKey } from '../services/authService';
import { log, LOG_TYPES } from '../services/cryptoLog';

function initials(name = '') {
  return name.split(' ').slice(0, 2).map((w) => w[0]?.toUpperCase()).join('');
}

// ── Compose directo ───────────────────────────────────────────────────────────
function ComposeDialog({ onClose, users, onSent }) {
  const [recipientId, setRecipientId] = useState('');
  const [plaintext, setPlaintext]     = useState('');
  const [loading, setLoading]         = useState(false);
  const [error, setError]             = useState('');
  const [success, setSuccess]         = useState('');

  async function handleSend() {
    if (!recipientId || !plaintext.trim()) return;
    setLoading(true); setError(''); setSuccess('');
    try {
      log(LOG_TYPES.INFO, '=== INICIO FLUJO CIFRADO DIRECTO ===');
      const publicKeyPem = await getUserPublicKey(recipientId);
      const encrypted    = await encryptMessage(plaintext, publicKeyPem);
      await sendDirectMessage(recipientId, encrypted);
      setSuccess('¡Mensaje enviado y cifrado correctamente!');
      setPlaintext('');
      onSent?.();
    } catch (e) {
      const msg = e?.data?.error || e?.message || 'Error al cifrar/enviar';
      log(LOG_TYPES.ERROR, `Error en envío: ${msg}`);
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-header">🔒 Nuevo mensaje cifrado</div>
        <div className="modal-body">
          {error   && <div className="alert alert-error">{error}</div>}
          {success && <div className="alert alert-success">{success}</div>}
          <div className="field">
            <label>Destinatario</label>
            <select value={recipientId} onChange={(e) => setRecipientId(e.target.value)}>
              <option value="">Selecciona un usuario…</option>
              {users.map((u) => (
                <option key={u.id} value={u.id}>{u.display_name} — {u.email}</option>
              ))}
            </select>
          </div>
          <div className="field">
            <label>Mensaje (plaintext)</label>
            <textarea
              rows={4} value={plaintext} onChange={(e) => setPlaintext(e.target.value)}
              placeholder="Escribe tu mensaje. Se cifrará con AES-256-GCM + RSA-OAEP antes de salir de tu navegador."
            />
            <span className="helper">El servidor nunca verá el contenido en texto plano.</span>
          </div>
        </div>
        <div className="modal-footer">
          <button className="btn btn-ghost btn-sm" onClick={onClose}>Cancelar</button>
          <button
            className="btn btn-primary btn-sm"
            onClick={handleSend}
            disabled={loading || !recipientId || !plaintext.trim()}
          >
            {loading ? <span className="spinner" /> : '📤 Cifrar y enviar'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Compose grupal ─────────────────────────────────────────────────────────────
function GroupDialog({ onClose, users, onSent }) {
  const [groupName, setGroupName]       = useState('');
  const [memberIds, setMemberIds]       = useState([]);
  const [plaintext, setPlaintext]       = useState('');
  const [groupId, setGroupId]           = useState(null);
  const [groupMembers, setGroupMembers] = useState([]);
  const [step, setStep]                 = useState('compose');
  const [loading, setLoading]           = useState(false);
  const [error, setError]               = useState('');
  const [success, setSuccess]           = useState('');

  function handleSelectMembers(e) {
    const opts = Array.from(e.target.selectedOptions).map((o) => o.value);
    setMemberIds(opts);
  }

  async function handleCreateGroup() {
    if (!groupName.trim() || memberIds.length === 0) return;
    setLoading(true); setError('');
    try {
      log(LOG_TYPES.INFO, '=== CREANDO GRUPO ===');
      const group = await createGroup(groupName, memberIds);
      setGroupId(group.id);
      setGroupMembers(group.members);
      setStep('created');
    } catch (e) {
      setError(e?.data?.error || e?.message || 'Error al crear grupo');
    } finally {
      setLoading(false);
    }
  }

  async function handleSendGroup() {
    if (!plaintext.trim()) return;
    setLoading(true); setError(''); setSuccess('');
    try {
      log(LOG_TYPES.INFO, '=== INICIO FLUJO CIFRADO GRUPAL ===');
      const payload = await encryptGroupMessage(plaintext, groupMembers);
      await sendGroupMessage(groupId, payload);
      setSuccess(`¡Mensaje grupal enviado a ${groupMembers.length} miembros!`);
      setPlaintext('');
      onSent?.();
    } catch (e) {
      const msg = e?.data?.error || e?.message || 'Error al cifrar/enviar';
      log(LOG_TYPES.ERROR, `Error en envío grupal: ${msg}`);
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-header">👥 Mensaje grupal cifrado</div>
        <div className="modal-body">
          {error   && <div className="alert alert-error">{error}</div>}
          {success && <div className="alert alert-success">{success}</div>}

          {step === 'compose' && (
            <>
              <div className="field">
                <label>Nombre del grupo</label>
                <input value={groupName} onChange={(e) => setGroupName(e.target.value)} />
              </div>
              <div className="field">
                <label>Miembros (Ctrl+click para seleccionar varios)</label>
                <select multiple value={memberIds} onChange={handleSelectMembers}>
                  {users.map((u) => (
                    <option key={u.id} value={u.id}>{u.display_name} — {u.email}</option>
                  ))}
                </select>
              </div>
            </>
          )}

          {step === 'created' && (
            <>
              <div className="alert alert-info">
                Grupo creado. La clave AES se cifrará con la llave pública de cada miembro.
              </div>
              <div className="field">
                <label>Mensaje grupal (plaintext)</label>
                <textarea rows={4} value={plaintext} onChange={(e) => setPlaintext(e.target.value)} />
                <span className="helper">Se generará 1 ciphertext y {groupMembers.length} encrypted_keys.</span>
              </div>
            </>
          )}
        </div>
        <div className="modal-footer">
          <button className="btn btn-ghost btn-sm" onClick={onClose}>Cancelar</button>
          {step === 'compose' && (
            <button
              className="btn btn-outline-sec btn-sm"
              onClick={handleCreateGroup}
              disabled={loading || !groupName.trim() || memberIds.length === 0}
            >
              {loading ? <span className="spinner spinner-dk" /> : '👥 Crear grupo'}
            </button>
          )}
          {step === 'created' && (
            <button
              className="btn btn-secondary btn-sm"
              onClick={handleSendGroup}
              disabled={loading || !plaintext.trim()}
            >
              {loading ? <span className="spinner" /> : '📤 Cifrar y enviar'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Diálogo descifrado ─────────────────────────────────────────────────────────
function DecryptDialog({ message, onClose }) {
  const [password, setPassword]   = useState('');
  const [showPass, setShowPass]   = useState(false);
  const [decrypted, setDecrypted] = useState('');
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState('');

  async function handleDecrypt() {
    if (!password) return;
    setLoading(true); setError('');
    try {
      log(LOG_TYPES.INFO, '=== INICIO FLUJO DESCIFRADO ===');
      const encPrivKey = getEncryptedPrivateKey();
      if (!encPrivKey) throw new Error('Llave privada no disponible. Vuelve a iniciar sesión.');
      const pkcs8Der  = await decryptPrivateKey(encPrivKey, password);
      const rsaPrivKey = await importRSAPrivateKey(pkcs8Der);
      const plaintext  = await decryptMessage(message, rsaPrivKey);
      setDecrypted(plaintext);
    } catch (e) {
      const msg = e?.message || 'Error al descifrar. ¿Contraseña incorrecta?';
      log(LOG_TYPES.ERROR, `Error descifrado: ${msg}`);
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-header">🔓 Descifrar mensaje</div>
        <div className="modal-body">
          {error && <div className="alert alert-error">{error}</div>}

          {!decrypted ? (
            <>
              <div className="alert alert-info">
                Introduce tu contraseña para derivar la llave privada y descifrar el mensaje.
              </div>
              <div className="field">
                <label>Tu contraseña</label>
                <div className="field-input-wrap">
                  <input
                    type={showPass ? 'text' : 'password'}
                    className="has-eye"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleDecrypt()}
                  />
                  <button type="button" className="eye-btn" onClick={() => setShowPass((s) => !s)}>
                    {showPass ? '🙈' : '👁'}
                  </button>
                </div>
              </div>
            </>
          ) : (
            <>
              <div className="alert alert-success">Mensaje descifrado exitosamente.</div>
              <div className="decrypt-box">
                <div className="decrypt-label">Contenido original:</div>
                <p>{decrypted}</p>
              </div>
            </>
          )}
        </div>
        <div className="modal-footer">
          <button className="btn btn-ghost btn-sm" onClick={onClose}>Cerrar</button>
          {!decrypted && (
            <button
              className="btn btn-success btn-sm"
              onClick={handleDecrypt}
              disabled={loading || !password}
            >
              {loading ? <span className="spinner" /> : '🔓 Descifrar'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Componente principal ───────────────────────────────────────────────────────
export default function Messaging() {
  const user = getSessionUser();
  const [users, setUsers]             = useState([]);
  const [messages, setMessages]       = useState([]);
  const [loadingMsgs, setLoadingMsgs] = useState(false);
  const [composeOpen, setComposeOpen] = useState(false);
  const [groupOpen, setGroupOpen]     = useState(false);
  const [decryptMsg, setDecryptMsg]   = useState(null);

  async function fetchUsers() {
    try {
      const all = await listUsers();
      setUsers(all.filter((u) => u.id !== user?.id));
    } catch { /* silencioso */ }
  }

  async function fetchMessages() {
    if (!user?.id) return;
    setLoadingMsgs(true);
    try {
      const msgs = await getMyMessages(user.id);
      setMessages(msgs);
    } catch { /* silencioso */ }
    finally { setLoadingMsgs(false); }
  }

  useEffect(() => { fetchUsers(); fetchMessages(); }, []);

  function formatDate(iso) {
    return new Date(iso).toLocaleString('es-GT', { dateStyle: 'short', timeStyle: 'short' });
  }

  return (
    <div className="card">
      <div className="card-header">
        <span>🔒</span>
        <span style={{ flex: 1 }}>Mensajería cifrada</span>
        <div className="msg-actions">
          <button className="btn btn-primary btn-sm" onClick={() => setComposeOpen(true)}>
            📤 Directo
          </button>
          <button className="btn btn-outline-sec btn-sm" onClick={() => setGroupOpen(true)}>
            👥 Grupal
          </button>
        </div>
      </div>

      <div className="msg-refresh">
        <button className="btn btn-ghost btn-sm" onClick={fetchMessages} disabled={loadingMsgs}>
          {loadingMsgs ? <span className="spinner spinner-dk" /> : '🔄 Actualizar'}
        </button>
      </div>

      <div className="msg-list">
        {messages.length === 0 && !loadingMsgs && (
          <div className="msg-empty">Sin mensajes. Los mensajes cifrados aparecerán aquí.</div>
        )}
        {messages.map((msg) => (
          <div key={msg.id} className="msg-item">
            <div className="av-sm">{initials(msg.sender_name || '?')}</div>
            <div className="msg-meta">
              <div className="msg-sender">
                {msg.sender_name || msg.sender_email || msg.sender_id?.slice(0, 8)}
                {msg.group_id && <span className="badge">Grupal</span>}
              </div>
              <div className="msg-cipher">{msg.ciphertext.slice(0, 48)}…</div>
              <div className="msg-date">{formatDate(msg.created_at)}</div>
            </div>
            <button
              className="btn btn-ghost btn-icon"
              title="Descifrar con tu llave privada"
              onClick={() => setDecryptMsg(msg)}
              style={{ color: '#2e7d32', fontSize: 20 }}
            >
              🔓
            </button>
          </div>
        ))}
      </div>

      {composeOpen && (
        <ComposeDialog users={users} onClose={() => setComposeOpen(false)} onSent={fetchMessages} />
      )}
      {groupOpen && (
        <GroupDialog users={users} onClose={() => setGroupOpen(false)} onSent={fetchMessages} />
      )}
      {decryptMsg && (
        <DecryptDialog message={decryptMsg} onClose={() => setDecryptMsg(null)} />
      )}
    </div>
  );
}
