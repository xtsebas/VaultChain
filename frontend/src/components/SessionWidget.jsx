import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  clearTokens, getSessionUser, getExpiresAt,
  enableMFA, confirmMFA, disableMFA, saveSession, updateSessionUser,
  getSessionPassword,
} from '../services/authService';

function initials(name = '') {
  return name.split(' ').slice(0, 2).map((w) => w[0]?.toUpperCase()).join('');
}

function formatExpiry(expiresAt) {
  if (!expiresAt) return '—';
  const diff = expiresAt - Date.now();
  if (diff <= 0) return 'Expirado';
  const mins = Math.floor(diff / 60000);
  const secs = Math.floor((diff % 60000) / 1000);
  return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
}

// ── Modal de activación MFA ────────────────────────────────────────────────────
function MFASetupModal({ user, onClose, onActivated }) {
  const [step, setStep] = useState('loading'); // loading | scan | confirm | success
  const [qrData, setQrData] = useState(null);
  const [secret, setSecret] = useState('');
  const [totpInput, setTotpInput] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const enableCalledRef = useRef(false);

  useEffect(() => {
    if (enableCalledRef.current) return;
    enableCalledRef.current = true;
    async function fetchQR() {
      try {
        const data = await enableMFA();
        setQrData(data.qr_code);
        setSecret(data.secret);
        setStep('scan');
      } catch (e) {
        setError(e?.data?.error || 'No se pudo generar el QR. Intenta de nuevo.');
        setStep('error');
      }
    }
    fetchQR();
  }, []);

  async function handleConfirm(e) {
    e.preventDefault();
    if (totpInput.length !== 6) return;
    setLoading(true);
    setError('');
    try {
      const data = await confirmMFA(totpInput);
      const password = getSessionPassword();
      saveSession(data, password);
      updateSessionUser({ mfa_enabled: true });
      setStep('success');
      setTimeout(() => { onActivated(); onClose(); }, 1500);
    } catch (e) {
      setError(e?.data?.error || 'Código incorrecto o expirado. Verifica tu app.');
      setTotpInput('');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-header">🔐 Activar autenticación MFA</div>

        <div className="modal-body">
          {step === 'loading' && (
            <div style={{ textAlign: 'center', padding: '2rem' }}>
              <span className="spinner spinner-dk" />
              <p style={{ marginTop: 12, color: '#555' }}>Generando QR…</p>
            </div>
          )}

          {step === 'error' && (
            <div className="alert alert-error">{error}</div>
          )}

          {step === 'scan' && (
            <>
              <div className="alert alert-info">
                <strong>Paso 1:</strong> Escanea el código QR con Google Authenticator.
              </div>
              <div style={{ textAlign: 'center', margin: '1rem 0' }}>
                <img src={qrData} alt="QR MFA" style={{ width: 200, height: 200, border: '1px solid #ddd', borderRadius: 8 }} />
              </div>
              <div style={{ background: '#f5f5f5', borderRadius: 6, padding: '8px 12px', marginBottom: 12 }}>
                <span style={{ fontSize: 11, color: '#888' }}>Clave manual:</span>
                <div style={{ fontFamily: 'monospace', fontSize: 13, letterSpacing: '0.15em', wordBreak: 'break-all' }}>
                  {secret}
                </div>
              </div>
              <button className="btn btn-primary btn-full" onClick={() => setStep('confirm')}>
                Ya escaneé el QR →
              </button>
            </>
          )}

          {step === 'confirm' && (
            <>
              <div className="alert alert-info">
                <strong>Paso 2:</strong> Ingresa el código de 6 dígitos que muestra tu app para confirmar la activación.
              </div>
              {error && <div className="alert alert-error">{error}</div>}
              <form onSubmit={handleConfirm}>
                <div className="field">
                  <label>Código TOTP</label>
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    autoFocus
                    value={totpInput}
                    onChange={(e) => { setTotpInput(e.target.value.replace(/\D/g, '')); setError(''); }}
                    placeholder="000000"
                    style={{ letterSpacing: '0.3em', fontSize: '1.4rem', textAlign: 'center' }}
                  />
                </div>
                <button
                  type="submit"
                  className="btn btn-primary btn-full mt-2"
                  disabled={loading || totpInput.length !== 6}
                >
                  {loading ? <span className="spinner" /> : 'Confirmar y activar MFA'}
                </button>
                <button type="button" className="btn btn-ghost btn-full mt-2" onClick={() => setStep('scan')}>
                  ← Ver QR de nuevo
                </button>
              </form>
            </>
          )}

          {step === 'success' && (
            <div className="alert alert-success" style={{ textAlign: 'center', padding: '1.5rem' }}>
              ✅ MFA activado correctamente. Tu cuenta está protegida.
            </div>
          )}
        </div>

        <div className="modal-footer">
          {step !== 'success' && (
            <button className="btn btn-ghost btn-sm" onClick={onClose}>Cancelar</button>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Modal de desactivación MFA ─────────────────────────────────────────────────
function MFADisableModal({ onClose, onDisabled }) {
  const [password, setPassword]   = useState('');
  const [showPass, setShowPass]   = useState(false);
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState('');

  async function handleDisable(e) {
    e.preventDefault();
    if (!password) return;
    setLoading(true); setError('');
    try {
      await disableMFA(password);
      updateSessionUser({ mfa_enabled: false });
      onDisabled();
      onClose();
    } catch (e) {
      setError(e?.data?.error || 'Contraseña incorrecta.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-header">🔓 Desactivar MFA</div>
        <div className="modal-body">
          <div className="alert alert-info">
            Confirma tu contraseña para desactivar la autenticación de dos factores.
          </div>
          {error && <div className="alert alert-error">{error}</div>}
          <form onSubmit={handleDisable}>
            <div className="field">
              <label>Contraseña actual</label>
              <div className="field-input-wrap">
                <input
                  type={showPass ? 'text' : 'password'}
                  className="has-eye"
                  value={password}
                  autoFocus
                  onChange={(e) => setPassword(e.target.value)}
                />
                <button type="button" className="eye-btn" onClick={() => setShowPass((s) => !s)}>
                  {showPass ? '🙈' : '👁'}
                </button>
              </div>
            </div>
            <button
              type="submit"
              className="btn btn-full mt-2"
              style={{ background: '#c62828', color: '#fff' }}
              disabled={loading || !password}
            >
              {loading ? <span className="spinner" /> : 'Desactivar MFA'}
            </button>
          </form>
        </div>
        <div className="modal-footer">
          <button className="btn btn-ghost btn-sm" onClick={onClose}>Cancelar</button>
        </div>
      </div>
    </div>
  );
}

// ── SessionWidget principal ────────────────────────────────────────────────────
export default function SessionWidget({ open, onClose }) {
  const navigate = useNavigate();
  const [user, setUser] = useState(getSessionUser());
  const expiresAt = getExpiresAt();
  const intervalRef = useRef(null);
  const [, setTick] = useState(0);
  const [showMFASetup, setShowMFASetup]       = useState(false);
  const [showMFADisable, setShowMFADisable]   = useState(false);

  if (!user || !open) return null;

  if (open && !intervalRef.current) {
    intervalRef.current = setInterval(() => setTick((t) => t + 1), 1000);
  }

  function handleClose() {
    clearInterval(intervalRef.current);
    intervalRef.current = null;
    onClose();
  }

  function handleLogout() {
    handleClose();
    clearTokens();
    navigate('/login');
  }

  function handleMFAActivated() { setUser(getSessionUser()); }
  function handleMFADisabled()  { setUser(getSessionUser()); }

  const nearExpiry = expiresAt - Date.now() < 120_000;

  return (
    <>
      <div className="popover-overlay" onClick={handleClose} />
      <div className="popover">
        <div className="popover-head">
          <div className="popover-av">{initials(user.display_name)}</div>
          <span className="popover-name">{user.display_name}</span>
        </div>
        <div className="popover-body">
          <div className="popover-row">
            <span className="popover-icon">✉️</span>
            <div>
              <div className="popover-label">Correo</div>
              <div className="popover-value">{user.email}</div>
            </div>
          </div>
          <div className="popover-row">
            <span className="popover-icon">🪪</span>
            <div>
              <div className="popover-label">ID de usuario</div>
              <div className="popover-value" style={{ fontSize: 11 }}>{user.id}</div>
            </div>
          </div>
          <div className="popover-row">
            <span className="popover-icon">⏱️</span>
            <div>
              <div className="popover-label">Token expira en</div>
              <div className={`popover-value ${nearExpiry ? 'expiry-warn' : 'expiry-ok'}`}>
                {formatExpiry(expiresAt)}
              </div>
            </div>
          </div>
          <div className="popover-row">
            <span className="popover-icon">{user.mfa_enabled ? '🔐' : '🔓'}</span>
            <div style={{ flex: 1 }}>
              <div className="popover-label">Autenticación MFA</div>
              {user.mfa_enabled ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <div className="popover-value" style={{ color: '#2e7d32', fontWeight: 600 }}>Activo</div>
                  <button
                    className="btn btn-ghost btn-sm"
                    style={{ color: '#c62828', padding: '2px 6px', fontSize: 11 }}
                    onClick={() => setShowMFADisable(true)}
                  >
                    Desactivar
                  </button>
                </div>
              ) : (
                <button
                  className="btn btn-outline-sec btn-sm"
                  style={{ marginTop: 4 }}
                  onClick={() => setShowMFASetup(true)}
                >
                  Activar MFA
                </button>
              )}
            </div>
          </div>
        </div>
        <div className="popover-divider" />
        <button className="popover-logout" onClick={handleLogout}>
          🚪 Cerrar sesión
        </button>
      </div>

      {showMFASetup && (
        <MFASetupModal
          user={user}
          onClose={() => setShowMFASetup(false)}
          onActivated={handleMFAActivated}
        />
      )}
      {showMFADisable && (
        <MFADisableModal
          onClose={() => setShowMFADisable(false)}
          onDisabled={handleMFADisabled}
        />
      )}
    </>
  );
}
