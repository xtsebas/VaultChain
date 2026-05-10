import { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { clearTokens, getSessionUser, getExpiresAt } from '../services/authService';

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

export default function SessionWidget({ open, onClose }) {
  const navigate = useNavigate();
  const user = getSessionUser();
  const expiresAt = getExpiresAt();
  const intervalRef = useRef(null);
  const [, setTick] = useState(0);

  if (!user || !open) return null;

  // tick every second to update expiry countdown
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
        </div>
        <div className="popover-divider" />
        <button className="popover-logout" onClick={handleLogout}>
          🚪 Cerrar sesión
        </button>
      </div>
    </>
  );
}
