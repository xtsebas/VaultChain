import { useEffect, useRef, useState } from 'react';
import { onLog, LOG_TYPES } from '../services/cryptoLog';

const TYPE_STYLE = {
  [LOG_TYPES.INFO]:    { bg: '#1e3a5f', color: '#60b0ff', label: 'INFO' },
  [LOG_TYPES.NETWORK]: { bg: '#1a3a2a', color: '#4ade80', label: 'NET' },
  [LOG_TYPES.KEY]:     { bg: '#3b2a00', color: '#fbbf24', label: 'KEY' },
  [LOG_TYPES.ENCRYPT]: { bg: '#2d1b69', color: '#a78bfa', label: 'ENC' },
  [LOG_TYPES.DECRYPT]: { bg: '#1a3a3a', color: '#2dd4bf', label: 'DEC' },
  [LOG_TYPES.CRYPTO]:  { bg: '#2a1a40', color: '#c084fc', label: 'CRYPTO' },
  [LOG_TYPES.SUCCESS]: { bg: '#0f2a1a', color: '#34d399', label: 'OK' },
  [LOG_TYPES.ERROR]:   { bg: '#3a0a0a', color: '#f87171', label: 'ERR' },
};

export default function CryptoLog() {
  const [open, setOpen]       = useState(false);
  const [entries, setEntries] = useState([]);
  const [unread, setUnread]   = useState(0);
  const bottomRef = useRef(null);

  useEffect(() => {
    return onLog((entry) => {
      setEntries((prev) => [...prev.slice(-500), entry]);
      if (!open) setUnread((u) => u + 1);
    });
  }, [open]);

  useEffect(() => {
    function onKey(e) {
      if (e.shiftKey && e.key === 'I') { setOpen((o) => !o); setUnread(0); }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    if (open) bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [entries, open]);

  if (!open) {
    return (
      <div className="cryptolog-fab" onClick={() => { setOpen(true); setUnread(0); }} title="Crypto Log (Shift+I)">
        <span style={{ color: '#7c4dff', fontWeight: 700 }}>&lt;/&gt;</span>
        <span>Crypto Log</span>
        {unread > 0 && <span className="cryptolog-badge">{unread}</span>}
      </div>
    );
  }

  return (
    <div className="cryptolog-panel">
      <div className="cryptolog-hdr">
        <span style={{ color: '#7c4dff', fontWeight: 700 }}>&lt;/&gt;</span>
        <span className="cryptolog-title">Crypto Log</span>
        <span className="cryptolog-hint">Shift+I para cerrar</span>
        <button className="cryptolog-hbtn" title="Limpiar" onClick={() => setEntries([])}>🗑</button>
        <button className="cryptolog-hbtn cls" title="Cerrar" onClick={() => setOpen(false)}>✕</button>
      </div>

      <div className="cryptolog-body">
        {entries.length === 0 && (
          <div className="cryptolog-empty">— Sin eventos. Envía un mensaje para ver el flujo criptográfico. —</div>
        )}
        {entries.map((entry) => {
          const s = TYPE_STYLE[entry.type] ?? TYPE_STYLE[LOG_TYPES.INFO];
          return (
            <div key={entry.id} className="log-entry">
              <span className="log-ts">{entry.ts}</span>
              <span className="log-badge" style={{ background: s.bg, color: s.color, border: `1px solid ${s.color}44` }}>
                {s.label}
              </span>
              <span className="log-msg">{entry.message}</span>
              {entry.value && <span className="log-val">{entry.value}</span>}
            </div>
          );
        })}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
