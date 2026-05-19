import { useEffect, useState } from 'react';
import { getBlockchain, verifyBlockchain } from '../services/blockchainService';

function short(hash = '') {
  if (!hash) return '—';
  return `${hash.slice(0, 10)}…${hash.slice(-6)}`;
}

function BlockCard({ block, isGenesis }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={`bc-block${isGenesis ? ' bc-block-genesis' : ''}`}>
      <div className="bc-block-header" onClick={() => setExpanded((s) => !s)}>
        <div className="bc-block-index">
          <span className="bc-block-num">#{block.index}</span>
          {isGenesis && <span className="bc-genesis-badge">Génesis</span>}
        </div>
        <div className="bc-block-summary">
          <span className="bc-hash-mono">{short(block.hash)}</span>
          <span className="bc-block-ts">
            {new Date(block.timestamp).toLocaleString('es-GT', { dateStyle: 'short', timeStyle: 'short' })}
          </span>
        </div>
        <button className="btn btn-ghost btn-icon bc-expand-btn" title={expanded ? 'Colapsar' : 'Expandir'}>
          {expanded ? '▲' : '▼'}
        </button>
      </div>

      {expanded && (
        <div className="bc-block-body">
          <div className="bc-row">
            <span className="bc-label">Índice</span>
            <span className="bc-val">{block.index}</span>
          </div>
          <div className="bc-row">
            <span className="bc-label">Timestamp</span>
            <span className="bc-val">{block.timestamp}</span>
          </div>
          <div className="bc-row">
            <span className="bc-label">Remitente</span>
            <span className="bc-val bc-mono">{block.sender_id ? short(block.sender_id) : '—'}</span>
          </div>
          <div className="bc-row">
            <span className="bc-label">Destinatario</span>
            <span className="bc-val bc-mono">{block.recipient_id ? short(block.recipient_id) : '—'}</span>
          </div>
          <div className="bc-row">
            <span className="bc-label">Hash del mensaje</span>
            <span className="bc-val bc-mono bc-hash-full">{block.message_hash || '—'}</span>
          </div>
          <div className="bc-row">
            <span className="bc-label">Hash anterior</span>
            <span className="bc-val bc-mono bc-hash-full">{block.previous_hash || '—'}</span>
          </div>
          <div className="bc-row">
            <span className="bc-label">Nonce</span>
            <span className="bc-val bc-mono">{block.nonce ?? '—'}</span>
          </div>
          <div className="bc-row bc-row-hash">
            <span className="bc-label">Hash del bloque</span>
            <span className="bc-val bc-mono bc-hash-full">{block.hash || '—'}</span>
          </div>
        </div>
      )}
    </div>
  );
}

function VerifyBanner({ result }) {
  if (!result) return null;
  if (result.valid) {
    return (
      <div className="alert alert-success bc-verify-banner">
        ✅ Cadena íntegra — todos los bloques encadenados correctamente.
      </div>
    );
  }
  return (
    <div className="alert alert-error bc-verify-banner">
      ⚠️ Cadena comprometida — se detectó una inconsistencia.
      {result.detail && <span className="bc-verify-detail"> {result.detail}</span>}
    </div>
  );
}

export default function Blockchain() {
  const [chain, setChain]           = useState([]);
  const [loading, setLoading]       = useState(false);
  const [verifying, setVerifying]   = useState(false);
  const [verifyResult, setVerify]   = useState(null);
  const [error, setError]           = useState('');

  async function fetchChain() {
    setLoading(true); setError(''); setVerify(null);
    try {
      const data = await getBlockchain();
      setChain(data.chain ?? []);
    } catch (e) {
      setError(e.message || 'Error al cargar la cadena');
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify() {
    setVerifying(true); setVerify(null);
    try {
      const result = await verifyBlockchain();
      setVerify(result);
    } catch (e) {
      setVerify({ valid: false, detail: e.message });
    } finally {
      setVerifying(false);
    }
  }

  useEffect(() => { fetchChain(); }, []);

  return (
    <div className="card">
      <div className="card-header">
        <span>⛓</span>
        <span style={{ flex: 1 }}>Blockchain — registro de auditoría</span>
        <div className="msg-actions">
          <button className="btn btn-ghost btn-sm" onClick={fetchChain} disabled={loading}>
            {loading ? <span className="spinner spinner-dk" /> : '🔄 Recargar'}
          </button>
          <button
            className="btn btn-outline btn-sm"
            onClick={handleVerify}
            disabled={verifying || loading}
          >
            {verifying ? <span className="spinner spinner-dk" /> : '🔍 Verificar integridad'}
          </button>
        </div>
      </div>

      <div style={{ padding: '8px 16px' }}>
        <VerifyBanner result={verifyResult} />

        {error && <div className="alert alert-error">{error}</div>}

        {!loading && chain.length === 0 && !error && (
          <div className="msg-empty">La cadena no tiene bloques aún.</div>
        )}

        {loading && (
          <div className="msg-empty">
            <span className="spinner spinner-dk" style={{ width: 24, height: 24 }} />
          </div>
        )}
      </div>

      <div className="bc-chain">
        {chain.map((block, i) => (
          <div key={block.index} className="bc-chain-item">
            <BlockCard block={block} isGenesis={block.index === 0} />
            {i < chain.length - 1 && (
              <div className="bc-connector">
                <span className="bc-arrow">▼</span>
                <span className="bc-connector-label">previous_hash apunta aquí</span>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
