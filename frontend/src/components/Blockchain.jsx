import { useEffect, useState } from 'react';
import { getBlockchain, verifyBlockchain, verifyBlockchainFrom } from '../services/blockchainService';
import BlockchainGraph from './BlockchainGraph';

function short(hash = '') {
  if (!hash) return '—';
  return `${hash.slice(0, 10)}…${hash.slice(-6)}`;
}

const STATUS_STYLE = {
  valid:    { border: '2px solid #22c55e', background: 'rgba(34,197,94,0.07)' },
  failed:   { border: '2px solid #ef4444', background: 'rgba(239,68,68,0.07)' },
  checking: { border: '2px solid #f59e0b', background: 'rgba(245,158,11,0.07)' },
  none:     {},
};

const STATUS_BADGE = {
  valid:    { label: '✅ Íntegro',      color: '#22c55e' },
  failed:   { label: '❌ Comprometido', color: '#ef4444' },
  checking: { label: '⏳ Verificando…', color: '#f59e0b' },
};

function BlockCard({ block, isGenesis, status, onVerifyFrom, verifying }) {
  const [expanded, setExpanded] = useState(false);
  const badge = STATUS_BADGE[status];

  return (
    <div
      className={`bc-block${isGenesis ? ' bc-block-genesis' : ''}`}
      style={STATUS_STYLE[status] ?? STATUS_STYLE.none}
    >
      <div className="bc-block-header" onClick={() => setExpanded((s) => !s)}>
        <div className="bc-block-index">
          <span className="bc-block-num">#{block.index}</span>
          {isGenesis && <span className="bc-genesis-badge">Génesis</span>}
          {badge && (
            <span style={{ fontSize: 11, color: badge.color, fontWeight: 600, marginLeft: 6 }}>
              {badge.label}
            </span>
          )}
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

          <div style={{ marginTop: 10 }}>
            <button
              className="btn btn-outline btn-sm"
              onClick={(e) => { e.stopPropagation(); onVerifyFrom(block.index); }}
              disabled={verifying}
              title={`Verificar cadena desde genesis hasta bloque #${block.index}`}
            >
              {verifying ? <span className="spinner spinner-dk" /> : `🔍 Verificar desde #${block.index}`}
            </button>
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

function VerifyFromPanel({ result, onClose }) {
  if (!result) return null;

  const isValid = result.valid;

  return (
    <div
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: 'var(--bg-card, #1e1e2e)',
          border: `2px solid ${isValid ? '#22c55e' : '#ef4444'}`,
          borderRadius: 12, padding: 28, minWidth: 340, maxWidth: 500,
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ fontSize: 22, fontWeight: 700, marginBottom: 12 }}>
          {isValid ? '✅ Verificación exitosa' : '❌ Cadena comprometida'}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 13 }}>
          <Row label="Desde bloque" value={`#${result.from_index}`} />
          <Row label="Bloques verificados" value={result.length} />
          {!isValid && <Row label="Fallo en bloque" value={`#${result.failed_at_index}`} color="#ef4444" />}
          {!isValid && <Row label="Razón" value={result.reason} color="#ef4444" />}
          <div style={{ marginTop: 6, color: 'var(--text-muted, #aaa)', fontSize: 12 }}>
            {result.detail}
          </div>
        </div>

        <button
          className="btn btn-outline btn-sm"
          style={{ marginTop: 18 }}
          onClick={onClose}
        >
          Cerrar
        </button>
      </div>
    </div>
  );
}

function Row({ label, value, color }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
      <span style={{ color: 'var(--text-muted, #aaa)' }}>{label}</span>
      <span style={{ fontWeight: 600, color: color || 'inherit', fontFamily: 'monospace' }}>{value}</span>
    </div>
  );
}

function computeBlockStatuses(chain, fromResult) {
  if (!fromResult) return {};

  const statuses = {};
  const { from_index, valid, failed_at_index } = fromResult;

  for (const block of chain) {
    if (block.index > from_index) continue;

    if (valid) {
      statuses[block.index] = 'valid';
    } else {
      if (block.index < failed_at_index) statuses[block.index] = 'valid';
      else if (block.index === failed_at_index) statuses[block.index] = 'failed';
      // bloques después del fallo quedan sin estado
    }
  }
  return statuses;
}

export default function Blockchain() {
  const [chain, setChain]             = useState([]);
  const [loading, setLoading]         = useState(false);
  const [verifying, setVerifying]     = useState(false);
  const [verifyingFrom, setVerifyingFrom] = useState(false);
  const [verifyResult, setVerify]     = useState(null);
  const [fromResult, setFromResult]   = useState(null);
  const [blockStatuses, setBlockStatuses] = useState({});
  const [showGraph, setShowGraph]     = useState(false);
  const [error, setError]             = useState('');

  async function fetchChain() {
    setLoading(true); setError(''); setVerify(null); setFromResult(null); setBlockStatuses({});
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

  async function handleVerifyFrom(index) {
    setVerifyingFrom(true); setFromResult(null); setBlockStatuses({});

    // Marca todos los bloques hasta index como "checking"
    const checking = {};
    for (const b of chain) {
      if (b.index <= index) checking[b.index] = 'checking';
    }
    setBlockStatuses(checking);

    try {
      const result = await verifyBlockchainFrom(index);
      setFromResult(result);
      setBlockStatuses(computeBlockStatuses(chain, result));
    } catch (e) {
      setFromResult({ valid: false, from_index: index, detail: e.message });
    } finally {
      setVerifyingFrom(false);
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
          <button
            className="btn btn-outline btn-sm"
            onClick={() => setShowGraph((s) => !s)}
            disabled={loading}
          >
            {showGraph ? '📋 Ver lista' : '⛓ Ver como Graph'}
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

      {showGraph && (
        <div style={{ padding: '0 16px 16px' }}>
          <BlockchainGraph
            chain={chain}
            blockStatuses={blockStatuses}
            onVerifyFrom={handleVerifyFrom}
            verifying={verifyingFrom}
          />
        </div>
      )}

      <div className="bc-chain" style={{ display: showGraph ? 'none' : undefined }}>
        {chain.map((block, i) => (
          <div key={block.index} className="bc-chain-item">
            <BlockCard
              block={block}
              isGenesis={block.index === 0}
              status={blockStatuses[block.index] ?? null}
              onVerifyFrom={handleVerifyFrom}
              verifying={verifyingFrom}
            />
            {i < chain.length - 1 && (
              <div className="bc-connector">
                <span className="bc-arrow">▼</span>
                <span className="bc-connector-label">previous_hash apunta aquí</span>
              </div>
            )}
          </div>
        ))}
      </div>

      <VerifyFromPanel result={fromResult} onClose={() => { setFromResult(null); }} />
    </div>
  );
}
