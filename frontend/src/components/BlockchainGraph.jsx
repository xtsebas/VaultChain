import { useEffect, useRef } from 'react';
import * as d3 from 'd3';

const NODE_W = 180;
const NODE_H = 72;
const GAP_X  = 80;
const PAD     = 24;

const COLOR = {
  genesis: '#7c3aed',
  default: '#2563eb',
  valid:   '#16a34a',
  failed:  '#dc2626',
};

export default function BlockchainGraph({ chain, blockStatuses, onVerifyFrom, verifying }) {
  const svgRef = useRef(null);

  useEffect(() => {
    if (!chain.length) return;

    const totalW = chain.length * (NODE_W + GAP_X) - GAP_X + PAD * 2;
    const totalH = NODE_H + PAD * 2 + 40;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();
    svg.attr('width', totalW).attr('height', totalH);

    const g = svg.append('g').attr('transform', `translate(${PAD},${PAD + 20})`);

    chain.forEach((block, i) => {
      const x = i * (NODE_W + GAP_X);
      const y = 0;

      const status = blockStatuses?.[block.index];
      const fill = status === 'valid'
        ? COLOR.valid
        : status === 'failed'
          ? COLOR.failed
          : block.index === 0
            ? COLOR.genesis
            : COLOR.default;

      // Flecha desde bloque anterior
      if (i > 0) {
        const x0 = (i - 1) * (NODE_W + GAP_X) + NODE_W;
        const x1 = x;
        const mx = (x0 + x1) / 2;
        const cy = NODE_H / 2;

        g.append('defs').append('marker')
          .attr('id', `arrow-${i}`)
          .attr('viewBox', '0 -5 10 10')
          .attr('refX', 8)
          .attr('refY', 0)
          .attr('markerWidth', 6)
          .attr('markerHeight', 6)
          .attr('orient', 'auto')
          .append('path')
          .attr('d', 'M0,-5L10,0L0,5')
          .attr('fill', '#64748b');

        g.append('path')
          .attr('d', `M${x0},${cy} C${mx},${cy} ${mx},${cy} ${x1},${cy}`)
          .attr('fill', 'none')
          .attr('stroke', '#64748b')
          .attr('stroke-width', 2)
          .attr('marker-end', `url(#arrow-${i})`);
      }

      // Nodo (rect)
      const node = g.append('g')
        .attr('transform', `translate(${x},${y})`)
        .style('cursor', 'pointer');

      node.append('rect')
        .attr('width', NODE_W)
        .attr('height', NODE_H)
        .attr('rx', 10)
        .attr('fill', fill)
        .attr('opacity', 0.92);

      // Título
      node.append('text')
        .attr('x', NODE_W / 2)
        .attr('y', 20)
        .attr('text-anchor', 'middle')
        .attr('fill', '#fff')
        .attr('font-size', 13)
        .attr('font-weight', 700)
        .text(block.index === 0 ? '⬡ Genesis' : `⬡ Bloque #${block.index}`);

      // Hash corto
      const shortHash = block.hash
        ? `${block.hash.slice(0, 8)}…${block.hash.slice(-6)}`
        : '—';
      node.append('text')
        .attr('x', NODE_W / 2)
        .attr('y', 38)
        .attr('text-anchor', 'middle')
        .attr('fill', 'rgba(255,255,255,0.8)')
        .attr('font-size', 10)
        .attr('font-family', 'monospace')
        .text(shortHash);

      // Estado badge
      if (status) {
        const label = status === 'valid' ? '✓ íntegro' : status === 'failed' ? '✗ fallo' : '…';
        node.append('text')
          .attr('x', NODE_W / 2)
          .attr('y', 54)
          .attr('text-anchor', 'middle')
          .attr('fill', 'rgba(255,255,255,0.9)')
          .attr('font-size', 10)
          .attr('font-weight', 600)
          .text(label);
      }

      // Botón "Verificar desde aquí"
      const btnY = NODE_H + 8;
      const btnG = g.append('g')
        .attr('transform', `translate(${x},${y})`)
        .style('cursor', verifying ? 'not-allowed' : 'pointer')
        .on('click', () => { if (!verifying) onVerifyFrom(block.index); });

      btnG.append('rect')
        .attr('x', (NODE_W - 140) / 2)
        .attr('y', btnY)
        .attr('width', 140)
        .attr('height', 24)
        .attr('rx', 6)
        .attr('fill', 'rgba(255,255,255,0.12)')
        .attr('stroke', 'rgba(255,255,255,0.3)')
        .attr('stroke-width', 1);

      btnG.append('text')
        .attr('x', NODE_W / 2)
        .attr('y', btnY + 15)
        .attr('text-anchor', 'middle')
        .attr('fill', '#fff')
        .attr('font-size', 10)
        .text(verifying ? '⏳ verificando…' : `🔍 verificar desde #${block.index}`);
    });

  }, [chain, blockStatuses, verifying]);

  if (!chain.length) return null;

  const totalW = chain.length * (NODE_W + GAP_X) - GAP_X + PAD * 2;

  return (
    <div style={{ overflowX: 'auto', padding: '12px 0' }}>
      <svg ref={svgRef} style={{ display: 'block', minWidth: totalW, height: NODE_H + PAD * 2 + 40 }} />
    </div>
  );
}
