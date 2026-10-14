import { useMemo } from 'react'

const TYPE_ORDER = ['ad_account', 'registrar', 'hosting', 'redirect_family']
const W = 840
const LX = 16, LW = 262
const RX = 520, RW = 270
const L_H = 36
const N_H = 26

const clip = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}\u2026` : s)

export default function ChokeGraph({ nodes, edges, scenarios, selected, onSelect }) {
  const layout = useMemo(() => {
    // right column: nodes grouped by type
    let y = 6
    const heads = []
    const right = {}
    TYPE_ORDER.forEach((t) => {
      const list = nodes.filter((n) => n.type === t)
      if (!list.length) return
      heads.push({ type: t, label: list[0].type_label, y: y + 14 })
      y += 22
      list.forEach((n) => {
        right[n.id] = { y, node: n }
        y += N_H + 6
      })
      y += 8
    })
    const H = y + 4
    // left column: scenarios, spread over the same height
    const step = (H - 12) / scenarios.length
    const left = {}
    scenarios.forEach((s, i) => { left[s.scenario_code] = { y: 6 + i * step + (step - L_H) / 2, s } })
    return { H, heads, right, left }
  }, [nodes, scenarios])

  const connected = useMemo(() => {
    if (!selected) return null
    const set = new Set([selected])
    edges.forEach((e) => {
      if (e.scenario_code === selected) set.add(e.node_id)
      if (e.node_id === selected) set.add(e.scenario_code)
    })
    return set
  }, [selected, edges])

  const toggle = (id) => onSelect(selected === id ? null : id)
  const key = (id) => (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggle(id) } }

  return (
    <div className="graph-scroll">
      <svg className="cgraph" width={W} height={layout.H} viewBox={`0 0 ${W} ${layout.H}`} role="group"
        aria-label="Graph linking attack scenarios to the shared infrastructure they use. Use the table below for the same information as text.">
        {edges.map((e) => {
          const l = layout.left[e.scenario_code]
          const r = layout.right[e.node_id]
          if (!l || !r) return null
          const x1 = LX + LW, y1 = l.y + L_H / 2, x2 = RX, y2 = r.y + N_H / 2
          const xm = (x1 + x2) / 2
          const on = connected && connected.has(e.scenario_code) && connected.has(e.node_id) &&
            (selected === e.scenario_code || selected === e.node_id)
          return (
            <path key={`${e.scenario_code}-${e.node_id}`} d={`M ${x1} ${y1} C ${xm} ${y1}, ${xm} ${y2}, ${x2} ${y2}`}
              className={`gedge ${on ? 'on' : connected ? 'dim' : ''}`} strokeWidth={1 + e.count * 0.55} />
          )
        })}

        {layout.heads.map((h) => (
          <text key={h.type} x={RX} y={h.y} className="ghead">{h.label}</text>
        ))}

        {scenarios.map((s) => {
          const p = layout.left[s.scenario_code]
          const cls = `gnode ${selected === s.scenario_code ? 'sel' : ''} ${connected && !connected.has(s.scenario_code) ? 'dim' : ''}`
          return (
            <g key={s.scenario_code} className={cls} role="button" tabIndex={0} aria-pressed={selected === s.scenario_code}
              aria-label={`${s.scenario_code} ${s.scenario_name}`} onClick={() => toggle(s.scenario_code)} onKeyDown={key(s.scenario_code)}>
              <rect x={LX} y={p.y} width={LW} height={L_H} rx={4} />
              <text x={LX + 10} y={p.y + 15} className="gcode">{s.scenario_code}</text>
              <text x={LX + 10} y={p.y + 29} className="gname">{clip(s.scenario_name, 40)}</text>
              <text x={LX + LW - 10} y={p.y + 22} textAnchor="end" className="gcount">{s.variants}</text>
            </g>
          )
        })}

        {nodes.map((n) => {
          const p = layout.right[n.id]
          const state = !n.safe ? 'unsafe' : n.curve_step ? 'step' : 'idle'
          const cls = `gnode gright ${state} ${selected === n.id ? 'sel' : ''} ${connected && !connected.has(n.id) ? 'dim' : ''}`
          return (
            <g key={n.id} className={cls} role="button" tabIndex={0} aria-pressed={selected === n.id}
              aria-label={`${n.type_label} ${n.name}, ${n.attack_count} attack paths${n.safe ? '' : ', also carries legitimate journeys'}`}
              onClick={() => toggle(n.id)} onKeyDown={key(n.id)}>
              <rect x={RX} y={p.y} width={RW} height={N_H} rx={4} />
              <text x={RX + 10} y={p.y + 17} className="gcode">{n.name}</text>
              <text x={RX + RW - 10} y={p.y + 17} textAnchor="end" className="gcount">{n.attack_count}</text>
              {n.curve_step && (
                <g>
                  <circle cx={RX + RW + 16} cy={p.y + N_H / 2} r={10} className="gbadge" />
                  <text x={RX + RW + 16} y={p.y + N_H / 2 + 4} textAnchor="middle" className="gbadge-t">{n.curve_step}</text>
                </g>
              )}
            </g>
          )
        })}
      </svg>
    </div>
  )
}

export function GraphLegend() {
  return (
    <ul className="legend" aria-label="Graph legend">
      <li><span className="swatch sw-gsafe" />Safe to block and part of the curve (number is the step)</li>
      <li><span className="swatch sw-gunsafe" />Also carries legitimate journeys, so unsafe to block wholesale</li>
      <li><span className="swatch sw-gidle" />Safe, but not needed once earlier steps are done</li>
      <li>Line thickness is the number of journeys. The number on each box is its journeys (left) or attack paths (right).</li>
    </ul>
  )
}
