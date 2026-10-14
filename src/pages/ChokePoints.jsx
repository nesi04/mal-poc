import { useState } from 'react'
import { Bar, BarChart, CartesianGrid, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { useCodeOf, useData } from '../lib/data.jsx'
import { OriginTag } from '../components/Tags.jsx'
import ScenarioCounts from '../components/ScenarioCounts.jsx'
import ChokeGraph, { GraphLegend } from '../components/ChokeGraph.jsx'

export default function ChokePoints() {
  const { data, run } = useData()
  const codeOf = useCodeOf()
  const [selected, setSelected] = useState(null)
  const c = data.chokepoints
  const rules = c.detection[run]
  const scenarios = c.attack_scenarios.map((code) => data.scenarios.find((s) => s.scenario_code === code))

  const top3 = c.curve[Math.min(2, c.curve.length - 1)]
  const chart = c.curve.map((s) => ({ name: `Step ${s.step}`, pct: s.cumulative_pct, label: s.label }))
  const singles = rules.filter((r) => r.needed_by.length > 0)

  const selNode = c.nodes.find((n) => n.id === selected)
  const selScen = scenarios.find((s) => s.scenario_code === selected)
  const detail = selNode
    ? `${selNode.type_label} ${selNode.name} carries ${selNode.attack_count} of ${c.attack_total} attack paths from ${Object.keys(selNode.by_scenario).length} scenarios. ` +
      `Action: ${selNode.action.toLowerCase()}. ` +
      (selNode.safe ? 'No legitimate journeys use it.' : `It also carries ${selNode.benign.length} legitimate journey${selNode.benign.length === 1 ? '' : 's'}, so blocking it would cause collateral damage.`) +
      ` ${selNode.per_run[run].uncontained} of its attack paths are still uncontained in this run.`
    : selScen
      ? `${selScen.scenario_code} ${selScen.scenario_name}: its ${selScen.variants} journeys run through ` +
        c.nodes.filter((n) => n.by_scenario[selScen.scenario_code]).map((n) => `${n.name} (${n.by_scenario[selScen.scenario_code]})`).join(', ') + '.'
      : 'Select a scenario or a choke point to trace the connections.'

  return (
    <>
      <h1>Choke points</h1>
      <p className="lede">
        A choke point is one place that many attack journeys pass through. Fixing or blocking it stops all of them at once,
        so it gives more protection for the effort than handling each journey separately.
      </p>
      <p className="muted small">
        This page looks at choke points from two sides: shared attacker infrastructure that one action can cut off, and
        detection rules that some journeys depend on alone.
      </p>

      <h2>How the journeys connect to shared infrastructure</h2>
      <ChokeGraph nodes={c.nodes} edges={c.edges} scenarios={scenarios} selected={selected} onSelect={setSelected} />
      <GraphLegend />
      <p className="graph-detail" aria-live="polite">{detail}</p>

      <h2>One action, many journeys</h2>
      <p>
        Acting on the top {Math.min(3, c.curve.length)} safe choke points cuts off {top3.covered} of {c.attack_total} attack
        paths ({top3.cumulative_pct}%). {c.curve.length} actions cover {c.curve[c.curve.length - 1].cumulative_pct}%.
      </p>

      <div className="chart-box" role="img"
        aria-label={`Cumulative coverage: ${c.curve.map((s) => `${s.label} brings coverage to ${s.cumulative_pct} percent`).join('; ')}`}>
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={chart} margin={{ top: 22, right: 12, left: 0, bottom: 0 }}>
            <CartesianGrid stroke="#D5DAE1" vertical={false} />
            <XAxis dataKey="name" tick={{ fontSize: 12 }} />
            <YAxis domain={[0, 100]} unit="%" tick={{ fontSize: 12 }} />
            <Tooltip formatter={(v, _n, p) => [`${v}% of attack paths`, p.payload.label]} />
            <Bar dataKey="pct" fill="#2457C5">
              <LabelList dataKey="pct" position="top" formatter={(v) => `${v}%`} style={{ fontSize: 12, fill: '#16202E' }} />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <ol className="steps">
        {c.curve.map((s) => (
          <li key={s.step}>
            <strong>{s.label}</strong> adds {s.newly_covered.length} path{s.newly_covered.length === 1 ? '' : 's'}
            {' ('}<ScenarioCounts ids={s.newly_covered} codeOf={codeOf} />{')'}
          </li>
        ))}
      </ol>
      <p className="muted small">
        Each step picks the node that covers the most paths not yet covered. {c.curve_note}
      </p>

      <h3>All choke points</h3>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Choke point</th>
              <th scope="col">Attack paths through it</th>
              <th scope="col">Still uncontained in this run</th>
              <th scope="col">Legitimate journeys also hit</th>
              <th scope="col">In the curve</th>
            </tr>
          </thead>
          <tbody>
            {c.nodes.map((n) => {
              const pr = n.per_run[run]
              return (
                <tr key={n.id}>
                  <th scope="row">
                    {n.type_label}: {n.name}
                    <span className="sub">{n.action}</span>
                  </th>
                  <td>
                    <span className="val-inline">{n.attack_count} of {c.attack_total}</span> ({n.attack_share}%)
                    <span className="sub"><ScenarioCounts ids={n.attack} codeOf={codeOf} /></span>
                  </td>
                  <td>
                    {pr.uncontained === 0 ? <span className="status-done">None</span> : (
                      <>
                        <span className="status-open">{pr.uncontained}</span>
                        <span className="sub"><ScenarioCounts ids={pr.uncontained_tests} codeOf={codeOf} /></span>
                      </>
                    )}
                  </td>
                  <td className={n.benign.length ? 'cell-warn' : ''}>
                    {n.benign.length ? (
                      <>
                        <span className="val-inline">{n.benign.length}</span>
                        <span className="sub"><ScenarioCounts ids={n.benign} codeOf={codeOf} /></span>
                        <span className="sub">Blocking this would cause collateral damage</span>
                      </>
                    ) : <span className="muted">None</span>}
                  </td>
                  <td className="num">{n.curve_step ? `Step ${n.curve_step}` : n.safe ? 'Not needed' : 'Not used (unsafe)'}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <h2>Detection rules that journeys depend on</h2>
      <p>
        {singles.length} of {rules.length} rules are the only detector for at least one attack scenario. If one of them is switched
        off or misses, those journeys go undetected, so each is a single point of failure.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Rule</th>
              <th scope="col">Status in this run</th>
              <th scope="col">Detects</th>
              <th scope="col">Only detector for</th>
              <th scope="col">Wrongly fires on</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => (
              <tr key={r.rule} className={!r.enabled && r.needed_by.length ? 'row-risk' : ''}>
                <th scope="row">{r.rule} {r.name.replaceAll('_', ' ').toLowerCase()}<span className="sub">{r.severity} severity</span></th>
                <td>{r.enabled ? <span className="status-done">Enabled</span> : <span className="status-open">Switched off</span>}</td>
                <td>{r.fires_on.length} <span className="sub"><ScenarioCounts ids={r.fires_on} codeOf={codeOf} /></span></td>
                <td>
                  <ScenarioCounts ids={r.needed_by} codeOf={codeOf} />
                  {r.needed_by.length > 0 && !r.enabled && <span className="sub">Undetected while this rule is off</span>}
                </td>
                <td className={r.false_positives.length ? 'cell-warn' : ''}><ScenarioCounts ids={r.false_positives} codeOf={codeOf} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small">
        "Only detector for" is measured with every rule enabled. A rule that is not the only detector still adds depth:
        if it fails, another rule can catch the journey.
      </p>

      <h3>How to read this page</h3>
      <ul className="notes">
        {c.notes.map((n) => <li key={n}>{n}</li>)}
        <li>Containment status comes from the selected run, so switching between Baseline and Retest changes the uncontained column.</li>
      </ul>
      <p><OriginTag origin="synthetic" /></p>
    </>
  )
}
