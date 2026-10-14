import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useCodeOf, useData } from '../lib/data.jsx'
import { fmtSec } from '../lib/format.js'
import { SeverityTag } from '../components/Tags.jsx'
import ScenarioCounts from '../components/ScenarioCounts.jsx'

export default function BlueTeam() {
  const { data, run } = useData()
  const codeOf = useCodeOf()
  const [sev, setSev] = useState('all')
  const k = data.metrics.runs[run].kpis
  const b = data.views.blue[run]
  const runInfo = data.meta.runs[run]
  const alerts = b.alerts.filter((a) => sev === 'all' || a.severity === sev)

  const items = [
    ['Alerts raised', `${k.alerts.total}`, `${k.alerts.true_positive} true, ${k.alerts.false_positive} false`],
    ['High severity', `${k.alerts.by_severity.High}`, ''],
    ['Medium severity', `${k.alerts.by_severity.Medium}`, ''],
    ['Attack paths detected', `${k.detection_coverage.num} of ${k.detection_coverage.den}`, `${b.undetected.length} undetected`],
    ['Contained', `${k.containment_success.num} of ${k.containment_success.den}`, `${k.containment_success.failed} blocks failed`],
    ['Legitimate destinations blocked', `${k.false_positive.legitimate_blocked} of ${k.false_positive.legitimate_tested}`, ''],
    ['Time to detection', fmtSec(k.ttd.mean), `median ${fmtSec(k.ttd.median)}`],
    ['Time to triage', fmtSec(k.ttt.mean), `median ${fmtSec(k.ttt.median)}`],
    ['Time to containment', fmtSec(k.ttc.mean), `median ${fmtSec(k.ttc.median)}`],
    ['Evidence completeness', `${k.evidence_completeness.value}%`, `${k.evidence_completeness.num} of ${k.evidence_completeness.den} items`],
    ['Open findings', `${b.open_findings} of ${b.findings_total}`, ''],
  ]

  return (
    <>
      <h1>What did the blue team see and do?</h1>
      <p className="lede">
        {runInfo.label} run. The security team raised {k.alerts.total} alerts, detected {k.detection_coverage.num} of {k.detection_coverage.den} attack
        paths and contained {k.containment_success.num}.
      </p>
      <p className="muted small">Timings are simulated. Means are shown, with medians underneath.</p>

      <dl className="summary">
        {items.map(([label, value, sub]) => (
          <div key={label}><dt>{label}</dt><dd>{value}{sub && <span className="sub">{sub}</span>}</dd></div>
        ))}
      </dl>

      <h2>Where the blue team fell short</h2>
      <div className="table-wrap">
        <table>
          <tbody>
            <tr><th scope="row">Undetected attack journeys</th><td className="num">{b.undetected.length}</td><td><ScenarioCounts ids={b.undetected} codeOf={codeOf} /></td></tr>
            <tr><th scope="row">Blocks that failed</th><td className="num">{b.containment_failed.length}</td><td><ScenarioCounts ids={b.containment_failed} codeOf={codeOf} /></td></tr>
            <tr><th scope="row">Legitimate journeys flagged</th><td className="num">{b.false_positives.length}</td><td><ScenarioCounts ids={b.false_positives} codeOf={codeOf} /></td></tr>
          </tbody>
        </table>
      </div>

      <h2>Alerts</h2>
      <div className="filters">
        <label className="select">
          Severity
          <select value={sev} onChange={(e) => setSev(e.target.value)}>
            <option value="all">All</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
          </select>
        </label>
        <span className="muted small" aria-live="polite">Showing {alerts.length} of {b.alerts.length} alerts</span>
      </div>
      <div className="table-wrap scroll-y">
        <table>
          <thead>
            <tr>
              <th scope="col">Alert</th><th scope="col">Journey</th><th scope="col">Severity</th><th scope="col">Detection type</th>
              <th scope="col">Investigation</th><th scope="col">Containment</th><th scope="col">Raised</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.alert_id}>
                <th scope="row" className="num">{a.alert_id}</th>
                <td><Link to={`/journeys/${a.test_id}`}>{a.scenario_code} variant {a.variant}</Link></td>
                <td><SeverityTag severity={a.severity} /></td>
                <td>{a.detection_type.replaceAll('_', ' ').toLowerCase()}</td>
                <td>{a.investigation}</td>
                <td>{a.containment}</td>
                <td className="num">{a.created_at.slice(11, 19)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}
