import { Link } from 'react-router-dom'
import { useData } from '../lib/data.jsx'
import { fmtSec, GAP_TEXT } from '../lib/format.js'
import { ResultTag } from '../components/Tags.jsx'

const pct = (v) => (v == null ? 'n/a' : `${v}%`)

const ROWS = [
  { group: 'Visibility', label: 'Impression to click', get: (k) => k.impression_click_visibility.value, fmt: pct, unit: 'pts', better: 'up',
    sub: (k) => `${k.impression_click_visibility.num} of ${k.impression_click_visibility.den} clicks linked to their impression` },
  { group: 'Visibility', label: 'Click to landing', get: (k) => k.click_landing_visibility.value, fmt: pct, unit: 'pts', better: null,
    sub: (k) => `${k.click_landing_visibility.blocked_inline} blocked before landing, ${k.click_landing_visibility.missing_telemetry} lost in telemetry` },
  { group: 'Visibility', label: 'Redirect inspection', get: (k) => k.redirect_inspection.value, fmt: pct, unit: 'pts', better: 'up',
    sub: (k) => `${k.redirect_inspection.num} of ${k.redirect_inspection.den} hops logged` },
  { group: 'Visibility', label: 'Evidence completeness', get: (k) => k.evidence_completeness.value, fmt: pct, unit: 'pts', better: 'up',
    sub: (k) => `${k.evidence_completeness.num} of ${k.evidence_completeness.den} expected items captured` },
  { group: 'Visibility', label: 'Journey reconstruction', get: (k) => k.journey_reconstruction.value, fmt: pct, unit: 'pts', better: 'up',
    sub: (k) => `${k.journey_reconstruction.num} of ${k.journey_reconstruction.den} journeys fully reconstructable` },
  { group: 'Detection', label: 'Detection coverage', get: (k) => k.detection_coverage.value, fmt: pct, unit: 'pts', better: 'up',
    sub: (k) => `${k.detection_coverage.num} of ${k.detection_coverage.den} attack paths detected` },
  { group: 'Detection', label: 'Identity protection', get: (k) => k.identity_protection.value, fmt: pct, unit: 'pts', better: 'up',
    sub: (k) => `${k.identity_protection.num} of ${k.identity_protection.den} credential tests detected` },
  { group: 'Detection', label: 'Alerts raised', get: (k) => k.alerts.total, fmt: (v) => String(v), unit: '', better: null,
    sub: (k) => `${k.alerts.true_positive} true, ${k.alerts.false_positive} false` },
  { group: 'Response speed', label: 'Time to detection (mean)', get: (k) => k.ttd.mean, fmt: fmtSec, unit: 's', better: null,
    sub: (k) => `median ${fmtSec(k.ttd.median)}, ${k.ttd.n} tests` },
  { group: 'Response speed', label: 'Time to triage (mean)', get: (k) => k.ttt.mean, fmt: fmtSec, unit: 's', better: null,
    sub: (k) => `median ${fmtSec(k.ttt.median)}, ${k.ttt.n} incidents` },
  { group: 'Response speed', label: 'Time to containment (mean)', get: (k) => k.ttc.mean, fmt: fmtSec, unit: 's', better: null,
    sub: (k) => `median ${fmtSec(k.ttc.median)}, ${k.ttc.n} contained` },
  { group: 'Containment', label: 'Containment success', get: (k) => k.containment_success.value, fmt: pct, unit: 'pts', better: 'up',
    sub: (k) => `${k.containment_success.num} of ${k.containment_success.den} attack paths contained` },
  { group: 'Containment', label: 'Blocking propagation (mean)', get: (k) => k.blocking_propagation.mean, fmt: fmtSec, unit: 's', better: null,
    sub: (k) => `median ${fmtSec(k.blocking_propagation.median)}` },
  { group: 'Safety', label: 'Legitimate destinations flagged', get: (k) => k.false_positive.legitimate_with_incident, fmt: (v) => String(v), unit: '', better: 'down',
    sub: (k) => `of ${k.false_positive.legitimate_tested} tested, ${k.false_positive.legitimate_blocked} blocked` },
]

function change(row, a, b) {
  if (a == null || b == null) return { text: 'n/a', cls: 'same' }
  const d = Math.round((b - a) * 10) / 10
  if (d === 0) return { text: 'no change', cls: 'same' }
  const sign = d > 0 ? '+' : '-'
  const abs = Math.abs(d)
  const unit = row.unit === 'pts' ? ` pts` : row.unit === 's' ? 's' : ''
  let cls = 'same'
  if (row.better === 'up') cls = d > 0 ? 'better' : 'worse'
  if (row.better === 'down') cls = d < 0 ? 'better' : 'worse'
  return { text: `${sign}${abs}${unit}`, cls }
}

export default function Overview() {
  const { data, run } = useData()
  const km = data.metrics.runs
  const k = km[run].kpis
  const rows = data.test_cases[run]
  const failing = rows.filter((r) => r.result === 'Fail')
  const runInfo = data.meta.runs[run]
  const groups = [...new Set(ROWS.map((r) => r.group))]

  return (
    <>
      <h1>Can we see the journey, detect it and stop it?</h1>
      <p className="lede">
        In the {runInfo.label.toLowerCase()} run, {k.detection_coverage.num} of {k.detection_coverage.den} attack paths
        were detected and {k.containment_success.num} were contained. {k.totals.pass_} of {k.totals.tests} tests passed.
      </p>
      <p className="muted small">{runInfo.description}</p>

      <section aria-labelledby="tests-h">
        <h2 id="tests-h">Test results</h2>
        <ul className="tiles">
          {rows.map((r) => (
            <li key={r.test_id}>
              <Link to={`/journeys/${r.test_id}`} className={`tile ${r.result === 'Pass' ? 'tile-pass' : 'tile-fail'}`}>
                <span className="tile-code">{r.scenario_code}</span>
                <span className="tile-name">{r.scenario_name}</span>
                <span className="tile-res">{r.result === 'Pass' ? 'Pass' : `${r.gaps.length} gap${r.gaps.length === 1 ? '' : 's'}`}</span>
              </Link>
            </li>
          ))}
        </ul>
      </section>

      <section aria-labelledby="score-h">
        <h2 id="score-h">Scorecard, baseline against retest</h2>
        <div className="table-wrap">
          <table className="score">
            <thead>
              <tr>
                <th scope="col">Metric</th>
                <th scope="col" className={run === 'baseline' ? 'col-active' : ''}>Baseline</th>
                <th scope="col" className={run === 'retest' ? 'col-active' : ''}>Retest</th>
                <th scope="col">Change</th>
              </tr>
            </thead>
            {groups.map((g) => (
              <tbody key={g}>
                <tr className="group-row"><th colSpan={4} scope="colgroup">{g}</th></tr>
                {ROWS.filter((r) => r.group === g).map((r) => {
                  const kb = km.baseline.kpis
                  const kr = km.retest.kpis
                  const ch = change(r, r.get(kb), r.get(kr))
                  return (
                    <tr key={r.label}>
                      <th scope="row">{r.label}</th>
                      <td className={run === 'baseline' ? 'col-active' : ''}>
                        <span className="val">{r.fmt(r.get(kb), kb)}</span>
                        <span className="sub">{r.sub(kb)}</span>
                      </td>
                      <td className={run === 'retest' ? 'col-active' : ''}>
                        <span className="val">{r.fmt(r.get(kr), kr)}</span>
                        <span className="sub">{r.sub(kr)}</span>
                      </td>
                      <td><span className={`delta delta-${ch.cls}`}>{ch.text}</span></td>
                    </tr>
                  )
                })}
              </tbody>
            ))}
          </table>
        </div>
        <p className="muted small">
          Timing rows are not marked better or worse because the set of detected tests changes between runs.
          Detection, triage and containment timings are simulated.
        </p>
      </section>

      <section aria-labelledby="attn-h">
        <h2 id="attn-h">Needs attention in this run</h2>
        {failing.length === 0 ? (
          <p>Every test in this run matched its expected outcome.</p>
        ) : (
          <ul className="attn">
            {failing.map((r) => (
              <li key={r.test_id}>
                <div>
                  <strong>{r.scenario_code} {r.scenario_name}</strong>
                  <ResultTag result={r.result} />
                </div>
                <ul>
                  {r.gaps.map((g) => <li key={g}>{GAP_TEXT[g]}</li>)}
                </ul>
                <Link to={`/journeys/${r.test_id}`}>Open journey</Link>
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  )
}
