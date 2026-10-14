import { Link } from 'react-router-dom'
import { useData } from '../lib/data.jsx'
import { SeverityTag } from '../components/Tags.jsx'
import { GAP_TEXT } from '../lib/format.js'

const gapList = (gaps) => (gaps.length ? gaps.map((g) => GAP_TEXT[g]).join('; ') : 'No gaps')

export default function Findings() {
  const { data } = useData()
  const { findings, severity_method } = data.findings
  const open = findings.filter((f) => f.status === 'Open').length
  const partial = findings.filter((f) => f.status.startsWith('Partially')).length
  const fixed = findings.length - open - partial
  const ordered = [...findings].sort((a, b) => (a.status === 'Open' ? 0 : 1) - (b.status === 'Open' ? 0 : 1) || a.finding_id.localeCompare(b.finding_id))

  return (
    <>
      <h1>Findings and retest</h1>
      <p className="lede">
        The baseline run produced {findings.length} findings. A control gap affects every variant of a scenario, so each finding
        covers a whole scenario. After the simulated fixes, {fixed} were verified in the retest
        {partial ? `, ${partial} were partly fixed` : ''} and {open} are still open.
      </p>
      <p className="muted small">
        A fix is only verified for the POC scenario it was tested on. It says nothing about other journeys. Severity method: {severity_method}
      </p>

      <h2>Finding register</h2>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">ID</th><th scope="col">Scenario</th><th scope="col">Finding</th><th scope="col">Severity</th>
              <th scope="col">Journeys affected</th><th scope="col">Impact</th><th scope="col">Remediation</th><th scope="col">Status</th>
            </tr>
          </thead>
          <tbody>
            {ordered.map((f) => (
              <tr key={f.finding_id}>
                <th scope="row" className="num">{f.finding_id}</th>
                <td><Link to={`/journeys/${f.test_id}`}>{f.scenario_code}</Link></td>
                <td>{f.finding_title}</td>
                <td><SeverityTag severity={f.severity} /></td>
                <td className="num">{f.affected_count}</td>
                <td>{f.impact}</td>
                <td>{f.remediation}</td>
                <td>
                  <span className={f.status === 'Open' ? 'status-open' : 'status-done'}>{f.status}</span>
                  <span className="sub">{f.retest_status}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2>Before and after, by scenario</h2>
      <div className="table-wrap">
        <table>
          <thead>
            <tr><th scope="col">Scenario</th><th scope="col">Baseline</th><th scope="col">Retest</th><th scope="col">What changed</th></tr>
          </thead>
          <tbody>
            {data.retest.map((r) => (
              <tr key={r.scenario_code}>
                <th scope="row">
                  <Link to={`/journeys/${r.first_test_id}`}>{r.scenario_code}</Link>
                  <span className="sub">{r.scenario_name}</span>
                </th>
                <td>
                  <span className={r.baseline.failed ? 'status-open' : 'status-done'}>{r.baseline.passed} of {r.baseline.journeys} pass</span>
                  <span className="sub">{gapList(r.baseline.gaps)}</span>
                </td>
                <td>
                  <span className={r.retest.failed ? 'status-open' : 'status-done'}>{r.retest.passed} of {r.retest.journeys} pass</span>
                  <span className="sub">{gapList(r.retest.gaps)}</span>
                </td>
                <td>{r.fixes_applied.length ? r.fixes_applied.join(' ') : r.changed ? 'Result changed' : 'No change'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}
