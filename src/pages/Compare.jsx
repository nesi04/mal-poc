import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useData } from '../lib/data.jsx'
import { GAP_TEXT, yesNo } from '../lib/format.js'
import { ResultTag } from '../components/Tags.jsx'

export default function Compare() {
  const { data, run } = useData()
  const [onlyFail, setOnlyFail] = useState(false)
  const all = data.test_cases[run]
  const rows = onlyFail ? all.filter((r) => r.result === 'Fail') : all

  const mismatch = (a, b) => (a !== b ? 'cell-gap' : '')

  return (
    <>
      <h1>Red team expected, blue team observed</h1>
      <p className="lede">
        Each row compares what the red team planned with what the blue team saw. A cell is marked when the two differ.
      </p>
      <label className="check">
        <input type="checkbox" checked={onlyFail} onChange={(e) => setOnlyFail(e.target.checked)} />
        Show failing tests only
      </label>
      <div className="table-wrap">
        <table className="compare">
          <thead>
            <tr>
              <th scope="col" rowSpan={2}>Test</th>
              <th scope="colgroup" colSpan={2}>Detection</th>
              <th scope="colgroup" colSpan={2}>Containment</th>
              <th scope="colgroup" colSpan={2}>Redirect hops</th>
              <th scope="col" rowSpan={2}>Gap</th>
              <th scope="col" rowSpan={2}>Result</th>
            </tr>
            <tr>
              <th scope="col">Expected</th><th scope="col">Actual</th>
              <th scope="col">Expected</th><th scope="col">Actual</th>
              <th scope="col">Expected</th><th scope="col">Logged</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.test_id}>
                <th scope="row">
                  <Link to={`/journeys/${r.test_id}`}>{r.scenario_code}</Link>
                  <span className="sub">{r.scenario_name}</span>
                </th>
                <td>{yesNo(r.expected_detection)}</td>
                <td className={mismatch(r.expected_detection, r.actual_detection)}>{yesNo(r.actual_detection)}</td>
                <td>{yesNo(r.expected_containment)}</td>
                <td className={mismatch(r.expected_containment, r.actual_containment)}>{yesNo(r.actual_containment)}</td>
                <td className="num">{r.expected_redirect_hops}</td>
                <td className={`num ${mismatch(r.expected_redirect_hops, r.logged_redirect_hops)}`}>{r.logged_redirect_hops}</td>
                <td>{r.gaps.length ? <ul className="plain">{r.gaps.map((g) => <li key={g}>{GAP_TEXT[g]}</li>)}</ul> : <span className="muted">None</span>}</td>
                <td><ResultTag result={r.result} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}
