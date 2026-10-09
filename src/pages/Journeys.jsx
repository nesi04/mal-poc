import { Link, useParams } from 'react-router-dom'
import { useData } from '../lib/data.jsx'
import { fmtTime, GAP_TEXT, yesNo } from '../lib/format.js'
import JourneyRoute, { RouteLegend } from '../components/JourneyRoute.jsx'
import { ResultTag, StatusTag, OriginTag } from '../components/Tags.jsx'

export default function Journeys() {
  const { testId } = useParams()
  const { data, run } = useData()
  const rows = data.test_cases[run]
  const row = rows.find((r) => r.test_id === testId) || rows[0]
  const journey = data.journeys[run][row.test_id]
  const scen = data.scenarios.find((s) => s.test_id === row.test_id)
  const t0 = journey.events.length ? new Date(journey.events[0].timestamp).getTime() : 0

  return (
    <>
      <h1>Journey explorer</h1>
      <div className="split">
        <nav className="picker" aria-label="Choose a test">
          <ul>
            {rows.map((r) => (
              <li key={r.test_id}>
                <Link to={`/journeys/${r.test_id}`} aria-current={r.test_id === row.test_id ? 'page' : undefined}
                  className={r.test_id === row.test_id ? 'pick active' : 'pick'}>
                  <span className={`dot ${r.result === 'Pass' ? 'dot-pass' : 'dot-fail'}`} aria-hidden="true" />
                  <span className="pick-id">{r.test_id}</span>
                  <span className="pick-name">{r.scenario_name}</span>
                </Link>
              </li>
            ))}
          </ul>
        </nav>

        <div className="detail">
          <header className="detail-head">
            <div>
              <h2>{row.scenario_code} {row.scenario_name}</h2>
              <p className="muted">{row.domain_profile}</p>
              <p className="small">Campaign {row.campaign_id}, ad {row.ad_id}, platform {row.platform}. Intended signal: {scen?.intended_signal}.</p>
            </div>
            <ResultTag result={row.result} />
          </header>

          <JourneyRoute stages={journey.stages} title={`${row.scenario_code} ${row.scenario_name}`} />
          <RouteLegend />

          <div className="facts">
            <dl>
              <div><dt>Expected detection</dt><dd>{yesNo(row.expected_detection)}</dd></div>
              <div><dt>Actual detection</dt><dd>{yesNo(row.actual_detection)}{row.detection_rule ? `, ${row.detection_rule}` : ''}</dd></div>
              <div><dt>Expected containment</dt><dd>{yesNo(row.expected_containment)}</dd></div>
              <div><dt>Actual containment</dt><dd>{yesNo(row.actual_containment)}</dd></div>
              <div><dt>Redirect hops</dt><dd>{row.logged_redirect_hops} logged of {row.expected_redirect_hops}</dd></div>
            </dl>
            <div>
              <h3>Gaps</h3>
              {row.gaps.length === 0 ? <p>None. Expected and actual match.</p> : (
                <ul>{row.gaps.map((g) => <li key={g}>{GAP_TEXT[g]}</li>)}</ul>
              )}
            </div>
          </div>

          <h3>Evidence checklist</h3>
          <ul className="evidence">
            {Object.entries(journey.evidence).map(([name, v]) => {
              const state = !v.expected ? 'na' : v.captured ? 'yes' : 'no'
              return (
                <li key={name} className={`ev ev-${state}`}>
                  <span className="ev-mark" aria-hidden="true">{state === 'yes' ? '\u2713' : state === 'no' ? '\u2717' : '\u2013'}</span>
                  <span>{name}</span>
                  <span className="ev-state">{state === 'yes' ? 'captured' : state === 'no' ? 'missing' : 'not expected'}</span>
                </li>
              )
            })}
          </ul>

          <h3>Stages</h3>
          <div className="table-wrap">
            <table>
              <thead><tr><th scope="col">Stage</th><th scope="col">Time</th><th scope="col">Status</th><th scope="col">Note</th></tr></thead>
              <tbody>
                {journey.stages.map((s) => (
                  <tr key={s.stage}>
                    <th scope="row">{s.stage}</th>
                    <td className="num">{fmtTime(s.timestamp)}</td>
                    <td><StatusTag status={s.status} /></td>
                    <td>{s.detail || s.domain || ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <h3>Event log</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th scope="col">Event</th><th scope="col">Elapsed</th><th scope="col">Type</th><th scope="col">Team</th><th scope="col">Domain</th><th scope="col">Data</th></tr>
              </thead>
              <tbody>
                {journey.events.map((e) => (
                  <tr key={e.event_id}>
                    <th scope="row" className="num">{e.event_id}</th>
                    <td className="num">+{Math.round((new Date(e.timestamp).getTime() - t0) / 1000)}s</td>
                    <td>{e.event_type.replaceAll('_', ' ').toLowerCase()}{e.hop_number ? ` ${e.hop_number}` : ''}</td>
                    <td>{e.source === 'red_team' ? 'Red' : 'Blue'}</td>
                    <td>{e.domain || ''}</td>
                    <td><OriginTag origin={e.data_origin} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  )
}
