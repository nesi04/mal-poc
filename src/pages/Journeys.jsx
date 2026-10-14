import { useMemo } from 'react'
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
  const scen = data.scenarios.find((s) => s.scenario_code === row.scenario_code)
  const t0 = journey.events.length ? new Date(journey.events[0].timestamp).getTime() : 0

  const groups = useMemo(() => {
    const m = new Map()
    rows.forEach((r) => {
      if (!m.has(r.scenario_code)) m.set(r.scenario_code, { code: r.scenario_code, name: r.scenario_name, rows: [] })
      m.get(r.scenario_code).rows.push(r)
    })
    return [...m.values()]
  }, [rows])

  return (
    <>
      <h1>Journey explorer</h1>
      <div className="split">
        <nav className="picker" aria-label="Choose a journey">
          {groups.map((g) => {
            const fails = g.rows.filter((r) => r.result === 'Fail').length
            return (
              <details key={g.code} open={g.code === row.scenario_code}>
                <summary>
                  <span className={`dot ${fails === 0 ? 'dot-pass' : 'dot-fail'}`} aria-hidden="true" />
                  <span className="pick-id">{g.code}</span>
                  <span className="pick-name">{g.name}</span>
                  <span className="pick-count">{g.rows.length - fails} of {g.rows.length} pass</span>
                </summary>
                <ul>
                  {g.rows.map((r) => (
                    <li key={r.test_id}>
                      <Link to={`/journeys/${r.test_id}`} aria-current={r.test_id === row.test_id ? 'page' : undefined}
                        className={r.test_id === row.test_id ? 'pick active' : 'pick'}>
                        <span className={`dot ${r.result === 'Pass' ? 'dot-pass' : 'dot-fail'}`} aria-hidden="true" />
                        <span className="pick-id">Variant {r.variant}</span>
                        <span className="pick-name">{r.test_id}</span>
                      </Link>
                    </li>
                  ))}
                </ul>
              </details>
            )
          })}
        </nav>

        <div className="detail">
          <header className="detail-head">
            <div>
              <h2>{row.scenario_code} {row.scenario_name}</h2>
              <p className="muted">Variant {row.variant} of {scen?.variants}, {row.test_id}. {row.domain_profile}</p>
              <p className="small">Campaign {row.campaign_id}, ad {row.ad_id}, platform {row.platform}. Intended signal: {scen?.intended_signal}.</p>
            </div>
            <ResultTag result={row.result} />
          </header>

          <JourneyRoute stages={journey.stages} title={`${row.scenario_code} variant ${row.variant}`} />
          <RouteLegend />

          <div className="facts">
            <dl>
              <div><dt>Ad shows</dt><dd>{row.display_domain}</dd></div>
              <div><dt>Redirect path</dt><dd>{row.hop_domains.join(' to ')}</dd></div>
              <div><dt>Expected detection</dt><dd>{yesNo(row.expected_detection)}</dd></div>
              <div><dt>Actual detection</dt><dd>{yesNo(row.actual_detection)}{row.detection_rule ? `, ${row.detection_rule}` : ''}</dd></div>
              <div><dt>Expected containment</dt><dd>{yesNo(row.expected_containment)}</dd></div>
              <div><dt>Actual containment</dt><dd>{yesNo(row.actual_containment)}</dd></div>
              <div><dt>Redirect hops</dt><dd>{row.logged_redirect_hops} logged of {row.expected_redirect_hops}</dd></div>
              <div><dt>Infrastructure (synthetic)</dt><dd>{row.infra.ad_account}, {row.infra.registrar}, {row.infra.hosting}</dd></div>
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
