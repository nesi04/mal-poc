import { Link } from 'react-router-dom'
import { useData } from '../lib/data.jsx'
import { yesNo } from '../lib/format.js'
import { OriginTag } from '../components/Tags.jsx'

export default function RedTeam() {
  const { data } = useData()
  const red = data.views.red
  const rows = data.scenarios
  const items = [
    ['Scenarios', red.scenarios], ['Journeys', red.journeys], ['Campaigns', red.campaigns], ['Ads', red.ads],
    ['Impressions', red.impressions], ['Clicks', red.clicks], ['Redirect hops', red.redirect_hops],
    ['Landings', red.landings], ['Credential test events', red.credential_tests],
    ['Download test events', red.download_tests], ['Expected detections', red.expected_detections],
    ['Expected containments', red.expected_containments], ['Benign controls', red.benign_controls],
  ]

  return (
    <>
      <h1>What did the red team run?</h1>
      <p className="lede">
        {red.journeys} controlled journeys from {red.scenarios} scenarios, {red.variants_per_scenario} variants each. Each one is
        modelled on a pattern from the case studies. All domains are reserved .test names, and no real ad platform, credential
        or malware is involved.
      </p>

      <h2>What was executed</h2>
      <dl className="summary">
        {items.map(([label, value]) => (
          <div key={label}><dt>{label}</dt><dd>{value}</dd></div>
        ))}
      </dl>
      <p className="muted small">{red.note} This page does not change with the Baseline and Retest switch, because the red team plan is the same in both runs.</p>

      <h2>Scenario catalog</h2>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Scenario</th><th scope="col">Campaign</th><th scope="col">Ad shows</th><th scope="col">Lands on</th>
              <th scope="col">Hops</th><th scope="col">Variants</th><th scope="col">Expected detection</th>
              <th scope="col">Modelled on</th><th scope="col">Data</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.scenario_code}>
                <th scope="row">
                  <Link to={`/journeys/${s.test_ids[0]}`}>{s.scenario_code}</Link>
                  <span className="sub">{s.scenario_name}</span>
                </th>
                <td>{s.campaign_id}<span className="sub">{s.campaign_type}, {s.keyword_class}</span></td>
                <td>{s.display_domain}</td>
                <td>{s.final_domain}{s.display_final_mismatch && <span className="sub">differs from the displayed domain</span>}</td>
                <td className="num">{s.hops_min === s.hops_max ? s.hops_min : `${s.hops_min} to ${s.hops_max}`}</td>
                <td className="num">{s.variants}</td>
                <td>{yesNo(s.expected_detection)}</td>
                <td>{s.pattern}<span className="sub">{s.intended_signal}</span></td>
                <td><OriginTag origin={s.data_origin} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small">Domains shown are the first variant. Later variants add a version prefix such as v2.</p>
    </>
  )
}
