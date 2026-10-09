import { useData } from '../lib/data.jsx'
import { yesNo } from '../lib/format.js'
import { OriginTag } from '../components/Tags.jsx'

export default function Scenarios() {
  const { data } = useData()
  const rows = data.scenarios
  return (
    <>
      <h1>Red team scenarios</h1>
      <p className="lede">
        {rows.length} controlled journeys. Each one is modelled on a pattern from the case studies. All domains are reserved
        .test names, and no real ad platform, credential or malware is involved.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Scenario</th><th scope="col">Campaign</th><th scope="col">Ad shows</th><th scope="col">Lands on</th>
              <th scope="col">Hops</th><th scope="col">Expected detection</th><th scope="col">Modelled on</th><th scope="col">Data</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.test_id}>
                <th scope="row">{s.scenario_code}<span className="sub">{s.scenario_name}</span></th>
                <td>{s.campaign_id}<span className="sub">{s.campaign_type}, {s.keyword_class}</span></td>
                <td>{s.display_domain}</td>
                <td>{s.final_domain}{s.display_final_mismatch && <span className="sub">differs from the displayed domain</span>}</td>
                <td className="num">{s.expected_redirect_hops}</td>
                <td>{yesNo(s.expected_detection)}</td>
                <td>{s.pattern}</td>
                <td><OriginTag origin={s.data_origin} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}
