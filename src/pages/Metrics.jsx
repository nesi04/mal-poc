import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { useData } from '../lib/data.jsx'
import { fmtSec } from '../lib/format.js'

export default function Metrics() {
  const { data, run } = useData()
  const { definitions, runs } = data.metrics
  const k = runs[run].kpis
  const perTest = runs[run].per_test.map((p) => ({
    name: p.scenario_code.replace('MAL-', ''),
    'Time to detection': p.ttd_s,
    'Time to triage': p.ttt_s,
    'Time to containment': p.ttc_s,
  }))
  const cats = [...new Set(definitions.map((d) => d.category))]
  const statRows = [
    ['Time to detection', k.ttd], ['Time to triage', k.ttt],
    ['Time to containment', k.ttc], ['Blocking propagation', k.blocking_propagation],
  ]

  return (
    <>
      <h1>Metrics</h1>
      <p className="lede">Every figure here is calculated from the synthetic event tables. Timings are simulated.</p>

      <h2>Timing per test</h2>
      <div className="chart-box" role="img" aria-label="Bar chart of detection, triage and containment times for each test, in seconds">
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={perTest} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid stroke="#D5DAE1" vertical={false} />
            <XAxis dataKey="name" tick={{ fontSize: 12 }} label={{ value: 'MAL scenario number', position: 'insideBottom', offset: -2, fontSize: 12 }} height={40} />
            <YAxis tick={{ fontSize: 12 }} label={{ value: 'Seconds', angle: -90, position: 'insideLeft', fontSize: 12 }} />
            <Tooltip formatter={(v) => (v == null ? 'n/a' : fmtSec(v))} />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            <Bar dataKey="Time to detection" fill="#2457C5" />
            <Bar dataKey="Time to triage" fill="#7C9BE0" />
            <Bar dataKey="Time to containment" fill="#16202E" />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <p className="muted small">A missing bar means the step did not happen for that test, for example no detection or a failed block.</p>

      <h2>Timing statistics</h2>
      <div className="table-wrap">
        <table>
          <thead><tr><th scope="col">Metric</th><th scope="col">Tests</th><th scope="col">Mean</th><th scope="col">Median</th><th scope="col">Min</th><th scope="col">Max</th></tr></thead>
          <tbody>
            {statRows.map(([name, s]) => (
              <tr key={name}>
                <th scope="row">{name}</th>
                <td className="num">{s.n}</td><td className="num">{fmtSec(s.mean)}</td><td className="num">{fmtSec(s.median)}</td>
                <td className="num">{fmtSec(s.min)}</td><td className="num">{fmtSec(s.max)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2>Definitions</h2>
      <p className="muted small">
        Attack event is the first redirect hop. Time to detection runs from the attack event to detection.
        Time to containment runs from alert creation to the block taking effect.
      </p>
      {cats.map((c) => (
        <section key={c}>
          <h3>{c}</h3>
          <dl className="defs">
            {definitions.filter((d) => d.category === c).map((d) => (
              <div key={d.id}>
                <dt>{d.name}</dt>
                <dd>
                  <span className="formula">{d.formula}</span>
                  {d.note && <span className="sub">{d.note}</span>}
                </dd>
              </div>
            ))}
          </dl>
        </section>
      ))}
    </>
  )
}
