import { useState } from 'react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { useData } from '../lib/data.jsx'
import { fmtSec, median } from '../lib/format.js'

const SERIES = [
  { key: 'ttd_s', label: 'Time to detection', bin: 10, color: '#2457C5' },
  { key: 'ttt_s', label: 'Time to triage', bin: 15, color: '#6C8FD8' },
  { key: 'ttc_s', label: 'Time to containment', bin: 30, color: '#16202E' },
  { key: 'propagation_s', label: 'Blocking propagation', bin: 15, color: '#1B8A6B' },
]

function histogram(values, bin) {
  const v = values.filter((x) => x != null)
  if (!v.length) return []
  const n = Math.floor(Math.max(...v) / bin) + 1
  const out = Array.from({ length: n }, (_, i) => ({ range: `${i * bin}-${(i + 1) * bin}`, count: 0 }))
  v.forEach((x) => { out[Math.floor(x / bin)].count += 1 })
  return out
}

export default function Metrics() {
  const { data, run } = useData()
  const [sel, setSel] = useState('ttd_s')
  const { definitions, runs } = data.metrics
  const k = runs[run].kpis
  const per = runs[run].per_test
  const series = SERIES.find((s) => s.key === sel)
  const hist = histogram(per.map((p) => p[sel]), series.bin)
  const cats = [...new Set(definitions.map((d) => d.category))]
  const statRows = [
    ['Time to detection', k.ttd], ['Time to triage', k.ttt],
    ['Time to containment', k.ttc], ['Blocking propagation', k.blocking_propagation],
  ]
  const codes = [...new Set(per.map((p) => p.scenario_code))]
  const byScenario = codes.map((c) => {
    const rs = per.filter((p) => p.scenario_code === c)
    return { code: c, name: data.scenarios.find((s) => s.scenario_code === c)?.scenario_name, n: rs.length,
      ttd: median(rs.map((r) => r.ttd_s)), ttt: median(rs.map((r) => r.ttt_s)), ttc: median(rs.map((r) => r.ttc_s)),
      detected: rs.filter((r) => r.ttd_s != null).length }
  })

  return (
    <>
      <h1>Metrics</h1>
      <p className="lede">Every figure here is calculated from the synthetic event tables. Timings are simulated.</p>

      <h2>How the timings are distributed</h2>
      <div className="seg-toggle" role="group" aria-label="Choose a timing metric">
        {SERIES.map((s) => (
          <button key={s.key} type="button" aria-pressed={sel === s.key} className={sel === s.key ? 'on' : ''} onClick={() => setSel(s.key)}>
            {s.label}
          </button>
        ))}
      </div>
      <div className="chart-box" role="img"
        aria-label={`Histogram of ${series.label.toLowerCase()} across ${hist.reduce((a, h) => a + h.count, 0)} journeys, in ${series.bin} second bins`}>
        <ResponsiveContainer width="100%" height={280}>
          <BarChart data={hist} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid stroke="#D5DAE1" vertical={false} />
            <XAxis dataKey="range" tick={{ fontSize: 11 }} height={44}
              label={{ value: `Seconds (${series.bin} second bins)`, position: 'insideBottom', offset: -2, fontSize: 12 }} />
            <YAxis allowDecimals={false} tick={{ fontSize: 12 }} label={{ value: 'Journeys', angle: -90, position: 'insideLeft', fontSize: 12 }} />
            <Tooltip formatter={(v) => [`${v} journeys`, series.label]} />
            <Bar dataKey="count" fill={series.color} />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <p className="muted small">Only journeys where the step happened are counted. Undetected or failed-containment journeys have no value.</p>

      <h2>Timing statistics</h2>
      <div className="table-wrap">
        <table>
          <thead><tr><th scope="col">Metric</th><th scope="col">Journeys</th><th scope="col">Mean</th><th scope="col">Median</th><th scope="col">Min</th><th scope="col">Max</th></tr></thead>
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

      <h2>Median timings by scenario</h2>
      <div className="table-wrap">
        <table>
          <thead><tr><th scope="col">Scenario</th><th scope="col">Journeys</th><th scope="col">Detected</th><th scope="col">Detection</th><th scope="col">Triage</th><th scope="col">Containment</th></tr></thead>
          <tbody>
            {byScenario.map((r) => (
              <tr key={r.code}>
                <th scope="row">{r.code}<span className="sub">{r.name}</span></th>
                <td className="num">{r.n}</td><td className="num">{r.detected}</td>
                <td className="num">{fmtSec(r.ttd)}</td><td className="num">{fmtSec(r.ttt)}</td><td className="num">{fmtSec(r.ttc)}</td>
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
