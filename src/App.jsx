import { HashRouter, NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { DataProvider, useData } from './lib/data.jsx'
import Overview from './pages/Overview.jsx'
import Journeys from './pages/Journeys.jsx'
import Compare from './pages/Compare.jsx'
import Findings from './pages/Findings.jsx'
import Metrics from './pages/Metrics.jsx'
import Scenarios from './pages/Scenarios.jsx'

const NAV = [
  ['/', 'Overview'],
  ['/journeys', 'Journey explorer'],
  ['/compare', 'Red vs blue'],
  ['/findings', 'Findings and retest'],
  ['/metrics', 'Metrics'],
  ['/scenarios', 'Red team scenarios'],
]

function Shell() {
  const { data, error, run, setRun } = useData()

  if (error) {
    return (
      <main className="state">
        <h1>The data files could not be loaded</h1>
        <p>{error}</p>
        <p>Run the pipeline first: <code>python pipeline/run_pipeline.py</code>. It writes the JSON files into <code>public/data</code>.</p>
      </main>
    )
  }
  if (!data) return <main className="state"><p>Loading the test data</p></main>

  return (
    <div className="app">
      <div className="banner" role="note">
        <ul className="labels" aria-label="Data labels">
          {data.meta.labels.map((l) => <li key={l}>{l}</li>)}
        </ul>
        <span>All events are simulated. No Microsoft Sentinel, Bing or production telemetry is used.</span>
      </div>
      <header className="top">
        <div>
          <p className="brand">{data.meta.title}</p>
          <p className="muted small">{data.meta.subtitle}. Public and synthetic data.</p>
        </div>
        <fieldset className="runswitch">
          <legend>Run shown</legend>
          {Object.entries(data.meta.runs).map(([id, r]) => (
            <label key={id} className={run === id ? 'on' : ''}>
              <input type="radio" name="run" value={id} checked={run === id} onChange={() => setRun(id)} />
              {r.label}
            </label>
          ))}
        </fieldset>
      </header>
      <div className="body">
        <nav className="side" aria-label="Pages">
          <ul>
            {NAV.map(([to, label]) => (
              <li key={to}><NavLink to={to} end={to === '/'}>{label}</NavLink></li>
            ))}
          </ul>
        </nav>
        <main className="main">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/journeys" element={<Journeys />} />
            <Route path="/journeys/:testId" element={<Journeys />} />
            <Route path="/compare" element={<Compare />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/metrics" element={<Metrics />} />
            <Route path="/scenarios" element={<Scenarios />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <HashRouter>
      <DataProvider><Shell /></DataProvider>
    </HashRouter>
  )
}
