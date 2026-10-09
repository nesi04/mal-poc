import { fmtTime } from '../lib/format.js'

const BLUE = new Set(['Detection', 'Alert', 'Triage', 'Containment'])
const COL_W = 118
const GUTTER = 108
const RED_Y = 84
const BLUE_Y = 214
const H = 296

const shortName = (s) => s.replace(' (test event)', '').replace(' (test artifact)', '')
const isBlue = (stage) => BLUE.has(stage)

function lineStyle(a, b) {
  const ok = (s) => s.status === 'observed'
  return ok(a) && ok(b) ? 'solid' : 'dashed'
}

export default function JourneyRoute({ stages, title }) {
  const n = stages.length
  const width = GUTTER + COL_W * n + 20
  const pos = stages.map((s, i) => ({
    ...s,
    x: GUTTER + COL_W * i + COL_W / 2,
    y: isBlue(s.stage) ? BLUE_Y : RED_Y,
    blue: isBlue(s.stage),
  }))

  const red = pos.filter((p) => !p.blue)
  const blue = pos.filter((p) => p.blue)
  const lastRed = [...red].reverse().find((p) => p.status !== 'not_expected') || red[red.length - 1]
  const firstBlue = blue[0]

  const segments = (list) =>
    list.slice(1).map((p, i) => {
      const a = list[i]
      const dashed = lineStyle(a, p) === 'dashed'
      return { x1: a.x, y1: a.y, x2: p.x, y2: p.y, dashed, key: `${a.stage}-${p.stage}` }
    })

  const summary = pos.map((p) => `${shortName(p.stage)}: ${p.status.replace('_', ' ')}`).join('. ')

  return (
    <div className="route-scroll">
      <svg
        className="route"
        width={width}
        height={H}
        viewBox={`0 0 ${width} ${H}`}
        role="img"
        aria-label={`Journey route for ${title}. ${summary}`}
      >
        <text x={0} y={RED_Y + 5} className="lane-caption lane-red">Red team</text>
        <text x={0} y={BLUE_Y + 5} className="lane-caption lane-blue">Blue team</text>
        <line x1={GUTTER - 14} y1={RED_Y} x2={width - 10} y2={RED_Y} className="lane-rail" />
        <line x1={GUTTER - 14} y1={BLUE_Y} x2={width - 10} y2={BLUE_Y} className="lane-rail" />

        {segments(red).map((s) => (
          <line key={s.key} x1={s.x1} y1={s.y1} x2={s.x2} y2={s.y2}
            className={`seg seg-red ${s.dashed ? 'seg-dashed' : ''}`} />
        ))}
        {segments(blue).map((s) => (
          <line key={s.key} x1={s.x1} y1={s.y1} x2={s.x2} y2={s.y2}
            className={`seg seg-blue ${s.dashed ? 'seg-dashed' : ''}`} />
        ))}

        {lastRed && firstBlue && (
          <path
            d={`M ${lastRed.x} ${lastRed.y + 10} C ${lastRed.x} ${(RED_Y + BLUE_Y) / 2}, ${firstBlue.x} ${(RED_Y + BLUE_Y) / 2}, ${firstBlue.x} ${firstBlue.y - 10}`}
            className="handoff"
          />
        )}

        {pos.map((p) => {
          const label = shortName(p.stage)
          const above = !p.blue
          const ly = above ? p.y - 24 : p.y + 30
          const ty = above ? p.y - 11 : p.y + 44
          return (
            <g key={p.stage}>
              <title>{`${p.stage}: ${p.status.replace('_', ' ')}${p.timestamp ? ' at ' + fmtTime(p.timestamp) : ''}${p.detail ? '. ' + p.detail : ''}`}</title>
              <circle
                cx={p.x} cy={p.y}
                r={p.status === 'not_expected' ? 5 : 9}
                className={`station station-${p.status} ${p.blue ? 'on-blue' : 'on-red'}`}
              />
              <text x={p.x} y={ly} textAnchor="middle" className="stn-label">{label}</text>
              <text x={p.x} y={ty} textAnchor="middle" className="stn-time">
                {p.status === 'missing' ? 'missing' : p.status === 'not_expected' ? 'not expected' : fmtTime(p.timestamp).replace(' UTC', '')}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}

export function RouteLegend() {
  return (
    <ul className="legend" aria-label="Route legend">
      <li><span className="swatch sw-observed" />Seen in telemetry</li>
      <li><span className="swatch sw-missing" />Expected but missing</li>
      <li><span className="swatch sw-notexpected" />Not expected for this test</li>
      <li><span className="swatch sw-unexpected" />Happened but should not have</li>
    </ul>
  )
}
