import { Link } from 'react-router-dom'
import { groupByScenario } from '../lib/format.js'

// Shows a set of journeys as "MAL-001 x8, MAL-002 x3", each linking to the first journey in the group.
export default function ScenarioCounts({ ids, codeOf }) {
  if (!ids || ids.length === 0) return <span className="muted">None</span>
  const groups = groupByScenario(ids, codeOf)
  return (
    <span className="codes">
      {groups.map((g, i) => (
        <span key={g.code}>
          <Link to={`/journeys/${g.ids[0]}`}>{g.code}</Link>
          {g.ids.length > 1 ? ` \u00d7${g.ids.length}` : ''}
          {i < groups.length - 1 ? ', ' : ''}
        </span>
      ))}
    </span>
  )
}
