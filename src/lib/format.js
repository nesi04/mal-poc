export const fmtSec = (s) => {
  if (s == null) return 'n/a'
  if (s < 60) return `${Math.round(s)}s`
  return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`
}

export const fmtTime = (iso) => (iso ? `${iso.slice(11, 19)} UTC` : 'not seen')

export const GAP_TEXT = {
  REDIRECT_HOP_MISSING: 'A redirect hop is missing from telemetry',
  DETECTION_MISSED: 'The expected detection did not fire',
  FALSE_POSITIVE: 'A legitimate destination was flagged and blocked',
  CONTAINMENT_FAILED: 'The block did not take effect',
  CLICK_NOT_CORRELATED: 'The click is not linked to its impression',
  LANDING_NOT_LOGGED: 'The landing event is missing from telemetry',
}

export const yesNo = (v) => (v ? 'Yes' : 'No')

export function groupByScenario(ids, codeOf) {
  const m = new Map()
  for (const id of ids) {
    const c = codeOf[id]
    if (!m.has(c)) m.set(c, [])
    m.get(c).push(id)
  }
  return [...m.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([code, list]) => ({ code, ids: list }))
}

export const median = (arr) => {
  const v = arr.filter((x) => x != null).sort((a, b) => a - b)
  if (!v.length) return null
  const m = Math.floor(v.length / 2)
  return v.length % 2 ? v[m] : (v[m - 1] + v[m]) / 2
}
