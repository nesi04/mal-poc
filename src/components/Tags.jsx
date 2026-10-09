export function ResultTag({ result }) {
  const cls = result === 'Pass' ? 'tag tag-pass' : 'tag tag-fail'
  return <span className={cls}>{result}</span>
}

export function SeverityTag({ severity }) {
  return <span className={`tag tag-sev-${String(severity).toLowerCase()}`}>{severity}</span>
}

export function OriginTag({ origin }) {
  const label = origin === 'public' ? 'Public data' : 'Synthetic'
  return <span className={`tag tag-origin tag-origin-${origin}`}>{label}</span>
}

export function StatusTag({ status }) {
  const text = {
    observed: 'Seen',
    missing: 'Missing',
    not_expected: 'Not expected',
    unexpected: 'Unexpected',
  }[status] || status
  return <span className={`tag tag-status-${status}`}>{text}</span>
}
