import { createContext, useContext, useEffect, useMemo, useState } from 'react'

const FILES = ['meta', 'metrics', 'test_cases', 'journeys', 'findings', 'retest', 'scenarios', 'chokepoints', 'views', 'data_sources']
const Ctx = createContext(null)

export function DataProvider({ children }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [run, setRun] = useState('baseline')

  useEffect(() => {
    Promise.all(
      FILES.map((f) =>
        fetch(`${import.meta.env.BASE_URL}data/${f}.json`).then((r) => {
          if (!r.ok) throw new Error(`${f}.json returned ${r.status}`)
          return r.json()
        })
      )
    )
      .then((arr) => setData(Object.fromEntries(FILES.map((f, i) => [f, arr[i]]))))
      .catch((e) => setError(e.message))
  }, [])

  return <Ctx.Provider value={{ data, error, run, setRun }}>{children}</Ctx.Provider>
}

export const useData = () => useContext(Ctx)

// test_id -> scenario code, used to show many journeys as "MAL-001 x8" instead of long lists
export function useCodeOf() {
  const { data } = useData()
  return useMemo(() => Object.fromEntries(data.test_cases.baseline.map((r) => [r.test_id, r.scenario_code])), [data])
}
