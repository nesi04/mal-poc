import { createContext, useContext, useEffect, useState } from 'react'

const FILES = ['meta', 'metrics', 'test_cases', 'journeys', 'findings', 'retest', 'scenarios']
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
