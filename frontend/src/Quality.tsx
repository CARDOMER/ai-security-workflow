import { useState } from 'react'

const categories = ['SECRET', 'SCA', 'SAST'] as const
type Category = typeof categories[number]
type Counts = { expected: number; matched: number; missed: number; unexpected: number }
type Location = {
  id: string | number; category: Category; path: string; class?: string; line?: number; endLine?: number
  group?: string; artifact?: string; version?: string; advisoryId?: string; advisoryIds?: string[]
}
type QualityResult = {
  total: Counts; byCategory: Record<Category, Counts>; missed: Location[]; unexpected: Location[]
  controls: { total: number; hits: Location[] }
}

function CountsRow({ label, counts }: { label: string; counts: Counts }) {
  return <tr><th scope="row">{label}</th><td>{counts.expected}</td><td>{counts.matched}</td>
    <td>{counts.missed}</td><td>{counts.unexpected}</td></tr>
}

function Locations({ label, items }: { label: string; items: Location[] }) {
  return <details>
    <summary>{label} · {items.length}</summary>
    {items.length ? <ul>{items.map(item => <li key={item.id}>
      <strong>{item.category}</strong>{' · '}
      <code>{item.category === 'SCA' ? `${item.group}:${item.artifact}:${item.version}` : item.class}</code>
      {item.advisoryId && <> · <code>{item.advisoryId}</code></>}
      {!!item.advisoryIds?.length && <> · <code>{item.advisoryIds.join(', ')}</code></>}
      {' · '}<code className="path">{item.path}{item.line && `:${item.line}`}{item.endLine && item.endLine !== item.line && `–${item.endLine}`}</code>
    </li>)}</ul> : <p>Нет находок.</p>}
  </details>
}

export function Quality() {
  const [result, setResult] = useState<QualityResult | null>(null)
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)

  async function check() {
    setPending(true)
    setError('')
    setResult(null)
    try {
      const response = await fetch('/api/quality', { method: 'POST', signal: AbortSignal.timeout(20000) })
      const data = await response.json()
      if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Не удалось сверить результаты.')
      setResult(data)
    } catch (problem) {
      setError(problem instanceof Error && problem.name === 'Error' ? problem.message : 'Не удалось сверить результаты. Проверьте связь с сервером.')
    } finally {
      setPending(false)
    }
  }

  return <section className="panel quality" aria-labelledby="quality" aria-busy={pending}>
    <div className="results-title">
      <h2 id="quality">Качество анализа</h2>
      <button className="secondary" type="button" disabled={pending} onClick={() => void check()}>Сверить с эталоном Repair Desk</button>
    </div>
    {pending && <p className="empty status" role="status">Запускаем три анализатора и сверяем их находки…</p>}
    {error && <p className="empty alert" role="alert">{error}</p>}
    {result && <>
      <div className="table-wrap"><table>
        <thead><tr><th scope="col">Категория</th><th scope="col">Ожидаемые</th><th scope="col">Совпадения</th>
          <th scope="col">Пропуски</th><th scope="col">Лишние срабатывания</th></tr></thead>
        <tbody>{categories.map(category => <CountsRow key={category} label={category} counts={result.byCategory[category]} />)}</tbody>
        <tfoot><CountsRow label="Всего" counts={result.total} /></tfoot>
      </table></div>
      <div className="history-detail">
        <p role="status">Безопасные контрольные примеры в отчёте: <strong>{result.controls.hits.length} из {result.controls.total}</strong></p>
        <div className="history-difference">
          <Locations label="Пропуски" items={result.missed} />
          <Locations label="Лишние срабатывания" items={result.unexpected} />
          {!!result.controls.hits.length && <Locations label="Срабатывания на контролях" items={result.controls.hits} />}
        </div>
      </div>
    </>}
  </section>
}
