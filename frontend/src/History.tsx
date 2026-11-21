import { useEffect, useState } from 'react'
import type { Finding, Report } from './main'

type RunEntry = {
  id: string; status: string; completedAt: string; source: string; projectKey: string
  analyzers: string[]; comparable: boolean; count: number | null
}
type SavedRun = RunEntry & {
  report: Report | null
  nodes: Record<string, { kind: string; status: string; detail: string }>
}
type Difference = { added: Finding[]; removed: Finding[]; unchanged: Finding[] }
const statusLabels: Record<string, string> = { done: 'Завершено', error: 'Ошибка', skipped: 'Пропущено' }

async function request<T>(url: string, method = 'GET'): Promise<T> {
  const response = await fetch(url, { method, signal: AbortSignal.timeout(8000) })
  const data = await response.json()
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Не удалось открыть историю.')
  return data
}

function stamp(run: RunEntry) {
  return new Date(run.completedAt).toLocaleString('ru-RU')
}

export function History({ revision, disabled, onOpen }: {
  revision: number; disabled: boolean; onOpen: (report: Report | null, source: string) => void
}) {
  const [runs, setRuns] = useState<RunEntry[]>([])
  const [selected, setSelected] = useState<SavedRun | null>(null)
  const [before, setBefore] = useState('')
  const [after, setAfter] = useState('')
  const [difference, setDifference] = useState<Difference | null>(null)
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)

  useEffect(() => {
    let keep = true
    request<RunEntry[]>('/api/workflow/history').then(
      entries => { if (keep) setRuns(entries) },
      problem => { if (keep) setError(problem.message) },
    )
    return () => { keep = false }
  }, [revision])

  async function open(id: string) {
    setPending(true)
    setError('')
    try {
      const run = await request<SavedRun>(`/api/workflow/history/${id}`)
      setSelected(run)
      onOpen(run.report, run.source)
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : 'Не удалось открыть отчёт.')
    } finally {
      setPending(false)
    }
  }

  const previous = runs.find(run => run.id === before)
  const candidates = runs.filter(run => previous && run.comparable && run.projectKey === previous.projectKey
    && run.analyzers.join(',') === previous.analyzers.join(',') && run.completedAt > previous.completedAt)

  async function compare() {
    setPending(true)
    setError('')
    setDifference(null)
    try {
      const params = new URLSearchParams({ before, after })
      setDifference(await request<Difference>(`/api/workflow/history/compare?${params}`, 'POST'))
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : 'Не удалось сравнить отчёты.')
    } finally {
      setPending(false)
    }
  }

  return <section className="panel" aria-labelledby="history">
    <div className="results-title"><h2 id="history">История запусков</h2></div>
    {error && <p className="empty alert" role="alert">{error}</p>}
    {!runs.length ? <p className="empty">Завершённые запуски появятся здесь.</p> : <div className="table-wrap"><table>
      <thead><tr><th>Время</th><th>Учебная цель</th><th>Анализаторы</th><th>Статус</th><th>Находки</th><th>Отчёт</th></tr></thead>
      <tbody>{runs.map(run => <tr key={run.id}>
        <td>{stamp(run)}</td><td>{run.source}</td><td>{run.analyzers.map(name => name.toUpperCase()).join(', ') || '—'}</td>
        <td>{statusLabels[run.status]}</td><td>{run.count ?? '—'}</td>
        <td><button className="secondary" type="button" disabled={disabled || pending} onClick={() => void open(run.id)}>
          {run.count === null ? 'Открыть статусы' : 'Открыть отчёт'}
        </button></td>
      </tr>)}</tbody>
    </table></div>}
    {selected && <div className="history-detail">
      <h3>{selected.source} · {stamp(selected)}</h3>
      <ul>{Object.entries(selected.nodes).map(([id, node]) => <li key={id}>
        {id === node.kind ? id : `${node.kind} (${id})`} · {statusLabels[node.status] ?? node.status}{node.detail ? ` · ${node.detail}` : ''}
      </li>)}</ul>
    </div>}
    {runs.some(run => run.comparable) && <div className="history-detail">
      <h3>Сравнение отчётов</h3>
      <div className="history-controls">
        <label>Предыдущий запуск <select value={before} disabled={pending} onChange={event => {
          setBefore(event.target.value); setAfter(''); setDifference(null)
        }}>
          <option value="">Выберите запуск</option>
          {runs.filter(run => run.comparable).map(run => <option value={run.id} key={run.id}>{run.source} · {stamp(run)}</option>)}
        </select></label>
        <label>Новый запуск <select value={after} disabled={pending || !candidates.length} onChange={event => {
          setAfter(event.target.value); setDifference(null)
        }}>
          <option value="">Выберите запуск</option>
          {candidates.map(run => <option value={run.id} key={run.id}>{run.source} · {stamp(run)}</option>)}
        </select></label>
        <button className="secondary" type="button" disabled={pending || !before || !after} onClick={() => void compare()}>Сравнить</button>
      </div>
      {before && !candidates.length && <p>Более позднего отчёта с той же целью и теми же анализаторами пока нет.</p>}
      {difference && <div className="history-difference">{([
        ['added', 'Новые'], ['removed', 'Исчезнувшие'], ['unchanged', 'Сохранившиеся'],
      ] as const).map(([key, label]) => <details key={key} open={key !== 'unchanged'}>
        <summary>{label} · {difference[key].length}</summary>
        {difference[key].length > 0 && <ul>{difference[key].map((item, index) => <li key={index}>
          {item.category === 'SCA' ? `${item.group}:${item.artifact}:${item.version} · ${item.advisoryId}` : item.class}
          {' · '}{item.path}{item.category !== 'SCA' ? `:${item.line}` : ''}
        </li>)}</ul>}
      </details>)}</div>}
    </div>}
  </section>
}
