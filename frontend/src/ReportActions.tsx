import { useEffect, useRef, useState } from 'react'

type Priority = { action: string; reason: string; findingIds: number[] }
export type Summary = { mode: 'llm' | 'rules'; provider?: 'gigachat' | 'yandex'; fallbackReason?: string; summary: string; priorities: Priority[] }
const providerTitles = { gigachat: 'Рекомендации GigaChat', yandex: 'Рекомендации YandexGPT' }
type Props = {
  report: { findings: unknown[] }; signature: string; runId?: string; busy: boolean
  onDownload: () => void; workflowSummary?: Summary
}

export function ReportActions({ report, signature, runId, busy, onDownload, workflowSummary }: Props) {
  const [manualSummary, setSummary] = useState<Summary | null>(null)
  const summary = manualSummary ?? workflowSummary
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  const request = useRef<AbortController | null>(null)

  useEffect(() => () => request.current?.abort(), [report])

  async function prepare() {
    if (request.current || busy) return
    const controller = new AbortController()
    request.current = controller
    setSummary(null)
    setError('')
    setPending(true)
    try {
      const url = runId ? `/api/workflow/history/${runId}/summary` : '/api/report/summary'
      const response = await fetch(url, {
        method: 'POST',
        ...(!runId ? {
          headers: { 'Content-Type': 'application/json', 'X-Report-Signature': signature },
          body: JSON.stringify(report),
        } : {}),
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(25000)]),
      })
      const data = await response.json()
      if (controller.signal.aborted) return
      if (!response.ok) {
        setError(typeof data.detail === 'string' ? data.detail : 'Не удалось разобрать этот отчёт.')
        return
      }
      setSummary(data)
    } catch (problem) {
      if (!controller.signal.aborted) {
        setError(problem instanceof DOMException && problem.name === 'TimeoutError'
          ? 'Истекло время ожидания рекомендаций. Попробуйте ещё раз.'
          : 'Не удалось получить рекомендации. Проверьте соединение с сервером.')
      }
    } finally {
      request.current = null
      if (!controller.signal.aborted) setPending(false)
    }
  }

  return (
    <>
      <div className="results-title">
        <h2 id="results">Результаты <span className="count">{report.findings.length}</span></h2>
        <div className="report-buttons">
          <button className="secondary" type="button" onClick={onDownload}>Скачать JSON</button>
          {!!report.findings.length && (signature || runId) && (
            <button className="secondary" type="button" onClick={prepare} disabled={pending || busy}>
              Подготовить рекомендации
            </button>
          )}
        </div>
      </div>
      {pending && <p className="summary-note status" role="status"><span className="spinner" aria-hidden="true" />Готовим рекомендации…</p>}
      {error && <p className="summary-note alert" role="alert">{error}</p>}
      {summary && (
        <section className="summary" aria-labelledby="summary-title">
          <h3 id="summary-title">{summary.mode === 'rules' ? 'Приоритизация по правилам'
            : summary.provider ? providerTitles[summary.provider] : 'ИИ-разбор отчёта'}</h3>
          {summary.fallbackReason && <p role="status">{summary.fallbackReason}</p>}
          <p>{summary.summary}</p>
          <ol>
            {summary.priorities.map((priority, index) => (
              <li key={index}>
                <strong>{priority.action}</strong>
                <p>{priority.reason}</p>
                <div className="finding-links">
                  {priority.findingIds.map(id => <a key={id} href={`#finding-${id}`}>Находка {id}</a>)}
                </div>
              </li>
            ))}
          </ol>
        </section>
      )}
    </>
  )
}
