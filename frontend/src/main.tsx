import { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { Workflow, type Graph, type NodeEvent, type NodeStatus } from './Workflow'
import { ReportActions, type Summary } from './ReportActions'
import { History } from './History'
import { FindingCard } from './FindingCard'
import { Quality } from './Quality'
import './style.css'

type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
type FindingDetails = { path: string; severity: Severity; description: string }
type SourceFinding = FindingDetails & {
  category: 'SECRET' | 'SAST'
  class: string
  line: number
  endLine?: number
  remediation: string
}
type ScaFinding = FindingDetails & {
  category: 'SCA'
  group: string
  artifact: string
  version: string
  advisoryId: string
}
export type Finding = SourceFinding | ScaFinding
export type Report = { findings: Finding[] }
type RunSnapshot = {
  status: string; nodes: Record<string, NodeStatus>; events: NodeEvent[]; report?: Report; signature?: string; summary?: Summary
  historyError?: string
  delivery?: {
    counts: Record<string, number>; maxSeverity: Severity | null
    reportComplete?: boolean; failedAnalyzers?: string[]
    reportUrl?: string; reportUrlUnavailable?: string
  }
}

async function readResponse(response: Response) {
  const data = await response.json()
  if (!response.ok) {
    const detail = typeof data.detail === 'string' ? data.detail
      : Array.isArray(data.detail) ? 'Проверьте параметры узлов графа.' : 'Запрос завершился ошибкой.'
    throw new Error(detail)
  }
  return data
}

const severityLabels: Record<Severity, string> = {
  LOW: 'Низкая', MEDIUM: 'Средняя', HIGH: 'Высокая', CRITICAL: 'Критическая',
}

const labels: Record<string, string> = {
  password: 'Встроенный пароль',
  'api-key': 'Ключ API',
  'configuration-token': 'Токен в конфигурации',
  'secret-fallback': 'Встроенный токен по умолчанию',
  'recoverable-token': 'Восстанавливаемый токен',
  'sql-injection': 'SQL-инъекция',
  'tls-verification': 'Ослабленная проверка TLS',
  'credentialed-cors': 'Широкий CORS с учётными данными',
  'route-authorization': 'Ошибка авторизации маршрута',
  'object-authorization': 'Ошибка проверки доступа к объекту',
}

function findingName(finding: Finding) {
  return finding.category === 'SCA' ? `${finding.group}:${finding.artifact}:${finding.version}`
    : labels[finding.class] ?? finding.class
}

function findingLocation(finding: Finding) {
  return finding.category === 'SCA' ? finding.path
    : `${finding.path}:${finding.line}${finding.endLine ? `–${finding.endLine}` : ''}`
}

function App() {
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    try {
      return localStorage.getItem('cyber-garden-theme') === 'light' ? 'light' : 'dark'
    } catch {
      return 'dark'
    }
  })
  const [result, setResult] = useState<{ report: Report; signature: string; runId?: string } | null>(null)
  const report = result?.report
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [run, setRun] = useState<RunSnapshot | null>(null)
  const [historyRevision, setHistoryRevision] = useState(0)
  const [savedSource, setSavedSource] = useState('')
  const [savedSummary, setSavedSummary] = useState<Summary | null>(null)
  const [activeFinding, setActiveFinding] = useState<Finding | null>(null)

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem('cyber-garden-theme', theme)
    } catch {
      // The selected theme still applies for this page.
    }
  }, [theme])

  useEffect(() => {
    if (savedSource) document.getElementById('results')?.scrollIntoView({ block: 'start' })
  }, [savedSource, report])

  useEffect(() => {
    const id = new URLSearchParams(window.location.search).get('run')
    if (!id) return
    if (!/^[a-f0-9]{32}$/.test(id)) {
      setError('Некорректная ссылка на отчёт.')
      return
    }
    const controller = new AbortController()
    setBusy(true)
    async function load() {
      try {
        const saved = await readResponse(await fetch(`/api/workflow/history/${id}`, {
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(10000)]),
        }))
        if (controller.signal.aborted) return
        if (!saved.report) throw new Error('У этого запуска нет сохранённого отчёта.')
        setResult({ report: saved.report, signature: '', runId: saved.status === 'running' ? undefined : saved.id })
        setSavedSource(saved.source)
        setSavedSummary(saved.summary ?? null)
      } catch (problem) {
        if (!controller.signal.aborted) setError(problem instanceof Error ? problem.message : 'Не удалось открыть отчёт.')
      } finally {
        if (!controller.signal.aborted) setBusy(false)
      }
    }
    void load()
    return () => controller.abort()
  }, [])

  function clearRun() {
    setRun(null)
    setResult(null)
    setError('')
    setSavedSource('')
    setSavedSummary(null)
    setActiveFinding(null)
  }

  async function runScan(graph: Graph) {
    if (busy) return
    clearRun()
    setBusy(true)
    try {
      const { id } = await readResponse(await fetch('/api/workflow/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(graph),
        signal: AbortSignal.timeout(10000),
      }))
      let shownReport = false
      for (;;) {
        const snapshot: RunSnapshot = await readResponse(await fetch(`/api/workflow/runs/${id}`, {
          signal: AbortSignal.timeout(10000),
        }))
        setRun(snapshot)
        if (!shownReport && snapshot.report && snapshot.signature) {
          shownReport = true
          setResult({ report: snapshot.report, signature: snapshot.signature, runId: id })
        }
        if (snapshot.status === 'done' || snapshot.status === 'error') {
          if (snapshot.status === 'error') setError('Сценарий завершился с ошибкой. Проверьте статусы нод.')
          setHistoryRevision(revision => revision + 1)
          break
        }
        await new Promise(resolve => window.setTimeout(resolve, snapshot.status === 'scheduled' ? 1000 : 250))
      }
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : 'Не удалось получить состояние запуска.')
    } finally {
      setBusy(false)
    }
  }

  function downloadReport() {
    if (!report) return
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json;charset=utf-8' }))
    const link = document.createElement('a')
    link.href = url
    link.download = 'security-report.json'
    link.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  const status = busy ? run?.status === 'scheduled' ? 'Запуск запланирован' : 'Сценарий выполняется…' : error ? 'Ошибка проверки'
    : report ? 'Проверка завершена' : 'Готов к запуску'

  return (
    <>
      <header><div className="frame brand">
        <span className="mark" aria-hidden="true">◈</span> Cyber Garden <span className="year">2026</span>
        <button className="secondary theme-switch" type="button" role="switch" aria-checked={theme === 'dark'}
          aria-label="Ночная тема" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
          {theme === 'dark' ? '☾ Ночь' : '☀ День'}
        </button>
      </div></header>
      <main className="frame">
        <section className="intro">
          <p className="project">Кейс банка «Центр-инвест»</p>
          <h1>AI Security Workflow</h1>
          <p>Статическая проверка безопасности учебных Kotlin-проектов</p>
        </section>
        <section className="panel workflow" aria-labelledby="scanner" aria-busy={busy}>
          <div className="scan">
          <div>
            <h2 id="scanner">Сценарий проверки</h2>
          </div>
          <div className="actions">
            <span role="status" className="status">{busy && <span className="spinner" aria-hidden="true" />}{status}</span>
          </div>
          </div>
          <Workflow theme={theme} busy={busy} progress={run?.nodes ?? {}} events={run?.events ?? []} onRun={runScan} onEdit={clearRun} />
          {run?.delivery && <p className="workflow-receipt">
            Webhook получен
            {run.delivery.reportComplete === false && <> · Неполный отчёт · Сбой: {run.delivery.failedAnalyzers?.map(name => name.toUpperCase()).join(', ')}</>}
            {' · '}{Object.entries(run.delivery.counts).map(([category, count]) => `${category}: ${count}`).join(' · ')}
            {run.delivery.maxSeverity ? ` · ${run.delivery.maxSeverity}` : ''}
            {run.delivery.reportUrl && <> · <a href={run.delivery.reportUrl}>Открыть сохранённый отчёт</a></>}
            {run.delivery.reportUrlUnavailable && <> · {run.delivery.reportUrlUnavailable}</>}
          </p>}
          {error && <p className="workflow-error alert" role="alert">{error}</p>}
          {run?.historyError && <p className="workflow-error alert" role="alert">{run.historyError}</p>}
        </section>
        <section className="panel results" aria-labelledby="results" aria-busy={busy && !report}>
          {result ? <ReportActions key={result.runId ?? result.signature} report={result.report} signature={result.signature}
            runId={run?.historyError ? undefined : result.runId} busy={busy} onDownload={downloadReport}
            workflowSummary={savedSummary ?? run?.summary} />
            : <div className="results-title"><h2 id="results">Результаты</h2></div>}
          {savedSource && <p className="history-context">Сохранённый отчёт · {savedSource}</p>}
          {!error && !report?.findings.length && <p className="empty">
            {busy ? 'Проверяем исходники и зависимости…' : report ? 'Находок нет.' : 'После запуска здесь появятся результаты проверки.'}
          </p>}
          {!!report?.findings.length && <div className="table-wrap"><table>
            <thead><tr><th>Категория</th><th>Находка</th><th>Критичность</th><th>Расположение</th></tr></thead>
            <tbody>{report.findings.map((finding, index) => {
              const sourceFinding = finding.category !== 'SCA'
              const name = findingName(finding)
              const location = findingLocation(finding)
              return (
              <tr id={`finding-${index + 1}`} key={sourceFinding ? `${finding.category}:${location}:${finding.class}` : `SCA:${location}:${name}:${finding.advisoryId}`}>
                <td><code>{finding.category}</code><span className="finding-number">№ {index + 1}</span></td>
                <td><button className="finding-name" type="button" aria-haspopup="dialog"
                  onClick={() => setActiveFinding(finding)}>{name}</button>{!sourceFinding && <p><code>{finding.advisoryId}</code></p>}<p>{finding.description}</p></td>
                <td><span className={`severity ${finding.severity.toLowerCase()}`}>{severityLabels[finding.severity]}</span></td>
                <td><code className="path">{location}</code></td>
              </tr>
              )
            })}</tbody>
          </table></div>}
        </section>
        <History revision={historyRevision} disabled={busy} onOpen={(saved, source, summary, runId) => {
          if (!saved || busy) return
          clearRun()
          setResult({ report: saved, signature: '', runId })
          setSavedSource(source)
          setSavedSummary(summary ?? null)
        }} />
        <Quality />
        {activeFinding && <FindingCard finding={activeFinding} name={findingName(activeFinding)}
          location={findingLocation(activeFinding)} severity={severityLabels[activeFinding.severity]}
          onClose={() => setActiveFinding(null)} />}
      </main>
    </>
  )
}

createRoot(document.getElementById('root')!).render(<App />)
