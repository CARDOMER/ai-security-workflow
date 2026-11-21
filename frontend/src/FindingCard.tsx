import { useEffect, useRef, useState } from 'react'
import type { Finding } from './main'

type VersionRange = { lower: string | null; lowerInclusive: boolean; upper: string; upperInclusive: boolean }
type Advisory = { ranges: VersionRange[]; fixedVersions: string[] }

function rangeText(range: VersionRange) {
  const upper = `${range.upperInclusive ? '≤' : '<'} ${range.upper}`
  return range.lower ? `${range.lowerInclusive ? '≥' : '>'} ${range.lower} и ${upper}` : upper
}

export function FindingCard({ finding, name, location, severity, onClose }: {
  finding: Finding; name: string; location: string; severity: string; onClose: () => void
}) {
  const dialog = useRef<HTMLDialogElement>(null)
  const [advisory, setAdvisory] = useState<Advisory | null>(null)
  const [advisoryStatus, setAdvisoryStatus] = useState(finding.category === 'SCA' ? 'loading' : 'idle')

  useEffect(() => {
    dialog.current?.showModal()
  }, [])

  useEffect(() => {
    if (finding.category !== 'SCA') return
    const controller = new AbortController()
    const params = new URLSearchParams({ group: finding.group, artifact: finding.artifact, advisoryId: finding.advisoryId })
    async function load() {
      try {
        const response = await fetch(`/api/sca/advisory?${params}`, {
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(8000)]),
        })
        if (!response.ok) throw new Error()
        const details: Advisory | null = await response.json()
        if (controller.signal.aborted) return
        setAdvisory(details)
        setAdvisoryStatus(details ? 'ready' : 'missing')
      } catch {
        if (!controller.signal.aborted) setAdvisoryStatus('error')
      }
    }
    void load()
    return () => controller.abort()
  }, [finding])

  return <dialog ref={dialog} className="finding-card" aria-labelledby="finding-card-title" onClose={onClose}>
    <div className="finding-card-header">
      <h2 id="finding-card-title">{name}</h2>
      <button className="secondary" type="button" autoFocus onClick={() => dialog.current?.close()}>Закрыть</button>
    </div>
    <dl>
      <dt>Категория</dt><dd><code>{finding.category}</code></dd>
      <dt>Критичность</dt><dd><span className={`severity ${finding.severity.toLowerCase()}`}>{severity}</span></dd>
      <dt>Расположение</dt><dd><code className="path">{location}</code></dd>
      {finding.category === 'SCA' ? <>
        <dt>Версия зависимости</dt><dd><code>{finding.version}</code></dd>
        <dt>Идентификатор advisory</dt><dd><code>{finding.advisoryId}</code></dd>
        {!!advisory?.ranges.length && <>
          <dt>Затронутые версии</dt>
          <dd>{advisory.ranges.map(rangeText).join(' или ')}</dd>
        </>}
      </> : <><dt>Класс</dt><dd><code>{finding.class}</code></dd></>}
    </dl>
    {advisoryStatus === 'loading' && <p className="status" role="status">Загружаем данные из справочника Maven…</p>}
    {advisoryStatus === 'missing' && <p className="status">Дополнительных данных об этой находке в справочнике нет.</p>}
    {advisoryStatus === 'error' && <p className="status" role="status">Не удалось открыть справочник Maven.</p>}
    <h3>Причина срабатывания</h3>
    <p>{finding.description}</p>
    <h3>Рекомендация по исправлению</h3>
    {finding.category !== 'SCA' ? <p>{finding.remediation}</p>
      : advisory?.fixedVersions.length ? <p>Выберите совместимую исправленную версию из справочника:
        {' '}<code>{advisory.fixedVersions.join(', ')}</code>. Обновите зависимость и повторите проверку.</p>
      : <p>Сверьте advisory с вашей веткой зависимости, выберите исправленную версию и повторите проверку.</p>}
  </dialog>
}
