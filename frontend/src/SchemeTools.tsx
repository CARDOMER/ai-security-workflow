import { useState } from 'react'

type Template = { id: string; title: string; description: string; draft: unknown }

async function request<T>(url: string, payload?: object): Promise<T> {
  const response = await fetch(url, {
    ...(payload ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) } : {}),
    signal: AbortSignal.timeout(payload && 'prompt' in payload ? 30000 : 10000),
  })
  const data = await response.json()
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Проверьте параметры схемы и поля формы.')
  return data
}

export function SchemeTools({ publicDemo, locked, getDraft, onApply, onBusy }: {
  publicDemo: boolean; locked: boolean; getDraft: () => object
  onApply: (draft: unknown, message: string) => void; onBusy: (busy: boolean) => void
}) {
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [prompt, setPrompt] = useState('')
  const [generationAvailable, setGenerationAvailable] = useState<boolean | null>(null)
  const [generationStatusError, setGenerationStatusError] = useState(false)
  const [templates, setTemplates] = useState<Template[] | null>(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  async function perform(action: () => Promise<void>) {
    onBusy(true)
    setError('')
    setMessage('')
    try { await action() }
    catch (problem) { setError(problem instanceof Error ? problem.message : 'Операция не завершилась.') }
    finally { onBusy(false) }
  }

  return <div className="scheme-tools">
    <details onToggle={event => {
      if (event.currentTarget.open && templates === null && !locked) void perform(async () => {
        setTemplates(await request<Template[]>('/api/workflow/templates'))
      })
    }}>
      <summary>Библиотека шаблонов</summary>
      <form onSubmit={event => {
        event.preventDefault()
        void perform(async () => {
          const entry = await request<Template>('/api/workflow/templates', { title, description, draft: getDraft() })
          setTemplates(items => [entry, ...(items ?? [])].slice(0, 30))
          setTitle('')
          setDescription('')
          setMessage('Шаблон опубликован.')
        })
      }}>
        <label>Название шаблона <input value={title} maxLength={80} required disabled={locked}
          onChange={event => setTitle(event.target.value)} /></label>
        <label>Описание шаблона <input value={description} maxLength={300} required disabled={locked}
          onChange={event => setDescription(event.target.value)} /></label>
        <button className="secondary" disabled={locked || !title.trim() || !description.trim()}>Опубликовать текущую схему</button>
      </form>
      <button className="secondary" type="button" disabled={locked} onClick={() => void perform(async () => {
        setTemplates(await request<Template[]>('/api/workflow/templates'))
      })}>Обновить библиотеку</button>
      {templates?.length === 0 && <p>В библиотеке пока нет шаблонов.</p>}
      {!!templates?.length && <ul>{templates.map(template => <li key={template.id}>
        <strong>{template.title}</strong>
        <p>{template.description}</p>
        <button className="secondary" type="button" disabled={locked} onClick={() => {
          setError('')
          setMessage('')
          try { onApply(template.draft, 'Шаблон скопирован в редактор.') }
          catch (problem) { setError(problem instanceof Error ? problem.message : 'Не удалось открыть шаблон.') }
        }}>Скопировать в редактор</button>
      </li>)}</ul>}
    </details>
    <details onToggle={event => {
      if (!event.currentTarget.open || !publicDemo) return
      setGenerationAvailable(null)
      setGenerationStatusError(false)
      void request<{ available: boolean }>('/api/workflow/generate')
        .then(data => setGenerationAvailable(data.available))
        .catch(() => setGenerationStatusError(true))
    }}>
      <summary>Создать схему по описанию</summary>
      {publicDemo && generationStatusError ? <p>Не удалось проверить доступность. Закройте и откройте раздел снова.</p> :
        publicDemo && generationAvailable === null ? <p role="status">Проверяем доступность генерации…</p> :
        publicDemo && !generationAvailable ? <p>Генерация схем сейчас недоступна.</p> :
        <form onSubmit={event => {
          event.preventDefault()
          void perform(async () => {
            const draft = await request<unknown>('/api/workflow/generate', { prompt })
            onApply(draft, 'Схема готова. Проверьте параметры перед запуском.')
          })
        }}>
          <label>Задача для AI <textarea maxLength={800} rows={3} value={prompt} disabled={locked}
            onChange={event => setPrompt(event.target.value)} /></label>
          <button className="secondary" disabled={locked || prompt.trim().length < 8}>Создать схему</button>
        </form>}
    </details>
    {error && <p className="alert" role="alert">{error}</p>}
    {message && <p role="status">{message}</p>}
  </div>
}
