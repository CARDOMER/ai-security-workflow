import { useEffect, useState } from 'react'
import {
  Background, Controls, Handle, MarkerType, Position, ReactFlow, addEdge,
  useEdgesState, useNodesState, type Edge, type Node, type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'

const publicDemo = import.meta.env.VITE_PUBLIC_DEMO === '1'

const names = {
  manual: 'Ручной запуск', schedule: 'Расписание', source: 'Учебный проект',
  secret: 'Secrets Scanner', sca: 'Maven SCA', sast: 'Kotlin SAST', merge: 'Объединение',
  report: 'Отчёт', condition: 'Условие', ai: 'ИИ-разбор', webhook: 'HTTP webhook',
}
type Kind = keyof typeof names
type Branch = 'yes' | 'no'
export type Step = {
  id: string; kind: Kind; metric?: 'count' | 'severity' | 'path'; minimum?: number
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'; pattern?: string; at?: string
}
export type Graph = {
  nodes: Step[]; edges: { source: string; target: string; branch?: Branch }[]
  trigger: 'manual' | 'schedule'; uploadId?: string; projectLabel?: string
}
export type NodeStatus = { status: string; detail: string }
export type NodeEvent = NodeStatus & { nodeId: string }
type WorkflowNode = Node<{ step: Step; progress?: NodeStatus }, 'workflow'>
const statuses: Record<string, string> = {
  waiting: 'Ожидает', running: 'Выполняется', done: 'Завершено', error: 'Ошибка', skipped: 'Пропущено',
}

const allowed: Record<Kind, Kind[]> = {
  manual: ['source'], schedule: ['source'], source: ['secret', 'sca', 'sast'],
  secret: ['merge'], sca: ['merge'], sast: ['merge'], merge: ['report'],
  report: ['condition', 'ai', 'webhook'], condition: ['ai', 'webhook'],
  ai: ['webhook'], webhook: [],
}
const kinds = Object.keys(names) as Kind[]

function step(kind: Kind, x: number, y: number, id: string = kind): WorkflowNode {
  return {
    id, type: 'workflow', position: { x, y },
    data: { step: { id, kind, ...(kind === 'condition' ? { metric: 'severity', severity: 'HIGH' } : {}) } },
  }
}

function link(source: string, target: string, branch?: Branch): Edge {
  return { id: `${source}:${target}:${branch ?? ''}`, source, target, sourceHandle: branch,
    markerEnd: { type: MarkerType.ArrowClosed }, label: branch === 'yes' ? 'Да' : branch === 'no' ? 'Нет' : undefined }
}

const startingNodes = [
  step('manual', 0, 104), step('source', 220, 104),
  step('secret', 440, 0), step('sca', 440, 104), step('sast', 440, 208),
  step('merge', 660, 104), step('report', 880, 104), step('condition', 1100, 104),
  step('ai', 1320, 28), step('webhook', 1540, 28), step('webhook', 1320, 205, 'webhook-no'),
]
const startingEdges = [
  link('manual', 'source'), link('source', 'secret'), link('source', 'sca'), link('source', 'sast'),
  link('secret', 'merge'), link('sca', 'merge'), link('sast', 'merge'), link('merge', 'report'),
  link('report', 'condition'), link('condition', 'ai', 'yes'), link('ai', 'webhook'),
  link('condition', 'webhook-no', 'no'),
]

const draftKey = 'cyber-garden.workflow.v1'
const idPattern = /^[A-Za-z0-9_-]{1,60}$/
const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value)

function snapshot(nodes: WorkflowNode[], edges: Edge[]) {
  const nodeIds = new Set(nodes.map(node => node.id))
  return {
    version: 1,
    nodes: nodes.map(node => ({ ...node.data.step, x: node.position.x, y: node.position.y })),
    edges: edges.filter(edge => nodeIds.has(edge.source) && nodeIds.has(edge.target))
      .map(({ source, target, sourceHandle }) => ({ source, target, branch: sourceHandle ?? undefined })),
  }
}

function readDraft(raw: string) {
  const value: unknown = JSON.parse(raw)
  if (!isRecord(value) || value.version !== 1 || !Array.isArray(value.nodes) || !Array.isArray(value.edges)
    || value.nodes.length > 24 || value.edges.length > 48) throw new Error('Неподдерживаемый формат схемы.')
  const ids = new Map<string, Kind>()
  const nodes = value.nodes.map((item: unknown) => {
    if (!isRecord(item) || typeof item.id !== 'string' || !idPattern.test(item.id) || ids.has(item.id)
      || typeof item.kind !== 'string' || !Object.hasOwn(names, item.kind)
      || typeof item.x !== 'number' || !Number.isFinite(item.x)
      || typeof item.y !== 'number' || !Number.isFinite(item.y)) throw new Error('Некорректная нода в схеме.')
    const kind = item.kind as Kind
    ids.set(item.id, kind)
    const node = step(kind, item.x, item.y, item.id)
    const data = node.data.step
    if (item.metric === 'count' || item.metric === 'severity' || item.metric === 'path') data.metric = item.metric
    if (typeof item.minimum === 'number' && Number.isInteger(item.minimum) && item.minimum >= 0
      && item.minimum <= 100000) data.minimum = item.minimum
    if (item.severity === 'LOW' || item.severity === 'MEDIUM'
      || item.severity === 'HIGH' || item.severity === 'CRITICAL') data.severity = item.severity
    if (typeof item.pattern === 'string' && item.pattern.length <= 120) data.pattern = item.pattern
    if (typeof item.at === 'string' && item.at.length <= 64) data.at = item.at
    return node
  })
  const edgeIds = new Set<string>()
  const edges = value.edges.map((item: unknown) => {
    if (!isRecord(item) || typeof item.source !== 'string' || typeof item.target !== 'string') {
      throw new Error('Некорректная связь в схеме.')
    }
    const from = ids.get(item.source)
    const to = ids.get(item.target)
    const branch = item.branch
    if (!from || !to || !allowed[from].includes(to)
      || (from === 'condition' ? branch !== 'yes' && branch !== 'no' : branch !== undefined)) {
      throw new Error('Несовместимая связь в схеме.')
    }
    const edge = link(item.source, item.target, branch as Branch | undefined)
    if (edgeIds.has(edge.id)) throw new Error('Повторяющаяся связь в схеме.')
    edgeIds.add(edge.id)
    return edge
  })
  return { nodes, edges }
}

function initialDraft() {
  try {
    const raw = localStorage.getItem(draftKey)
    if (raw) return readDraft(raw)
  } catch {
    // The editor can still open when browser storage is disabled or stale.
  }
  return { nodes: startingNodes, edges: startingEdges }
}

function StepNode({ data }: NodeProps<WorkflowNode>) {
  const { step: current, progress } = data
  const kind = current.kind
  return <div className={`workflow-step ${progress?.status === 'error' ? 'failed' : progress?.status ?? ''}`}>
    {kind !== 'manual' && kind !== 'schedule' && <Handle type="target" position={Position.Left} />}
    <strong>{names[kind]}</strong>
    {progress && <span>{statuses[progress.status]}</span>}
    {kind === 'condition' ? <>
      <Handle type="source" id="yes" aria-label="Да" position={Position.Right} style={{ top: '30%' }} />
      <Handle type="source" id="no" aria-label="Нет" position={Position.Right} style={{ top: '70%' }} />
      <span>Да · Нет</span>
    </> : kind !== 'webhook' && <Handle type="source" position={Position.Right} />}
  </div>
}

const nodeTypes = { workflow: StepNode }
type Props = {
  theme: 'light' | 'dark'
  busy: boolean; progress: Record<string, NodeStatus>; events: NodeEvent[]
  onRun: (graph: Graph) => void; onEdit: () => void
}

export function Workflow({ theme, busy, progress, events, onRun, onEdit }: Props) {
  const [initial] = useState(initialDraft)
  const [nodes, setNodes, onNodesChange] = useNodesState(initial.nodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(initial.edges)
  const [selected, setSelected] = useState(initial.nodes.find(item => item.data.step.kind === 'condition')?.id ?? '')
  const [draftMessage, setDraftMessage] = useState('')
  const [draftError, setDraftError] = useState('')
  const [importing, setImporting] = useState(false)
  const [kind, setKind] = useState<Kind>('schedule')
  const [upload, setUpload] = useState<{ id: string; name: string } | null>(null)
  const [projectLabel, setProjectLabel] = useState('')
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const current = nodes.find(node => node.id === selected)?.data.step
  const locked = busy || uploading || importing

  useEffect(() => {
    if (nodes.some(node => node.dragging)) return
    try {
      localStorage.setItem(draftKey, JSON.stringify(snapshot(nodes, edges)))
    } catch {
      setDraftMessage('Автосохранение недоступно. Экспортируйте схему в JSON.')
    }
  }, [nodes, edges])

  function exportDraft() {
    const blob = new Blob([JSON.stringify(snapshot(nodes, edges), null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'workflow-scheme.json'
    anchor.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  async function importDraft(file: File) {
    setImporting(true)
    setDraftError('')
    setDraftMessage('')
    try {
      if (file.size > 256 * 1024) throw new Error('Размер файла схемы должен быть до 256 КБ.')
      const draft = readDraft(await file.text())
      setNodes(draft.nodes)
      setEdges(draft.edges)
      setSelected(draft.nodes.find(item => item.data.step.kind === 'condition')?.id ?? '')
      setUpload(null)
      setUploadError('')
      setDraftMessage('Схема импортирована. Источник проекта — встроенный Repair Desk.')
      onEdit()
    } catch (error) {
      setDraftError(error instanceof Error && !(error instanceof SyntaxError)
        ? error.message : 'Не удалось прочитать JSON схемы.')
    } finally {
      setImporting(false)
    }
  }

  function update(values: Partial<Step>) {
    setNodes(items => items.map(item => item.id === selected
      ? { ...item, data: { step: { ...item.data.step, ...values } } } : item))
    onEdit()
  }

  function preset(scaOnly: boolean) {
    const next = scaOnly ? new Set(['secret', 'sast']) : new Set<string>()
    setNodes(startingNodes.filter(item => !next.has(item.id)))
    setEdges(startingEdges.filter(item => !next.has(item.source) && !next.has(item.target)))
    setSelected('condition')
    onEdit()
  }

  async function sendArchive(file: File) {
    if (!authorized) return
    setUploading(true)
    setUploadError('')
    try {
      const response = await fetch('/api/workflow/uploads', {
        method: 'POST', body: file, headers: { 'X-Training-Project': 'authorized' },
      })
      const data = await response.json()
      if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Загрузка ZIP завершилась ошибкой.')
      setUpload({ id: data.uploadId, name: file.name })
      onEdit()
    } catch (error) {
      setUpload(null)
      setUploadError(error instanceof Error ? error.message : 'Не удалось загрузить ZIP.')
      onEdit()
    } finally {
      setUploading(false)
    }
  }

  function run(trigger: Graph['trigger']) {
    onRun({
      trigger, uploadId: upload?.id, projectLabel: upload ? projectLabel.trim() || undefined : undefined,
      nodes: nodes.map(item => item.data.step),
      edges: edges.map(item => ({ source: item.source, target: item.target,
        branch: item.sourceHandle === 'yes' || item.sourceHandle === 'no' ? item.sourceHandle : undefined })),
    })
  }

  return <>
    <div className="workflow-options">
      <button className="secondary" disabled={locked} onClick={() => preset(false)}>Полная схема</button>
      <button className="secondary" disabled={locked} onClick={() => preset(true)}>Только Maven SCA</button>
      <label>Тип ноды <select disabled={locked} value={kind} onChange={event => setKind(event.target.value as Kind)}>
        {kinds.map(item => <option key={item} value={item}>{names[item]}</option>)}
      </select></label>
      <button className="secondary" disabled={locked || nodes.length >= 24 || (kind !== 'webhook' && nodes.some(item => item.data.step.kind === kind))}
        onClick={() => {
          const id = crypto.randomUUID()
          setNodes(items => [...items, step(kind, 160, 280, id)])
          setSelected(id)
          onEdit()
        }}>Добавить ноду</button>
      <button className="secondary" disabled={locked} onClick={exportDraft}>Экспорт схемы</button>
      <label className="secondary scheme-import">Импорт схемы
        <input aria-label="Импорт схемы" type="file" accept=".json,application/json" disabled={locked}
          onChange={event => { const file = event.target.files?.[0]; if (file) void importDraft(file); event.target.value = '' }} />
      </label>
    </div>
    {draftError && <p className="workflow-error alert" role="alert">{draftError}</p>}
    {draftMessage && <p className="workflow-error" role="status">{draftMessage}</p>}
    <div className="workflow-options">
      <label><input type="checkbox" checked={authorized} disabled={locked}
        onChange={event => setAuthorized(event.target.checked)} />Разрешённый учебный проект</label>
      <label>Загрузить ZIP <input type="file" accept=".zip,application/zip" disabled={locked || !authorized}
        onChange={event => { const file = event.target.files?.[0]; if (file) void sendArchive(file); event.target.value = '' }} /></label>
      <span role="status">{uploading ? 'Загружаем ZIP…' : uploadError ? 'ZIP не выбран' : upload?.name ?? 'Встроенный Repair Desk'}</span>
      {(upload || uploadError) && <button className="secondary" disabled={locked} onClick={() => {
        setUpload(null)
        setUploadError('')
        onEdit()
      }}>Вернуть Repair Desk</button>}
      {upload && !publicDemo && <label>Имя учебной цели для сравнения
        <input value={projectLabel} maxLength={60} disabled={locked} placeholder="Одинаковое имя для двух версий"
          onChange={event => { setProjectLabel(event.target.value); onEdit() }} />
      </label>}
    </div>
    {publicDemo && <div className="workflow-options demo-downloads">
      <span>Архивы Demo Desk для сравнения</span>
      <a href="/demo/check-before.zip" download>Скачать ZIP до исправлений</a>
      <a href="/demo/check-after.zip" download>Скачать ZIP после исправлений</a>
    </div>}
    {uploadError && <p className="workflow-error alert" role="alert">{uploadError}</p>}
    <div className="workflow-canvas">
      <ReactFlow colorMode={theme} nodes={nodes.map(item => ({ ...item, data: { ...item.data, progress: progress[item.id] } }))}
        edges={edges} nodeTypes={nodeTypes}
        nodesConnectable={!locked} edgesReconnectable={false} deleteKeyCode={locked ? null : ['Delete', 'Backspace']}
        onNodesChange={changes => {
          onNodesChange(changes)
          if (changes.some(item => item.type === 'remove')) onEdit()
        }}
        onEdgesChange={changes => {
          onEdgesChange(changes)
          if (changes.some(item => item.type === 'remove')) onEdit()
        }}
        onNodeClick={(_, item) => setSelected(item.id)}
        isValidConnection={edge => {
          const from = nodes.find(item => item.id === edge.source)?.data.step.kind
          const to = nodes.find(item => item.id === edge.target)?.data.step.kind
          return !locked && edges.length < 48 && !!from && !!to && allowed[from].includes(to)
        }}
        onConnect={edge => {
          const branch = edge.sourceHandle === 'yes' || edge.sourceHandle === 'no' ? edge.sourceHandle : undefined
          setEdges(items => addEdge(link(edge.source, edge.target, branch), items))
          onEdit()
        }}
        fitView fitViewOptions={{ padding: 0.09 }} minZoom={0.15}>
        <Background gap={20} color="var(--grid-dot)" /><Controls showInteractive={false} />
      </ReactFlow>
    </div>
    {current && <div className="workflow-options workflow-inspector">
      <strong>{names[current.kind]}</strong>
      {current.kind === 'source' && <span>{upload?.name ?? 'Repair Desk'}</span>}
      {current.kind === 'webhook' && <span>Получатель задаётся на сервере</span>}
      {current.kind === 'condition' && <>
        <label>Проверка <select disabled={locked} value={current.metric ?? 'count'}
          onChange={event => update({ metric: event.target.value as Step['metric'] })}>
          <option value="count">Число находок</option><option value="severity">Критичность</option><option value="path">Путь по выражению</option>
        </select></label>
        {(current.metric ?? 'count') === 'count' && <label>Минимум <input type="number" min={0} value={current.minimum ?? 1}
          disabled={locked} onChange={event => update({ minimum: Number(event.target.value) })} /></label>}
        {current.metric === 'severity' && <label>Уровень не ниже <select disabled={locked} value={current.severity ?? 'HIGH'}
          onChange={event => update({ severity: event.target.value as Step['severity'] })}>
          {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(value => <option key={value}>{value}</option>)}
        </select></label>}
        {current.metric === 'path' && <label>Выражение <input disabled={locked} maxLength={120}
          value={current.pattern ?? ''} onChange={event => update({ pattern: event.target.value })} /></label>}
      </>}
      {current.kind === 'schedule' && <label>Дата и время со смещением
        <input disabled={locked} maxLength={64} placeholder="2026-11-21T14:30:00+03:00" value={current.at ?? ''}
          onChange={event => update({ at: event.target.value })} /></label>}
      <span>{progress[current.id]?.detail || 'Выберите ноду для просмотра параметров и результата.'}</span>
      {!!progress[current.id] && <span className="node-timeline" aria-label="Журнал ноды">
        {events.filter(item => item.nodeId === current.id).map(item => statuses[item.status]).join(' → ')}
      </span>}
    </div>}
    <div className="workflow-run">
      <p>Соединяйте узлы за круглые контакты. Клавиша Delete удаляет выбранную ноду или связь.</p>
      {nodes.some(item => item.data.step.kind === 'schedule') && <button className="secondary" disabled={locked || !!uploadError} onClick={() => run('schedule')}>Запланировать</button>}
      <button disabled={locked || !!uploadError} onClick={() => run('manual')}>Запустить проверку</button>
    </div>
  </>
}
