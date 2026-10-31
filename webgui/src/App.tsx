import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Menu, PanelRight, PanelLeftOpen, Radar, Settings, Sun, Moon, SquarePen,
  ChevronDown, Wifi, WifiOff, CircleDot,
} from 'lucide-react'
import { Sidebar } from './components/Sidebar'
import { Chat } from './components/Chat'
import { Composer, type ComposerOptions } from './components/Composer'
import { RightPanel } from './components/RightPanel'
import { SettingsModal } from './components/SettingsModal'
import { ScansModal } from './components/ScansModal'
import { CommandPalette } from './components/CommandPalette'
import { Toasts, type ToastItem } from './components/Toasts'
import { api, streamChat, subscribeJob } from './lib/api'
import type { AskPart, Attachment, Message, ModelProfile, SseEvent, Thread, ToolPart } from './lib/types'

const LS = {
  theme: 'agui:theme',
  mode: 'agui:mode',
  effort: 'agui:effort',
  auto: 'agui:auto',
  right: 'agui:right',
}

function load<T extends string>(key: string, fallback: T): T {
  const v = localStorage.getItem(key)
  return (v as T) || fallback
}

export default function App() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => load(LS.theme, 'dark'))
  const [threads, setThreads] = useState<Thread[]>([])
  const [activeId, setActiveId] = useState<string | null>(null)
  const [messages, setMessages] = useState<Message[]>([])
  const [streaming, setStreaming] = useState<Message | null>(null)
  const [loadingMessages, setLoadingMessages] = useState(false)
  const [models, setModels] = useState<ModelProfile[]>([])
  const [activeModel, setActiveModel] = useState<string | null>(null)
  const [online, setOnline] = useState(true)

  const [query, setQuery] = useState('')
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [collapsed, setCollapsed] = useState(false)
  const [rightOpen, setRightOpen] = useState(() =>
    typeof window !== 'undefined' && window.innerWidth >= 1024 && localStorage.getItem(LS.right) !== '0')
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [scansOpen, setScansOpen] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)

  const [mode, setMode] = useState<'agent' | 'chat'>(() => load(LS.mode, 'agent'))
  const [effort, setEffort] = useState<'quick' | 'balanced' | 'deep'>(() => load(LS.effort, 'deep'))
  const [autoApprove, setAutoApprove] = useState(() => localStorage.getItem(LS.auto) !== '0')
  const [showThinking, setShowThinking] = useState(() => localStorage.getItem('agui:thinking') === '1')

  const [toasts, setToasts] = useState<ToastItem[]>([])
  const abortRef = useRef<AbortController | null>(null)
  const jobAbortRef = useRef<AbortController | null>(null)
  const toastId = useRef(0)

  const pushToast = useCallback((msg: string, kind: 'ok' | 'err' = 'ok') => {
    const id = ++toastId.current
    setToasts(t => [...t.slice(-3), { id, msg, kind }])
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 4200)
  }, [])

  // ── theme ────────────────────────────────────────────────────────────
  useEffect(() => {
    document.documentElement.classList.toggle('light', theme === 'light')
    document.documentElement.classList.toggle('dark', theme === 'dark')
    localStorage.setItem(LS.theme, theme)
  }, [theme])

  useEffect(() => { localStorage.setItem(LS.mode, mode) }, [mode])

  // v2: Agent (CLI engine) is the default; reset stale Chat selections once
  useEffect(() => {
    if (localStorage.getItem('agui:modev') !== '2') {
      setMode('agent')
      localStorage.setItem('agui:modev', '2')
    }
    if (localStorage.getItem('agui:effortv') !== '2') {
      setEffort('deep')
      localStorage.setItem('agui:effortv', '2')
    }
  }, [])
  useEffect(() => { localStorage.setItem(LS.effort, effort) }, [effort])
  useEffect(() => { localStorage.setItem(LS.auto, autoApprove ? '1' : '0') }, [autoApprove])
  useEffect(() => { localStorage.setItem('agui:thinking', showThinking ? '1' : '0') }, [showThinking])
  useEffect(() => { localStorage.setItem(LS.right, rightOpen ? '1' : '0') }, [rightOpen])

  // ── bootstrap ────────────────────────────────────────────────────────
  const loadModels = useCallback(async () => {
    try {
      const r = await api.models()
      setModels(r.profiles)
      setActiveModel(r.active)
      setOnline(true)
    } catch {
      setOnline(false)
    }
  }, [])

  const loadThreads = useCallback(async () => {
    try {
      const r = await api.threads()
      setThreads(r.threads)
      return r.threads
    } catch {
      return []
    }
  }, [])

  useEffect(() => {
    (async () => {
      await Promise.all([loadModels(), loadThreads()])
    })()
    const t = setInterval(() => { api.health().then(() => setOnline(true)).catch(() => setOnline(false)) }, 20000)
    return () => {
      clearInterval(t)
      jobAbortRef.current?.abort()
    }
  }, [loadModels, loadThreads])

  const openThread = useCallback(async (id: string) => {
    setActiveId(id)
    setSidebarOpen(false)
    setLoadingMessages(true)
    setStreaming(null)
    abortRef.current?.abort()
    jobAbortRef.current?.abort()
    try {
      const r = await api.messages(id)
      setMessages(r.messages)
      attachJobIfRunning(id)
    } catch (e) {
      pushToast(e instanceof Error ? e.message : 'failed to load chat', 'err')
      setMessages([])
    } finally {
      setLoadingMessages(false)
    }
  }, [pushToast])

  const createThread = useCallback(async (): Promise<Thread | null> => {
    try {
      const t = await api.createThread(activeModel ?? undefined)
      const thread: Thread = { ...t, msg_count: 0, pinned: false, mode: 'agent', updated_iso: '' }
      setThreads(prev => [thread, ...prev])
      setActiveId(t.id)
      setMessages([])
      setStreaming(null)
      setSidebarOpen(false)
      return thread
    } catch (e) {
      pushToast(e instanceof Error ? e.message : 'could not create chat', 'err')
      return null
    }
  }, [activeModel, pushToast])

  const ensureThread = useCallback(async (): Promise<string | null> => {
    if (activeId) return activeId
    const t = await createThread()
    return t?.id ?? null
  }, [activeId, createThread])

  const deleteThread = async (id: string) => {
    try {
      await api.deleteThread(id)
      setThreads(prev => prev.filter(t => t.id !== id))
      if (activeId === id) {
        setActiveId(null); setMessages([]); setStreaming(null)
      }
    } catch (e) { pushToast(e instanceof Error ? e.message : 'delete failed', 'err') }
  }

  const renameThread = async (id: string, title: string) => {
    setThreads(prev => prev.map(t => t.id === id ? { ...t, title } : t))
    api.patchThread(id, { title }).catch(() => {})
  }

  const pinThread = async (id: string, pinned: boolean) => {
    setThreads(prev => prev.map(t => t.id === id ? { ...t, pinned } : t))
    api.patchThread(id, { pinned }).catch(() => {})
  }

  const changeModel = async (name: string) => {
    try {
      await api.setModel(name)
      setActiveModel(name)
      setModels(prev => prev.map(m => ({ ...m, active: m.name === name })))
      if (activeId) api.patchThread(activeId, { model: name }).catch(() => {})
      pushToast(`model → ${name}`, 'ok')
    } catch (e) { pushToast(e instanceof Error ? e.message : 'model switch failed', 'err') }
  }

  // ── streaming ────────────────────────────────────────────────────────
  const patchStreaming = (fn: (m: Message) => Message) => setStreaming(prev => prev ? fn(prev) : prev)

  const appendText = (text: string) => patchStreaming(m => {
    const parts = [...m.parts]
    const last = parts[parts.length - 1]
    if (last && last.type === 'text') {
      parts[parts.length - 1] = { type: 'text', text: last.text + text }
    } else {
      parts.push({ type: 'text', text })
    }
    return { ...m, parts }
  })

  const handleEvent = (ev: SseEvent) => {
    switch (ev.type) {
      case 'start': {
        setMessages(prev => [
          ...prev.filter(m => !m.id.startsWith('local-')),
          ...(prev.some(m => m.id === ev.user_message.id) ? [] : [ev.user_message]),
        ])
        setStreaming({
          id: `stream-${Date.now()}`,
          thread_id: ev.user_message.thread_id,
          role: 'assistant',
          content: '',
          parts: [],
          attachments: [],
          meta: { status: 'THINKING' },
          created: Date.now() / 1000,
          created_iso: new Date().toISOString(),
          streaming: true,
        })
        if (ev.title) {
          setThreads(prev => prev.map(t => t.id === ev.user_message.thread_id ? { ...t, title: ev.title } : t))
        }
        break
      }
      case 'delta':
        appendText(ev.text)
        break
      case 'note':
        patchStreaming(m => ({ ...m, parts: [...m.parts, { type: 'note', text: ev.text }] }))
        break
      case 'retry':
        patchStreaming(m => ({ ...m, parts: [], meta: { ...m.meta, status: 'THINKING' } }))
        break
      case 'thinking':
        patchStreaming(m => {
          const parts = [...m.parts]
          const idx = parts.findIndex(p => p.type === 'thought')
          if (idx >= 0) {
            const cur = parts[idx] as { type: 'thought'; text: string; duration_ms: number }
            parts[idx] = { ...cur, text: cur.text + ev.text }
          } else {
            parts.unshift({ type: 'thought', text: ev.text, duration_ms: 0 })
          }
          return { ...m, parts }
        })
        break
      case 'status':
        patchStreaming(m => ({ ...m, meta: { ...m.meta, status: ev.status } }))
        break
      case 'ask': {
        const ask: AskPart = {
          type: 'ask', question_id: ev.id, prompt: ev.prompt,
          choices: ev.choices || [], secret: ev.secret, status: 'waiting',
        }
        patchStreaming(m => ({ ...m, parts: [...m.parts, ask] }))
        break
      }
      case 'file_edit':
        patchStreaming(m => {
          if (m.parts.some(p => p.type === 'tool' && p.call_id === ev.id)) return m
          const tool: ToolPart = {
            type: 'tool', tool: 'edit',
            args: { path: ev.path, action: ev.action, bytes: ev.bytes },
            output: ev.content, language: ev.language,
            ok: true, status: 'done', call_id: ev.id,
          }
          return { ...m, parts: [...m.parts, tool] }
        })
        break
      case 'tool_delta':
        patchStreaming(m => ({
          ...m,
          parts: m.parts.map(p => p.type === 'tool' && p.call_id === ev.id
            ? { ...p, output: (p.output || '') + ev.output }
            : p),
        }))
        break
      case 'text_final':
        patchStreaming(m => {
          const parts = [...m.parts]
          const last = parts[parts.length - 1]
          if (last && last.type === 'text') parts[parts.length - 1] = { type: 'text', text: ev.text }
          else parts.push({ type: 'text', text: ev.text })
          return { ...m, parts }
        })
        break
      case 'tool_start':
      case 'tool_approval':
        patchStreaming(m => {
          if (m.parts.some(p => p.type === 'tool' && p.call_id === ev.id)) return m
          const tool: ToolPart = {
            type: 'tool',
            tool: ev.tool,
            args: ev.args,
            output: '',
            ok: null,
            status: ev.type === 'tool_approval' ? 'awaiting' : 'running',
            call_id: ev.id,
          }
          return { ...m, parts: [...m.parts, tool] }
        })
        break
      case 'tool_end':
        patchStreaming(m => ({
          ...m,
          parts: m.parts.map(p => p.type === 'tool' && p.call_id === ev.id
            ? { ...p, ok: ev.ok, output: ev.output, status: ev.status }
            : p),
        }))
        break
      case 'done':
        setMessages(prev => prev.some(m => m.id === ev.message.id) ? prev : [...prev, ev.message])
        if (ev.title) {
          setThreads(prev => prev.map(t => t.id === ev.message.thread_id ? { ...t, title: String(ev.title) } : t))
        }
        setStreaming(null)
        loadThreads()
        break
      case 'error':
        pushToast(ev.message, 'err')
        patchStreaming(m => ({
          ...m,
          parts: [...m.parts, { type: 'text', text: `\n\n> **error** · ${ev.message}` }],
        }))
        break
    }
  }

  const attachJobIfRunning = async (id: string) => {
    try {
      const st = await api.jobStatus(id)
      if (!st.running) return
      jobAbortRef.current?.abort()
      const ctrl = new AbortController()
      jobAbortRef.current = ctrl
      setStreaming({
        id: `stream-job-${Date.now()}`,
        thread_id: id,
        role: 'assistant',
        content: '',
        parts: [],
        attachments: [],
        meta: { status: 'THINKING' },
        created: Date.now() / 1000,
        created_iso: new Date().toISOString(),
        streaming: true,
      })
      await subscribeJob(id, handleEvent, ctrl.signal)
    } catch { /* job may have finished */ }
  }

  const send = async (text: string, attachments: Attachment[], opts: ComposerOptions) => {
    let tid = activeId
    if (!tid) {
      const t = await createThread()
      if (!t) return
      tid = t.id
      await new Promise(r => setTimeout(r, 60))
    }
    if (abortRef.current) abortRef.current.abort()
    const ctrl = new AbortController()
    abortRef.current = ctrl
    setMessages(prev => [...prev, {
      id: `local-${Date.now()}`,
      thread_id: tid!,
      role: 'user',
      content: text,
      parts: [{ type: 'text', text }],
      attachments,
      meta: {},
      created: Date.now() / 1000,
      created_iso: new Date().toISOString(),
    }])
    try {
      await streamChat({
        thread_id: tid,
        text,
        attachments: attachments.map(a => a.id),
        model: opts.model,
        mode: opts.mode,
        auto_approve: opts.autoApprove,
        effort: opts.effort,
      }, handleEvent, ctrl.signal)
    } catch (e) {
      if (!ctrl.signal.aborted) {
        setMessages(prev => prev.filter(m => !m.id.startsWith('local-')))
        pushToast(e instanceof Error ? e.message : 'stream failed', 'err')
      }
    } finally {
      setStreaming(null)
      loadThreads()
    }
  }

  const stop = () => {
    const tid = activeId
    if (tid) {
      api.cancelJob(tid).catch(() => {})
      api.agentStop(tid).catch(() => {})
    }
    pushToast('stopping…', 'ok')
    // never abort the background job; wait for the done event, then reconcile
    setTimeout(() => {
      if (tid && !jobAbortRef.current?.signal.aborted) openThread(tid)
    }, 7000)
  }

  // ── keyboard ─────────────────────────────────────────────────────────
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const meta = e.metaKey || e.ctrlKey
      if (meta && e.key.toLowerCase() === 'k') { e.preventDefault(); setPaletteOpen(v => !v) }
      else if (meta && e.key.toLowerCase() === 'n') { e.preventDefault(); createThread() }
      else if (meta && e.key === ',') { e.preventDefault(); setSettingsOpen(true) }
      else if (e.key === 'Escape') {
        setPaletteOpen(false); setSettingsOpen(false); setScansOpen(false)
        setSidebarOpen(false); setRightOpen(false)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [createThread])

  const filteredThreads = useMemo(() => {
    if (!query.trim()) return threads
    const q = query.toLowerCase()
    return threads.filter(t => t.title.toLowerCase().includes(q))
  }, [threads, query])

  const activeThread = threads.find(t => t.id === activeId) ?? null
  const currentModel = models.find(m => m.name === activeModel)
  const isBusy = !!streaming

  return (
    <div className="relative z-10 flex h-[100dvh] w-full overflow-hidden">
      {!collapsed && (
        <Sidebar
          threads={filteredThreads}
          activeId={activeId}
          query={query}
          setQuery={setQuery}
          onSelect={openThread}
          onNew={createThread}
          onDelete={deleteThread}
          onRename={renameThread}
          onPin={pinThread}
          onOpenSettings={() => setSettingsOpen(true)}
          onOpenScans={() => setScansOpen(true)}
          onToggleTheme={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
          theme={theme}
          mobileOpen={sidebarOpen}
          onCloseMobile={() => setSidebarOpen(false)}
          onCollapse={() => setCollapsed(true)}
        />
      )}

      {collapsed && (
        <div className="hidden w-[58px] shrink-0 flex-col items-center gap-2 border-r border-line bg-panel/40 py-3 md:flex">
          <button className="icon-btn" onClick={() => setCollapsed(false)} title="Expand sidebar">
            <PanelLeftOpen size={17} />
          </button>
          <button className="icon-btn" onClick={createThread} title="New chat"><SquarePen size={17} /></button>
          <button className="icon-btn" onClick={() => setScansOpen(true)} title="Scans"><Radar size={17} /></button>
          <span className="flex-1" />
          <button className="icon-btn" onClick={() => setSettingsOpen(true)} title="Settings"><Settings size={17} /></button>
          <button className="icon-btn" onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')} title="Theme">
            {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
          </button>
        </div>
      )}

      <main className="flex min-w-0 flex-1 flex-col">
        <header className="glass z-20 flex h-14 shrink-0 items-center gap-2 border-b border-line px-2 sm:px-4">
          <button className="icon-btn md:hidden" onClick={() => setSidebarOpen(true)} aria-label="Menu">
            <Menu size={18} />
          </button>
          <button className="icon-btn hidden md:inline-flex" onClick={() => setCollapsed(c => !c)} aria-label="Toggle sidebar">
            {collapsed ? <PanelLeftOpen size={17} /> : <Menu size={17} />}
          </button>

          <div className="min-w-0 flex-1 px-1">
            <div className="flex items-center gap-2">
              <h1 className="truncate text-[13.5px] font-semibold tracking-tight">
                {activeThread?.title ?? 'New chat'}
              </h1>
            </div>
            <div className="flex items-center gap-1.5 truncate text-[10.5px] text-faint">
              {online ? <Wifi size={10} className="text-mint" /> : <WifiOff size={10} className="text-rose" />}
              <span>{online ? 'connected' : 'offline'}</span>
              <span className="text-line2">·</span>
              <span className="truncate">{currentModel?.label ?? currentModel?.model ?? 'no model'}</span>
              <span className="hidden items-center gap-1 sm:flex">
                <span className="text-line2">·</span>
                <CircleDot size={9} className={mode === 'agent' ? 'text-accent' : 'text-muted'} />
                {mode}
              </span>
            </div>
          </div>

          <button
            className="chip h-8 gap-1.5 border-line bg-panel2/70 px-2.5 text-[11.5px] hover:border-line2"
            onClick={() => setSettingsOpen(true)}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${currentModel?.configured ? 'bg-mint' : 'bg-amber'}`} />
            <span className="hidden max-w-[150px] truncate sm:inline">{currentModel?.label ?? currentModel?.model ?? 'model'}</span>
            <ChevronDown size={11} className="text-faint" />
          </button>
          <button
            className={`icon-btn ${rightOpen ? 'bg-panel3 text-ink' : ''}`}
            onClick={() => setRightOpen(v => !v)} aria-label="Toggle context panel"
          >
            <PanelRight size={17} />
          </button>
        </header>

        <Chat
          messages={messages}
          streaming={streaming}
          threadId={activeId}
          loading={loadingMessages}
          showThinking={showThinking}
          onSuggestion={text => send(text, [], { mode, effort, autoApprove, model: activeModel })}
        />

        <Composer
          threadId={activeId}
          ensureThread={ensureThread}
          streaming={isBusy}
          models={models}
          activeModel={activeModel}
          onModelChange={changeModel}
          mode={mode}
          setMode={setMode}
          effort={effort}
          setEffort={setEffort}
          autoApprove={autoApprove}
          setAutoApprove={setAutoApprove}
          onSend={send}
          onStop={stop}
          pushToast={pushToast}
          onToggleThinking={(next) => setShowThinking(v => typeof next === 'boolean' ? next : !v)}
        />
      </main>

      <RightPanel
        open={rightOpen}
        onClose={() => setRightOpen(false)}
        thread={activeThread}
        messages={messages}
        onOpenScans={() => setScansOpen(true)}
      />

      <SettingsModal
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        models={models}
        active={activeModel}
        onModel={changeModel}
        pushToast={pushToast}
      />

      <ScansModal open={scansOpen} onClose={() => setScansOpen(false)} pushToast={pushToast} />

      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        threads={threads}
        onSelectThread={openThread}
        onNew={createThread}
        onSettings={() => setSettingsOpen(true)}
        onScans={() => setScansOpen(true)}
        onToggleTheme={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
        onExport={() => {
          if (activeId) window.open(api.exportUrl(activeId), '_blank')
          else pushToast('no chat to export', 'err')
        }}
      />

      <Toasts items={toasts} dismiss={id => setToasts(t => t.filter(x => x.id !== id))} />
    </div>
  )
}
