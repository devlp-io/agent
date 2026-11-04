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
import { TodoPanel } from './components/TodoPanel'
import { api, streamChat, subscribeJob } from './lib/api'
import type { AskPart, Attachment, Message, ModelProfile, RunInfo, SseEvent, Thread, TodoItem, ToolPart } from './lib/types'

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
  const [streams, setStreams] = useState<Record<string, Message>>({})
  const [loadingMessages, setLoadingMessages] = useState(false)
  const [todos, setTodos] = useState<TodoItem[]>([])
  const [models, setModels] = useState<ModelProfile[]>([])
  const [activeModel, setActiveModel] = useState<string | null>(null)
  const [runInfo, setRunInfo] = useState<RunInfo | null>(null)
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
  const [draftRestore, setDraftRestore] = useState<{ text: string; seq: number } | null>(null)
  const abortRef = useRef<Record<string, AbortController>>({})
  const jobAbortRef = useRef<Record<string, AbortController>>({})
  const doneRef = useRef<Record<string, boolean>>({})
  const streamsRef = useRef<Record<string, Message>>({})
  const activeRef = useRef<string | null>(null)
  const openSeq = useRef(0)
  const bufs = useRef<Record<string, {
    text: string
    replaceNext: boolean
    tools: Record<string, string>
    timer: number | null
  }>>({})
  const toastId = useRef(0)
  const restoreSeq = useRef(0)

  const bufFor = (tid: string) => {
    if (!bufs.current[tid]) {
      bufs.current[tid] = { text: '', replaceNext: false, tools: {}, timer: null }
    }
    return bufs.current[tid]
  }

  useEffect(() => { streamsRef.current = streams }, [streams])

  const streaming = activeId ? streams[activeId] ?? null : null

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
      Object.values(jobAbortRef.current).forEach(c => c.abort())
    }
  }, [loadModels, loadThreads])

  const openThread = useCallback(async (id: string) => {
    const seq = ++openSeq.current
    activeRef.current = id
    setActiveId(id)
    setSidebarOpen(false)
    setLoadingMessages(true)
    setMessages([])
    setTodos([])
    try {
      const r = await api.messages(id)
      if (seq !== openSeq.current || activeRef.current !== id) return
      setMessages(r.messages)
      setRunInfo(r.run ?? null)
      attachJobIfRunning(id)
      api.todos(id)
        .then(t => { if (activeRef.current === id) setTodos(t.todos) })
        .catch(() => { if (activeRef.current === id) setTodos([]) })
    } catch (e) {
      if (seq !== openSeq.current) return
      pushToast(e instanceof Error ? e.message : 'failed to load chat', 'err')
      setMessages([])
    } finally {
      if (seq === openSeq.current) setLoadingMessages(false)
    }
  }, [pushToast])

  const wasOnline = useRef(true)
  useEffect(() => {
    if (!wasOnline.current && online) {
      pushToast('backend reconnected', 'ok')
      if (activeId && !streaming) openThread(activeId)
    }
    wasOnline.current = online
  }, [online, activeId, streaming, openThread, pushToast])

  const createThread = useCallback(async (): Promise<Thread | null> => {
    try {
      const t = await api.createThread(activeModel ?? undefined)
      const thread: Thread = { ...t, msg_count: 0, pinned: false, mode: 'agent', updated_iso: '' }
      setThreads(prev => [thread, ...prev])
      activeRef.current = t.id
      setActiveId(t.id)
      setMessages([])
      setRunInfo(null)
      setTodos([])
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
    abortRef.current[id]?.abort()
    jobAbortRef.current[id]?.abort()
    delete abortRef.current[id]
    delete jobAbortRef.current[id]
    dropStream(id)
    api.cancelJob(id).catch(() => {})
    try {
      await api.deleteThread(id)
      setThreads(prev => prev.filter(t => t.id !== id))
      if (activeRef.current === id) {
        activeRef.current = null
        setActiveId(null); setMessages([]); setRunInfo(null); setLoadingMessages(false); setTodos([])
      }
    } catch (e) {
      pushToast(e instanceof Error ? e.message : 'delete failed', 'err')
    }
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

  // ── streaming (per thread; several sessions may run at once) ─────────
  const patchStream = (tid: string, fn: (m: Message) => Message) => {
    setStreams(prev => (prev[tid] ? { ...prev, [tid]: fn(prev[tid]) } : prev))
  }

  const dropStream = (tid: string) => {
    setStreams(prev => {
      if (!prev[tid]) return prev
      const next = { ...prev }
      delete next[tid]
      return next
    })
  }

  const flushStreaming = (tid: string) => {
    const b = bufFor(tid)
    if (b.timer !== null) {
      window.clearTimeout(b.timer)
      b.timer = null
    }
    const text = b.text
    b.text = ''
    if (text) appendText(tid, text)
    const toolOut = b.tools
    b.tools = {}
    const ids = Object.keys(toolOut)
    if (ids.length) {
      patchStream(tid, m => ({
        ...m,
        parts: m.parts.map(p => p.type === 'tool' && toolOut[p.call_id]
          ? { ...p, output: (p.output || '') + toolOut[p.call_id] }
          : p),
      }))
    }
  }

  const scheduleFlush = (tid: string) => {
    const b = bufFor(tid)
    if (b.timer !== null) return
    b.timer = window.setTimeout(() => flushStreaming(tid), 70)
  }

  const appendText = (tid: string, text: string) => {
    const b = bufFor(tid)
    patchStream(tid, m => {
      const parts = [...m.parts]
      const last = parts[parts.length - 1]
      if (b.replaceNext) {
        b.replaceNext = false
        if (last && last.type === 'text') parts[parts.length - 1] = { type: 'text', text }
        else parts.push({ type: 'text', text })
        return { ...m, parts }
      }
      if (last && last.type === 'text') {
        parts[parts.length - 1] = { type: 'text', text: last.text + text }
      } else {
        parts.push({ type: 'text', text })
      }
      return { ...m, parts }
    })
  }

  const handleEvent = (ev: SseEvent, sourceTid?: string) => {
    const evTid =
      ev.type === 'start' ? ev.user_message.thread_id
      : ev.type === 'done' ? ev.message.thread_id
      : (sourceTid || activeRef.current || '')
    if (!evTid) return
    const isActive = evTid === activeRef.current
    if (!['delta', 'tool_delta', 'thinking'].includes(ev.type)) flushStreaming(evTid)

    switch (ev.type) {
      case 'start': {
        if (isActive) {
          setMessages(prev => [
            ...prev.filter(m => !m.id.startsWith('local-')),
            ...(prev.some(m => m.id === ev.user_message.id) ? [] : [ev.user_message]),
          ])
        }
        bufFor(evTid).replaceNext = false
        setStreams(prev => ({
          ...prev,
          [evTid]: {
            id: `stream-${Date.now()}`,
            thread_id: evTid,
            role: 'assistant',
            content: '',
            parts: [],
            attachments: [],
            meta: { status: 'THINKING' },
            created: Date.now() / 1000,
            created_iso: new Date().toISOString(),
            streaming: true,
          },
        }))
        if (ev.title) {
          setThreads(prev => prev.map(t => t.id === evTid ? { ...t, title: ev.title } : t))
        }
        break
      }
      case 'delta':
        bufFor(evTid).text += ev.text
        scheduleFlush(evTid)
        break
      case 'note':
        patchStream(evTid, m => ({ ...m, parts: [...m.parts, { type: 'note', text: ev.text }] }))
        break
      case 'todos':
        if (isActive) setTodos(ev.items)
        break
      case 'retry':
        patchStream(evTid, m => ({ ...m, parts: [], meta: { ...m.meta, status: 'THINKING' } }))
        break
      case 'thinking':
        patchStream(evTid, m => {
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
        patchStream(evTid, m => ({ ...m, meta: { ...m.meta, status: ev.status } }))
        break
      case 'ask': {
        const ask: AskPart = {
          type: 'ask', question_id: ev.id, prompt: ev.prompt,
          choices: ev.choices || [], secret: ev.secret, status: 'waiting',
        }
        patchStream(evTid, m => ({ ...m, parts: [...m.parts, ask] }))
        break
      }
      case 'file_edit':
        patchStream(evTid, m => {
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
      case 'tool_delta': {
        const b = bufFor(evTid)
        b.tools[ev.id] = (b.tools[ev.id] || '') + ev.output
        scheduleFlush(evTid)
        break
      }
      case 'text_final':
        patchStream(evTid, m => {
          // One rolling status block: each turn replaces the previous summary
          // instead of stacking another paragraph above the action cards.
          const actions = m.parts.filter(p => p.type !== 'text')
          return {
            ...m,
            parts: ev.text.trim() ? [{ type: 'text' as const, text: ev.text }, ...actions] : actions,
          }
        })
        bufFor(evTid).replaceNext = true
        break
      case 'tool_start':
      case 'tool_approval':
        patchStream(evTid, m => {
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
        patchStream(evTid, m => ({
          ...m,
          parts: m.parts.map(p => p.type === 'tool' && p.call_id === ev.id
            ? { ...p, ok: ev.ok, output: ev.output, status: ev.status }
            : p),
        }))
        break
      case 'done':
        bufFor(evTid).replaceNext = false
        doneRef.current[evTid] = true
        dropStream(evTid)
        if (isActive) {
          setRunInfo(null)
          setMessages(prev => {
            const idx = prev.findIndex(m => m.id === ev.message.id)
            if (idx === -1) return [...prev, ev.message]
            const next = prev.slice()
            next[idx] = ev.message
            return next
          })
          if (ev.title) {
            setThreads(prev => prev.map(t => t.id === evTid ? { ...t, title: String(ev.title) } : t))
          }
        } else {
          pushToast('a session finished in the background', 'ok')
        }
        loadThreads()
        break
      case 'error':
        if (isActive) pushToast(ev.message, 'err')
        patchStream(evTid, m => ({
          ...m,
          parts: [...m.parts, { type: 'text', text: `\n\n> **error** · ${ev.message}` }],
        }))
        break
    }
  }

  const attachJobIfRunning = async (id: string) => {
    try {
      if (streamsRef.current[id]) return  // live stream already attached
      const st = await api.jobStatus(id)
      if (!st.running || activeRef.current !== id) return
      jobAbortRef.current[id]?.abort()
      const ctrl = new AbortController()
      jobAbortRef.current[id] = ctrl
      setStreams(prev => ({
        ...prev,
        [id]: {
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
        },
      }))
      if (activeRef.current !== id) return
      await subscribeJob(id, ev => handleEvent(ev, id), ctrl.signal)
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
    // Only replace a stream in this same session; other sessions keep running.
    abortRef.current[tid]?.abort()
    setRunInfo(null)
    const ctrl = new AbortController()
    abortRef.current[tid] = ctrl
    delete doneRef.current[tid]
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
      }, ev => handleEvent(ev, tid as string), ctrl.signal)
    } catch (e) {
      if (!ctrl.signal.aborted) {
        pushToast(e instanceof Error ? e.message : 'stream failed — state is saved locally', 'err')
        // The run is persisted server-side; reload whatever was saved.
        api.messages(tid).then(r => {
          if (activeRef.current !== tid) return
          setMessages(r.messages)
          setRunInfo(r.run ?? null)
        }).catch(() => {})
      }
    } finally {
      delete abortRef.current[tid]
      if (!doneRef.current[tid]) dropStream(tid as string)
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
      if (tid && !jobAbortRef.current[tid]?.signal.aborted) openThread(tid)
    }, 7000)
  }

  const undoMessage = useCallback(async (m: Message) => {
    if (m.role !== 'user') return
    if (streaming) {
      pushToast('stop the current run before undoing', 'err')
      return
    }
    const lastUser = [...messages].reverse().find(x => x.role === 'user')
    const latest = lastUser?.id === m.id

    if (latest && !m.id.startsWith('local-') && activeId) {
      try {
        await api.undoMessage(m.id)
      } catch (e) {
        pushToast(e instanceof Error ? e.message : 'undo failed', 'err')
        return
      }
      try {
        const r = await api.messages(activeId)
        if (activeRef.current === activeId) setMessages(r.messages)
      } catch { /* keep the local view */ }
    } else if (latest) {
      setMessages(prev => prev.filter(x => x.id !== m.id))
    }

    setDraftRestore({ text: m.content || '', seq: ++restoreSeq.current })
    pushToast(latest ? 'undone — back in the composer' : 'loaded into the composer')
  }, [messages, streaming, activeId, pushToast])

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
          runningIds={Object.keys(streams)}
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

        {runInfo?.status === 'interrupted' && (
          <div className="mx-auto w-full max-w-3xl px-3 pt-2 sm:px-5 xl:max-w-4xl">
            <div className="flex items-center gap-2 rounded-xl border border-amber/40 bg-amber/10 px-3 py-2 text-[11.5px] text-amber">
              <CircleDot size={12} />
              <span className="min-w-0 flex-1 truncate">
                Previous task was interrupted — saved state is available.
              </span>
              <button
                type="button"
                className="btn h-7 shrink-0 px-2.5 text-[11px]"
                onClick={() => send('continue', [], { mode, effort, autoApprove, model: activeModel })}
              >
                Continue
              </button>
            </div>
          </div>
        )}

        <Chat
          messages={messages}
          streaming={streaming}
          threadId={activeId}
          loading={loadingMessages}
          showThinking={showThinking}
          onUndo={undoMessage}
          onSuggestion={text => send(text, [], { mode, effort, autoApprove, model: activeModel })}
        />

        <TodoPanel items={todos} />

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
          restore={draftRestore}
        />
      </main>

      <RightPanel
        open={rightOpen}
        onClose={() => setRightOpen(false)}
        thread={activeThread}
        messages={messages}
        models={models}
        onOpenScans={() => setScansOpen(true)}
      />

      <SettingsModal
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        models={models}
        active={activeModel}
        onModel={changeModel}
        pushToast={pushToast}
        onSaved={loadModels}
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
