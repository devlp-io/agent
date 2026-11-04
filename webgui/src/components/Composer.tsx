import { useCallback, useEffect, useRef, useState } from 'react'
import {
  ArrowUp, Square, Paperclip, X, ChevronDown, Bot, MessageSquare,
  Zap, Scale, Brain, ShieldOff, ImageIcon, FileText, Loader2,
} from 'lucide-react'
import type { Attachment, ModelProfile, ModelVariant } from '../lib/types'
import { api } from '../lib/api'

export type ComposerOptions = {
  mode: 'agent' | 'chat'
  effort: 'quick' | 'balanced' | 'deep'
  autoApprove: boolean
  model: string | null
}

export function Composer({
  threadId, ensureThread, streaming, models, activeModel, onModelChange,
  mode, setMode, effort, setEffort,
  onSend, onStop, pushToast, onToggleThinking, restore,
}: {
  threadId: string | null
  ensureThread: () => Promise<string | null>
  streaming: boolean
  models: ModelProfile[]
  activeModel: string | null
  onModelChange: (name: string) => void
  mode: 'agent' | 'chat'
  setMode: (m: 'agent' | 'chat') => void
  effort: 'quick' | 'balanced' | 'deep'
  setEffort: (e: 'quick' | 'balanced' | 'deep') => void
  autoApprove: boolean
  setAutoApprove: (v: boolean) => void
  onSend: (text: string, attachments: Attachment[], opts: ComposerOptions) => void
  onStop: () => void
  pushToast: (msg: string, kind?: 'ok' | 'err') => void
  onToggleThinking: (next?: boolean) => void
  restore?: { text: string; seq: number } | null
}) {
  const [text, setText] = useState('')
  const [files, setFiles] = useState<Attachment[]>([])
  const [uploading, setUploading] = useState(0)
  const [dragging, setDragging] = useState(false)
  const [menu, setMenu] = useState<'model' | 'mode' | null>(null)
  const taRef = useRef<HTMLTextAreaElement>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const wrapRef = useRef<HTMLDivElement>(null)

  const draftKey = `agui:draft:${threadId ?? 'new'}`
  const prevThread = useRef<string | null>(threadId)

  useEffect(() => {
    const prev = prevThread.current
    if (prev === threadId) return
    prevThread.current = threadId
    // null -> new thread (lazy create from send/upload): keep the draft in place
    if (prev === null && threadId) return
    setText(sessionStorage.getItem(draftKey) || '')
    setFiles([])
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [threadId])

  useEffect(() => {
    sessionStorage.setItem(draftKey, text)
  }, [text, draftKey])

  // Undo from a user bubble: restore the text and put the caret at the end.
  useEffect(() => {
    if (!restore) return
    setText(restore.text)
    setFiles([])
    requestAnimationFrame(() => {
      const el = taRef.current
      if (!el) return
      el.focus()
      const end = restore.text.length
      el.setSelectionRange(end, end)
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [restore?.seq])

  useEffect(() => {
    const el = taRef.current
    if (!el) return
    el.style.height = 'auto'
    el.style.height = `${Math.min(el.scrollHeight, 220)}px`
  }, [text])

  // click-outside closes menus; clicks inside the composer never do
  useEffect(() => {
    if (!menu) return
    const onDown = (e: PointerEvent) => {
      if (!wrapRef.current?.contains(e.target as Node)) setMenu(null)
    }
    document.addEventListener('pointerdown', onDown)
    return () => document.removeEventListener('pointerdown', onDown)
  }, [menu])

  const upload = useCallback(async (list: FileList | File[]) => {
    const arr = Array.from(list).slice(0, 10)
    if (!arr.length) return
    let tid = threadId
    if (!tid) {
      tid = await ensureThread()
      if (!tid) { pushToast('could not create chat', 'err'); return }
    }
    setUploading(n => n + arr.length)
    for (const f of arr) {
      try {
        const a = await api.upload(f, tid)
        setFiles(prev => [...prev, a])
      } catch (e) {
        pushToast(e instanceof Error ? e.message : 'upload failed', 'err')
      } finally {
        setUploading(n => Math.max(0, n - 1))
      }
    }
  }, [threadId, ensureThread, pushToast])

  const submit = () => {
    const t = text.trim()
    if (t.toLowerCase().startsWith('/thinking')) {
      const arg = t.split(/\s+/)[1]?.toLowerCase()
      onToggleThinking(arg === 'on' ? true : arg === 'off' ? false : undefined)
      setText('')
      sessionStorage.removeItem(draftKey)
      return
    }
    if ((!t && !files.length) || streaming) return
    onSend(t, files, { mode, effort, autoApprove: true, model: activeModel })
    setText('')
    setFiles([])
    sessionStorage.removeItem(draftKey)
  }

  const activeProfile = models.find(m => m.name === activeModel)
  const variants: ModelVariant[] = activeProfile?.variants?.length
    ? activeProfile.variants
    : [
        { key: 'quick', label: 'Quick' },
        { key: 'balanced', label: 'Balanced' },
        { key: 'deep', label: 'Deep' },
      ]
  const effectiveLabel = variants.find(v => v.key === effort)?.label
    ?? activeProfile?.label ?? activeProfile?.model ?? 'model'
  const variantIcon = { quick: Zap, balanced: Scale, deep: Brain } as const
  const canSend = (text.trim().length > 0 || files.length > 0) && !streaming

  return (
    <div ref={wrapRef} className="relative mx-auto w-full max-w-3xl px-3 pb-[calc(10px+var(--safe-b))] pt-2 sm:px-5 xl:max-w-4xl">
      <div
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={e => {
          e.preventDefault(); setDragging(false)
          if (e.dataTransfer.files?.length) upload(e.dataTransfer.files)
        }}
        className={[
          'glass rounded-2xl border transition-all duration-200',
          dragging ? 'border-accent/70 shadow-[0_0_0_4px_rgba(124,140,255,0.14)]' : 'border-line2 shadow-[0_18px_45px_-24px_rgba(0,0,0,0.9)]',
        ].join(' ')}
      >
        {(files.length > 0 || uploading > 0) && (
          <div className="flex flex-wrap gap-2 rounded-t-2xl border-b border-line px-3 py-2.5">
            {files.map(a => (
              <div key={a.id} className="group relative flex items-center gap-2 rounded-lg border border-line bg-panel3/80 py-1.5 pl-1.5 pr-7">
                {a.kind === 'image'
                  ? <img src={a.url} alt="" className="h-8 w-8 rounded-md object-cover" />
                  : <span className="grid h-8 w-8 place-items-center rounded-md bg-panel text-muted">
                      {a.kind === 'text' ? <FileText size={14} /> : <ImageIcon size={14} />}
                    </span>}
                <div className="min-w-0 max-w-[140px]">
                  <div className="truncate text-[11.5px] text-ink">{a.filename}</div>
                  <div className="text-[10px] text-faint">{Math.max(1, Math.round(a.size / 1024))} KB</div>
                </div>
                <button
                  type="button"
                  onClick={() => setFiles(p => p.filter(x => x.id !== a.id))}
                  className="absolute right-1 top-1/2 grid h-5 w-5 -translate-y-1/2 place-items-center rounded-md text-faint transition hover:bg-panel hover:text-rose"
                  aria-label="Remove attachment"
                >
                  <X size={12} />
                </button>
              </div>
            ))}
            {uploading > 0 && (
              <div className="flex items-center gap-2 rounded-lg border border-line bg-panel3/60 px-2.5 py-1.5 text-[11.5px] text-muted">
                <Loader2 size={13} className="spin-slow" /> uploading {uploading}
              </div>
            )}
          </div>
        )}

        <textarea
          ref={taRef}
          value={text}
          onChange={e => setText(e.target.value)}
          onPaste={e => {
            const items = e.clipboardData?.files
            if (items?.length) { e.preventDefault(); upload(items) }
          }}
          onKeyDown={e => {
            if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
              e.preventDefault()
              submit()
            }
          }}
          rows={1}
          placeholder={mode === 'agent'
            ? 'Tell the agent what to do — it runs commands, scans, builds…'
            : 'Ask anything…'}
          className="max-h-[220px] w-full resize-none bg-transparent px-3.5 py-3 text-[14.5px] leading-relaxed text-ink outline-none placeholder:text-faint"
        />

        <div className="flex items-center gap-1 px-2 pb-2 pt-0.5">
          <input
            ref={fileRef} type="file" multiple className="hidden"
            onChange={e => { if (e.target.files) upload(e.target.files); e.target.value = '' }}
          />
          <button
            type="button" className="icon-btn h-8 w-8"
            onClick={() => fileRef.current?.click()}
            aria-label="Attach media" title="Attach image / file"
          >
            <Paperclip size={16} />
          </button>

          {mode === 'agent' ? (
            <span
              className="chip h-7 cursor-default border-transparent bg-transparent pl-2 pr-2 text-[11px]"
              title="Agent mode drives the CLI engine: real shell, scans, files"
            >
              <ShieldOff size={12} className="text-mint" />
              <span className="hidden sm:inline">tools live</span>
            </span>
          ) : null}

          <div className="ml-auto flex items-center gap-1">
            <button
              type="button"
              aria-label={`Mode: ${mode === 'agent' ? 'Agent' : 'Chat'}`}
              onClick={() => setMenu(m => m === 'mode' ? null : 'mode')}
              className="chip h-7 border-transparent bg-transparent px-2 text-[11.5px] hover:bg-panel3"
            >
              {mode === 'agent' ? <Bot size={12.5} /> : <MessageSquare size={12.5} />}
              <span>{mode === 'agent' ? 'Agent' : 'Chat'}</span>
              <ChevronDown size={11} className="text-faint" />
            </button>

            <button
              type="button"
              aria-label="Select model"
              onClick={() => setMenu(m => m === 'model' ? null : 'model')}
              className="chip h-7 max-w-[170px] border-transparent bg-transparent px-2 text-[11.5px] hover:bg-panel3"
            >
              <span className="truncate">{effectiveLabel}</span>
              <ChevronDown size={11} className="shrink-0 text-faint" />
            </button>

            {streaming ? (
              <button type="button" onClick={onStop} className="btn btn-icon h-8 w-8 border-line2 bg-panel3" aria-label="Stop">
                <Square size={13} className="fill-current" />
              </button>
            ) : (
              <button
                type="button" onClick={submit} disabled={!canSend}
                className="btn btn-primary btn-icon h-8 w-8 rounded-full p-0"
                aria-label="Send"
              >
                <ArrowUp size={16} strokeWidth={2.6} />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Menus live outside the clipped composer shell */}
      {menu === 'mode' && (
        <div className="pop absolute bottom-[64px] right-3 z-40 w-56 overflow-hidden rounded-xl border border-line bg-panel shadow-2xl">
          <button
            className="flex w-full items-start gap-2.5 px-3 py-2.5 text-left hover:bg-panel3"
            onClick={() => { setMode('agent'); setMenu(null) }}
          >
            <Bot size={15} className="mt-0.5 text-accent" />
            <span>
              <span className="block text-[12.5px]">Agent</span>
              <span className="block text-[10.5px] text-faint">CLI engine · runs tools</span>
            </span>
          </button>
          <button
            className="flex w-full items-start gap-2.5 px-3 py-2.5 text-left hover:bg-panel3"
            onClick={() => { setMode('chat'); setMenu(null) }}
          >
            <MessageSquare size={15} className="mt-0.5 text-muted" />
            <span>
              <span className="block text-[12.5px]">Chat</span>
              <span className="block text-[10.5px] text-faint">Answer only, no tools</span>
            </span>
          </button>
        </div>
      )}

      {menu === 'model' && (
        <div className="pop absolute bottom-[64px] right-2 z-40 w-[min(20rem,calc(100vw-1rem))] overflow-hidden rounded-xl border border-line bg-panel shadow-2xl sm:right-3">
          <div className="flex items-center justify-between gap-2 border-b border-line px-3 py-2">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-faint">Model</span>
            <span className="max-w-[60%] truncate text-[10px] text-faint">{effectiveLabel}</span>
          </div>
          <div className="max-h-[min(56vh,320px)] overflow-y-auto py-1">
            {models.map(p => (
              <button
                key={p.name}
                onClick={() => { onModelChange(p.name); setMenu(null) }}
                className={[
                  'flex w-full items-center gap-2 px-3 py-2 text-left text-[12.5px] hover:bg-panel3',
                  p.active ? 'text-ink' : 'text-muted',
                ].join(' ')}
              >
                <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${p.configured ? 'bg-mint' : 'bg-faint'}`} />
                <span className="min-w-0 flex-1 truncate">{p.label ?? p.model}</span>
                <span className="shrink-0 text-[10px] text-faint">{p.name}</span>
              </button>
            ))}
          </div>
          <div className="border-t border-line px-2 pb-2 pt-1.5">
            <div className="px-1 pb-1 text-[9.5px] uppercase tracking-wider text-faint">
              Variants · {activeProfile?.label ?? 'model'}
            </div>
            <div className="flex gap-1">
              {variants.map(v => {
                const Icon = variantIcon[v.key] ?? Scale
                return (
                  <button
                    key={v.key}
                    onClick={() => { setEffort(v.key); setMenu(null) }}
                    className={[
                      'flex min-w-0 flex-1 flex-col items-center justify-center gap-0.5 rounded-lg px-1.5 py-2 text-[10.5px] transition',
                      effort === v.key ? 'bg-accent/12 text-accent' : 'text-muted hover:bg-panel3',
                    ].join(' ')}
                    title={v.model && v.model !== activeProfile?.model ? v.model : undefined}
                  >
                    <Icon size={12} />
                    <span className="max-w-full truncate">{v.label}</span>
                  </button>
                )
              })}
            </div>
          </div>
        </div>
      )}

      <div className="mt-1.5 hidden items-center justify-center gap-3 text-[10.5px] text-faint sm:flex">
        <span><span className="kbd">Enter</span> send</span>
        <span><span className="kbd">Shift</span>+<span className="kbd">Enter</span> newline</span>
        <span><span className="kbd">⌘</span>+<span className="kbd">K</span> commands</span>
      </div>
    </div>
  )
}
