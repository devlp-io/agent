import { useEffect, useState } from 'react'
import {
  Terminal, Globe, Search, FolderOpen, FileText, PenLine, Radar,
  ChevronRight, Check, X, Loader2, ShieldAlert, CheckCheck, Paperclip,
  Download, FilePlus2, FilePen, Wrench, Copy,
} from 'lucide-react'
import { Markdown } from './Markdown'
import type { AskPart, Attachment, Message, Part, ToolPart } from '../lib/types'
import { api } from '../lib/api'

/* ── professional action labels ─────────────────────────────────────── */

function shellLabel(cmd: string): { title: string; detail: string } {
  const c = (cmd || '').trim()
  const base = c.split(/\s+/)[0] || 'shell'
  const detail = c.length > 160 ? c.slice(0, 157) + '…' : c

  const sed = c.match(/^sed\s+-n\s+['"]?(\d+),(\d+)p['"]?\s+(\S+)/)
  if (sed) return { title: `Analyzed ${short(sed[3])} L${sed[1]}-${sed[2]}`, detail }

  if (/&&|;|\|/.test(c)) return { title: 'Ran shell command', detail }

  if (/^(cat|head|tail|less|more|bat|nl)\b/.test(c)) {
    const f = c.split(/\s+/).filter(t => !t.startsWith('-')).pop() || ''
    return { title: f ? `Read ${short(f)}` : 'Read file', detail }
  }
  if (/^(ls|tree|du|stat)\b/.test(c)) return { title: 'Listed files', detail }
  if (/^(grep|rg|ag|ack)\b/.test(c)) return { title: 'Searched files', detail }
  if (/^find\b/.test(c)) return { title: 'Searched filesystem', detail }
  if (/^(curl|wget|http|httpie)\b/.test(c)) return { title: 'Fetched URL', detail }
  if (/^(mkdir|touch|cp|mv|rm|chmod|chown)\b/.test(c)) {
    const verb: Record<string, string> = {
      mkdir: 'Created directory', touch: 'Created file', cp: 'Copied files',
      mv: 'Moved files', rm: 'Removed files', chmod: 'Changed permissions', chown: 'Changed ownership',
    }
    return { title: verb[base] || 'Modified filesystem', detail }
  }
  const git = c.match(/^git\s+(\w+)/)
  if (git) return { title: `Ran git ${git[1]}`, detail }
  if (/^(npm|pnpm|yarn|bun|pip|pip3|uv|cargo|go|apt|apt-get|brew)\b/.test(c)) {
    return { title: `Ran ${base}`, detail }
  }
  if (/^(python|python3|node|deno|bash|sh|zsh|ruby|perl)\b/.test(c)) return { title: 'Ran script', detail }
  if (/^(make|cmake|gcc|g\+\+|clang|rustc)\b/.test(c)) return { title: 'Compiled project', detail }
  return { title: 'Ran shell command', detail }
}

function short(p: string): string {
  const parts = p.split('/')
  const name = parts[parts.length - 1] || p
  return name.length > 34 ? name.slice(0, 31) + '…' : name
}

const RUNNING_MAP: Array<[string, string]> = [
  ['Ran shell command', 'Running shell'],
  ['Read ', 'Reading '],
  ['Listed files', 'Listing files'],
  ['Searched filesystem', 'Searching filesystem'],
  ['Searched files', 'Searching files'],
  ['Analyzed ', 'Analyzing '],
  ['Fetched URL', 'Fetching URL'],
  ['Created directory', 'Creating directory'],
  ['Created file', 'Creating file'],
  ['Copied files', 'Copying files'],
  ['Moved files', 'Moving files'],
  ['Removed files', 'Removing files'],
  ['Changed permissions', 'Changing permissions'],
  ['Changed ownership', 'Changing ownership'],
  ['Ran git ', 'Running git '],
  ['Ran script', 'Running script'],
  ['Compiled project', 'Compiling project'],
  ['Started scan', 'Scanning'],
  ['Wrote ', 'Writing '],
  ['Searched the web', 'Searching the web'],
]
const PAST_MAP: Array<[string, string]> = [
  ['Ran shell command', 'Ran shell'],
]

function toRunning(title: string): string {
  for (const [a, b] of RUNNING_MAP) if (title.startsWith(a)) return b + title.slice(a.length)
  if (title.startsWith('Ran ')) return 'Running ' + title.slice(4)
  return title
}

function toPast(title: string): string {
  for (const [a, b] of PAST_MAP) if (title.startsWith(a)) return b + title.slice(a.length)
  return title
}

function toolLabel(part: ToolPart): { title: string; detail: string; icon: typeof Terminal } {
  const running = part.status === 'running'
  if (part.tool === 'shell') {
    const { title, detail } = shellLabel(String(part.args.cmd ?? ''))
    return { title: running ? toRunning(title) : toPast(title), detail, icon: Terminal }
  }
  if (part.tool === 'edit') {
    const isNew = String(part.args.action ?? '') === 'created'
    const name = short(String(part.args.path ?? 'file'))
    return {
      title: running
        ? `${isNew ? 'Creating' : 'Editing'} ${name}`
        : `${isNew ? 'Created' : 'Edited'} ${name}`,
      detail: '',
      icon: isNew ? FilePlus2 : FilePen,
    }
  }
  if (part.tool === 'fetch') return { title: running ? 'Fetching URL' : 'Fetched URL', detail: String(part.args.url ?? ''), icon: Globe }
  if (part.tool === 'read') return { title: `${running ? 'Reading' : 'Read'} ${short(String(part.args.path ?? ''))}`, detail: '', icon: FileText }
  if (part.tool === 'write') return { title: `${running ? 'Writing' : 'Wrote'} ${short(String(part.args.path ?? ''))}`, detail: '', icon: PenLine }
  if (part.tool === 'list') return { title: running ? 'Listing files' : 'Listed files', detail: String(part.args.path ?? ''), icon: FolderOpen }
  if (part.tool === 'web_search') return { title: running ? 'Searching the web' : 'Searched the web', detail: String(part.args.query ?? ''), icon: Search }
  if (part.tool === 'scan') return { title: running ? 'Scanning' : 'Started scan', detail: String(part.args.target ?? ''), icon: Radar }
  if (part.tool === 'finish') return { title: 'Finished', detail: '', icon: CheckCheck }
  return { title: part.tool, detail: '', icon: Wrench }
}

const STATUS_COLOR: Record<string, string> = {
  running: 'text-accent',
  done: 'text-mint',
  error: 'text-rose',
  denied: 'text-amber',
  cancelled: 'text-faint',
  awaiting: 'text-amber',
}

/* ── action rows (antigravity style) ────────────────────────────────── */

function ToolCard({ part, defaultOpen }: { part: ToolPart; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  const { title, detail, icon: Icon } = toolLabel(part)
  const [busy, setBusy] = useState(false)
  const [copied, setCopied] = useState(false)

  useEffect(() => { setOpen(defaultOpen) }, [defaultOpen])

  const decide = async (allow: boolean) => {
    setBusy(true)
    try { await api.approve(part.call_id, allow) } catch { /* stream ended */ }
    finally { setBusy(false) }
  }

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(part.output || '')
      setCopied(true); setTimeout(() => setCopied(false), 1300)
    } catch { /* blocked */ }
  }

  return (
    <div className="rise my-1 overflow-hidden rounded-xl border border-line bg-panel2/50">
      <button
        onClick={() => setOpen(v => !v)}
        className="flex w-full items-center gap-2.5 px-3 py-2 text-left transition hover:bg-panel3/50"
      >
        <span className={`shrink-0 ${STATUS_COLOR[part.status] ?? 'text-muted'}`}>
          {part.status === 'running'
            ? <Loader2 size={14} className="spin-slow" />
            : part.status === 'done'
              ? <Check size={14} />
              : part.status === 'awaiting' || part.status === 'denied'
                ? <ShieldAlert size={14} />
                : <X size={14} />}
        </span>
        <Icon size={13.5} className="shrink-0 text-muted" />
        <span className={`shrink-0 text-[12.5px] font-medium ${part.status === 'running' ? 'text-ink' : 'text-ink/90'}`}>
          {title}
        </span>
        {detail && (
          <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-faint">{detail}</span>
        )}
        <ChevronRight size={13} className={`shrink-0 text-faint transition-transform ${open ? 'rotate-90' : ''}`} />
      </button>

      {open && (
        <div className="border-t border-line">
          {part.tool === 'edit' ? (
            <div className="max-h-[420px] overflow-auto p-2.5">
              <Markdown text={'```' + (part.language || '') + '\n' + (part.output || '') + '\n```'} raw />
            </div>
          ) : (
            <div className="relative">
              {part.output ? (
                <>
                  <button
                    onClick={copy}
                    className="absolute right-2 top-2 flex h-6 items-center gap-1 rounded-md border border-line bg-panel/90 px-1.5 text-[10.5px] text-muted backdrop-blur transition hover:text-ink"
                  >
                    {copied ? <Check size={10} className="text-mint" /> : <Copy size={10} />}
                    {copied ? 'Copied' : 'Copy'}
                  </button>
                  <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words bg-[#06070a] px-3 py-2.5 font-mono text-[11.5px] leading-relaxed text-ink/85">
                    {part.output}
                  </pre>
                </>
              ) : (
                <div className="px-3 py-2.5 text-[11.5px] text-faint">
                  {part.status === 'running' ? 'running…' : '(no output)'}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {part.status === 'awaiting' && (
        <div className="flex items-center gap-2 border-t border-line bg-amber/5 px-3 py-2">
          <span className="flex-1 text-[12px] text-amber">Approve this tool call?</span>
          <button disabled={busy} onClick={() => decide(true)} className="btn h-7 px-2.5 text-[12px]">
            <Check size={13} /> Allow
          </button>
          <button disabled={busy} onClick={() => decide(false)} className="btn btn-ghost h-7 px-2.5 text-[12px] text-rose">
            <X size={13} /> Deny
          </button>
        </div>
      )}
    </div>
  )
}

/* ── ask card ───────────────────────────────────────────────────────── */

function AskCard({ part, threadId }: { part: AskPart; threadId: string }) {
  const [value, setValue] = useState('')
  const [sent, setSent] = useState(part.status === 'answered')
  const [busy, setBusy] = useState(false)

  const send = async (answer: string) => {
    setBusy(true)
    try {
      await api.answerQuestion(threadId, part.question_id, answer)
      setSent(true)
    } catch { /* expired */ }
    finally { setBusy(false) }
  }

  return (
    <div className="my-2 overflow-hidden rounded-xl border border-amber/35 bg-amber/5">
      <div className="flex items-start gap-2.5 px-3 py-2.5">
        <ShieldAlert size={15} className="mt-0.5 shrink-0 text-amber" />
        <div className="min-w-0 flex-1">
          <div className="text-[12.5px] font-medium text-ink">Agent needs input</div>
          <p className="mt-1 whitespace-pre-wrap break-words text-[12.5px] text-muted">{part.prompt}</p>
        </div>
      </div>
      <div className="border-t border-amber/20 p-2.5">
        {sent ? (
          <div className="flex items-center gap-1.5 text-[12px] text-mint"><Check size={13} /> answered</div>
        ) : part.choices?.length ? (
          <div className="flex flex-wrap gap-1.5">
            {part.choices.map(c => (
              <button key={c} className="btn h-7 px-2.5 text-[12px]" disabled={busy} onClick={() => send(c)}>{c}</button>
            ))}
          </div>
        ) : (
          <div className="flex gap-2">
            <input
              type={part.secret ? 'password' : 'text'}
              value={value}
              onChange={e => setValue(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && value.trim()) send(value) }}
              placeholder="Type your answer…"
              className="field h-8 flex-1 text-[12.5px]"
              autoComplete="off"
            />
            <button className="btn btn-primary h-8" disabled={busy || !value.trim()} onClick={() => send(value)}>
              Send
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

/* ── attachments ────────────────────────────────────────────────────── */

function AttachmentGrid({ items }: { items: Attachment[] }) {
  if (!items?.length) return null
  return (
    <div className="mb-2 flex flex-wrap gap-2">
      {items.map(a => (
        a.kind === 'image' ? (
          <a key={a.id} href={a.url} target="_blank" rel="noreferrer" className="group relative block overflow-hidden rounded-xl border border-line">
            <img src={a.url} alt={a.filename} className="max-h-48 max-w-[260px] object-cover" />
            <span className="absolute inset-x-0 bottom-0 truncate bg-black/60 px-2 py-1 text-[10.5px] text-white/80 opacity-0 backdrop-blur transition group-hover:opacity-100">
              {a.filename}
            </span>
          </a>
        ) : (
          <a key={a.id} href={`${a.url}?download=1`} target="_blank" rel="noreferrer"
             className="group flex max-w-[260px] items-center gap-2 rounded-xl border border-line bg-panel2 px-2.5 py-2 transition hover:border-line2">
            <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-panel3 text-muted">
              <Paperclip size={14} />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-[12px] text-ink">{a.filename}</span>
              <span className="block text-[10.5px] text-faint">{Math.max(1, Math.round(a.size / 1024))} KB</span>
            </span>
            <Download size={13} className="shrink-0 text-faint group-hover:text-muted" />
          </a>
        )
      ))}
    </div>
  )
}

/* ── footer ─────────────────────────────────────────────────────────── */

function useTick(active: boolean) {
  const [, force] = useState(0)
  useEffect(() => {
    if (!active) return
    const t = setInterval(() => force(n => n + 1), 250)
    return () => clearInterval(t)
  }, [active])
}

function Dots() {
  return (
    <span className="dots" aria-hidden>
      <span /><span /><span />
    </span>
  )
}

function Footer({ m, actions }: { m: Message; actions: number }) {
  useTick(!!m.streaming)
  const elapsed = Math.max(0, (Date.now() / 1000) - m.created)
  const totalSecs = Number(m.meta?.duration_ms ?? 0) / 1000

  if (m.streaming) {
    const status = String(m.meta?.status ?? '')
    const working = /RUNNING|WORKING/i.test(status)
    return (
      <div className="relative z-10 mt-3 flex items-center gap-1.5 text-[11.5px] text-faint">
        <span className="text-muted">{working ? 'Working' : 'Thinking'}</span>
        <Dots />
        <span className="ml-1 tabular-nums">{elapsed > 1 ? `${elapsed.toFixed(0)}s` : ''}</span>
      </div>
    )
  }

  const stopped = Boolean(m.meta?.aborted || m.meta?.stop_reason)
  const stopReason = m.meta?.stop_reason ? ` (${String(m.meta.stop_reason)})` : ''
  const bits: string[] = [stopped
    ? `Stopped after ${totalSecs > 0.2 ? totalSecs.toFixed(1) : Math.max(0.1, elapsed).toFixed(1)}s${stopReason}`
    : `Worked ${totalSecs > 0.2 ? totalSecs.toFixed(1) : Math.max(0.1, elapsed).toFixed(1)}s`]
  if (actions > 0) bits.push(`${actions} action${actions === 1 ? '' : 's'}`)
  return <div className="relative z-10 mt-3 text-[11px] text-faint">{bits.join(' · ')}</div>
}

function ThinkingBlock({ text }: { text: string }) {
  return (
    <div className="my-1.5 max-h-48 overflow-y-auto border-l-2 border-line pl-3 text-[11.5px] leading-relaxed text-faint/80">
      <pre className="whitespace-pre-wrap break-words font-sans">{text}</pre>
    </div>
  )
}

/* ── message ────────────────────────────────────────────────────────── */

export function MessageItem({ m, showThinking }: { m: Message; showThinking: boolean }) {
  const [showAllSteps, setShowAllSteps] = useState(false)
  const isUser = m.role === 'user'
  const parts: Part[] = m.parts?.length
    ? m.parts
    : (m.content ? [{ type: 'text', text: m.content } as const] : [])

  if (isUser) {
    return (
      <div className="rise flex justify-end px-0.5">
        <div className="max-w-[86%] sm:max-w-[75%]">
          <AttachmentGrid items={m.attachments} />
          {m.content && (
            <div className="whitespace-pre-wrap break-words rounded-2xl rounded-br-md border border-accent/25 bg-accent/12 px-3.5 py-2.5 text-[14.5px] leading-relaxed">
              {m.content}
            </div>
          )}
        </div>
      </div>
    )
  }

  if (!parts.length && !m.content && !m.streaming) return null

  const actionIdx = parts
    .map((p, i) => (p.type === 'tool' ? i : -1))
    .filter(i => i >= 0)
  const shellIdx = parts
    .map((p, i) => (p.type === 'tool' && p.tool === 'shell' ? i : -1))
    .filter(i => i >= 0)
  const lastShell = shellIdx.length ? shellIdx[shellIdx.length - 1] : -1
  const activityIdx = parts
    .map((p, i) => (p.type === 'tool' || p.type === 'note' ? i : -1))
    .filter(i => i >= 0)
  const firstActivity = activityIdx.length ? activityIdx[0] : -1
  // Keep actions visible by default; only fold very long runs.
  const doneCollapse = !m.streaming && activityIdx.length > 20 && !showAllSteps
  const collapse = m.streaming && !showAllSteps && actionIdx.length > 20
  const firstShownAction = collapse ? actionIdx[actionIdx.length - 3] : -1
  const hiddenSteps = collapse ? actionIdx.length - 3 : 0

  return (
    <div className="rise px-0.5">
      <div className="mb-1.5 flex items-center gap-2">
        <span className="grid h-5 w-5 place-items-center rounded-md bg-gradient-to-br from-accent2 to-accent text-white">
          <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" strokeWidth="2.4">
            <path d="M12 2 22 12 12 22 2 12Z" />
          </svg>
        </span>
        <span className="text-[11.5px] font-medium text-muted">SOM-SCAN</span>
      </div>

      <div className="pl-7">
        {parts.map((p, i) => {
          const activity = p.type === 'tool' || p.type === 'note'

          if (doneCollapse && activity) {
            if (i !== firstActivity) return null
            return (
              <button
                key={`activity-${i}`}
                onClick={() => setShowAllSteps(true)}
                className="my-1.5 flex items-center gap-1.5 rounded-lg border border-line bg-panel2/40 px-2.5 py-1.5 text-[11px] text-faint transition hover:border-line2 hover:text-muted"
              >
                <ChevronRight size={11} />
                Show {activityIdx.length} step{activityIdx.length === 1 ? '' : 's'}
              </button>
            )
          }

          if (showAllSteps && !m.streaming && activity && i === firstActivity) {
            return (
              <div key={`hide-${i}`}>
                <button
                  onClick={() => setShowAllSteps(false)}
                  className="my-1.5 flex items-center gap-1.5 text-[11px] text-faint transition hover:text-muted"
                >
                  <ChevronRight size={11} className="rotate-90" />
                  Hide steps
                </button>
                {p.type === 'tool'
                  ? <ToolCard part={p} defaultOpen={p.tool === 'shell' && i === lastShell} />
                  : (
                    <div className="my-1 flex items-start gap-1.5 text-[11.5px] leading-snug text-faint">
                      <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-faint/70" />
                      <span className="min-w-0 break-words">{p.text.length > 220 ? p.text.slice(0, 217) + '…' : p.text}</span>
                    </div>
                  )}
              </div>
            )
          }

          if (p.type === 'tool') {
            if (collapse && i < firstShownAction) return null
            return (
              <>
                {collapse && i === firstShownAction && (
                  <button
                    key={`more-${i}`}
                    onClick={() => setShowAllSteps(true)}
                    className="my-1.5 flex items-center gap-1.5 text-[11px] text-faint transition hover:text-muted"
                  >
                    <ChevronRight size={11} />
                    Show {hiddenSteps} earlier step{hiddenSteps === 1 ? '' : 's'}
                  </button>
                )}
                <ToolCard key={p.call_id || i} part={p} defaultOpen={p.tool === 'shell' && i === lastShell} />
              </>
            )
          }
          if (p.type === 'ask') return <AskCard key={p.question_id || i} part={p} threadId={m.thread_id} />
          if (p.type === 'thought') return showThinking && p.text?.trim() ? <ThinkingBlock key={i} text={p.text} /> : null
          if (p.type === 'note') {
            if (collapse && firstShownAction >= 0 && i < firstShownAction) return null
            return (
              <div key={i} className="my-1 flex items-start gap-1.5 text-[11.5px] leading-snug text-faint">
                <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-faint/70" />
                <span className="min-w-0 break-words">{p.text.length > 220 ? p.text.slice(0, 217) + '…' : p.text}</span>
              </div>
            )
          }
          return p.text?.trim() ? <Markdown key={i} text={p.text} plain={m.meta?.engine === 'cli'} /> : null
        })}

        <Footer m={m} actions={actionIdx.length} />
      </div>
    </div>
  )
}
