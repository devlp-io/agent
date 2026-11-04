import { useMemo, useRef, useState } from 'react'
import {
  Plus, Search, Settings, Pin, PinOff, Trash2, Pencil, X,
  Sun, Moon, Radar, PanelLeftClose, Check, MoreHorizontal,
} from 'lucide-react'
import type { Thread } from '../lib/types'

function dayBucket(ts: number): string {
  const d = new Date(ts * 1000)
  const now = new Date()
  const startOf = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime()
  const diff = Math.round((startOf(now) - startOf(d)) / 86_400_000)
  if (diff <= 0) return 'Today'
  if (diff === 1) return 'Yesterday'
  if (diff < 7) return 'Previous 7 days'
  if (diff < 30) return 'Previous 30 days'
  return 'Earlier'
}

export function Sidebar({
  threads, activeId, query, setQuery,
  onSelect, onNew, onDelete, onRename, onPin,
  onOpenSettings, onOpenScans, onToggleTheme, theme,
  mobileOpen, onCloseMobile, onCollapse, runningIds,
}: {
  threads: Thread[]
  activeId: string | null
  query: string
  setQuery: (v: string) => void
  onSelect: (id: string) => void
  onNew: () => void
  onDelete: (id: string) => void
  onRename: (id: string, title: string) => void
  onPin: (id: string, pinned: boolean) => void
  onOpenSettings: () => void
  onOpenScans: () => void
  onToggleTheme: () => void
  theme: 'dark' | 'light'
  mobileOpen: boolean
  onCloseMobile: () => void
  onCollapse: () => void
  runningIds?: string[]
}) {
  const [editing, setEditing] = useState<string | null>(null)
  const [draft, setDraft] = useState('')
  const [sheet, setSheet] = useState<Thread | null>(null)
  const holdTimer = useRef<number | null>(null)
  const longPressed = useRef(false)

  const cancelHold = () => {
    if (holdTimer.current !== null) {
      window.clearTimeout(holdTimer.current)
      holdTimer.current = null
    }
  }

  const startHold = (t: Thread) => (e: React.PointerEvent<HTMLDivElement>) => {
    if (e.button !== 0) return
    if ((e.target as HTMLElement).closest('button, input')) return
    longPressed.current = false
    cancelHold()
    holdTimer.current = window.setTimeout(() => {
      longPressed.current = true
      setSheet(t)
      if (navigator.vibrate) navigator.vibrate(12)
    }, 480)
  }

  const openSheet = (t: Thread) => {
    cancelHold()
    setSheet(t)
  }

  const deleteFromSheet = () => {
    if (!sheet) return
    onDelete(sheet.id)
    setSheet(null)
  }

  const groups = useMemo(() => {
    const order = ['Today', 'Yesterday', 'Previous 7 days', 'Previous 30 days', 'Earlier']
    const map = new Map<string, Thread[]>()
    for (const t of threads) {
      const k = t.pinned ? 'Pinned' : dayBucket(t.updated)
      if (!map.has(k)) map.set(k, [])
      map.get(k)!.push(t)
    }
    return [...map.entries()].sort(
      (a, b) => (order.indexOf(a[0]) + 1 || 0) - (order.indexOf(b[0]) + 1 || 0) ||
        (a[0] === 'Pinned' ? -1 : 1),
    )
  }, [threads])

  const commitRename = (id: string) => {
    const v = draft.trim()
    setEditing(null)
    if (v) onRename(id, v)
  }

  return (
    <>
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/55 backdrop-blur-sm md:hidden"
          onClick={onCloseMobile}
        />
      )}

      <aside
        className={[
          'fixed inset-y-0 left-0 z-50 flex w-[286px] flex-col border-r border-line bg-panel/95 backdrop-blur-xl transition-transform duration-300',
          'md:static md:z-auto md:translate-x-0 md:bg-panel/60',
          mobileOpen ? 'translate-x-0' : '-translate-x-full',
        ].join(' ')}
      >
        <div className="flex h-14 shrink-0 items-center gap-2 px-3">
          <div className="flex min-w-0 flex-1 items-center gap-2.5">
            <span className="grid h-8 w-8 shrink-0 place-items-center rounded-[10px] border border-accent/35 bg-gradient-to-br from-accent/25 to-accent2/20">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" className="text-accent">
                <path d="M12 2 22 12 12 22 2 12Z" />
                <circle cx="12" cy="12" r="2.6" fill="currentColor" stroke="none" />
              </svg>
            </span>
            <div className="min-w-0">
              <div className="truncate text-[13px] font-semibold tracking-tight">SOM-SCAN</div>
              <div className="truncate text-[10px] uppercase tracking-[0.16em] text-faint">agent console</div>
            </div>
          </div>
          <button className="icon-btn md:hidden" onClick={onCloseMobile} aria-label="Close sidebar">
            <X size={16} />
          </button>
          <button className="icon-btn hidden md:inline-flex" onClick={onCollapse} aria-label="Collapse sidebar" title="Collapse sidebar">
            <PanelLeftClose size={16} />
          </button>
        </div>

        <div className="px-3 pb-2">
          <button className="btn btn-primary w-full" onClick={onNew}>
            <Plus size={16} /> New chat
          </button>
        </div>

        <div className="px-3 pb-2">
          <div className="relative">
            <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
            <input
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Search chats"
              className="field h-9 py-0 pl-8 pr-8 text-[12.5px]"
            />
            {query && (
              <button
                className="icon-btn absolute right-1 top-1/2 h-7 w-7 -translate-y-1/2"
                onClick={() => setQuery('')} aria-label="Clear search"
              >
                <X size={13} />
              </button>
            )}
          </div>
        </div>

        <nav className="flex-1 overflow-y-auto px-2 pb-3">
          {groups.length === 0 && (
            <div className="px-3 py-10 text-center text-[12px] text-faint">
              {query ? 'No matches.' : 'No chats yet.'}
            </div>
          )}
          {groups.map(([label, items]) => (
            <div key={label} className="mb-1">
              <div className="px-2.5 pb-1 pt-3 text-[10px] font-semibold uppercase tracking-[0.14em] text-faint">
                {label}
              </div>
              {items.map(t => (
                <div
                  key={t.id}
                  onPointerDown={startHold(t)}
                  onPointerUp={cancelHold}
                  onPointerCancel={cancelHold}
                  onPointerLeave={cancelHold}
                  onContextMenu={e => { e.preventDefault(); openSheet(t) }}
                  onClick={() => {
                    if (longPressed.current) { longPressed.current = false; return }
                    if (editing !== t.id) onSelect(t.id)
                  }}
                  className={[
                    'select-none [-webkit-touch-callout:none]',
                    'group relative flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-2 transition',
                    activeId === t.id
                      ? 'bg-accent/12 text-ink'
                      : 'text-muted hover:bg-panel3/70 hover:text-ink',
                  ].join(' ')}
                >
                  {activeId === t.id && (
                    <span className="absolute left-0 top-1/2 h-4 w-[2px] -translate-y-1/2 rounded-full bg-accent" />
                  )}
                  {editing === t.id ? (
                    <input
                      autoFocus
                      value={draft}
                      onChange={e => setDraft(e.target.value)}
                      onBlur={() => commitRename(t.id)}
                      onKeyDown={e => {
                        if (e.key === 'Enter') commitRename(t.id)
                        if (e.key === 'Escape') setEditing(null)
                      }}
                      onClick={e => e.stopPropagation()}
                      className="field h-7 flex-1 px-2 text-[12px]"
                    />
                  ) : (
                    <>
                      <span className="min-w-0 flex-1 truncate text-[12.5px] leading-5">{t.title}</span>
                      {runningIds?.includes(t.id) && (
                        <span className="h-1.5 w-1.5 shrink-0 animate-pulse rounded-full bg-accent" title="running" />
                      )}
                      {t.pinned && <Pin size={11} className="shrink-0 text-accent/80" />}
                      <span className="flex shrink-0 items-center gap-0.5 opacity-0 transition group-hover:opacity-100 focus-within:opacity-100">
                        <button
                          className="icon-btn h-6 w-6" title={t.pinned ? 'Unpin' : 'Pin'}
                          onClick={e => { e.stopPropagation(); onPin(t.id, !t.pinned) }}
                        >
                          {t.pinned ? <PinOff size={12} /> : <Pin size={12} />}
                        </button>
                        <button
                          className="icon-btn h-6 w-6" title="Rename"
                          onClick={e => {
                            e.stopPropagation()
                            setEditing(t.id); setDraft(t.title)
                          }}
                        >
                          <Pencil size={12} />
                        </button>
                        <button
                          className="icon-btn h-6 w-6 hover:!text-rose" title="More"
                          onClick={e => { e.stopPropagation(); openSheet(t) }}
                        >
                          <MoreHorizontal size={13} />
                        </button>
                      </span>
                    </>
                  )}
                </div>
              ))}
            </div>
          ))}
        </nav>

        <div className="shrink-0 border-t border-line p-2">
          <button
            className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-[12.5px] text-muted transition hover:bg-panel3/70 hover:text-ink"
            onClick={onOpenScans}
          >
            <Radar size={15} /> Scans &amp; runs
          </button>
          <div className="mt-0.5 flex items-center gap-1">
            <button
              className="flex flex-1 items-center gap-2.5 rounded-lg px-2.5 py-2 text-[12.5px] text-muted transition hover:bg-panel3/70 hover:text-ink"
              onClick={onOpenSettings}
            >
              <Settings size={15} /> Settings
            </button>
            <button className="icon-btn" onClick={onToggleTheme} aria-label="Toggle theme" title="Toggle theme">
              {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
            </button>
          </div>
          <div className="mt-1 flex items-center gap-1.5 px-2.5 py-1 text-[10px] text-faint">
            <Check size={10} className="text-mint" /> saved locally · SQLite
          </div>
        </div>
      </aside>

      {sheet && (
        <div
          className="fixed inset-0 z-[75] flex items-end justify-center bg-black/60 backdrop-blur-sm sm:items-center"
          onClick={() => setSheet(null)}
        >
          <div
            className="pop w-full max-w-md overflow-hidden rounded-t-2xl border border-line bg-panel shadow-2xl sm:rounded-2xl"
            onClick={e => e.stopPropagation()}
          >
            <div className="border-b border-line px-4 py-3">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-faint">Session</div>
              <div className="mt-0.5 truncate text-[13.5px] font-medium">{sheet.title}</div>
              <div className="mt-0.5 text-[10.5px] text-faint">
                {sheet.msg_count} message{sheet.msg_count === 1 ? '' : 's'} · {sheet.model || 'default model'}
              </div>
            </div>
            <div className="p-2">
              <button
                className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2.5 text-left text-[13px] text-muted transition hover:bg-panel3 hover:text-ink"
                onClick={() => {
                  setEditing(sheet.id)
                  setDraft(sheet.title)
                  setSheet(null)
                }}
              >
                <Pencil size={15} /> Rename
              </button>
              <button
                className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2.5 text-left text-[13px] text-muted transition hover:bg-panel3 hover:text-ink"
                onClick={() => { onPin(sheet.id, !sheet.pinned); setSheet(null) }}
              >
                {sheet.pinned ? <PinOff size={15} /> : <Pin size={15} />}
                {sheet.pinned ? 'Unpin session' : 'Pin to top'}
              </button>
              <button
                className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2.5 text-left text-[13px] text-rose transition hover:bg-rose/10"
                onClick={deleteFromSheet}
              >
                <Trash2 size={15} /> Delete session
              </button>
            </div>
            <div className="border-t border-line p-2">
              <button className="btn w-full" onClick={() => setSheet(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
