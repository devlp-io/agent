import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Search, MessageSquarePlus, Settings, Radar, SunMoon, FileDown, CornerDownLeft, MessagesSquare,
} from 'lucide-react'
import type { Thread } from '../lib/types'

type Cmd = {
  id: string
  label: string
  hint?: string
  icon: typeof Search
  run: () => void
  group: string
}

export function CommandPalette({
  open, onClose, threads, onSelectThread, onNew, onSettings, onScans, onToggleTheme, onExport,
}: {
  open: boolean
  onClose: () => void
  threads: Thread[]
  onSelectThread: (id: string) => void
  onNew: () => void
  onSettings: () => void
  onScans: () => void
  onToggleTheme: () => void
  onExport: () => void
}) {
  const [q, setQ] = useState('')
  const [idx, setIdx] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (open) {
      setQ(''); setIdx(0)
      requestAnimationFrame(() => inputRef.current?.focus())
    }
  }, [open])

  const items = useMemo<Cmd[]>(() => {
    const base: Cmd[] = [
      { id: 'new', label: 'New chat', icon: MessageSquarePlus, run: onNew, group: 'Actions', hint: '⌘N' },
      { id: 'scans', label: 'Scans & runs', icon: Radar, run: onScans, group: 'Actions' },
      { id: 'settings', label: 'Settings', icon: Settings, run: onSettings, group: 'Actions', hint: '⌘,' },
      { id: 'theme', label: 'Toggle theme', icon: SunMoon, run: onToggleTheme, group: 'Actions' },
      { id: 'export', label: 'Export current chat', icon: FileDown, run: onExport, group: 'Actions' },
    ]
    const chats: Cmd[] = threads.slice(0, 40).map(t => ({
      id: `t-${t.id}`,
      label: t.title,
      icon: MessagesSquare,
      group: 'Chats',
      run: () => onSelectThread(t.id),
    }))
    const all = [...base, ...chats]
    const needle = q.trim().toLowerCase()
    return needle ? all.filter(i => i.label.toLowerCase().includes(needle)) : all
  }, [q, threads, onNew, onScans, onSettings, onToggleTheme, onExport, onSelectThread])

  useEffect(() => { setIdx(0) }, [q])

  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(`[data-i="${idx}"]`)
    el?.scrollIntoView({ block: 'nearest' })
  }, [idx])

  if (!open) return null

  const run = (cmd: Cmd | undefined) => {
    if (!cmd) return
    onClose()
    cmd.run()
  }

  return (
    <div
      className="fixed inset-0 z-[70] flex items-start justify-center bg-black/60 px-4 pt-[12vh] backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="pop w-full max-w-lg overflow-hidden rounded-2xl border border-line bg-panel shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center gap-2.5 border-b border-line px-4">
          <Search size={16} className="text-faint" />
          <input
            ref={inputRef}
            value={q}
            onChange={e => setQ(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'ArrowDown') { e.preventDefault(); setIdx(i => Math.min(i + 1, items.length - 1)) }
              else if (e.key === 'ArrowUp') { e.preventDefault(); setIdx(i => Math.max(0, i - 1)) }
              else if (e.key === 'Enter') { e.preventDefault(); run(items[idx]) }
              else if (e.key === 'Escape') onClose()
            }}
            placeholder="Search commands and chats…"
            className="h-12 flex-1 bg-transparent text-[14px] outline-none placeholder:text-faint"
          />
          <span className="kbd">esc</span>
        </div>
        <div ref={listRef} className="max-h-[52vh] overflow-y-auto p-1.5">
          {items.length === 0 && <div className="py-10 text-center text-[12.5px] text-faint">Nothing found.</div>}
          {items.map((item, i) => {
            const showGroup = i === 0 || items[i - 1].group !== item.group
            return (
              <div key={item.id}>
                {showGroup && (
                  <div className="px-2.5 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider text-faint">
                    {item.group}
                  </div>
                )}
                <button
                  data-i={i}
                  onMouseEnter={() => setIdx(i)}
                  onClick={() => run(item)}
                  className={[
                    'flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-[13px] transition',
                    i === idx ? 'bg-accent/12 text-ink' : 'text-muted hover:bg-panel2',
                  ].join(' ')}
                >
                  <item.icon size={15} className="shrink-0" />
                  <span className="min-w-0 flex-1 truncate">{item.label}</span>
                  {item.hint && <span className="kbd">{item.hint}</span>}
                  {i === idx && <CornerDownLeft size={12} className="text-faint" />}
                </button>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
