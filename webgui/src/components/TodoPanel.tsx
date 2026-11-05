import { useState } from 'react'
import { Check, ChevronRight, Circle, Loader2, ListChecks, X } from 'lucide-react'
import type { TodoItem } from '../lib/types'

/** The agent's own plan for the current mission. Collapsed by default. */
export function TodoPanel({ items, active = false }: { items: TodoItem[]; active?: boolean }) {
  const [open, setOpen] = useState(false)
  if (!items.length) return null
  const openItems = items.some(i => i.status === 'todo' || i.status === 'doing')
  if (!active && !openItems) return null

  const done = items.filter(i => i.status === 'done').length
  const doing = [...items].reverse().find(i => i.status === 'doing')

  return (
    <div className="mx-auto w-full max-w-3xl px-3 sm:px-5 xl:max-w-4xl">
      <div className="mb-2 overflow-hidden rounded-xl border border-line bg-panel2/60">
        <button
          type="button"
          onClick={() => setOpen(v => !v)}
          title={open ? 'Hide plan' : 'Show plan'}
          className="flex w-full items-center gap-2 px-3 py-2 text-left transition hover:bg-panel3/50"
        >
          <ListChecks size={14} className="shrink-0 text-accent" />
          <span className="text-[11.5px] font-medium text-ink">Plan</span>
          <span className="text-[10.5px] tabular-nums text-faint">{done}/{items.length}</span>
          {!open && doing && (
            <span className="min-w-0 flex-1 truncate text-[11px] text-faint">· {doing.text}</span>
          )}
          <ChevronRight
            size={13}
            className={`ml-auto shrink-0 text-faint transition-transform ${open ? 'rotate-90' : ''}`}
          />
        </button>
        {open && (
          <ul className="max-h-[168px] overflow-y-auto border-t border-line px-3 py-1.5">
            {items.map(i => (
              <li key={i.id} className="flex items-start gap-2 py-[3px]">
                {i.status === 'done'
                  ? <Check size={12} className="mt-0.5 shrink-0 text-mint" />
                  : i.status === 'doing'
                    ? <Loader2 size={12} className="mt-0.5 shrink-0 animate-spin text-accent" />
                    : i.status === 'cancelled'
                      ? <X size={12} className="mt-0.5 shrink-0 text-faint" />
                      : <Circle size={12} className="mt-0.5 shrink-0 text-faint" />}
                <span className={`min-w-0 break-words text-[12px] leading-snug ${
                  i.status === 'done'
                    ? 'text-faint line-through'
                    : i.status === 'cancelled' ? 'text-faint' : 'text-muted'
                }`}>
                  {i.text}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
