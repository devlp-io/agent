import { Check, Circle, Loader2, ListChecks } from 'lucide-react'
import type { TodoItem } from '../lib/types'

/** The agent's own plan for the current mission. Hidden when empty. */
export function TodoPanel({ items }: { items: TodoItem[] }) {
  if (!items.length) return null
  const done = items.filter(i => i.status === 'done').length

  return (
    <div className="mx-auto w-full max-w-3xl px-3 sm:px-5 xl:max-w-4xl">
      <div className="mb-2 overflow-hidden rounded-xl border border-line bg-panel2/60">
        <div className="flex items-center gap-2 border-b border-line px-3 py-2">
          <ListChecks size={14} className="text-accent" />
          <span className="text-[11.5px] font-medium text-ink">Plan</span>
          <span className="ml-auto text-[10.5px] tabular-nums text-faint">{done}/{items.length}</span>
        </div>
        <ul className="max-h-[132px] overflow-y-auto px-3 py-1.5">
          {items.map(i => (
            <li key={i.id} className="flex items-start gap-2 py-[3px]">
              {i.status === 'done'
                ? <Check size={12} className="mt-0.5 shrink-0 text-mint" />
                : i.status === 'doing'
                  ? <Loader2 size={12} className="mt-0.5 shrink-0 animate-spin text-accent" />
                  : <Circle size={12} className="mt-0.5 shrink-0 text-faint" />}
              <span className={`min-w-0 break-words text-[12px] leading-snug ${
                i.status === 'done' ? 'text-faint line-through' : 'text-muted'
              }`}>
                {i.text}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}
