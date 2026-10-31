import { CheckCircle2, XCircle, X } from 'lucide-react'

export type ToastItem = { id: number; msg: string; kind: 'ok' | 'err' }

export function Toasts({ items, dismiss }: { items: ToastItem[]; dismiss: (id: number) => void }) {
  return (
    <div className="pointer-events-none fixed bottom-[calc(92px+var(--safe-b))] left-1/2 z-[80] flex w-full max-w-sm -translate-x-1/2 flex-col items-center gap-2 px-3 sm:bottom-6 sm:left-auto sm:right-4 sm:translate-x-0 sm:items-end">
      {items.map(t => (
        <div
          key={t.id}
          className="pop pointer-events-auto flex w-full items-center gap-2.5 rounded-xl border border-line bg-panel/95 px-3 py-2.5 text-[12.5px] shadow-2xl backdrop-blur"
        >
          {t.kind === 'ok'
            ? <CheckCircle2 size={15} className="shrink-0 text-mint" />
            : <XCircle size={15} className="shrink-0 text-rose" />}
          <span className="min-w-0 flex-1 break-words">{t.msg}</span>
          <button className="icon-btn h-6 w-6 shrink-0" onClick={() => dismiss(t.id)} aria-label="Dismiss">
            <X size={12} />
          </button>
        </div>
      ))}
    </div>
  )
}
