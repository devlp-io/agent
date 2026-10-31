import { useEffect, useState } from 'react'
import {
  X, FileText, Download, Layers, Cpu, Activity, Wrench, Radar, Image as ImageIcon, Boxes,
} from 'lucide-react'
import type { Message, Thread } from '../lib/types'
import { api } from '../lib/api'

type Tab = 'overview' | 'files' | 'runs'

export function RightPanel({
  open, onClose, thread, messages, onOpenScans,
}: {
  open: boolean
  onClose: () => void
  thread: Thread | null
  messages: Message[]
  onOpenScans: () => void
}) {
  const [tab, setTab] = useState<Tab>('overview')
  const [uploads, setUploads] = useState<{ id: string; filename: string; mime: string; size: number; url: string }[]>([])

  useEffect(() => {
    if (!thread) { setUploads([]); return }
    api.uploads(thread.id).then(r => setUploads(r.uploads)).catch(() => setUploads([]))
  }, [thread, messages.length])

  const runs = messages
    .flatMap(m => {
      const tools = (m.meta?.tools as { tool: string; ok: boolean }[] | undefined) ?? []
      return tools.map(t => ({ ...t, at: m.created }))
    })
    .slice(-30)
    .reverse()

  const toolCounts = runs.reduce<Record<string, number>>((acc, r) => {
    acc[r.tool] = (acc[r.tool] ?? 0) + 1
    return acc
  }, {})

  if (!open) return null

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm lg:hidden" onClick={onClose} />
      <aside className="fixed inset-y-0 right-0 z-50 flex w-[330px] max-w-[92vw] flex-col border-l border-line bg-panel/95 backdrop-blur-xl lg:static lg:z-auto lg:bg-panel/40">
        <header className="flex h-14 shrink-0 items-center gap-2 border-b border-line px-3">
          <Boxes size={15} className="text-accent" />
          <span className="flex-1 text-[12.5px] font-semibold">Context</span>
          <button className="icon-btn" onClick={onClose} aria-label="Close panel"><X size={16} /></button>
        </header>

        <div className="flex shrink-0 gap-1 border-b border-line p-1.5">
          {(['overview', 'files', 'runs'] as Tab[]).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={[
                'flex-1 rounded-lg px-2 py-1.5 text-[11.5px] capitalize transition',
                tab === t ? 'bg-panel3 text-ink' : 'text-muted hover:text-ink',
              ].join(' ')}
            >
              {t}
            </button>
          ))}
        </div>

        <div className="flex-1 overflow-y-auto p-3">
          {tab === 'overview' && (
            <div className="space-y-3">
              <div className="card p-3">
                <div className="text-[10px] font-semibold uppercase tracking-wider text-faint">Thread</div>
                <div className="mt-1 truncate text-[13px] font-medium">{thread?.title ?? '—'}</div>
                <div className="mt-2 grid grid-cols-2 gap-2 text-[11px]">
                  <Meta icon={Cpu} label="model" value={thread?.model ?? '—'} />
                  <Meta icon={Activity} label="messages" value={String(messages.length)} />
                  <Meta icon={Layers} label="mode" value={thread?.mode ?? 'agent'} />
                  <Meta icon={Wrench} label="tool calls" value={String(runs.length)} />
                </div>
              </div>

              <div className="card p-3">
                <div className="mb-2 flex items-center justify-between">
                  <span className="text-[10px] font-semibold uppercase tracking-wider text-faint">Tool mix</span>
                  <span className="text-[10px] text-faint">last {runs.length}</span>
                </div>
                {Object.keys(toolCounts).length === 0 && (
                  <div className="py-3 text-center text-[11.5px] text-faint">No tool calls yet.</div>
                )}
                <div className="space-y-1.5">
                  {Object.entries(toolCounts).sort((a, b) => b[1] - a[1]).map(([name, n]) => (
                    <div key={name} className="flex items-center gap-2 text-[11.5px]">
                      <span className="w-24 shrink-0 truncate font-mono text-muted">{name}</span>
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-panel3">
                        <div
                          className="h-full rounded-full bg-gradient-to-r from-accent to-accent2"
                          style={{ width: `${Math.max(8, Math.round((n / runs.length) * 100))}%` }}
                        />
                      </div>
                      <span className="w-5 text-right text-faint">{n}</span>
                    </div>
                  ))}
                </div>
              </div>

              <a
                href={thread ? api.exportUrl(thread.id) : '#'}
                className="btn w-full"
                onClick={e => { if (!thread) e.preventDefault() }}
              >
                <FileText size={14} /> Export as Markdown
              </a>
            </div>
          )}

          {tab === 'files' && (
            <div className="space-y-2">
              {uploads.length === 0 && (
                <div className="py-10 text-center text-[12px] text-faint">No uploaded files in this thread.</div>
              )}
              {uploads.map(u => (
                <a
                  key={u.id}
                  href={`${u.url}?download=1`}
                  target="_blank" rel="noreferrer"
                  className="flex items-center gap-2.5 rounded-xl border border-line bg-panel2 p-2 transition hover:border-line2"
                >
                  <span className="grid h-9 w-9 shrink-0 place-items-center overflow-hidden rounded-lg bg-panel3 text-muted">
                    {u.mime.startsWith('image/')
                      ? <img src={u.url} alt="" className="h-full w-full object-cover" />
                      : u.mime.startsWith('text/') ? <FileText size={15} /> : <ImageIcon size={15} />}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[12px]">{u.filename}</span>
                    <span className="block text-[10px] text-faint">{Math.max(1, Math.round(u.size / 1024))} KB</span>
                  </span>
                  <Download size={13} className="shrink-0 text-faint" />
                </a>
              ))}
            </div>
          )}

          {tab === 'runs' && (
            <div className="space-y-2">
              <button className="btn w-full" onClick={onOpenScans}>
                <Radar size={14} /> Open scans &amp; runs
              </button>
              {runs.length === 0 && (
                <div className="py-10 text-center text-[12px] text-faint">No agent activity yet.</div>
              )}
              {runs.map((r, i) => (
                <div key={i} className="flex items-center gap-2 rounded-lg border border-line bg-panel2 px-2.5 py-2 text-[11.5px]">
                  <span className={`h-1.5 w-1.5 rounded-full ${r.ok ? 'bg-mint' : 'bg-rose'}`} />
                  <span className="flex-1 font-mono text-muted">{r.tool}</span>
                  <span className="text-[10px] text-faint">
                    {new Date(r.at * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </aside>
    </>
  )
}

function Meta({ icon: Icon, label, value }: { icon: typeof Cpu; label: string; value: string }) {
  return (
    <div className="rounded-lg bg-panel3/60 px-2 py-1.5">
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-faint">
        <Icon size={10} /> {label}
      </div>
      <div className="mt-0.5 truncate font-mono text-[11px] text-ink">{value}</div>
    </div>
  )
}
