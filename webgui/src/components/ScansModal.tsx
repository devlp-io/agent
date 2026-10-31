import { useCallback, useEffect, useRef, useState } from 'react'
import {
  X, Radar, Play, Square, RefreshCw, Loader2, Terminal, ArrowLeft, Crosshair,
} from 'lucide-react'
import type { RunningJob, Scan } from '../lib/types'
import { api, openScanStream } from '../lib/api'

export function ScansModal({
  open, onClose, pushToast,
}: {
  open: boolean
  onClose: () => void
  pushToast: (msg: string, kind?: 'ok' | 'err') => void
}) {
  const [scans, setScans] = useState<Scan[]>([])
  const [running, setRunning] = useState<RunningJob[]>([])
  const [loading, setLoading] = useState(false)
  const [task, setTask] = useState('')
  const [attack, setAttack] = useState(false)
  const [selected, setSelected] = useState<{ target: string; ts: string; title: string } | null>(null)
  const [lines, setLines] = useState<string[]>([])
  const logRef = useRef<HTMLDivElement>(null)

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const r = await api.scans()
      setScans(r.scans)
      setRunning(r.running)
    } catch (e) {
      pushToast(e instanceof Error ? e.message : 'failed to load scans', 'err')
    } finally { setLoading(false) }
  }, [pushToast])

  useEffect(() => {
    if (!open) return
    refresh()
    const t = setInterval(refresh, 4000)
    return () => clearInterval(t)
  }, [open, refresh])

  useEffect(() => {
    if (!selected) { setLines([]); return }
    setLines([])
    const close = openScanStream(selected.target, selected.ts, (_f, line) => {
      setLines(prev => (prev.length > 2500 ? prev.slice(-2000) : prev).concat(line))
    })
    api.scanLog(selected.target, selected.ts, 400)
      .then(r => setLines(prev => [...r.lines, ...prev]))
      .catch(() => { /* ignore */ })
    return close
  }, [selected])

  useEffect(() => {
    const el = logRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [lines])

  if (!open) return null

  const start = async () => {
    if (!task.trim()) return
    try {
      await api.startScan(task.trim(), attack)
      pushToast('scan started', 'ok')
      setTask('')
      refresh()
    } catch (e) {
      pushToast(e instanceof Error ? e.message : 'start failed', 'err')
    }
  }

  const kill = async (key: string) => {
    try {
      await api.killScan(key)
      pushToast('stopped', 'ok')
      refresh()
    } catch (e) {
      pushToast(e instanceof Error ? e.message : 'kill failed', 'err')
    }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-end justify-center bg-black/60 p-0 backdrop-blur-sm sm:items-center sm:p-6">
      <div className="pop flex h-[92dvh] w-full max-w-4xl flex-col overflow-hidden rounded-t-2xl border border-line bg-panel shadow-2xl sm:h-[85dvh] sm:rounded-2xl">
        <header className="flex h-14 shrink-0 items-center gap-3 border-b border-line px-4">
          {selected ? (
            <>
              <button className="icon-btn" onClick={() => setSelected(null)} aria-label="Back"><ArrowLeft size={17} /></button>
              <div className="min-w-0 flex-1">
                <div className="truncate text-[13px] font-medium">{selected.title}</div>
                <div className="truncate font-mono text-[10.5px] text-faint">{selected.target} · {selected.ts}</div>
              </div>
              <span className="flex items-center gap-1.5 text-[11px] text-mint">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-mint" /> live
              </span>
            </>
          ) : (
            <>
              <Radar size={17} className="text-accent" />
              <div className="flex-1">
                <div className="text-[13px] font-semibold">Scans &amp; runs</div>
                <div className="text-[10.5px] text-faint">{scans.length} stored · {running.filter(r => r.alive).length} live</div>
              </div>
              <button className="btn btn-ghost btn-icon" onClick={refresh} aria-label="Refresh">
                <RefreshCw size={15} className={loading ? 'spin-slow' : ''} />
              </button>
            </>
          )}
          <button className="icon-btn" onClick={onClose} aria-label="Close"><X size={18} /></button>
        </header>

        {selected ? (
          <div ref={logRef} className="flex-1 overflow-y-auto bg-[#05060a] px-3 py-3 font-mono text-[11.5px] leading-relaxed">
            {lines.length === 0 && <div className="text-faint">waiting for output…</div>}
            {lines.map((l, i) => (
              <div key={i} className="whitespace-pre-wrap break-words text-[#c9d1d9]">{l || '\u00a0'}</div>
            ))}
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto">
            <div className="border-b border-line p-4">
              <div className="mb-2 flex items-center gap-2 text-[11px] uppercase tracking-wider text-faint">
                <Crosshair size={12} /> New scan
              </div>
              <div className="flex flex-col gap-2 sm:flex-row">
                <input
                  value={task}
                  onChange={e => setTask(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') start() }}
                  placeholder="assess https://target.example"
                  className="field flex-1"
                />
                <label className="flex cursor-pointer items-center gap-2 px-1 text-[12px] text-muted">
                  <input type="checkbox" checked={attack} onChange={e => setAttack(e.target.checked)} className="accent-[var(--color-accent)]" />
                  attack mode
                </label>
                <button className="btn btn-primary" onClick={start} disabled={!task.trim()}>
                  <Play size={14} /> Start
                </button>
              </div>
            </div>

            {running.length > 0 && (
              <div className="border-b border-line p-2">
                <div className="px-2 pb-1 pt-1 text-[10px] font-semibold uppercase tracking-wider text-faint">Live now</div>
                {running.map(r => (
                  <div key={r.key} className="flex items-center gap-2 rounded-lg px-2 py-2 hover:bg-panel2">
                    <Loader2 size={14} className="spin-slow text-mint" />
                    <span className="min-w-0 flex-1 truncate text-[12px]">{r.task}</span>
                    {r.target && r.ts && (
                      <button
                        className="btn h-7 px-2 text-[11px]"
                        onClick={() => setSelected({ target: r.target!, ts: r.ts!, title: r.task })}
                      >
                        <Terminal size={12} /> logs
                      </button>
                    )}
                    <button className="btn h-7 px-2 text-[11px] text-rose" onClick={() => kill(r.key)}>
                      <Square size={11} className="fill-current" /> stop
                    </button>
                  </div>
                ))}
              </div>
            )}

            <div className="p-2">
              <div className="px-2 pb-1 pt-1 text-[10px] font-semibold uppercase tracking-wider text-faint">History</div>
              {scans.length === 0 && <div className="px-3 py-10 text-center text-[12px] text-faint">No scans yet.</div>}
              {scans.map(s => (
                <button
                  key={`${s.target}/${s.ts}`}
                  onClick={() => setSelected({ target: s.target, ts: s.ts, title: s.target })}
                  className="flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left transition hover:bg-panel2"
                >
                  <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${s.is_live ? 'bg-mint' : 'bg-faint'}`} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[12.5px]">{s.target}</span>
                    <span className="block font-mono text-[10.5px] text-faint">
                      {s.ts}{typeof s.turn === 'number' ? ` · turn ${s.turn}` : ''}
                    </span>
                  </span>
                  <Terminal size={13} className="text-faint" />
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
