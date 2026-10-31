import { useEffect, useState } from 'react'
import {
  X, Save, Cpu, Server, KeyRound, Wrench, Check, Download, Loader2, ExternalLink,
} from 'lucide-react'
import type { ModelProfile, Settings } from '../lib/types'
import { api } from '../lib/api'

const KEY_FIELDS = ['AG_MODEL', 'AG_BASE', 'AG_KEY', 'DEEPSEEK_KEY', 'AG_PROXY', 'AG_SCAN_ROOT'] as const

const KEY_LABELS: Record<string, string> = {
  AG_MODEL: 'Model id',
  AG_BASE: 'API base URL',
  AG_KEY: 'API key',
  DEEPSEEK_KEY: 'DeepSeek key (alias)',
  AG_PROXY: 'Proxy',
  AG_SCAN_ROOT: 'Scan root',
}

export function SettingsModal({
  open, onClose, models, onModel, pushToast,
}: {
  open: boolean
  onClose: () => void
  models: ModelProfile[]
  active?: string | null
  onModel: (name: string) => void
  pushToast: (msg: string, kind?: 'ok' | 'err') => void
}) {
  const [tab, setTab] = useState<'general' | 'tools'>('general')
  const [settings, setSettings] = useState<Settings | null>(null)
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState(false)
  const [tools, setTools] = useState<{ name: string; category: string; desc: string; installed: boolean }[]>([])
  const [toolBusy, setToolBusy] = useState<string | null>(null)
  const [toolQuery, setToolQuery] = useState('')
  const [toolkit, setToolkit] = useState<{ running: boolean; installed?: number; missing?: number } | null>(null)

  useEffect(() => {
    if (!open) return
    api.settings().then(setSettings).catch(() => {})
    api.tools().then(r => setTools(r.tools)).catch(() => {})
  }, [open])

  useEffect(() => {
    if (!open || tab !== 'tools' || tools.length) return
    api.tools().then(r => setTools(r.tools)).catch(() => {})
  }, [open, tab, tools.length])

  useEffect(() => {
    if (!open || tab !== 'tools') return
    let alive = true
    const load = () => api.toolkits().then(r => {
      if (!alive) return
      const core = (r.pool?.core_installed as string[] | undefined) || []
      const missing = (r.pool?.core_missing as string[] | undefined) || []
      setToolkit({ running: r.state.running, installed: core.length, missing: missing.length })
    }).catch(() => {})
    load()
    const t = setInterval(load, 4000)
    return () => { alive = false; clearInterval(t) }
  }, [open, tab])

  if (!open) return null

  const save = async () => {
    if (Object.keys(draft).length === 0) { onClose(); return }
    setSaving(true)
    try {
      await api.saveSettings(draft)
      pushToast('settings saved', 'ok')
      setDraft({})
      const s = await api.settings()
      setSettings(s)
    } catch (e) {
      pushToast(e instanceof Error ? e.message : 'save failed', 'err')
    } finally { setSaving(false) }
  }

  const install = async (name: string) => {
    setToolBusy(name)
    try {
      const r = await api.installTool(name)
      pushToast(`${name}: ${r.result.slice(0, 90)}`, 'ok')
      const t = await api.tools()
      setTools(t.tools)
    } catch (e) {
      pushToast(e instanceof Error ? e.message : 'install failed', 'err')
    } finally { setToolBusy(null) }
  }

  const filtered = tools.filter(t =>
    !toolQuery || t.name.toLowerCase().includes(toolQuery.toLowerCase()) ||
    t.category.toLowerCase().includes(toolQuery.toLowerCase()),
  )

  return (
    <div className="fixed inset-0 z-[60] flex items-end justify-center bg-black/60 backdrop-blur-sm sm:items-center sm:p-6">
      <div className="pop flex h-[88dvh] w-full max-w-2xl flex-col overflow-hidden rounded-t-2xl border border-line bg-panel shadow-2xl sm:h-auto sm:max-h-[82dvh] sm:rounded-2xl">
        <header className="flex h-14 shrink-0 items-center gap-2 border-b border-line px-4">
          <Cpu size={16} className="text-accent" />
          <span className="flex-1 text-[13px] font-semibold">Settings</span>
          <button className="icon-btn" onClick={onClose} aria-label="Close"><X size={18} /></button>
        </header>

        <div className="flex shrink-0 gap-1 border-b border-line px-3 py-1.5">
          {(['general', 'tools'] as const).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={[
                'rounded-lg px-3 py-1.5 text-[12px] capitalize transition',
                tab === t ? 'bg-panel3 text-ink' : 'text-muted hover:text-ink',
              ].join(' ')}
            >
              {t === 'tools' ? 'Security tools' : 'General'}
            </button>
          ))}
        </div>

        <div className="flex-1 overflow-y-auto p-4">
          {tab === 'general' && (
            <div className="space-y-5">
              <section>
                <Label icon={Cpu}>Active model</Label>
                <div className="mt-2 grid gap-1.5">
                  {models.map(m => (
                    <button
                      key={m.name}
                      onClick={() => onModel(m.name)}
                      className={[
                        'flex items-center gap-2.5 rounded-xl border px-3 py-2 text-left transition',
                        m.active ? 'border-accent/50 bg-accent/10' : 'border-line hover:border-line2',
                      ].join(' ')}
                    >
                      <span className={`h-1.5 w-1.5 rounded-full ${m.configured ? 'bg-mint' : 'bg-faint'}`} />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[12.5px]">{m.label ?? m.model}</span>
                        <span className="block truncate font-mono text-[10px] text-faint">{m.base}</span>
                      </span>
                      {m.active && <Check size={14} className="text-accent" />}
                    </button>
                  ))}
                </div>
              </section>

              <section>
                <Label icon={KeyRound}>Provider &amp; runtime</Label>
                <div className="mt-2 grid gap-2.5 sm:grid-cols-2">
                  {KEY_FIELDS.map(k => (
                    <label key={k} className="block">
                      <span className="mb-1 block text-[11px] text-muted">{KEY_LABELS[k]}</span>
                      <input
                        type={k.includes('KEY') ? 'password' : 'text'}
                        className="field font-mono text-[12px]"
                        placeholder={settings?.keys?.[k] || (k === 'AG_KEY' ? 'sk-…' : '')}
                        value={draft[k] ?? ''}
                        onChange={e => setDraft(d => ({ ...d, [k]: e.target.value }))}
                        autoComplete="off"
                        spellCheck={false}
                      />
                    </label>
                  ))}
                </div>
                <p className="mt-2 text-[11px] text-faint">
                  Empty fields keep their current value. Saved to <span className="font-mono">{settings?.path}</span>.
                </p>
              </section>

              <section className="grid gap-2 sm:grid-cols-2">
                <Info icon={Server} label="Scan root" value={settings?.scan_root ?? '—'} />
                <Info icon={Server} label="Data dir" value={settings?.data_dir ?? '—'} />
              </section>
            </div>
          )}

          {tab === 'tools' && (
            <div>
              <div className="mb-3 rounded-xl border border-line bg-panel2/60 p-3">
                <div className="flex items-center gap-2">
                  <Wrench size={14} className="text-accent" />
                  <span className="flex-1 text-[12px] font-medium">Modern toolkit pool</span>
                  <span className="text-[11px] text-faint">
                    {toolkit ? `${toolkit.installed ?? 0} ready${toolkit.missing ? ` · ${toolkit.missing} missing` : ''}` : '—'}
                  </span>
                </div>
                <p className="mt-1 text-[11px] leading-snug text-faint">
                  Installs the curated modern stack (OSINT, AD, cloud, RE, web) and adds it to the agent pool.
                </p>
                <button
                  className="btn btn-primary mt-2 h-8 w-full text-[12px]"
                  disabled={!!toolkit?.running}
                  onClick={async () => {
                    try {
                      await api.preinstallToolkits()
                      pushToast('toolkit preinstall started', 'ok')
                    } catch (e) {
                      pushToast(e instanceof Error ? e.message : 'preinstall failed', 'err')
                    }
                  }}
                >
                  {toolkit?.running ? <Loader2 size={14} className="spin-slow" /> : <Download size={14} />}
                  {toolkit?.running ? 'Installing toolkit…' : 'Preinstall modern toolkit'}
                </button>
              </div>
              <input
                value={toolQuery}
                onChange={e => setToolQuery(e.target.value)}
                placeholder="Filter tools…"
                className="field mb-3"
              />
              <div className="space-y-1.5">
                {filtered.map(t => (
                  <div key={t.name} className="flex items-center gap-2.5 rounded-xl border border-line bg-panel2/60 px-3 py-2">
                    <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-panel3 text-muted">
                      <Wrench size={14} />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center gap-2">
                        <span className="truncate font-mono text-[12px]">{t.name}</span>
                        <span className="chip scale-90 px-1.5 py-0 text-[9.5px]">{t.category}</span>
                      </span>
                      <span className="mt-0.5 block truncate text-[10.5px] text-faint">{t.desc}</span>
                    </span>
                    {t.installed ? (
                      <span className="flex items-center gap-1 text-[11px] text-mint"><Check size={12} /> ready</span>
                    ) : (
                      <button
                        className="btn h-7 px-2 text-[11px]"
                        disabled={toolBusy === t.name}
                        onClick={() => install(t.name)}
                      >
                        {toolBusy === t.name
                          ? <Loader2 size={12} className="spin-slow" />
                          : <Download size={12} />} install
                      </button>
                    )}
                  </div>
                ))}
                {filtered.length === 0 && <div className="py-10 text-center text-[12px] text-faint">No tools matched.</div>}
              </div>
            </div>
          )}
        </div>

        <footer className="flex shrink-0 items-center gap-2 border-t border-line px-4 py-3">
          <a href="/api/v2/docs" target="_blank" rel="noreferrer" className="btn btn-ghost text-[12px]">
            <ExternalLink size={13} /> API docs
          </a>
          <span className="flex-1" />
          <button className="btn btn-ghost" onClick={onClose}>Close</button>
          <button className="btn btn-primary" onClick={save} disabled={saving}>
            {saving ? <Loader2 size={14} className="spin-slow" /> : <Save size={14} />} Save
          </button>
        </footer>
      </div>
    </div>
  )
}

function Label({ icon: Icon, children }: { icon: typeof Cpu; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">
      <Icon size={12} /> {children}
    </div>
  )
}

function Info({ icon: Icon, label, value }: { icon: typeof Server; label: string; value: string }) {
  return (
    <div className="rounded-xl border border-line bg-panel2/60 px-3 py-2">
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-faint"><Icon size={10} /> {label}</div>
      <div className="mt-0.5 truncate font-mono text-[11px] text-muted">{value}</div>
    </div>
  )
}
