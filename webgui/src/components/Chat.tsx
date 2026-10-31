import { useEffect, useRef } from 'react'
import { Sparkles, Radar, Code2, ShieldAlert, Bug, TerminalSquare } from 'lucide-react'
import { MessageItem } from './MessageItem'
import type { Message } from '../lib/types'

const SUGGESTIONS = [
  { icon: Radar, title: 'Recon a target', text: 'Run a full recon pass on example.com: subdomains, tech stack, exposed endpoints, and rank the attack surface.' },
  { icon: Code2, title: 'Build a tool', text: 'Write a Python port scanner with async concurrency, banner grabbing, and JSON output. Save it to ./tools/portscan.py.' },
  { icon: ShieldAlert, title: 'Review for risk', text: 'Audit this repo for risky patterns: unsafe deserialization, command injection, secrets in history, and dependency CVEs.' },
  { icon: Bug, title: 'Hunt a bug class', text: 'Look for IDOR and broken authz in the API routes and write a proof-of-concept request for each confirmed case.' },
  { icon: TerminalSquare, title: 'Automate ops', text: 'Set up a scheduled job that checks uptime and TLS expiry for my hosts and posts a summary to my webhook.' },
  { icon: Sparkles, title: 'Explain a bug', text: 'Explain how prototype pollution can turn into RCE, with a minimal example and the fix.' },
]

export function Chat({
  messages, streaming, threadId, loading, onSuggestion, showThinking,
}: {
  messages: Message[]
  streaming: Message | null
  threadId: string | null
  loading: boolean
  onSuggestion: (text: string) => void
  showThinking: boolean
}) {
  const endRef = useRef<HTMLDivElement>(null)
  const scrollRef = useRef<HTMLDivElement>(null)
  const pinned = useRef(true)

  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    const onScroll = () => {
      pinned.current = el.scrollHeight - el.scrollTop - el.clientHeight < 140
    }
    el.addEventListener('scroll', onScroll, { passive: true })
    return () => el.removeEventListener('scroll', onScroll)
  }, [])

  useEffect(() => {
    if (!messages.length && !streaming) return
    if (pinned.current) endRef.current?.scrollIntoView({ block: 'end' })
  }, [messages, streaming?.parts, streaming?.content, streaming])

  useEffect(() => {
    pinned.current = true
    const el = scrollRef.current
    if (!el) return
    if (!messages.length) {
      el.scrollTop = 0
      return
    }
    endRef.current?.scrollIntoView({ block: 'end' })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [threadId])

  const empty = !loading && messages.length === 0 && !streaming

  return (
    <div ref={scrollRef} className="fx-scroll flex-1 overflow-y-auto">
      <div className="mx-auto w-full max-w-3xl px-3 pb-6 pt-4 sm:px-5">
        {empty && (
          <div className="flex min-h-[calc(100dvh-19rem)] flex-col items-center justify-center py-8 text-center">
            <div className="orb relative mb-7 grid h-20 w-20 place-items-center">
              <div className="absolute inset-0 rounded-[26px] bg-gradient-to-br from-accent/35 via-accent2/25 to-transparent blur-xl" />
              <div className="relative grid h-16 w-16 place-items-center rounded-[22px] border border-accent/30 bg-panel2/90 shadow-2xl">
                <svg viewBox="0 0 24 24" width="30" height="30" fill="none" stroke="currentColor" strokeWidth="1.4" className="text-accent">
                  <path d="M12 2.5 21.5 12 12 21.5 2.5 12Z" />
                  <circle cx="12" cy="12" r="3" fill="currentColor" stroke="none" />
                </svg>
              </div>
            </div>
            <h1 className="mb-2 bg-gradient-to-br from-ink to-muted bg-clip-text text-[26px] font-semibold tracking-tight text-transparent sm:text-[32px]">
              What are we breaking today?
            </h1>
            <p className="mb-8 max-w-md text-[13.5px] leading-relaxed text-muted">
              Give the agent a target or a build. It plans, runs real tools on this machine,
              and reports back with evidence.
            </p>
            <div className="grid w-full max-w-2xl grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {SUGGESTIONS.map(s => (
                <button
                  key={s.title}
                  onClick={() => onSuggestion(s.text)}
                  className="group flex flex-col items-start gap-2 rounded-xl border border-line bg-panel2/50 p-3 text-left transition hover:-translate-y-0.5 hover:border-accent/35 hover:bg-panel2"
                >
                  <span className="grid h-7 w-7 place-items-center rounded-lg bg-panel3 text-accent transition group-hover:bg-accent/15">
                    <s.icon size={14} />
                  </span>
                  <span className="text-[12.5px] font-medium text-ink">{s.title}</span>
                  <span className="line-clamp-2 text-[11px] leading-snug text-faint">{s.text}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {loading && (
          <div className="space-y-5 py-6">
            {[0, 1, 2].map(i => (
              <div key={i} className="flex gap-3">
                <div className="h-6 w-6 shrink-0 animate-pulse rounded-md bg-panel3" />
                <div className="flex-1 space-y-2">
                  <div className="h-3 w-1/3 animate-pulse rounded bg-panel3" />
                  <div className="h-3 w-5/6 animate-pulse rounded bg-panel3" />
                  <div className="h-3 w-2/3 animate-pulse rounded bg-panel3" />
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="flex flex-col gap-5">
          {messages.map(m => <MessageItem key={m.id} m={m} showThinking={showThinking} />)}
          {streaming && <MessageItem key={streaming.id} m={streaming} showThinking={showThinking} />}
        </div>
        <div ref={endRef} className="h-2" />
      </div>
    </div>
  )
}
