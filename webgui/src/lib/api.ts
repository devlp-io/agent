import type {
  Attachment, Message, ModelProfile, RunningJob, RunInfo, Scan, Settings, SseEvent, Thread, Usage,
} from './types'

const API = '/api/v2'

const TOKEN_KEY = 'agui:token'

function initToken(): string {
  try {
    const url = new URL(window.location.href)
    const fromUrl = url.searchParams.get('token')
    if (fromUrl) {
      localStorage.setItem(TOKEN_KEY, fromUrl)
      url.searchParams.delete('token')
      window.history.replaceState({}, '', url.toString())
      return fromUrl
    }
    return localStorage.getItem(TOKEN_KEY) || ''
  } catch {
    return ''
  }
}

let TOKEN = initToken()

export function setToken(token: string) {
  TOKEN = token
  if (token) localStorage.setItem(TOKEN_KEY, token)
  else localStorage.removeItem(TOKEN_KEY)
}

export function hasToken() { return !!TOKEN }

function authHeaders(): Record<string, string> {
  return TOKEN ? { 'X-GUI-Token': TOKEN } : {}
}

async function j<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json', ...authHeaders(), ...(init?.headers || {}) },
    ...init,
  })
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body?.detail || detail
    } catch { /* ignore */ }
    throw new Error(`${res.status} ${detail}`)
  }
  return res.json() as Promise<T>
}

export const api = {
  health: () => j<{
    ok: boolean; version: string; model: string; provider: string;
    data_dir: string; dist_built: boolean; time: string
  }>('/health'),

  models: () => j<{
    profiles: ModelProfile[]; active: string; model: string; provider: string
  }>('/models'),

  setModel: (name: string) => j<{ ok: boolean; message: string; active: string }>(
    '/models/active', { method: 'POST', body: JSON.stringify({ name }) },
  ),

  threads: (q = '') => j<{ threads: Thread[] }>(`/threads${q ? `?q=${encodeURIComponent(q)}` : ''}`),

  createThread: (model?: string) => j<Thread>(
    '/threads', { method: 'POST', body: JSON.stringify({ model: model ?? null }) },
  ),

  patchThread: (id: string, patch: Partial<{ title: string; pinned: boolean; archived: boolean; model: string }>) =>
    j<{ thread: Thread }>(`/threads/${id}`, { method: 'PATCH', body: JSON.stringify(patch) }),

  deleteThread: (id: string) => j<{ ok: boolean }>(`/threads/${id}`, { method: 'DELETE' }),

  messages: (id: string) => j<{ thread: { id: string; title: string; model: string; mode: string }; run?: RunInfo | null; messages: Message[] }>(
    `/threads/${id}/messages`,
  ),

  usage: (id: string) => j<Usage>(`/threads/${id}/usage`),

  exportUrl: (id: string) => `${API}/threads/${id}/export?fmt=md`,

  upload: async (file: File, threadId: string): Promise<Attachment> => {
    const fd = new FormData()
    fd.append('file', file)
    fd.append('thread_id', threadId)
    const res = await fetch(`${API}/upload`, { method: 'POST', body: fd, headers: authHeaders() })
    if (!res.ok) throw new Error(`upload failed: ${res.status}`)
    return res.json()
  },

  approve: (callId: string, allow: boolean) =>
    j<{ ok: boolean }>('/approve', { method: 'POST', body: JSON.stringify({ call_id: callId, allow }) }),

  answerQuestion: (threadId: string, questionId: string, answer: string) =>
    j<{ ok: boolean }>('/agent/answer', {
      method: 'POST',
      body: JSON.stringify({ thread_id: threadId, question_id: questionId, answer }),
    }),

  jobStatus: (threadId: string) =>
    j<{ running: boolean; done: boolean; cancelled?: boolean; events: number }>(
      `/jobs/${encodeURIComponent(threadId)}`,
    ),

  cancelJob: (threadId: string) =>
    j<{ ok: boolean }>(`/jobs/${encodeURIComponent(threadId)}/cancel`, { method: 'POST' }),

  agentStop: (threadId: string) =>
    j<{ ok: boolean; stopped: boolean }>('/agent/stop', {
      method: 'POST', body: JSON.stringify({ thread_id: threadId }),
    }),

  scans: () => j<{ scans: Scan[]; running: RunningJob[]; root: string }>('/scans'),

  startScan: (task: string, attack = false) =>
    j<Record<string, unknown>>('/scan/start', {
      method: 'POST', body: JSON.stringify({ task, attack, resume: false, dry: false }),
    }),

  killScan: (key: string) =>
    j<Record<string, unknown>>(`/scan/kill/${encodeURIComponent(key)}`, { method: 'POST' }),

  scanLog: (target: string, ts: string, tail = 300) =>
    j<{ file: string; lines: string[]; size: number }>(
      `/scan/${encodeURIComponent(target)}/${encodeURIComponent(ts)}/log?file=live.log&tail=${tail}`,
    ),

  settings: () => j<Settings>('/settings'),

  saveSettings: (updates: Record<string, string>) =>
    j<{ saved: string[]; path: string }>('/settings', { method: 'POST', body: JSON.stringify({ updates }) }),

  tools: () => j<{ tools: { name: string; category: string; desc: string; installed: boolean; missing: boolean }[]; platform: string }>('/tools'),

  toolkits: () => j<{ state: { running: boolean; result: unknown }; pool: Record<string, unknown> }>('/toolkits'),

  preinstallToolkits: () => j<{ ok: boolean; running: boolean }>('/toolkits/preinstall', { method: 'POST' }),

  installTool: (name: string) =>
    j<{ result: string }>('/tools/install', { method: 'POST', body: JSON.stringify({ name }) }),

  uploads: (threadId = '') =>
    j<{ uploads: { id: string; filename: string; mime: string; size: number; created: number; url: string }[] }>(
      `/uploads${threadId ? `?thread_id=${encodeURIComponent(threadId)}` : ''}`,
    ),
}

export type ChatPayload = {
  thread_id: string
  text: string
  attachments: string[]
  model?: string | null
  variant?: 'quick' | 'balanced' | 'deep'
  mode: 'agent' | 'chat'
  auto_approve: boolean
  effort: 'quick' | 'balanced' | 'deep'
}

export async function streamChat(
  payload: ChatPayload,
  onEvent: (e: SseEvent) => void,
  signal: AbortSignal,
): Promise<void> {
  const res = await fetch(`${API}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(payload),
    signal,
  })
  if (!res.ok || !res.body) {
    let detail = `${res.status}`
    try { detail = (await res.json())?.detail ?? detail } catch { /* ignore */ }
    throw new Error(detail)
  }
  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    let idx
    while ((idx = buffer.indexOf('\n\n')) !== -1) {
      const frame = buffer.slice(0, idx)
      buffer = buffer.slice(idx + 2)
      for (const line of frame.split('\n')) {
        if (!line.startsWith('data:')) continue
        const raw = line.slice(5).trim()
        if (!raw) continue
        try { onEvent(JSON.parse(raw) as SseEvent) } catch { /* ignore bad frame */ }
      }
    }
  }
}

export async function subscribeJob(
  threadId: string,
  onEvent: (e: SseEvent) => void,
  signal: AbortSignal,
): Promise<void> {
  const res = await fetch(`${API}/jobs/${encodeURIComponent(threadId)}/stream?compact=1`, {
    headers: { ...authHeaders() },
    signal,
  })
  if (!res.ok || !res.body) throw new Error(`job stream ${res.status}`)
  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    let idx
    while ((idx = buffer.indexOf('\n\n')) !== -1) {
      const frame = buffer.slice(0, idx)
      buffer = buffer.slice(idx + 2)
      for (const line of frame.split('\n')) {
        if (!line.startsWith('data:')) continue
        try { onEvent(JSON.parse(line.slice(5).trim()) as SseEvent) } catch { /* ignore */ }
      }
    }
  }
}

export function openScanStream(
  target: string, ts: string,
  onLine: (file: string, line: string) => void,
): () => void {
  const ctrl = new AbortController()
  ;(async () => {
    try {
      const res = await fetch(
        `${API}/scan/${encodeURIComponent(target)}/${encodeURIComponent(ts)}/stream`,
        { signal: ctrl.signal, headers: authHeaders() },
      )
      if (!res.body) return
      const reader = res.body.getReader()
      const dec = new TextDecoder()
      let buf = ''
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += dec.decode(value, { stream: true })
        let i
        while ((i = buf.indexOf('\n\n')) !== -1) {
          const frame = buf.slice(0, i)
          buf = buf.slice(i + 2)
          for (const line of frame.split('\n')) {
            if (!line.startsWith('data:')) continue
            try {
              const ev = JSON.parse(line.slice(5).trim())
              if (ev.type === 'log') onLine(ev.file, ev.line)
            } catch { /* ignore */ }
          }
        }
      }
    } catch { /* aborted */ }
  })()
  return () => ctrl.abort()
}
