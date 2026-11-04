export type Attachment = {
  id: string
  filename: string
  mime: string
  size: number
  kind: 'image' | 'text' | 'file'
  url: string
}

export type ToolPart = {
  type: 'tool'
  tool: string
  args: Record<string, unknown>
  output: string
  ok: boolean | null
  status: 'running' | 'done' | 'error' | 'denied' | 'cancelled' | 'awaiting'
  call_id: string
  language?: string
}

export type TodoItem = {
  id: string
  text: string
  status: 'todo' | 'doing' | 'done'
}

export type TextPart = { type: 'text'; text: string }

export type AskPart = {
  type: 'ask'
  question_id: string
  prompt: string
  choices: string[]
  secret: boolean
  status: 'waiting' | 'answered'
}

export type ThoughtPart = { type: 'thought'; text: string; duration_ms: number }

export type NotePart = { type: 'note'; text: string }

export type Part = TextPart | ToolPart | AskPart | ThoughtPart | NotePart

export type Message = {
  id: string
  thread_id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  parts: Part[]
  attachments: Attachment[]
  meta: Record<string, unknown>
  created: number
  created_iso: string
  streaming?: boolean
}

export type Thread = {
  id: string
  title: string
  created: number
  updated: number
  updated_iso?: string
  model: string | null
  mode: string
  pinned: boolean
  msg_count: number
  in_tokens?: number
  out_tokens?: number
  cost_usd?: number
  requests?: number
}

export type ModelVariant = {
  key: 'quick' | 'balanced' | 'deep'
  label: string
  model?: string
  effort?: string
}

export type ModelProfile = {
  name: string
  label?: string
  model: string
  base: string
  provider?: string
  key_var?: string
  configured: boolean
  active: boolean
  variants?: ModelVariant[]
  price_in?: number
  price_out?: number
}

export type RunInfo = {
  thread_id: string
  message_id?: string | null
  status: 'running' | 'interrupted' | 'cancelled' | 'done' | 'idle'
  objective?: string | null
  started?: number | null
  updated?: number | null
}

export type Usage = {
  input_tokens: number
  output_tokens: number
  total_tokens: number
  cost_usd: number
  requests: number
  model?: string | null
  label?: string
}

export type Scan = {
  target: string
  ts: string
  turn?: number
  is_live?: boolean
  started_at?: string
  [k: string]: unknown
}

export type RunningJob = {
  kind: 'spawn' | 'disk'
  key: string
  pid: number | null
  task: string
  alive: boolean
  target: string | null
  ts: string | null
  lines: string[]
  [k: string]: unknown
}

export type Settings = {
  keys: Record<string, string>
  effective: Record<string, boolean>
  path: string
  model: string
  provider: string
  scan_root: string
  data_dir: string
}

export type SseEvent =
  | { type: 'start'; user_message: Message; title: string }
  | { type: 'delta'; text: string }
  | { type: 'text_final'; text: string }
  | { type: 'tool_start'; id: string; tool: string; args: Record<string, unknown> }
  | { type: 'tool_approval'; id: string; tool: string; args: Record<string, unknown> }
  | { type: 'tool_delta'; id: string; output: string }
  | { type: 'tool_end'; id: string; tool?: string; ok: boolean; output: string; status: ToolPart['status'] }
  | { type: 'note'; text: string }
  | { type: 'todos'; items: TodoItem[] }
  | { type: 'thinking'; text: string }
  | { type: 'retry'; attempt: number }
  | { type: 'ask'; id: string; prompt: string; choices: string[]; secret: boolean }
  | { type: 'status'; status: string }
  | { type: 'file_edit'; id: string; path: string; action: string; bytes: number; language: string; content: string }
  | { type: 'done'; message: Message; title?: string | null }
  | { type: 'error'; message: string }
  | { type: 'ready'; [k: string]: unknown }
  | { type: 'log'; file: string; line: string }
