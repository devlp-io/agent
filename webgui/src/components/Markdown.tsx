import { isValidElement, memo, useRef, useState, type ReactNode } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import rehypeHighlight from 'rehype-highlight'
import { Check, Copy } from 'lucide-react'

function codeLanguage(children: ReactNode): string {
  const arr = Array.isArray(children) ? children : [children]
  for (const child of arr) {
    if (isValidElement(child)) {
      const cls = String((child.props as { className?: string }).className || '')
      const m = cls.match(/language-([\w+#.-]+)/)
      if (m) return m[1].replace(/:[\w./-]+$/, '')
    }
  }
  return ''
}

function Pre({ children }: { children?: ReactNode }) {
  const ref = useRef<HTMLPreElement>(null)
  const [copied, setCopied] = useState(false)
  const lang = codeLanguage(children)

  const copy = async () => {
    const text = ref.current?.querySelector('code')?.textContent ?? ''
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1400)
    } catch { /* clipboard blocked */ }
  }

  return (
    <div className="group relative">
      <pre ref={ref}>{children}</pre>
      <button
        type="button"
        onClick={copy}
        aria-label="Copy code"
        className="absolute right-2 top-2 flex h-7 items-center gap-1.5 rounded-md border border-line bg-panel/90 px-2 text-[10.5px] text-muted opacity-70 backdrop-blur transition hover:opacity-100 hover:text-ink"
      >
        {lang && <span className="font-mono text-[9.5px] uppercase tracking-wide text-faint">{lang}</span>}
        {copied ? <Check size={12} className="text-mint" /> : <Copy size={12} />}
        {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  )
}

const CODE_SIGNAL = /(<!doctype|<html|<\/html|<head|<body|<div|<style|<script|function\s+\w+\s*\(|class\s+\w+|def\s+\w+\s*\(|import\s+[\w.]+|from\s+[\w.]+\s+import|const\s+\w+\s*=|let\s+\w+\s*=|#include|public\s+static)/i

function autoFence(text: string): string {
  if (!text || text.includes('```')) return text
  if (!CODE_SIGNAL.test(text)) return text
  const braces = (text.match(/[{};<>]/g) || []).length
  if (braces < 4) return text
  const lang = /<html|<div|<style|<body|<script/i.test(text)
    ? 'html'
    : /\bdef\s|^import\s|^from\s/m.test(text)
      ? 'python'
      : /#include|public\s+static|std::/i.test(text)
        ? 'cpp'
        : /\bconst\s|=>|function\s/i.test(text)
          ? 'js'
          : ''
  return '```' + lang + '\n' + text.trim() + '\n```'
}

export const Markdown = memo(function Markdown({ text, raw = false }: { text: string; raw?: boolean }) {
  return (
    <div className="prose-md">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[[rehypeHighlight, { detect: true, ignoreMissing: true }]]}
        components={{
          pre: Pre,
          a: ({ href, children }) => (
            <a href={href} target="_blank" rel="noreferrer noopener">{children}</a>
          ),
        }}
      >
        {raw ? text : autoFence(text)}
      </ReactMarkdown>
    </div>
  )
})
