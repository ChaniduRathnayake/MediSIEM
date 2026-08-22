// Floating, data-aware AI assistant — available on every dashboard page (mounted once
// in App.tsx's DashboardLayout). Unlike the one-shot AI features elsewhere (triage
// explanations, close-drafts), this is a real back-and-forth conversation, and the
// backend gives the model function-calling access to live alert/device data
// (see backend/services/chatAssistantService.js) so it can actually answer
// "how many Immediate alerts in ICU today" instead of guessing.
import React, { useEffect, useRef, useState } from 'react';
import { Sparkles, X, Send, Loader2, AlertCircle, Bot } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { apiChatWithAssistant } from '../services/chatApi';
import type { ChatMessage } from '../services/chatApi';

const EXAMPLE_PROMPTS = [
  'How many alerts in the last 24 hours?',
  'Show recent Immediate alerts',
  'List critical devices in the ICU',
];

const AiChatWidget: React.FC = () => {
  const { token, isAuthenticated } = useAuth();
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, loading, open]);

  useEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  if (!isAuthenticated || !token) return null;

  const send = async (text: string) => {
    const question = text.trim();
    if (!question || loading) return;
    setError('');
    setInput('');
    const nextMessages: ChatMessage[] = [...messages, { role: 'user', content: question }];
    setMessages(nextMessages);
    setLoading(true);
    try {
      const { reply } = await apiChatWithAssistant(token, nextMessages);
      setMessages((prev) => [...prev, { role: 'assistant', content: reply }]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'AI assistant request failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      {open && (
        <div className="fixed bottom-24 right-6 z-50 w-[380px] max-w-[calc(100vw-3rem)] h-[540px] max-h-[calc(100vh-8rem)] flex flex-col rounded-2xl shadow-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/50 flex-shrink-0">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-full bg-cyan-500/15 flex items-center justify-center">
                <Sparkles className="w-3.5 h-3.5 text-cyan-500" />
              </div>
              <div>
                <p className="text-sm font-semibold text-slate-900 dark:text-white leading-tight">MediSIEM Assistant</p>
                <p className="text-[11px] text-slate-400 dark:text-slate-600 leading-tight">Ask about alerts, devices, and cases</p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setOpen(false)}
              aria-label="Close assistant"
              className="p-1.5 rounded-lg text-slate-400 dark:text-slate-500 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Messages */}
          <div ref={scrollRef} className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
            {messages.length === 0 && (
              <div className="h-full flex flex-col items-center justify-center text-center gap-3 py-6">
                <div className="w-10 h-10 rounded-full bg-cyan-500/10 flex items-center justify-center">
                  <Bot className="w-5 h-5 text-cyan-500" />
                </div>
                <p className="text-xs text-slate-400 dark:text-slate-600 max-w-[260px]">
                  Ask a question about live alerts, devices, or recent activity — answers are pulled from real data, not guesses.
                </p>
                <div className="flex flex-col gap-1.5 w-full">
                  {EXAMPLE_PROMPTS.map((p) => (
                    <button
                      key={p}
                      type="button"
                      onClick={() => send(p)}
                      className="text-xs text-left px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                    >
                      {p}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {messages.map((m, i) => (
              <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div
                  className={`max-w-[85%] rounded-xl px-3 py-2 text-xs leading-relaxed whitespace-pre-wrap ${
                    m.role === 'user'
                      ? 'bg-cyan-500 text-white rounded-br-sm'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 rounded-bl-sm'
                  }`}
                >
                  {m.content}
                </div>
              </div>
            ))}

            {loading && (
              <div className="flex justify-start">
                <div className="flex items-center gap-1.5 rounded-xl rounded-bl-sm px-3 py-2 bg-slate-100 dark:bg-slate-800 text-slate-400 dark:text-slate-500">
                  <Loader2 className="w-3 h-3 animate-spin" />
                  <span className="text-xs">Thinking…</span>
                </div>
              </div>
            )}

            {error && (
              <div className="flex items-start gap-1.5 px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 dark:text-red-400 text-xs">
                <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" /> <span>{error}</span>
              </div>
            )}
          </div>

          {/* Input */}
          <form
            onSubmit={(e) => { e.preventDefault(); send(input); }}
            className="flex items-center gap-2 px-3 py-3 border-t border-slate-200 dark:border-slate-800 flex-shrink-0"
          >
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask a question…"
              disabled={loading}
              className="flex-1 px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 disabled:opacity-60"
            />
            <button
              type="submit"
              disabled={loading || !input.trim()}
              aria-label="Send"
              className="flex-shrink-0 p-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed text-white transition-colors"
            >
              <Send className="w-3.5 h-3.5" />
            </button>
          </form>
        </div>
      )}

      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-label={open ? 'Close AI assistant' : 'Open AI assistant'}
        className="fixed bottom-6 right-6 z-50 w-14 h-14 rounded-full bg-cyan-500 hover:bg-cyan-400 shadow-lg shadow-cyan-500/25 flex items-center justify-center text-white transition-all hover:scale-105 active:scale-95"
      >
        {open ? <X className="w-5 h-5" /> : <Sparkles className="w-5 h-5" />}
      </button>
    </>
  );
};

export default AiChatWidget;
