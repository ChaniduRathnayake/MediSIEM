import { BASE_URL } from './api';

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

// Same storage key useWazuh.ts saves the connected Wazuh Manager config under — this
// backend never stores those credentials itself (see backend/services/wazuhAgentStatus.js),
// so the get_agent_status tool only works if the browser already connected Wazuh in this
// session. Mirrors wazuhApi.ts's own configHeaders() exactly.
const WAZUH_STORAGE_KEY = 'medisiem_wazuh_cfg';

function wazuhHeaders(): Record<string, string> {
  try {
    const raw = localStorage.getItem(WAZUH_STORAGE_KEY);
    if (!raw) return {};
    const cfg = JSON.parse(raw) as { host?: string; port?: string; username?: string; password?: string };
    if (!cfg.host || !cfg.username || !cfg.password) return {};
    return {
      'x-wazuh-host': cfg.host,
      'x-wazuh-port': cfg.port ?? '55000',
      'x-wazuh-user': cfg.username,
      'x-wazuh-pass': cfg.password,
    };
  } catch {
    return {};
  }
}

export async function apiChatWithAssistant(token: string, messages: ChatMessage[]): Promise<{ reply: string }> {
  const res = await fetch(`${BASE_URL}/assistant/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...wazuhHeaders() },
    body: JSON.stringify({ messages }),
  });
  const json = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
  if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`);
  return json;
}
