import express from 'express';
import { protect } from '../middleware/auth.js';
import { runChat } from '../services/chatAssistantService.js';

const router = express.Router();

// Same x-wazuh-* header convention routes/wazuh.js's own getConfig() uses — the
// browser sends whatever it has saved locally (useWazuh.ts's 'medisiem_wazuh_cfg'),
// this backend never stores it. Deliberately duplicated rather than imported: see
// services/wazuhAgentStatus.js's header comment for why.
function getWazuhConfig(req) {
  const host = (req.headers['x-wazuh-host'] || '').trim();
  const port = (req.headers['x-wazuh-port'] || '55000').trim();
  const username = (req.headers['x-wazuh-user'] || '').trim();
  const password = (req.headers['x-wazuh-pass'] || '').trim();
  if (!host || !username || !password) return null;
  return { host, port, username, password };
}

// POST /api/assistant/chat — the floating AI chat widget (AiChatWidget.tsx). Any
// authenticated role can use it; it's read-only data access, same visibility the
// caller already has on the dashboard, nothing more.
router.post('/chat', protect, async (req, res) => {
  try {
    const { messages } = req.body || {};
    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'messages must be a non-empty array.' });
    }
    const reply = await runChat(messages, getWazuhConfig(req));
    res.json({ reply });
  } catch (err) {
    console.error('[assistantChat]', err);
    res.status(502).json({ error: err.message || 'AI assistant request failed.' });
  }
});

export default router;
