import express from 'express';
import { protect, adminOnly } from '../middleware/auth.js';
import SystemSettings from '../models/SystemSettings.js';
import { logAudit } from '../utils/auditLog.js';
import { sendEmail, sendSlackMessage, sendTeamsMessage } from '../services/notificationService.js';

const router = express.Router();

async function getOrCreateSettings() {
  let settings = await SystemSettings.findOne().select('+smtp.pass +slackWebhookUrl +teamsWebhookUrl +anthropicApiKey +abuseIpdbApiKey');
  if (!settings) settings = new SystemSettings();
  return settings;
}

// Never echo a stored secret back to the browser — only whether one is set.
// Same shape whether returned from GET or PATCH so the frontend can just
// reuse the response either way.
function toMaskedResponse(settings) {
  return {
    smtp: {
      host: settings.smtp?.host || '',
      port: settings.smtp?.port ?? 587,
      secure: !!settings.smtp?.secure,
      user: settings.smtp?.user || '',
      fromAddress: settings.smtp?.fromAddress || '',
      passConfigured: !!settings.smtp?.pass,
    },
    notifyEmailRecipients: settings.notifyEmailRecipients || [],
    slackConfigured: !!settings.slackWebhookUrl,
    teamsConfigured: !!settings.teamsWebhookUrl,
    anthropicConfigured: !!settings.anthropicApiKey,
    abuseIpdbConfigured: !!settings.abuseIpdbApiKey,
    mfaRequiredForAdmin: !!settings.mfaRequiredForAdmin,
    lockout: {
      maxAttempts: settings.lockout?.maxAttempts ?? 5,
      lockDurationMinutes: settings.lockout?.lockDurationMinutes ?? 15,
    },
    notifyOnImmediateCas: !!settings.notifyOnImmediateCas,
    notifyChannels: {
      email: !!settings.notifyChannels?.email,
      slack: !!settings.notifyChannels?.slack,
      teams: !!settings.notifyChannels?.teams,
    },
    updatedBy: settings.updatedBy || null,
    updatedAt: settings.updatedAt || null,
  };
}

// ─── GET /api/settings  (admin only) ───────────────────────────────────────────
router.get('/', protect, adminOnly, async (req, res) => {
  try {
    const settings = await getOrCreateSettings();
    res.json({ settings: toMaskedResponse(settings) });
  } catch (err) {
    console.error('[getSettings]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── PATCH /api/settings  (admin only) ─────────────────────────────────────────
// Every secret field follows the same convention: omit it to leave it
// untouched, send '' to clear it, send a non-empty string to replace it.
router.patch('/', protect, adminOnly, async (req, res) => {
  try {
    const body = req.body || {};
    const settings = await getOrCreateSettings();

    if (body.smtp && typeof body.smtp === 'object') {
      const { host, port, secure, user, pass, fromAddress } = body.smtp;
      if (host !== undefined) settings.smtp.host = String(host).trim();
      if (port !== undefined) {
        const n = Number(port);
        if (!Number.isFinite(n) || n < 1 || n > 65535) {
          return res.status(400).json({ error: 'SMTP port must be a number between 1 and 65535.' });
        }
        settings.smtp.port = n;
      }
      if (secure !== undefined) settings.smtp.secure = !!secure;
      if (user !== undefined) settings.smtp.user = String(user).trim();
      if (fromAddress !== undefined) settings.smtp.fromAddress = String(fromAddress).trim();
      if (pass !== undefined) settings.smtp.pass = String(pass);
    }

    if (body.notifyEmailRecipients !== undefined) {
      if (!Array.isArray(body.notifyEmailRecipients) || !body.notifyEmailRecipients.every((e) => typeof e === 'string')) {
        return res.status(400).json({ error: 'notifyEmailRecipients must be a list of email addresses.' });
      }
      settings.notifyEmailRecipients = body.notifyEmailRecipients.map((e) => e.trim()).filter(Boolean);
    }

    const secretFields = ['slackWebhookUrl', 'teamsWebhookUrl', 'anthropicApiKey', 'abuseIpdbApiKey'];
    for (const field of secretFields) {
      if (body[field] !== undefined) {
        if (typeof body[field] !== 'string') {
          return res.status(400).json({ error: `${field} must be a string.` });
        }
        settings[field] = body[field];
      }
    }

    if (body.mfaRequiredForAdmin !== undefined) settings.mfaRequiredForAdmin = !!body.mfaRequiredForAdmin;
    if (body.lockout && typeof body.lockout === 'object') {
      const { maxAttempts, lockDurationMinutes } = body.lockout;
      if (maxAttempts !== undefined) {
        const n = Number(maxAttempts);
        if (!Number.isFinite(n) || n < 3 || n > 20) {
          return res.status(400).json({ error: 'Lockout max attempts must be between 3 and 20.' });
        }
        settings.lockout.maxAttempts = n;
      }
      if (lockDurationMinutes !== undefined) {
        const n = Number(lockDurationMinutes);
        if (!Number.isFinite(n) || n < 1 || n > 1440) {
          return res.status(400).json({ error: 'Lockout duration must be between 1 and 1440 minutes.' });
        }
        settings.lockout.lockDurationMinutes = n;
      }
    }
    if (body.notifyOnImmediateCas !== undefined) settings.notifyOnImmediateCas = !!body.notifyOnImmediateCas;
    if (body.notifyChannels && typeof body.notifyChannels === 'object') {
      settings.notifyChannels = {
        email: !!body.notifyChannels.email,
        slack: !!body.notifyChannels.slack,
        teams: !!body.notifyChannels.teams,
      };
    }

    settings.updatedBy = { id: req.user.id, name: req.user.name };
    await settings.save();

    await logAudit({
      action: 'update_settings',
      actor: { id: req.user.id, name: req.user.name, email: req.user.email },
      details: 'Updated integration settings',
    });

    res.json({ settings: toMaskedResponse(settings) });
  } catch (err) {
    console.error('[updateSettings]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── POST /api/settings/test-email  (admin only) ───────────────────────────────
router.post('/test-email', protect, adminOnly, async (req, res) => {
  try {
    const to = typeof req.body?.to === 'string' && req.body.to ? req.body.to : req.user.email;
    await sendEmail({
      to,
      subject: 'MediSIEM test email',
      text: 'This is a test email from MediSIEM Settings → Integrations. SMTP is configured correctly.',
      html: '<p>This is a test email from MediSIEM Settings → Integrations. SMTP is configured correctly.</p>',
    });
    res.json({ sent: true });
  } catch (err) {
    res.status(400).json({ error: err.message || 'Failed to send test email.' });
  }
});

// ─── POST /api/settings/test-webhook  (admin only) — body: { channel: 'slack' | 'teams' } ──
router.post('/test-webhook', protect, adminOnly, async (req, res) => {
  try {
    const { channel } = req.body || {};
    const text = 'This is a test message from MediSIEM Settings → Integrations. The webhook is configured correctly.';
    if (channel === 'slack') await sendSlackMessage(text);
    else if (channel === 'teams') await sendTeamsMessage(text);
    else return res.status(400).json({ error: "channel must be 'slack' or 'teams'." });
    res.json({ sent: true });
  } catch (err) {
    res.status(400).json({ error: err.message || 'Failed to send test message.' });
  }
});

export default router;
