import express from 'express';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { protect, adminOnly } from '../middleware/auth.js';
import SystemSettings from '../models/SystemSettings.js';
import { logAudit } from '../utils/auditLog.js';
import { sendEmail, sendSlackMessage, sendTeamsMessage } from '../services/notificationService.js';
import { invalidateCasWeightsCache } from '../services/caapService.js';

const router = express.Router();

// Same shared/cas_config.json every runtime reads — used here only to surface
// the built-in AHP-justified weight profiles as reset targets / initial
// values for the Settings -> CAS Weights panel, never mutated.
const _CAS_CONFIG_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'shared', 'cas_config.json');
const CAS_CONFIG = JSON.parse(readFileSync(_CAS_CONFIG_PATH, 'utf-8'));
const CAS_WEIGHT_KEYS = ['TR', 'CC', 'TS', 'AE', 'TC'];

function validateWeightProfile(profile, label) {
  for (const k of CAS_WEIGHT_KEYS) {
    const v = Number(profile[k]);
    if (!Number.isFinite(v) || v < 0 || v > 1) {
      throw new Error(`${label}: ${k} must be a number between 0 and 1.`);
    }
  }
  const total = CAS_WEIGHT_KEYS.reduce((sum, k) => sum + Number(profile[k]), 0);
  if (Math.abs(total - 1) > 0.01) {
    throw new Error(`${label}: weights must sum to 1.00 (got ${total.toFixed(3)}).`);
  }
  return CAS_WEIGHT_KEYS.reduce((o, k) => ({ ...o, [k]: Number(profile[k]) }), {});
}

async function getOrCreateSettings() {
  let settings = await SystemSettings.findOne().select('+smtp.pass +slackWebhookUrl +teamsWebhookUrl +googleApiKey +abuseIpdbApiKey');
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
    googleConfigured: !!settings.googleApiKey,
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
    casWeights: {
      // The admin's own overrides, if any — null means "not customized, use
      // the built-in default/profile below".
      default: settings.casWeights?.default || null,
      scenarios: settings.casWeights?.scenarios || {},
      // The AHP-justified built-ins (shared/cas_config.json) — always
      // present, used by the frontend both as the "Reset to AHP default"
      // target and as sensible pre-fill values for un-customized scenarios.
      builtInDefault: CAS_CONFIG.default_weights,
      builtInScenarioProfiles: CAS_CONFIG.scenario_weight_profiles,
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

    const secretFields = ['slackWebhookUrl', 'teamsWebhookUrl', 'googleApiKey', 'abuseIpdbApiKey'];
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

    // casWeights: default/each scenario key is either omitted (leave
    // untouched), null (reset to the built-in AHP/scenario default), or a
    // full 5-dimension profile that must sum to 1.00 — same
    // omit/clear/replace convention the secret fields above already use.
    if (body.casWeights && typeof body.casWeights === 'object') {
      if (!settings.casWeights) settings.casWeights = {};
      try {
        if (body.casWeights.default !== undefined) {
          settings.casWeights.default = body.casWeights.default === null
            ? undefined
            : validateWeightProfile(body.casWeights.default, 'Default weights');
        }
        if (body.casWeights.scenarios && typeof body.casWeights.scenarios === 'object') {
          const scenarios = { ...(settings.casWeights.scenarios || {}) };
          for (const [key, profile] of Object.entries(body.casWeights.scenarios)) {
            if (profile === null) {
              delete scenarios[key];
            } else {
              scenarios[key] = validateWeightProfile(profile, `Scenario "${key}"`);
            }
          }
          settings.casWeights.scenarios = Object.keys(scenarios).length ? scenarios : undefined;
        }
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
      settings.markModified('casWeights');
    }

    settings.updatedBy = { id: req.user.id, name: req.user.name };
    await settings.save();
    invalidateCasWeightsCache();

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
