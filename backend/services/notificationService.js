// Outbound notifications (email/Slack/Teams), credentials read from the
// SystemSettings singleton rather than .env. Each send function throws when
// unconfigured; alert-pipeline callers catch and log instead of letting a
// notification failure break alert processing.
import nodemailer from 'nodemailer';
import SystemSettings from '../models/SystemSettings.js';

async function getSettings() {
  return SystemSettings.findOne().select('+smtp.pass +slackWebhookUrl +teamsWebhookUrl');
}

// Cache the nodemailer transport keyed by its config so a settings change
// takes effect on the next send without needing a process restart, but
// repeated sends between changes don't rebuild the transport every time.
let cachedTransport = null;
let cachedKey = null;

function smtpConfigKey(smtp) {
  return JSON.stringify([smtp?.host, smtp?.port, smtp?.secure, smtp?.user, smtp?.pass, smtp?.fromAddress]);
}

async function getTransport() {
  const settings = await getSettings();
  const smtp = settings?.smtp;
  if (!smtp?.host || !smtp?.user || !smtp?.pass) return null;

  const key = smtpConfigKey(smtp);
  if (!cachedTransport || cachedKey !== key) {
    cachedTransport = nodemailer.createTransport({
      host: smtp.host,
      port: smtp.port || 587,
      secure: !!smtp.secure,
      auth: { user: smtp.user, pass: smtp.pass },
    });
    cachedKey = key;
  }
  return { transport: cachedTransport, from: smtp.fromAddress || smtp.user };
}

export async function isEmailConfigured() {
  return !!(await getTransport());
}

export async function sendEmail({ to, subject, text, html }) {
  const ctx = await getTransport();
  if (!ctx) throw new Error('SMTP is not configured — set it up in Settings → Integrations.');
  await ctx.transport.sendMail({ from: ctx.from, to, subject, text, html });
}

async function postWebhook(url, payload) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`Webhook request failed (HTTP ${res.status}).`);
  }
}

export async function sendSlackMessage(text) {
  const settings = await getSettings();
  if (!settings?.slackWebhookUrl) throw new Error('Slack webhook is not configured — set it up in Settings → Integrations.');
  await postWebhook(settings.slackWebhookUrl, { text });
}

export async function sendTeamsMessage(text) {
  const settings = await getSettings();
  if (!settings?.teamsWebhookUrl) throw new Error('Teams webhook is not configured — set it up in Settings → Integrations.');
  // Teams incoming webhooks expect MessageCard-shaped JSON, not a bare `text`
  // field like Slack — https://learn.microsoft.com/outlook/actionable-messages
  await postWebhook(settings.teamsWebhookUrl, {
    '@type': 'MessageCard',
    '@context': 'http://schema.org/extensions',
    summary: 'MediSIEM alert',
    text,
  });
}

// Called by alertPipeline.js for every newly-scored alert; no-ops unless
// notifyOnImmediateCas is on and the alert actually scored Immediate, so
// it's cheap to call unconditionally from the pipeline's hot path.
export async function sendImmediateCasAlert(alert) {
  const settings = await SystemSettings.findOne().select('+slackWebhookUrl +teamsWebhookUrl');
  if (!settings?.notifyOnImmediateCas || alert.action !== 'Immediate') return;

  const summary =
    `Immediate CAS alert — ${alert.ruleDescription || alert.label || 'Unknown event'} on ` +
    `${alert.agent || 'unknown device'}${alert.department ? ` (${alert.department})` : ''}. ` +
    `CAS ${alert.CAS ?? '?'}.`;

  const jobs = [];
  if (settings.notifyChannels?.email && settings.notifyEmailRecipients?.length) {
    jobs.push(
      sendEmail({
        to: settings.notifyEmailRecipients.join(','),
        subject: `[MediSIEM] Immediate CAS alert — ${alert.agent || 'unknown device'}`,
        text: summary,
        html: `<p>${summary}</p>`,
      })
    );
  }
  if (settings.notifyChannels?.slack) jobs.push(sendSlackMessage(summary));
  if (settings.notifyChannels?.teams) jobs.push(sendTeamsMessage(summary));

  const results = await Promise.allSettled(jobs);
  for (const r of results) {
    if (r.status === 'rejected') console.warn('[notificationService] Immediate-CAS notification failed:', r.reason?.message || r.reason);
  }
}
