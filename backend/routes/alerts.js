import express from 'express';
import { protect, allowRoles, adminOnly } from '../middleware/auth.js';
import { getBufferedAlerts, getAlertStats } from '../services/alertPipeline.js';
import AlertAssignment from '../models/AlertAssignment.js';
import AlertClosure from '../models/AlertClosure.js';
import AlertNote from '../models/AlertNote.js';
import AlertSnooze from '../models/AlertSnooze.js';
import User from '../models/User.js';
import { logAudit } from '../utils/auditLog.js';
import { generateTriageExplanation, isTriageAssistantConfigured } from '../services/triageAssistantService.js';
import { generateCloseDraft, generateCaseSummary, parseAlertQuery } from '../services/aiAssistantService.js';

const router = express.Router();

// A CRITICAL alert unassigned this long gets flagged `escalated` so it can't quietly age out unattended.
const ESCALATION_THRESHOLD_MS = 10 * 60 * 1000;

const HISTORY_LIMIT = 500; // caps how many historical assignments/closures GET / reconstructs from

// Lean permanent copy of an alert — not the full EnrichedAlert. `flow` is kept only when
// present so a closed, verdict-tagged case can later feed training-feedback-export.
function pickSnapshotFields(alert) {
  if (!alert) return null;
  return {
    timestamp: alert.timestamp,
    agent: alert.agent,
    department: alert.department,
    deviceType: alert.deviceType,
    deviceCriticality: alert.deviceCriticality,
    ruleDescription: alert.ruleDescription,
    label: alert.label,
    CAS: alert.CAS,
    action: alert.action,
    mitre: alert.mitre ?? null,
    flow: alert.flow ?? null,
    matchedRules: alert.matchedRules ?? [],
  };
}

// GET /api/alerts — CAS-ranked enriched alerts.
router.get('/', protect, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const sortByCas = req.query.sort !== 'time';
    const bufferedAlerts = getBufferedAlerts({ limit, sortByCas });
    const bufferedIds = new Set(bufferedAlerts.map((a) => a.id));

    // Pulled unfiltered (bounded by HISTORY_LIMIT) so a case whose alert aged out of the
    // buffer is reconstructed below from alertSnapshot instead of vanishing from view.
    const [assignments, closures, snoozes] = await Promise.all([
      AlertAssignment.find().sort({ updatedAt: -1 }).limit(HISTORY_LIMIT),
      AlertClosure.find().sort({ createdAt: -1 }).limit(HISTORY_LIMIT),
      AlertSnooze.find({ snoozedUntil: { $gt: new Date() } }),
    ]);
    const assignedByAlertId = new Map(assignments.map((a) => [a.alertId, a.analyst]));
    const closureByAlertId = new Map(closures.map((c) => [c.alertId, c]));
    const snoozeByAlertId = new Map(snoozes.map((s) => [s.alertId, s]));

    const reconstructed = new Map();
    for (const c of closures) {
      if (bufferedIds.has(c.alertId) || reconstructed.has(c.alertId) || !c.alertSnapshot) continue;
      reconstructed.set(c.alertId, { id: c.alertId, ...c.alertSnapshot });
    }
    for (const a of assignments) {
      if (bufferedIds.has(a.alertId) || reconstructed.has(a.alertId) || !a.alertSnapshot) continue;
      reconstructed.set(a.alertId, { id: a.alertId, ...a.alertSnapshot });
    }

    const now = Date.now();
    const toRow = (a) => {
      const assignedTo = assignedByAlertId.get(a.id) ?? null;
      const closure = closureByAlertId.get(a.id) ?? null;
      const snoozeDoc = snoozeByAlertId.get(a.id) ?? null;
      const snoozed = snoozeDoc
        ? { snoozedUntil: snoozeDoc.snoozedUntil, reason: snoozeDoc.reason, snoozedBy: snoozeDoc.snoozedBy }
        : null;
      const escalated = // doesn't escalate while snoozed
        (a.CAS ?? 0) >= 8 && !assignedTo && !closure && !snoozed && now - new Date(a.timestamp).getTime() >= ESCALATION_THRESHOLD_MS;
      return { ...a, assignedTo, closure, snoozed, escalated };
    };

    const withAssignments = [...bufferedAlerts.map(toRow), ...[...reconstructed.values()].map(toRow)];

    res.json({ alerts: withAssignments, count: withAssignments.length, ...getAlertStats() });
  } catch (err) {
    console.error('[getAlerts]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// PATCH /api/alerts/:id/assign — assign/unassign an alert to an analyst.
router.patch('/:id/assign', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const { analystId } = req.body;
    const alertId = req.params.id;

    if (analystId !== undefined && typeof analystId !== 'string') {
      return res.status(400).json({ error: 'analystId must be a string.' });
    }

    if (!analystId) {
      const existing = await AlertAssignment.findOne({ alertId });
      await AlertAssignment.deleteOne({ alertId });
      if (existing) {
        await logAudit({
          action: 'unassign_alert',
          actor: { id: req.user.id, name: req.user.name, email: req.user.email },
          target: { id: alertId, name: existing.analyst?.name },
          details: `Unassigned from ${existing.analyst?.name ?? 'analyst'}`,
        });
      }
      return res.json({ assignedTo: null });
    }

    const analyst = await User.findById(analystId);
    if (!analyst) {
      return res.status(404).json({ error: 'Analyst not found.' });
    }
    if (analyst.role !== 'user') {
      return res.status(400).json({ error: 'Alerts can only be assigned to SOC analysts, not admins.' });
    }

    const alertData = getBufferedAlerts({ limit: 500 }).find((a) => a.id === alertId);

    const assignment = await AlertAssignment.findOneAndUpdate(
      { alertId },
      {
        alertId,
        analyst: { id: analyst._id.toString(), name: analyst.name, email: analyst.email },
        assignedBy: { id: req.user.id, name: req.user.name },
        ...(alertData ? { alertSnapshot: pickSnapshotFields(alertData) } : {}),
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    await logAudit({
      action: 'assign_alert',
      actor: { id: req.user.id, name: req.user.name, email: req.user.email },
      target: { id: alertId, name: analyst.name, email: analyst.email },
      details: `Assigned to ${analyst.name}`,
    });

    res.json({ assignedTo: assignment.analyst });
  } catch (err) {
    console.error('[assignAlert]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

const VALID_VERDICTS = ['true_positive', 'false_positive', 'benign', 'uncertain'];

// PATCH /api/alerts/:id/close — close a case with a reason + evidence. Restricted to the
// analyst the alert is currently assigned to, or an admin.
router.patch('/:id/close', protect, async (req, res) => {
  try {
    const alertId = req.params.id;
    const reason = (req.body.reason || '').trim();
    const evidence = (req.body.evidence || '').trim();
    const verdict = req.body.verdict || null;

    if (!reason || !evidence) {
      return res.status(400).json({ error: 'Both a reason and supporting evidence are required to close a case.' });
    }
    if (verdict && !VALID_VERDICTS.includes(verdict)) {
      return res.status(400).json({ error: `Verdict must be one of: ${VALID_VERDICTS.join(', ')}.` });
    }

    if (req.user.role !== 'admin') {
      const assignment = await AlertAssignment.findOne({ alertId });
      if (!assignment || assignment.analyst.id !== req.user.id) {
        return res.status(403).json({ error: 'You can only close cases assigned to you.' });
      }
    }

    // Falls back to an existing assignment's snapshot if the alert already aged out of the buffer.
    const alertData = getBufferedAlerts({ limit: 500 }).find((a) => a.id === alertId);
    const snapshot = pickSnapshotFields(alertData) ?? (await AlertAssignment.findOne({ alertId }))?.alertSnapshot ?? null;

    const closure = await AlertClosure.findOneAndUpdate(
      { alertId },
      {
        alertId,
        reason,
        evidence,
        verdict,
        closedBy: { id: req.user.id, name: req.user.name, email: req.user.email },
        ...(snapshot ? { alertSnapshot: snapshot } : {}),
      },
      { upsert: true, new: true, setDefaultsOnInsert: true, runValidators: true }
    );

    await logAudit({
      action: 'close_alert',
      actor: { id: req.user.id, name: req.user.name, email: req.user.email },
      target: { id: alertId },
      details: `Closed${verdict ? ` as ${verdict.replace('_', ' ')}` : ''} — ${reason}`,
    });

    res.json({ closure });
  } catch (err) {
    console.error('[closeAlert]', err);
    res.status(400).json({ error: err.message || 'Failed to close case.' });
  }
});

// Resolves "@Name" mentions against the analyst/admin roster — longest-name-first so
// "@Jane Doe" isn't shadowed by a coincidental "@Jane" match.
function resolveMentions(text, roster, authorId) {
  const lower = text.toLowerCase();
  const matched = [];
  for (const u of [...roster].sort((a, b) => b.name.length - a.name.length)) {
    if (u.id === authorId) continue;
    if (lower.includes(`@${u.name.toLowerCase()}`)) matched.push(u);
  }
  return matched;
}

// GET /api/alerts/:id/notes — investigation notes for a case, oldest first.
router.get('/:id/notes', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const notes = await AlertNote.find({ alertId: req.params.id }).sort({ createdAt: 1 }).limit(200);
    res.json({ notes });
  } catch (err) {
    console.error('[getAlertNotes]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// POST /api/alerts/:id/notes — add an investigation note, resolving @mentions.
router.post('/:id/notes', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const alertId = req.params.id;
    const text = (req.body.text || '').trim();
    if (!text) return res.status(400).json({ error: 'Note text is required.' });

    const roster = await User.find({ role: { $in: ['admin', 'user'] } }).select('_id name email');
    const mentioned = resolveMentions(text, roster, req.user.id);

    const note = await AlertNote.create({
      alertId,
      author: { id: req.user.id, name: req.user.name, email: req.user.email },
      text,
      mentions: mentioned.map((u) => u._id.toString()),
    });

    await logAudit({
      action: 'add_alert_note',
      actor: { id: req.user.id, name: req.user.name, email: req.user.email },
      target: { id: alertId },
      details: `Added a note${mentioned.length ? ` mentioning ${mentioned.map((u) => u.name).join(', ')}` : ''}`,
    });

    // Broadcast-to-everyone, filter-on-the-client — no per-user socket rooms exist.
    if (mentioned.length > 0) {
      const io = req.app.get('io');
      const alert = getBufferedAlerts({ limit: 500 }).find((a) => a.id === alertId);
      io?.emit('alert:mention', {
        alertId,
        alertLabel: alert ? (alert.label !== 'Unclassified' ? alert.label : alert.ruleDescription) : alertId,
        mentionedUserIds: mentioned.map((u) => u._id.toString()),
        from: { id: req.user.id, name: req.user.name },
        text,
      });
    }

    res.status(201).json({ note });
  } catch (err) {
    console.error('[addAlertNote]', err);
    res.status(400).json({ error: err.message || 'Failed to add note.' });
  }
});

// PATCH /api/alerts/:id/snooze — hide a case from the active queue for a while.
router.patch('/:id/snooze', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const alertId = req.params.id;
    const { minutes, reason } = req.body;

    if (minutes === undefined || minutes === null) {
      const existing = await AlertSnooze.findOneAndDelete({ alertId });
      if (existing) {
        await logAudit({
          action: 'unsnooze_alert',
          actor: { id: req.user.id, name: req.user.name, email: req.user.email },
          target: { id: alertId },
          details: 'Unsnoozed',
        });
      }
      return res.json({ snoozed: null });
    }

    const mins = Number(minutes);
    if (!Number.isFinite(mins) || mins <= 0 || mins > 60 * 24 * 14) {
      return res.status(400).json({ error: 'minutes must be a number between 1 and 20160 (14 days).' });
    }

    const snoozedUntil = new Date(Date.now() + mins * 60 * 1000);
    const snooze = await AlertSnooze.findOneAndUpdate(
      { alertId },
      {
        alertId,
        snoozedUntil,
        reason: (reason || '').trim(),
        snoozedBy: { id: req.user.id, name: req.user.name, email: req.user.email },
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    await logAudit({
      action: 'snooze_alert',
      actor: { id: req.user.id, name: req.user.name, email: req.user.email },
      target: { id: alertId },
      details: `Snoozed until ${snoozedUntil.toLocaleString()}${reason ? ` — ${reason}` : ''}`,
    });

    res.json({ snoozed: { snoozedUntil: snooze.snoozedUntil, reason: snooze.reason, snoozedBy: snooze.snoozedBy } });
  } catch (err) {
    console.error('[snoozeAlert]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// GET /api/alerts/my-stats — the calling analyst's own resolution stats.
router.get('/my-stats', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const since7d = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const [closures, closedThisWeek] = await Promise.all([
      AlertClosure.find({ 'closedBy.id': req.user.id }).sort({ createdAt: -1 }).limit(2000),
      AlertClosure.countDocuments({ 'closedBy.id': req.user.id, createdAt: { $gte: since7d } }),
    ]);

    const verdictCounts = { true_positive: 0, false_positive: 0, benign: 0, uncertain: 0, unset: 0 };
    let resolutionMsSum = 0;
    let resolutionMsCount = 0;
    for (const c of closures) {
      verdictCounts[c.verdict ?? 'unset'] += 1;
      // Detection -> closure timestamp as a time-to-resolve proxy (not true assignment-to-close MTTR).
      const detectedAt = c.alertSnapshot?.timestamp ? new Date(c.alertSnapshot.timestamp).getTime() : null;
      if (detectedAt) {
        resolutionMsSum += c.createdAt.getTime() - detectedAt;
        resolutionMsCount += 1;
      }
    }

    res.json({
      totalClosed: closures.length,
      closedThisWeek,
      verdictCounts,
      avgResolutionMinutes: resolutionMsCount > 0 ? Math.round(resolutionMsSum / resolutionMsCount / 60000) : null,
    });
  } catch (err) {
    console.error('[getMyStats]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// GET /api/alerts/my-history — search/export the calling analyst's own closed cases, including
// ones aged out of the live buffer. Also backs the "My Case History" report (from/to, no search text).
router.get('/my-history', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const search = (req.query.search || '').trim();
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 2000);
    const filter = { 'closedBy.id': req.user.id };

    // Filters on createdAt (closure time, not detection time).
    const from = req.query.from ? new Date(req.query.from) : null;
    const to = req.query.to ? new Date(req.query.to) : null;
    if ((from && !Number.isNaN(from.getTime())) || (to && !Number.isNaN(to.getTime()))) {
      filter.createdAt = {};
      if (from && !Number.isNaN(from.getTime())) filter.createdAt.$gte = from;
      if (to && !Number.isNaN(to.getTime())) filter.createdAt.$lte = to;
    }

    if (search) {
      // Escapes regex metacharacters so a search term like "a.*" is literal text, not a pattern.
      const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const re = new RegExp(escaped, 'i');
      filter.$or = [
        { reason: re },
        { evidence: re },
        { 'alertSnapshot.ruleDescription': re },
        { 'alertSnapshot.label': re },
        { 'alertSnapshot.agent': re },
      ];
    }
    const closures = await AlertClosure.find(filter).sort({ createdAt: -1 }).limit(limit);
    res.json({ closures });
  } catch (err) {
    console.error('[getMyHistory]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

const TRAINING_EXPORT_LIMIT = 5000; // caps a single export the same way HISTORY_LIMIT bounds GET /

function csvEscape(value) {
  const s = value === null || value === undefined ? '' : String(value);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

// GET /api/alerts/training-feedback-export — closed, verdict-tagged alerts as CSV, in the shape
// train.py expects. Manual export -> data/train/ -> rerun train.py, not an automated pipeline.
router.get('/training-feedback-export', protect, adminOnly, async (req, res) => {
  try {
    const closures = await AlertClosure.find({
      verdict: { $in: ['true_positive', 'false_positive', 'benign'] },
      'alertSnapshot.flow': { $exists: true, $ne: null },
    })
      .sort({ createdAt: -1 })
      .limit(TRAINING_EXPORT_LIMIT);

    if (closures.length === 0) {
      return res.status(404).json({ error: 'No verdict-tagged closures with captured flow data to export yet.' });
    }

    // Column order: union of every flow feature key present, sorted for a stable/reproducible CSV.
    const featureKeys = new Set();
    for (const c of closures) {
      const flow = c.alertSnapshot?.flow;
      if (flow) Object.keys(flow).forEach((k) => featureKeys.add(k));
    }
    const columns = [...featureKeys].sort();
    const header = ['label', ...columns];

    const lines = [header.join(',')];
    for (const c of closures) {
      const flow = c.alertSnapshot?.flow;
      if (!flow) continue;
      // A confirmed true positive keeps the model's predicted label; anything else relabels Benign.
      const label = c.verdict === 'true_positive' ? c.alertSnapshot.label || 'Benign' : 'Benign';
      const row = [label, ...columns.map((col) => flow[col] ?? '')];
      lines.push(row.map(csvEscape).join(','));
    }

    await logAudit({
      action: 'export_training_feedback',
      actor: { id: req.user.id, name: req.user.name, email: req.user.email },
      details: `Exported ${lines.length - 1} verdict-tagged rows for training feedback`,
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="medisiem-training-feedback-${new Date().toISOString().slice(0, 10)}.csv"`);
    res.send(lines.join('\n'));
  } catch (err) {
    console.error('[trainingFeedbackExport]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// POST /api/alerts/:id/triage — LLM-generated plain-language triage note.
router.post('/:id/triage', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const configured = await isTriageAssistantConfigured();
    if (!configured) {
      return res.status(409).json({ error: 'AI triage assistant is not configured — add an API key in Settings → Integrations.' });
    }

    const alertId = req.params.id;
    const alert = getBufferedAlerts({ limit: 500 }).find((a) => a.id === alertId);
    if (!alert) {
      return res.status(404).json({ error: 'Alert not found in the current buffer.' });
    }

    const explanation = await generateTriageExplanation(alert);
    res.json({ explanation });
  } catch (err) {
    console.error('[triageAlert]', err);
    res.status(502).json({ error: err.message || 'AI triage assistant request failed.' });
  }
});

// "What else happened on this device recently" — same 2-hour window CaseTable.tsx/
// AlertDetailsModal.tsx use client-side, computed here from the live buffer.
function countRelated(alert) {
  const t = new Date(alert.timestamp).getTime();
  const windowMs = 2 * 60 * 60 * 1000;
  return getBufferedAlerts({ limit: 500 }).filter(
    (a) => a.id !== alert.id && a.agent === alert.agent && Math.abs(new Date(a.timestamp).getTime() - t) <= windowMs
  ).length;
}

// POST /api/alerts/:id/draft-close — AI-drafted verdict + reason + evidence for the Close Case modal.
router.post('/:id/draft-close', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const alertId = req.params.id;
    const alert = getBufferedAlerts({ limit: 500 }).find((a) => a.id === alertId);
    if (!alert) return res.status(404).json({ error: 'Alert not found in the current buffer.' });

    const notes = await AlertNote.find({ alertId }).sort({ createdAt: 1 }).limit(200);
    const draft = await generateCloseDraft(alert, notes, countRelated(alert));
    res.json({ draft });
  } catch (err) {
    console.error('[draftClose]', err);
    res.status(502).json({ error: err.message || 'AI assistant request failed.' });
  }
});

// POST /api/alerts/:id/summarize-notes — "catch me up" for a case with a long note history.
router.post('/:id/summarize-notes', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const alertId = req.params.id;
    const alert = getBufferedAlerts({ limit: 500 }).find((a) => a.id === alertId);
    if (!alert) return res.status(404).json({ error: 'Alert not found in the current buffer.' });

    const notes = await AlertNote.find({ alertId }).sort({ createdAt: 1 }).limit(200);
    if (notes.length === 0) return res.status(400).json({ error: 'No investigation notes to summarize yet.' });

    const summary = await generateCaseSummary(alert, notes);
    res.json({ summary });
  } catch (err) {
    console.error('[summarizeNotes]', err);
    res.status(502).json({ error: err.message || 'AI assistant request failed.' });
  }
});

// POST /api/alerts/parse-query — natural-language search -> AlertsPanel filter shape.
// A fixed literal path, registered alongside /:id/... routes above without collision
// (Express only matches :id patterns against same-shape URLs).
router.post('/parse-query', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const prompt = (req.body.prompt || '').trim();
    if (!prompt) return res.status(400).json({ error: 'A search query is required.' });
    const departments = Array.isArray(req.body.departments) ? req.body.departments.filter((d) => typeof d === 'string') : [];
    const filters = await parseAlertQuery(prompt, departments);
    res.json({ filters });
  } catch (err) {
    console.error('[parseAlertQuery]', err);
    res.status(502).json({ error: err.message || 'AI assistant request failed.' });
  }
});

export default router;
