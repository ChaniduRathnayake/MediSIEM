// Report generation — reads from durable storage (closures/assignments/AlertLog),
// not the in-memory alert buffer, so a report window doesn't under-count evicted alerts.
import express from 'express';
import { protect, allowRoles, adminOnly } from '../middleware/auth.js';
import AlertClosure from '../models/AlertClosure.js';
import AlertAssignment from '../models/AlertAssignment.js';
import AlertLog from '../models/AlertLog.js';
import { generateThreatNarrative, generateComplianceNarrative } from '../services/aiAssistantService.js';

const router = express.Router();

const DEFAULT_WINDOW_DAYS = 30;
const MAX_ROWS = 5000; // caps a user-chosen report window from pulling in an unbounded number of documents

function parseRange(req) {
  const to = req.query.to ? new Date(req.query.to) : new Date();
  const from = req.query.from
    ? new Date(req.query.from)
    : new Date(to.getTime() - DEFAULT_WINDOW_DAYS * 24 * 60 * 60 * 1000);
  return {
    from: Number.isNaN(from.getTime()) ? new Date(to.getTime() - DEFAULT_WINDOW_DAYS * 24 * 60 * 60 * 1000) : from,
    to: Number.isNaN(to.getTime()) ? new Date() : to,
  };
}

// 'all' is silently downgraded to 'mine' for non-admins instead of erroring.
function resolveScope(req) {
  const requested = req.query.scope === 'all' ? 'all' : 'mine';
  return requested === 'all' && req.user.role === 'admin' ? 'all' : 'mine';
}

// GET /api/reports/detection-accuracy?from=&to=&scope=mine|all — verdict breakdown by alert label.
router.get('/detection-accuracy', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const { from, to } = parseRange(req);
    const scope = resolveScope(req);
    const filter = { createdAt: { $gte: from, $lte: to } };
    if (scope === 'mine') filter['closedBy.id'] = req.user.id;

    const closures = await AlertClosure.find(filter).limit(MAX_ROWS);

    const byLabel = new Map();
    const overall = { true_positive: 0, false_positive: 0, benign: 0, uncertain: 0, unset: 0 };
    for (const c of closures) {
      const label = c.alertSnapshot?.label || 'Unknown';
      const verdict = c.verdict ?? 'unset';
      overall[verdict] += 1;
      if (!byLabel.has(label)) {
        byLabel.set(label, { label, total: 0, true_positive: 0, false_positive: 0, benign: 0, uncertain: 0, unset: 0 });
      }
      const row = byLabel.get(label);
      row.total += 1;
      row[verdict] += 1;
    }

    const rows = [...byLabel.values()]
      .map((r) => ({
        ...r,
        falsePositiveRate:
          r.true_positive + r.false_positive > 0 ? Math.round((r.false_positive / (r.true_positive + r.false_positive)) * 1000) / 10 : null,
      }))
      .sort((a, b) => b.total - a.total);

    res.json({ from, to, scope, totalClosed: closures.length, overall, byLabel: rows });
  } catch (err) {
    console.error('[detectionAccuracyReport]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// GET /api/reports/escalation-backlog?from=&to=&scope=mine|all — how long CAS-critical
// alerts sat before being claimed. Approximate: AlertAssignment is current-state only,
// so a reassigned case loses its original claim timing.
router.get('/escalation-backlog', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const { from, to } = parseRange(req);
    const scope = resolveScope(req);
    const filter = { createdAt: { $gte: from, $lte: to }, 'alertSnapshot.CAS': { $gte: 8 } };
    if (scope === 'mine') filter['analyst.id'] = req.user.id;

    const assignments = await AlertAssignment.find(filter).limit(MAX_ROWS);

    const rows = [];
    let sum = 0;
    for (const a of assignments) {
      const detectedAt = a.alertSnapshot?.timestamp ? new Date(a.alertSnapshot.timestamp) : null;
      if (!detectedAt) continue;
      const minutesToClaim = Math.round(((a.createdAt.getTime() - detectedAt.getTime()) / 60000) * 10) / 10;
      if (minutesToClaim < 0) continue; // clock skew/bad snapshot — skip rather than show a negative
      sum += minutesToClaim;
      rows.push({
        alertId: a.alertId,
        label: a.alertSnapshot?.label || a.alertSnapshot?.ruleDescription || 'Unknown',
        agent: a.alertSnapshot?.agent ?? null,
        department: a.alertSnapshot?.department ?? null,
        CAS: a.alertSnapshot?.CAS ?? null,
        detectedAt,
        claimedAt: a.createdAt,
        minutesToClaim,
        claimedBy: a.analyst?.name ?? null,
      });
    }
    rows.sort((x, y) => y.minutesToClaim - x.minutesToClaim);

    res.json({
      from, to, scope,
      count: rows.length,
      avgMinutesToClaim: rows.length > 0 ? Math.round((sum / rows.length) * 10) / 10 : null,
      rows: rows.slice(0, 200),
    });
  } catch (err) {
    console.error('[escalationBacklogReport]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// GET /api/reports/off-hours?from=&to= — alerts before 06:00 or at/after 22:00 server-local
// (same night-shift window caapService.js's TC scoring uses). Filtered in app code, not a
// Mongo $hour aggregation, since $hour defaults to UTC and would disagree with getHours().
router.get('/off-hours', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const { from, to } = parseRange(req);
    const logs = await AlertLog.find({ timestamp: { $gte: from, $lte: to } }).sort({ timestamp: -1 }).limit(MAX_ROWS);

    const isOffHours = (d) => { const h = d.getHours(); return h < 6 || h >= 22; };
    const offHours = logs.filter((l) => isOffHours(new Date(l.timestamp)));

    const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const l of offHours) if (l.severity) bySeverity[l.severity] = (bySeverity[l.severity] ?? 0) + 1;

    res.json({
      from, to,
      totalInRange: logs.length,
      offHoursCount: offHours.length,
      offHoursPercentage: logs.length > 0 ? Math.round((offHours.length / logs.length) * 1000) / 10 : 0,
      bySeverity,
      rows: offHours.slice(0, 200).map((l) => ({
        alertId: l.alertId, timestamp: l.timestamp, severity: l.severity, CAS: l.CAS,
        agent: l.agent, department: l.department, label: l.label || l.ruleDescription,
      })),
    });
  } catch (err) {
    console.error('[offHoursReport]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// GET /api/reports/device-risk?from=&to= — per-device alert volume/severity over the window.
router.get('/device-risk', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const { from, to } = parseRange(req);
    const rows = await AlertLog.aggregate([
      { $match: { timestamp: { $gte: from, $lte: to }, agent: { $ne: null } } },
      {
        $group: {
          _id: '$agent',
          alertCount: { $sum: 1 },
          avgCAS: { $avg: '$CAS' },
          criticalCount: { $sum: { $cond: [{ $gte: ['$CAS', 8] }, 1, 0] } },
          department: { $first: '$department' },
          deviceType: { $first: '$deviceType' },
          deviceCriticality: { $first: '$deviceCriticality' },
        },
      },
      { $sort: { alertCount: -1 } },
      { $limit: 50 },
    ]);

    res.json({
      from, to,
      devices: rows.map((r) => ({
        agent: r._id,
        department: r.department,
        deviceType: r.deviceType,
        deviceCriticality: r.deviceCriticality,
        alertCount: r.alertCount,
        avgCAS: Math.round((r.avgCAS ?? 0) * 10) / 10,
        criticalCount: r.criticalCount,
      })),
    });
  } catch (err) {
    console.error('[deviceRiskReport]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// GET /api/reports/threat-summary?from=&to= — volume by severity/department, top labels, busiest devices.
router.get('/threat-summary', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const { from, to } = parseRange(req);
    const match = { $match: { timestamp: { $gte: from, $lte: to } } };

    const [total, bySeverity, byDepartment, topLabels, topDevices, byAction] = await Promise.all([
      AlertLog.countDocuments({ timestamp: { $gte: from, $lte: to } }),
      AlertLog.aggregate([match, { $group: { _id: '$severity', count: { $sum: 1 } } }]),
      AlertLog.aggregate([match, { $match: { department: { $ne: null } } }, { $group: { _id: '$department', count: { $sum: 1 } } }, { $sort: { count: -1 } }]),
      AlertLog.aggregate([match, { $match: { label: { $ne: null } } }, { $group: { _id: '$label', count: { $sum: 1 } } }, { $sort: { count: -1 } }, { $limit: 10 }]),
      AlertLog.aggregate([match, { $match: { agent: { $ne: null } } }, { $group: { _id: '$agent', count: { $sum: 1 } } }, { $sort: { count: -1 } }, { $limit: 10 }]),
      AlertLog.aggregate([match, { $match: { action: { $ne: null } } }, { $group: { _id: '$action', count: { $sum: 1 } } }]),
    ]);

    const toRecord = (buckets) => buckets.reduce((acc, b) => ({ ...acc, [b._id]: b.count }), {});

    res.json({
      from, to,
      totalAlerts: total,
      bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, ...toRecord(bySeverity) },
      byAction: { Immediate: 0, Investigate: 0, Monitor: 0, ...toRecord(byAction) },
      byDepartment: byDepartment.map((b) => ({ department: b._id, count: b.count })),
      topLabels: topLabels.map((b) => ({ label: b._id, count: b.count })),
      topDevices: topDevices.map((b) => ({ agent: b._id, count: b.count })),
    });
  } catch (err) {
    console.error('[threatSummaryReport]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// POST /api/reports/threat-summary/narrative — turns an already-fetched Threat Summary
// report (sent in the body, not re-queried) into a short plain-English narrative.
router.post('/threat-summary/narrative', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const narrative = await generateThreatNarrative(req.body.summary ?? {});
    res.json({ narrative });
  } catch (err) {
    console.error('[threatSummaryNarrative]', err);
    res.status(502).json({ error: err.message || 'AI assistant request failed.' });
  }
});

// POST /api/reports/compliance-narrative — same pattern for the Compliance Evidence report,
// whose data lives in the Wazuh Indexer and is already in hand client-side.
router.post('/compliance-narrative', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const framework = req.body.framework === 'gdpr' ? 'gdpr' : 'hipaa';
    const narrative = await generateComplianceNarrative(req.body.summary ?? {}, framework);
    res.json({ narrative });
  } catch (err) {
    console.error('[complianceNarrative]', err);
    res.status(502).json({ error: err.message || 'AI assistant request failed.' });
  }
});

// GET /api/reports/trending-devices — devices whose CAS is climbing within the last hour
// but haven't crossed CRITICAL yet, so a quietly-escalating pattern doesn't stay invisible
// until an alert finally crosses the threshold on its own.
const TREND_WINDOW_MS = 60 * 60 * 1000;
router.get('/trending-devices', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const since = new Date(Date.now() - TREND_WINDOW_MS);
    const logs = await AlertLog.find({ timestamp: { $gte: since }, agent: { $ne: null } }).sort({ timestamp: 1 }).limit(MAX_ROWS);

    const byAgent = new Map();
    for (const l of logs) {
      if (!byAgent.has(l.agent)) byAgent.set(l.agent, []);
      byAgent.get(l.agent).push(l);
    }

    const midpoint = Date.now() - TREND_WINDOW_MS / 2;
    const trending = [];
    for (const [agent, rows] of byAgent) {
      const maxCas = Math.max(...rows.map((r) => r.CAS ?? 0));
      if (maxCas >= 8) continue; // already visibly CRITICAL — this is for the quiet climbers
      const earlier = rows.filter((r) => new Date(r.timestamp).getTime() < midpoint);
      const recent = rows.filter((r) => new Date(r.timestamp).getTime() >= midpoint);
      if (recent.length < 2) continue; // not enough signal in the recent half to call it a trend
      const avg = (arr) => arr.reduce((s, r) => s + (r.CAS ?? 0), 0) / arr.length;
      const earlierAvg = earlier.length ? avg(earlier) : avg(recent); // no earlier activity -> compare against itself, i.e. skip
      const recentAvg = avg(recent);
      if (earlier.length > 0 && recentAvg - earlierAvg >= 1.5) {
        trending.push({
          agent, department: rows[0].department, deviceType: rows[0].deviceType, deviceCriticality: rows[0].deviceCriticality,
          alertCount: rows.length, earlierAvgCas: Math.round(earlierAvg * 10) / 10, recentAvgCas: Math.round(recentAvg * 10) / 10, maxCas,
        });
      }
    }
    trending.sort((a, b) => (b.recentAvgCas - b.earlierAvgCas) - (a.recentAvgCas - a.earlierAvgCas));

    res.json({ windowMinutes: TREND_WINDOW_MS / 60000, devices: trending.slice(0, 20) });
  } catch (err) {
    console.error('[trendingDevicesReport]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// GET /api/reports/rule-health — per-DetectionRule false-positive rate from real analyst
// verdicts, using AlertClosure.alertSnapshot.matchedRules (only populated for cases closed
// after that field was added — older closures won't have it, so counts start from then).
router.get('/rule-health', protect, adminOnly, async (req, res) => {
  try {
    const { from, to } = parseRange(req);
    const closures = await AlertClosure.find({
      createdAt: { $gte: from, $lte: to },
      'alertSnapshot.matchedRules.0': { $exists: true },
    }).limit(MAX_ROWS);

    const byRule = new Map();
    for (const c of closures) {
      for (const r of c.alertSnapshot.matchedRules ?? []) {
        if (!byRule.has(r.name)) byRule.set(r.name, { rule: r.name, total: 0, false_positive: 0, true_positive: 0, benign: 0, uncertain: 0, unset: 0 });
        const row = byRule.get(r.name);
        row.total += 1;
        row[c.verdict ?? 'unset'] += 1;
      }
    }

    const rows = [...byRule.values()]
      .map((r) => ({
        ...r,
        falsePositiveRate: r.true_positive + r.false_positive > 0 ? Math.round((r.false_positive / (r.true_positive + r.false_positive)) * 1000) / 10 : null,
      }))
      .filter((r) => r.total >= 5) // enough closures to say something meaningful, not noise from 1-2 cases
      .sort((a, b) => (b.falsePositiveRate ?? 0) - (a.falsePositiveRate ?? 0));

    res.json({ from, to, rules: rows });
  } catch (err) {
    console.error('[ruleHealthReport]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

export default router;
