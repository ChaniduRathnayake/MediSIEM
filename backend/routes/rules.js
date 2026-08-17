import express from 'express';
import { protect, adminOnly } from '../middleware/auth.js';
import DetectionRule from '../models/DetectionRule.js';
import { draftDetectionRule } from '../services/aiAssistantService.js';

const router = express.Router();

// POST /api/rules/draft — plain-English -> structured rule draft (admin reviews/edits before saving).
router.post('/draft', protect, adminOnly, async (req, res) => {
  try {
    const prompt = (req.body.prompt || '').trim();
    if (!prompt) return res.status(400).json({ error: 'A description is required.' });
    const draft = await draftDetectionRule(prompt);
    res.json({ draft });
  } catch (err) {
    console.error('[draftRule]', err);
    res.status(502).json({ error: err.message || 'AI assistant request failed.' });
  }
});

// ─── GET /api/rules  (any authenticated user — Alerts pages need rule names for badges) ──
router.get('/', protect, async (req, res) => {
  try {
    const rules = await DetectionRule.find().sort({ createdAt: -1 });
    res.json({ rules });
  } catch (err) {
    console.error('[getRules]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── POST /api/rules  (admin only) ─────────────────────────────────────────────
router.post('/', protect, adminOnly, async (req, res) => {
  try {
    const { name, description, conditions, enabled } = req.body;
    if (!name || !Array.isArray(conditions) || conditions.length === 0) {
      return res.status(400).json({ error: 'Name and at least one condition are required.' });
    }
    const rule = await DetectionRule.create({
      name,
      description: description || '',
      conditions,
      enabled: enabled ?? true,
      createdBy: { id: req.user.id, name: req.user.name },
    });
    res.status(201).json({ rule });
  } catch (err) {
    console.error('[createRule]', err);
    res.status(400).json({ error: err.message || 'Failed to create rule.' });
  }
});

// ─── PATCH /api/rules/:id  (admin only) ────────────────────────────────────────
router.patch('/:id', protect, adminOnly, async (req, res) => {
  try {
    const { name, description, conditions, enabled } = req.body;
    const update = {};
    if (name !== undefined) update.name = name;
    if (description !== undefined) update.description = description;
    if (conditions !== undefined) update.conditions = conditions;
    if (enabled !== undefined) update.enabled = enabled;

    const rule = await DetectionRule.findByIdAndUpdate(req.params.id, update, { new: true, runValidators: true });
    if (!rule) return res.status(404).json({ error: 'Rule not found.' });
    res.json({ rule });
  } catch (err) {
    console.error('[updateRule]', err);
    res.status(400).json({ error: err.message || 'Failed to update rule.' });
  }
});

// ─── DELETE /api/rules/:id  (admin only) ───────────────────────────────────────
router.delete('/:id', protect, adminOnly, async (req, res) => {
  try {
    const rule = await DetectionRule.findByIdAndDelete(req.params.id);
    if (!rule) return res.status(404).json({ error: 'Rule not found.' });
    res.json({ ok: true });
  } catch (err) {
    console.error('[deleteRule]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── POST /api/rules/seed-samples  (admin only) ────────────────────────────────
// Inserts a fixed set of example rules, skipping any name that already
// exists — safe to click more than once.
const SAMPLE_RULES = [
  {
    name: 'Ransomware signature',
    description: 'Wazuh rule description mentions ransomware.',
    conditions: [{ field: 'ruleDescription', operator: 'contains', value: 'ransomware' }],
  },
  {
    name: 'Brute force login attempt',
    description: 'Wazuh rule description mentions brute force or repeated auth failures.',
    conditions: [{ field: 'ruleDescription', operator: 'contains', value: 'brute force' }],
  },
  {
    name: 'Critical ICU alert',
    description: 'Any alert on an ICU device with CAS ≥ 8.',
    conditions: [
      { field: 'department', operator: 'equals', value: 'ICU' },
      { field: 'CAS', operator: 'gte', value: 8 },
    ],
  },
  {
    name: 'High Clinical Alert Score',
    description: 'Catch-all for anything the CAS model scores as critical.',
    conditions: [{ field: 'CAS', operator: 'gte', value: 8 }],
  },
  {
    name: 'Suspicious network scan',
    description: 'Wazuh rule description mentions a port scan or reconnaissance activity.',
    conditions: [{ field: 'ruleDescription', operator: 'contains', value: 'scan' }],
  },
];

router.post('/seed-samples', protect, adminOnly, async (req, res) => {
  try {
    const existingNames = new Set((await DetectionRule.find({}, 'name')).map((r) => r.name));
    const toInsert = SAMPLE_RULES.filter((r) => !existingNames.has(r.name)).map((r) => ({
      ...r,
      enabled: true,
      createdBy: { id: req.user.id, name: req.user.name },
    }));
    const inserted = toInsert.length ? await DetectionRule.insertMany(toInsert) : [];
    res.json({ inserted: inserted.length, skipped: SAMPLE_RULES.length - inserted.length });
  } catch (err) {
    console.error('[seedSampleRules]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

export default router;
