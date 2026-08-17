// Admin Settings panel for managing custom detection rules (AND-combined
// field/operator/value conditions) — CRUD only, evaluated server-side in
// backend/services/alertPipeline.js.
import React, { useEffect, useState } from 'react';
import { Plus, Pencil, Trash2, Loader2, AlertCircle, X, Sparkles, Zap, ShieldAlert, Wand2 } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import {
  apiGetRules, apiCreateRule, apiUpdateRule, apiDeleteRule, apiSeedSampleRules, apiDraftRule,
  RULE_FIELDS, NUMERIC_RULE_FIELDS,
} from '../../services/rulesApi';
import type { DetectionRule, RuleCondition, RuleField, RuleOperator } from '../../services/rulesApi';
import { apiGetRuleHealth } from '../../services/reportsApi';
import type { RuleHealthRow } from '../../services/reportsApi';

const FIELD_LABELS: Record<RuleField, string> = {
  ruleDescription: 'Rule description',
  ruleLevel: 'Wazuh rule level',
  agent: 'Device / agent',
  department: 'Department',
  CAS: 'Clinical Alert Score (CAS)',
  label: 'ML classification label',
  action: 'Recommended action',
  cluster: 'Cluster',
  deviceType: 'Device type',
  deviceCriticality: 'Device criticality',
};

const OPERATOR_LABELS: Record<RuleOperator, string> = {
  contains: 'contains',
  equals: 'equals',
  gte: '≥',
  lte: '≤',
  gt: '>',
  lt: '<',
};

const operatorsFor = (field: RuleField): RuleOperator[] =>
  NUMERIC_RULE_FIELDS.includes(field) ? ['gte', 'lte', 'gt', 'lt', 'equals'] : ['contains', 'equals'];

const conditionSummary = (conditions: RuleCondition[]): string =>
  conditions.map((c) => `${FIELD_LABELS[c.field]} ${OPERATOR_LABELS[c.operator]} "${c.value}"`).join('  AND  ');

// ─── Create / edit modal ────────────────────────────────────────────────────────
const RuleFormModal: React.FC<{
  mode: 'create' | 'edit';
  initial?: DetectionRule;
  token: string | null;
  onClose: () => void;
  onSaved: (rule: DetectionRule) => void;
}> = ({ mode, initial, token, onClose, onSaved }) => {
  const [name, setName] = useState(initial?.name ?? '');
  const [description, setDescription] = useState(initial?.description ?? '');
  const [conditions, setConditions] = useState<RuleCondition[]>(
    initial?.conditions ?? [{ field: 'ruleDescription', operator: 'contains', value: '' }]
  );
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [aiPrompt, setAiPrompt] = useState('');
  const [aiDrafting, setAiDrafting] = useState(false);
  const [aiError, setAiError] = useState('');

  const draftWithAi = async () => {
    if (!token || !aiPrompt.trim()) return;
    setAiDrafting(true);
    setAiError('');
    try {
      const { draft } = await apiDraftRule(token, aiPrompt.trim());
      setName(draft.name);
      setDescription(draft.description);
      setConditions(draft.conditions);
    } catch (err: unknown) {
      setAiError(err instanceof Error ? err.message : 'AI assistant request failed.');
    } finally {
      setAiDrafting(false);
    }
  };

  const updateCondition = (i: number, patch: Partial<RuleCondition>) => {
    setConditions((prev) => prev.map((c, idx) => {
      if (idx !== i) return c;
      const next = { ...c, ...patch };
      // Switching field can invalidate the current operator (e.g. numeric → contains) — reset to a valid one.
      if (patch.field && !operatorsFor(patch.field).includes(next.operator)) {
        next.operator = operatorsFor(patch.field)[0];
      }
      return next;
    }));
  };
  const addCondition = () => setConditions((prev) => [...prev, { field: 'ruleDescription', operator: 'contains', value: '' }]);
  const removeCondition = (i: number) => setConditions((prev) => prev.filter((_, idx) => idx !== i));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) { setError('Name is required.'); return; }
    if (conditions.some((c) => c.value === '')) { setError('Every condition needs a value.'); return; }
    if (!token) { setError('Your session has expired. Please sign in again.'); return; }

    setSubmitting(true);
    setError('');
    try {
      if (mode === 'create') {
        const { rule } = await apiCreateRule(token, { name: name.trim(), description: description.trim(), conditions });
        onSaved(rule);
      } else {
        const { rule } = await apiUpdateRule(token, initial!.id, { name: name.trim(), description: description.trim(), conditions });
        onSaved(rule);
      }
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : `Failed to ${mode === 'create' ? 'create' : 'update'} rule.`);
    } finally {
      setSubmitting(false);
    }
  };

  const inputCls =
    'w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white ' +
    'placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-all';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex-shrink-0">
          <h2 className="text-sm font-bold text-slate-900 dark:text-white">{mode === 'create' ? 'New Detection Rule' : 'Edit Detection Rule'}</h2>
          <button onClick={onClose} aria-label="Close" className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="px-6 py-5 space-y-4 overflow-y-auto">
          {error && (
            <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 dark:text-red-400 text-xs">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {mode === 'create' && (
            <div className="p-3 rounded-lg bg-violet-500/5 border border-violet-500/20 space-y-2">
              <label className="text-xs font-medium text-violet-700 dark:text-violet-300 flex items-center gap-1.5">
                <Wand2 className="w-3.5 h-3.5" /> Draft with AI (optional)
              </label>
              <div className="flex items-center gap-2">
                <input
                  value={aiPrompt}
                  onChange={(e) => setAiPrompt(e.target.value)}
                  placeholder="e.g. Flag any critical-CAS alert on an ICU device"
                  className="flex-1 min-w-0 px-2.5 py-1.5 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg text-xs text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:border-violet-500/60"
                />
                <button
                  type="button"
                  onClick={draftWithAi}
                  disabled={aiDrafting || !aiPrompt.trim()}
                  className="flex-shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-violet-500 hover:bg-violet-400 disabled:opacity-50 disabled:cursor-not-allowed text-white transition-colors"
                >
                  {aiDrafting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Wand2 className="w-3.5 h-3.5" />} Draft
                </button>
              </div>
              {aiError && <p className="text-xs text-red-500 dark:text-red-400">{aiError}</p>}
              <p className="text-[11px] text-slate-400 dark:text-slate-500">Fills in the fields below — review and edit before saving, same as any other draft.</p>
            </div>
          )}

          <div>
            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Rule name</label>
            <input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Ransomware signature" />
          </div>

          <div>
            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Description (optional)</label>
            <input className={inputCls} value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What this rule is looking for" />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-medium text-slate-500 dark:text-slate-400">
                Conditions <span className="text-slate-400 dark:text-slate-600">— all must match</span>
              </label>
              <button type="button" onClick={addCondition} className="flex items-center gap-1 text-xs text-cyan-500 dark:text-cyan-400 hover:text-cyan-600 dark:hover:text-cyan-300 font-medium">
                <Plus className="w-3.5 h-3.5" /> Add condition
              </button>
            </div>
            <div className="space-y-2">
              {conditions.map((c, i) => (
                <div key={i} className="flex items-center gap-2">
                  <select
                    value={c.field}
                    onChange={(e) => updateCondition(i, { field: e.target.value as RuleField })}
                    className="flex-[1.4] px-2 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60"
                  >
                    {RULE_FIELDS.map((f) => <option key={f} value={f}>{FIELD_LABELS[f]}</option>)}
                  </select>
                  <select
                    value={c.operator}
                    onChange={(e) => updateCondition(i, { operator: e.target.value as RuleOperator })}
                    className="flex-shrink-0 w-20 px-2 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60"
                  >
                    {operatorsFor(c.field).map((op) => <option key={op} value={op}>{OPERATOR_LABELS[op]}</option>)}
                  </select>
                  <input
                    value={c.value}
                    onChange={(e) => updateCondition(i, { value: e.target.value })}
                    placeholder="value"
                    className="flex-1 min-w-0 px-2 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60"
                  />
                  {conditions.length > 1 && (
                    <button type="button" onClick={() => removeCondition(i)} className="flex-shrink-0 p-2 text-slate-400 dark:text-slate-500 hover:text-red-500 dark:hover:text-red-400 transition-colors">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>

          {conditions.some((c) => c.value !== '') && (
            <div className="p-3 rounded-lg bg-cyan-500/5 border border-cyan-500/20">
              <p className="text-xs text-cyan-700 dark:text-cyan-300">
                Preview: <span className="font-mono">{conditionSummary(conditions.filter((c) => c.value !== ''))}</span>
              </p>
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full flex items-center justify-center gap-2 py-2.5 mt-2 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 font-semibold text-sm rounded-lg transition-colors"
          >
            {submitting ? (
              <><Loader2 className="w-4 h-4 animate-spin" /> {mode === 'create' ? 'Creating…' : 'Saving…'}</>
            ) : mode === 'create' ? (
              <><Plus className="w-4 h-4" /> Create Rule</>
            ) : (
              <><Pencil className="w-4 h-4" /> Save Changes</>
            )}
          </button>
        </form>
      </div>
    </div>
  );
};

// ─── Delete confirmation ────────────────────────────────────────────────────────
const ConfirmDeleteRuleModal: React.FC<{
  rule: DetectionRule;
  token: string | null;
  onClose: () => void;
  onDeleted: (id: string) => void;
}> = ({ rule, token, onClose, onDeleted }) => {
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleDelete = async () => {
    if (!token) { setError('Your session has expired. Please sign in again.'); return; }
    setSubmitting(true);
    setError('');
    try {
      await apiDeleteRule(token, rule.id);
      onDeleted(rule.id);
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete rule.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-sm rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800">
          <h2 className="text-sm font-bold text-slate-900 dark:text-white">Delete Rule</h2>
          <button onClick={onClose} aria-label="Close" className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="px-6 py-5 space-y-4">
          {error && (
            <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 dark:text-red-400 text-xs">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}
          <p className="text-sm text-slate-700 dark:text-slate-300">
            Permanently delete <span className="font-semibold text-slate-900 dark:text-white">{rule.name}</span>? Alerts already tagged with it keep the tag; new alerts will stop matching it.
          </p>
          <div className="flex gap-2">
            <button onClick={onClose} className="flex-1 py-2.5 rounded-lg text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors">
              Cancel
            </button>
            <button
              onClick={handleDelete}
              disabled={submitting}
              className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold text-white bg-red-500 hover:bg-red-400 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
            >
              {submitting ? <><Loader2 className="w-4 h-4 animate-spin" /> Deleting…</> : 'Delete'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// ─── Main panel ─────────────────────────────────────────────────────────────────
type ModalState = { mode: 'create' } | { mode: 'edit'; rule: DetectionRule } | null;

const RulesPanel: React.FC = () => {
  const { token } = useAuth();
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [modal, setModal] = useState<ModalState>(null);
  const [deleteTarget, setDeleteTarget] = useState<DetectionRule | null>(null);
  const [seeding, setSeeding] = useState(false);
  const [seedMessage, setSeedMessage] = useState('');
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [unhealthyRules, setUnhealthyRules] = useState<RuleHealthRow[]>([]);

  const loadRules = () => {
    if (!token) { setError('Your session has expired. Please sign in again.'); setLoading(false); return; }
    setLoading(true);
    setError('');
    apiGetRules(token)
      .then((data) => setRules(data.rules))
      .catch((err: unknown) => setError(err instanceof Error ? err.message : 'Failed to load rules.'))
      .finally(() => setLoading(false));
  };

  useEffect(loadRules, [token]);

  // False-positive-rate nudge — high-FP rules are worth a look, not an alarm.
  useEffect(() => {
    if (!token) return;
    apiGetRuleHealth(token, {})
      .then((data) => setUnhealthyRules(data.rules.filter((r) => (r.falsePositiveRate ?? 0) >= 50)))
      .catch(() => {});
  }, [token]);

  const handleToggle = async (rule: DetectionRule) => {
    if (!token) return;
    setTogglingId(rule.id);
    try {
      const { rule: updated } = await apiUpdateRule(token, rule.id, { enabled: !rule.enabled });
      setRules((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
    } catch (err) {
      console.error('Failed to toggle rule', err);
    } finally {
      setTogglingId(null);
    }
  };

  const handleSeed = async () => {
    if (!token) return;
    setSeeding(true);
    setSeedMessage('');
    try {
      const { inserted, skipped } = await apiSeedSampleRules(token);
      setSeedMessage(inserted > 0 ? `Added ${inserted} sample rule${inserted === 1 ? '' : 's'}${skipped ? ` (${skipped} already existed)` : ''}.` : 'All sample rules already exist.');
      loadRules();
    } catch (err: unknown) {
      setSeedMessage(err instanceof Error ? err.message : 'Failed to load sample rules.');
    } finally {
      setSeeding(false);
    }
  };

  return (
    <div className="p-5 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Detection Rules</h2>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
            Custom AND-combined field rules, evaluated against every alert alongside the ML pipeline
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleSeed}
            disabled={seeding}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white text-sm transition-colors disabled:opacity-60"
          >
            {seeding ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
            Load sample rules
          </button>
          <button
            onClick={() => setModal({ mode: 'create' })}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-sm font-semibold transition-colors"
          >
            <Plus className="w-4 h-4" /> New Rule
          </button>
        </div>
      </div>

      {seedMessage && (
        <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-700 dark:text-cyan-300 text-xs">
          <Sparkles className="w-3.5 h-3.5 flex-shrink-0" /> {seedMessage}
        </div>
      )}

      {unhealthyRules.length > 0 && (
        <div className="flex items-start gap-2 px-4 py-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-700 dark:text-amber-400 text-xs">
          <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
          <span>
            {unhealthyRules.length} rule{unhealthyRules.length === 1 ? ' has' : 's have'} a false-positive rate of 50%+ from real analyst verdicts (last 30 days): {unhealthyRules.map((r) => `${r.rule} (${r.falsePositiveRate}%)`).join(', ')}. Worth a second look.
          </span>
        </div>
      )}

      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center gap-2 py-14 text-slate-500 text-sm">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading rules…
          </div>
        ) : error ? (
          <div className="flex items-center gap-2 px-5 py-6 text-red-500 dark:text-red-400 text-sm">
            <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
          </div>
        ) : rules.length === 0 ? (
          <div className="py-14 text-center">
            <ShieldAlert className="w-8 h-8 text-slate-300 dark:text-slate-700 mx-auto mb-3" />
            <p className="text-sm text-slate-500">No detection rules yet.</p>
            <p className="text-xs text-slate-400 dark:text-slate-600 mt-1">Create one, or load the sample set to get started.</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                <th className="py-2.5 px-5 text-left">Rule</th>
                <th className="py-2.5 px-5 text-left">Conditions</th>
                <th className="py-2.5 px-5 text-left">Status</th>
                <th className="py-2.5 px-5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id} className="border-b border-slate-100 dark:border-slate-800/60 last:border-0 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-5 align-top">
                    <p className="text-sm text-slate-900 dark:text-white font-medium">{rule.name}</p>
                    {rule.description && <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">{rule.description}</p>}
                  </td>
                  <td className="py-3 px-5 align-top text-xs text-slate-500 dark:text-slate-400 font-mono max-w-md">
                    {conditionSummary(rule.conditions)}
                  </td>
                  <td className="py-3 px-5 align-top">
                    <button
                      onClick={() => handleToggle(rule)}
                      disabled={togglingId === rule.id}
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-medium transition-colors disabled:opacity-50 ${
                        rule.enabled
                          ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-600 dark:text-emerald-400'
                          : 'bg-slate-100 dark:bg-slate-800 border-slate-300 dark:border-slate-700 text-slate-400 dark:text-slate-500'
                      }`}
                    >
                      <Zap className="w-3 h-3" /> {rule.enabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </td>
                  <td className="py-3 px-5 align-top text-right">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => setModal({ mode: 'edit', rule })}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-500 dark:text-slate-400 hover:text-cyan-500 dark:hover:text-cyan-400 hover:bg-cyan-500/10 transition-colors"
                      >
                        <Pencil className="w-3.5 h-3.5" /> Edit
                      </button>
                      <button
                        onClick={() => setDeleteTarget(rule)}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-500 dark:text-slate-400 hover:text-red-500 dark:hover:text-red-400 hover:bg-red-500/10 transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" /> Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {modal && (
        <RuleFormModal
          mode={modal.mode}
          initial={modal.mode === 'edit' ? modal.rule : undefined}
          token={token}
          onClose={() => setModal(null)}
          onSaved={(r) =>
            setRules((prev) => (modal.mode === 'create' ? [r, ...prev] : prev.map((existing) => (existing.id === r.id ? r : existing))))
          }
        />
      )}

      {deleteTarget && (
        <ConfirmDeleteRuleModal
          rule={deleteTarget}
          token={token}
          onClose={() => setDeleteTarget(null)}
          onDeleted={(id) => setRules((prev) => prev.filter((r) => r.id !== id))}
        />
      )}
    </div>
  );
};

export default RulesPanel;
