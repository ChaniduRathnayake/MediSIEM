// Admin panel for the CAS scoring weight vector — previously 5 hardcoded
// number literals duplicated across ai_server/src/app.py, cas_engine.py, and
// caapService.js. Now sourced from shared/cas_config.json by default, with
// optional per-scenario overrides an admin can tune here, live, with no
// redeploy — see backend/services/caapService.js's resolveCasWeights().
import React, { useEffect, useState } from 'react';
import { SlidersHorizontal, Loader2, AlertCircle, CheckCircle2, RotateCcw } from 'lucide-react';
import { apiGetSettings, apiUpdateSettings } from '../../services/settingsApi';
import type { SystemSettings, SystemSettingsUpdate, CasWeightVector } from '../../services/settingsApi';

const DIMENSIONS: { key: keyof CasWeightVector; label: string; hint: string; badgeClass: string }[] = [
  { key: 'CC', label: 'Clinical Criticality', hint: 'How life-critical the device is (device profile / admin-set criticality)', badgeClass: 'bg-blue-500/15 text-blue-600 dark:text-blue-400' },
  { key: 'TR', label: 'Threat Risk', hint: 'Random Forest classification confidence', badgeClass: 'bg-red-500/15 text-red-600 dark:text-red-400' },
  { key: 'TS', label: 'Time Sensitivity', hint: 'Isolation Forest anomaly signal + time of day', badgeClass: 'bg-amber-500/15 text-amber-600 dark:text-amber-400' },
  { key: 'AE', label: 'Active Exploitation', hint: 'Attack-type base severity + known-exploited CVE boost', badgeClass: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400' },
  { key: 'TC', label: 'Temporal Context', hint: 'Hospital shift — staff availability', badgeClass: 'bg-purple-500/15 text-purple-600 dark:text-purple-400' },
];

const PROFILE_TABS: { key: string; label: string }[] = [
  { key: 'default', label: 'Default (AHP baseline)' },
  { key: 'icu_critical_care', label: 'ICU / Critical Care' },
  { key: 'general_ward_admin', label: 'General Ward / Admin' },
  { key: 'hospital_wide_mixed', label: 'Hospital-Wide Mixed' },
];

// Purely illustrative example raw dimension scores (1-10 scale, matching
// app.py's live convention) for the live preview below — doesn't affect what
// gets saved, just shows how a weight change would move a realistic alert.
const PREVIEW_EXAMPLES: Record<string, { raw: CasWeightVector; label: string }> = {
  default: { raw: { TR: 9, CC: 10, TS: 10, AE: 8, TC: 10 }, label: 'ICU Ventilator + ARP Spoofing + Night shift' },
  icu_critical_care: { raw: { TR: 9, CC: 10, TS: 10, AE: 8, TC: 10 }, label: 'ICU Ventilator + ARP Spoofing + Night shift' },
  general_ward_admin: { raw: { TR: 6, CC: 4, TS: 4, AE: 4, TC: 2 }, label: 'Admin Workstation + Recon + Day shift' },
  hospital_wide_mixed: { raw: { TR: 7, CC: 6, TS: 6, AE: 6, TC: 6 }, label: 'Mixed-severity blended example' },
};

function sumWeights(w: CasWeightVector): number {
  return w.TR + w.CC + w.TS + w.AE + w.TC;
}
function isValidSum(w: CasWeightVector): boolean {
  return Math.abs(sumWeights(w) - 1) <= 0.01;
}
function computeCas(raw: CasWeightVector, w: CasWeightVector): number {
  return raw.TR * w.TR + raw.CC * w.CC + raw.TS * w.TS + raw.AE * w.AE + raw.TC * w.TC;
}
function actionFor(cas: number): 'Immediate' | 'Investigate' | 'Monitor' {
  return cas >= 8 ? 'Immediate' : cas >= 5 ? 'Investigate' : 'Monitor';
}
const ACTION_BADGE_CLASS: Record<string, string> = {
  Immediate: 'bg-red-500/15 text-red-500 dark:text-red-400',
  Investigate: 'bg-amber-500/15 text-amber-600 dark:text-amber-400',
  Monitor: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400',
};

type EditState = { vector: CasWeightVector } | { reset: true };

const CasWeightsSettingsPanel: React.FC<{ token: string | null }> = ({ token }) => {
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [activeProfile, setActiveProfile] = useState<string>('default');
  const [edits, setEdits] = useState<Record<string, EditState>>({});

  const load = () => {
    if (!token) { setError('Your session has expired. Please sign in again.'); setLoading(false); return; }
    setLoading(true);
    apiGetSettings(token)
      .then(({ settings: s }) => setSettings(s))
      .catch((err: unknown) => setError(err instanceof Error ? err.message : 'Failed to load settings.'))
      .finally(() => setLoading(false));
  };
  useEffect(load, [token]); // eslint-disable-line react-hooks/exhaustive-deps

  if (loading) {
    return (
      <div className="flex items-center justify-center gap-2 py-14 text-slate-500 text-sm">
        <Loader2 className="w-4 h-4 animate-spin" /> Loading CAS weights…
      </div>
    );
  }
  if (error && !settings) {
    return (
      <div className="flex items-center gap-2 px-5 py-6 text-red-500 dark:text-red-400 text-sm">
        <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
      </div>
    );
  }
  if (!settings) return null;

  const builtInFor = (profileKey: string): CasWeightVector =>
    profileKey === 'default' ? settings.casWeights.builtInDefault : (settings.casWeights.builtInScenarioProfiles[profileKey] ?? settings.casWeights.builtInDefault);

  const storedOverrideFor = (profileKey: string): CasWeightVector | null =>
    profileKey === 'default' ? settings.casWeights.default : (settings.casWeights.scenarios[profileKey] ?? null);

  const effectiveFor = (profileKey: string): CasWeightVector => {
    const edit = edits[profileKey];
    if (edit && 'vector' in edit) return edit.vector;
    if (edit && 'reset' in edit) return builtInFor(profileKey);
    return storedOverrideFor(profileKey) ?? builtInFor(profileKey);
  };

  const isCustomizedNow = (profileKey: string): boolean => {
    const edit = edits[profileKey];
    if (edit && 'reset' in edit) return false;
    if (edit && 'vector' in edit) return true;
    return storedOverrideFor(profileKey) !== null;
  };

  const current = effectiveFor(activeProfile);
  const total = sumWeights(current);
  const valid = isValidSum(current);

  const updateDim = (key: keyof CasWeightVector, value: number) => {
    setEdits((prev) => ({ ...prev, [activeProfile]: { vector: { ...effectiveFor(activeProfile), [key]: value } } }));
  };

  const resetActive = () => {
    setEdits((prev) => ({ ...prev, [activeProfile]: { reset: true } }));
  };

  const anyInvalidEdit = Object.entries(edits).some(([, e]) => 'vector' in e && !isValidSum(e.vector));
  const hasEdits = Object.keys(edits).length > 0;

  const handleSave = async () => {
    if (!token) return;
    setSaving(true);
    setError('');
    setSaved(false);
    try {
      const payload: SystemSettingsUpdate = { casWeights: {} };
      const defaultEdit = edits.default;
      if (defaultEdit) {
        payload.casWeights!.default = 'reset' in defaultEdit ? null : defaultEdit.vector;
      }
      const scenarioEntries = Object.entries(edits).filter(([k]) => k !== 'default');
      if (scenarioEntries.length) {
        payload.casWeights!.scenarios = {};
        for (const [key, edit] of scenarioEntries) {
          payload.casWeights!.scenarios![key] = 'reset' in edit ? null : edit.vector;
        }
      }
      const { settings: updated } = await apiUpdateSettings(token, payload);
      setSettings(updated);
      setEdits({});
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to save CAS weights.');
    } finally {
      setSaving(false);
    }
  };

  const example = PREVIEW_EXAMPLES[activeProfile] ?? PREVIEW_EXAMPLES.default;
  const previewCas = Math.round(computeCas(example.raw, current) * 10) / 10;
  const previewAction = actionFor(previewCas);

  return (
    <div className="p-5 space-y-5 max-w-3xl">
      <div>
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
          <SlidersHorizontal className="w-4.5 h-4.5 text-cyan-500" /> CAS Weights
        </h2>
        <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
          The relative importance of each dimension in the Clinical Alert Score. The Default profile is the
          AHP-derived, standards-justified vector documented in the CAS Weight Justification page — every scenario
          below starts as an identical copy of it. Alerts pick a profile automatically from the device's department
          (see cas_config.py's resolve_scenario_key) unless overridden here.
        </p>
      </div>

      {error && (
        <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 dark:text-red-400 text-xs">
          <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" /> <span>{error}</span>
        </div>
      )}

      {/* ─── Profile tabs ───────────────────────────────────────────────── */}
      <div className="flex flex-wrap gap-1.5">
        {PROFILE_TABS.map((tab) => (
          <button
            key={tab.key}
            type="button"
            onClick={() => setActiveProfile(tab.key)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
              activeProfile === tab.key
                ? 'border-cyan-500/60 bg-cyan-500/10 text-cyan-600 dark:text-cyan-400'
                : 'border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            {tab.label}
            {isCustomizedNow(tab.key) && <span className="w-1.5 h-1.5 rounded-full bg-cyan-500" title="Customized" />}
          </button>
        ))}
      </div>

      {/* ─── Sliders ────────────────────────────────────────────────────── */}
      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 space-y-5">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
            {PROFILE_TABS.find((t) => t.key === activeProfile)?.label}
          </h3>
          <button
            type="button"
            onClick={resetActive}
            disabled={!isCustomizedNow(activeProfile)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <RotateCcw className="w-3 h-3" /> Reset to AHP default
          </button>
        </div>

        <div className="space-y-4">
          {DIMENSIONS.map((dim) => (
            <div key={dim.key} className="flex items-center gap-3">
              <span className={`flex-shrink-0 w-9 text-center text-[10px] font-mono font-bold px-1.5 py-1 rounded-md ${dim.badgeClass}`}>
                {dim.key}
              </span>
              <div className="flex-1">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-slate-600 dark:text-slate-400">{dim.label}</span>
                  <span className="text-xs font-mono text-slate-900 dark:text-white">{current[dim.key].toFixed(2)}</span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={1}
                  step={0.01}
                  value={current[dim.key]}
                  onChange={(e) => updateDim(dim.key, Number(e.target.value))}
                  className="w-full accent-slate-600 dark:accent-slate-300"
                />
                <p className="text-[11px] text-slate-400 dark:text-slate-600 mt-0.5">{dim.hint}</p>
              </div>
            </div>
          ))}
        </div>

        <div className={`flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium ${valid ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'bg-red-500/10 text-red-500 dark:text-red-400'}`}>
          <span>Sum of weights</span>
          <span className="font-mono">{total.toFixed(3)} {valid ? '✓ valid (1.00 ± 0.01)' : '— must sum to 1.00'}</span>
        </div>
      </div>

      {/* ─── Live preview ───────────────────────────────────────────────── */}
      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6">
        <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-1">Live preview</h3>
        <p className="text-xs text-slate-400 dark:text-slate-600 mb-4">{example.label} (illustrative — doesn't affect what's saved)</p>
        <div className="flex items-center gap-6">
          <div>
            <div className="text-[10px] text-slate-400 dark:text-slate-600 uppercase tracking-wider mb-1">CAS Score</div>
            <div className="text-4xl font-mono font-bold text-slate-900 dark:text-white">{valid ? previewCas.toFixed(2) : '—'}</div>
          </div>
          {valid && (
            <span className={`px-3 py-1.5 rounded-full text-xs font-bold ${ACTION_BADGE_CLASS[previewAction]}`}>
              {previewAction.toUpperCase()}
            </span>
          )}
        </div>
      </div>

      {anyInvalidEdit && (
        <div className="flex items-start gap-2 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-600 dark:text-amber-400 text-xs">
          <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
          <span>One or more edited profiles don't sum to 1.00 yet — fix them before saving.</span>
        </div>
      )}

      <div className="flex items-center gap-3 sticky bottom-0 bg-white/90 dark:bg-slate-950/90 backdrop-blur py-3">
        <button
          onClick={handleSave}
          disabled={saving || !hasEdits || anyInvalidEdit}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 text-sm font-semibold transition-colors"
        >
          {saving ? <><Loader2 className="w-4 h-4 animate-spin" /> Saving…</> : 'Save CAS Weights'}
        </button>
        {saved && (
          <span className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400">
            <CheckCircle2 className="w-3.5 h-3.5" /> Saved
          </span>
        )}
        {hasEdits && !saved && <span className="text-xs text-slate-400 dark:text-slate-600">Unsaved changes</span>}
      </div>
    </div>
  );
};

export default CasWeightsSettingsPanel;
