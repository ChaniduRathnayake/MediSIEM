// Both reason and evidence are required — closures always leave a real audit trail.
import React, { useState } from 'react';
import { X, CheckCircle2, Loader2, AlertCircle, ShieldCheck, ShieldX, ShieldQuestion, HelpCircle, Zap, Wand2 } from 'lucide-react';
import type { AlertVerdict } from '../../services/alertsApi';
import { apiDraftCloseReason } from '../../services/alertsApi';

const VERDICT_OPTIONS: { value: AlertVerdict; label: string; icon: React.ReactNode; activeClass: string }[] = [
  { value: 'true_positive', label: 'True positive', icon: <ShieldCheck className="w-3.5 h-3.5" />, activeClass: 'bg-red-600 text-white border-red-600' },
  { value: 'false_positive', label: 'False positive', icon: <ShieldX className="w-3.5 h-3.5" />, activeClass: 'bg-emerald-600 text-white border-emerald-600' },
  { value: 'benign', label: 'Benign', icon: <ShieldQuestion className="w-3.5 h-3.5" />, activeClass: 'bg-slate-600 text-white border-slate-600' },
  { value: 'uncertain', label: 'Uncertain', icon: <HelpCircle className="w-3.5 h-3.5" />, activeClass: 'bg-amber-500 text-white border-amber-500' },
];

// One click fills verdict + reason + a starting point for evidence, for closures that recur.
const QUICK_PRESETS: { label: string; verdict: AlertVerdict; reason: string; evidence: string }[] = [
  {
    label: 'Known scanner IP',
    verdict: 'false_positive',
    reason: 'False positive — known vulnerability scanner IP',
    evidence: 'Source IP matches our scheduled vulnerability scanner range. ',
  },
  {
    label: 'Duplicate case',
    verdict: 'benign',
    reason: 'Duplicate of an already-open case',
    evidence: 'Same root cause as case ',
  },
  {
    label: 'Benign — confirmed with owner',
    verdict: 'benign',
    reason: 'Benign — confirmed with device owner',
    evidence: 'Contacted the device/service owner, who confirmed this was expected activity: ',
  },
  {
    label: 'Rule too broad',
    verdict: 'false_positive',
    reason: 'False positive — detection rule too broad for this context',
    evidence: 'Rule fired on legitimate activity that doesn\'t indicate a real threat. ',
  },
];

const CloseAlertModal: React.FC<{
  alertTitle: string;
  submitting: boolean;
  error: string | null;
  onClose: () => void;
  onSubmit: (reason: string, evidence: string, verdict: AlertVerdict) => void;
  // Enables the "Draft with AI" button — omitted callers just don't get it.
  alertId?: string;
  token?: string | null;
}> = ({ alertTitle, submitting, error, onClose, onSubmit, alertId, token }) => {
  const [reason, setReason] = useState('');
  const [evidence, setEvidence] = useState('');
  const [verdict, setVerdict] = useState<AlertVerdict | null>(null);
  const [aiDrafting, setAiDrafting] = useState(false);
  const [aiError, setAiError] = useState('');

  const canSubmit = reason.trim().length > 0 && evidence.trim().length > 0 && !!verdict && !submitting;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit || !verdict) return;
    onSubmit(reason.trim(), evidence.trim(), verdict);
  };

  const draftWithAi = async () => {
    if (!token || !alertId) return;
    setAiDrafting(true);
    setAiError('');
    try {
      const { draft } = await apiDraftCloseReason(token, alertId);
      setVerdict(draft.verdict);
      setReason(draft.reason);
      setEvidence(draft.evidence);
    } catch (err: unknown) {
      setAiError(err instanceof Error ? err.message : 'AI assistant request failed.');
    } finally {
      setAiDrafting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div
        className="w-full max-w-lg rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800">
          <div className="min-w-0">
            <h2 className="text-sm font-bold text-slate-900 dark:text-white">Close case</h2>
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5 truncate">{alertTitle}</p>
          </div>
          <button onClick={onClose} aria-label="Close" className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors flex-shrink-0 ml-3">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="px-6 py-5 space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1.5 flex items-center gap-1.5">
              <Zap className="w-3 h-3 text-cyan-500 dark:text-cyan-400" /> Quick fill
            </label>
            <div className="flex flex-wrap gap-1.5">
              {QUICK_PRESETS.map((p) => (
                <button
                  key={p.label}
                  type="button"
                  onClick={() => { setVerdict(p.verdict); setReason(p.reason); setEvidence(p.evidence); }}
                  className="px-2.5 py-1 rounded-full text-[11px] font-medium border border-cyan-500/30 bg-cyan-500/5 text-cyan-700 dark:text-cyan-400 hover:bg-cyan-500/15 transition-colors"
                >
                  {p.label}
                </button>
              ))}
              {alertId && token && (
                <button
                  type="button"
                  onClick={draftWithAi}
                  disabled={aiDrafting}
                  className="flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-medium border border-violet-500/30 bg-violet-500/5 text-violet-600 dark:text-violet-400 hover:bg-violet-500/15 disabled:opacity-50 transition-colors"
                >
                  {aiDrafting ? <Loader2 className="w-3 h-3 animate-spin" /> : <Wand2 className="w-3 h-3" />} Draft with AI
                </button>
              )}
            </div>
            {aiError && <p className="text-[11px] text-red-500 dark:text-red-400 mt-1.5">{aiError}</p>}
            <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-1.5">Fills verdict, reason, and a starting point for evidence — finish the specifics below before submitting.</p>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1.5">
              Verdict <span className="text-red-500">*</span>
            </label>
            <div className="grid grid-cols-2 gap-2">
              {VERDICT_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => setVerdict(opt.value)}
                  className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium border transition-colors ${
                    verdict === opt.value
                      ? opt.activeClass
                      : 'bg-slate-100 dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  {opt.icon} {opt.label}
                </button>
              ))}
            </div>
            <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-1.5">
              Was this a real threat? This is the only ground truth MediSIEM captures about its own detection accuracy — it feeds the Detection Performance panel.
            </p>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1.5">
              Reason <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. False positive — benign vendor scan"
              maxLength={500}
              className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/60"
              autoFocus
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1.5">
              Evidence <span className="text-red-500">*</span>
            </label>
            <textarea
              value={evidence}
              onChange={(e) => setEvidence(e.target.value)}
              placeholder="What did you check to reach this conclusion? Log excerpts, ticket links, device owner confirmation, etc."
              maxLength={5000}
              rows={5}
              className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/60 resize-y"
            />
            <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-1">
              Kept permanently on the case for future reference — be specific.
            </p>
          </div>

          {error && (
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 dark:text-red-400 text-xs">
              <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" /> {error}
            </div>
          )}

          <div className="flex items-center justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-2 rounded-lg text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!canSubmit}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-medium text-white bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {submitting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
              Close case
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default CloseAlertModal;
