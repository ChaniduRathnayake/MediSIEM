// frontend/src/pages/dashboard/CloseAlertModal.tsx
//
// Small, focused modal: an analyst can only close a case by typing why (reason)
// and what they found (evidence) — both required, so closures always leave a
// real audit trail behind instead of a bare "resolved" toggle.
import React, { useState } from 'react';
import { X, CheckCircle2, Loader2, AlertCircle, ShieldCheck, ShieldX, ShieldQuestion, HelpCircle } from 'lucide-react';
import type { AlertVerdict } from '../../services/alertsApi';

const VERDICT_OPTIONS: { value: AlertVerdict; label: string; icon: React.ReactNode; activeClass: string }[] = [
  { value: 'true_positive', label: 'True positive', icon: <ShieldCheck className="w-3.5 h-3.5" />, activeClass: 'bg-red-600 text-white border-red-600' },
  { value: 'false_positive', label: 'False positive', icon: <ShieldX className="w-3.5 h-3.5" />, activeClass: 'bg-emerald-600 text-white border-emerald-600' },
  { value: 'benign', label: 'Benign', icon: <ShieldQuestion className="w-3.5 h-3.5" />, activeClass: 'bg-slate-600 text-white border-slate-600' },
  { value: 'uncertain', label: 'Uncertain', icon: <HelpCircle className="w-3.5 h-3.5" />, activeClass: 'bg-amber-500 text-white border-amber-500' },
];

const CloseAlertModal: React.FC<{
  alertTitle: string;
  submitting: boolean;
  error: string | null;
  onClose: () => void;
  onSubmit: (reason: string, evidence: string, verdict: AlertVerdict) => void;
}> = ({ alertTitle, submitting, error, onClose, onSubmit }) => {
  const [reason, setReason] = useState('');
  const [evidence, setEvidence] = useState('');
  const [verdict, setVerdict] = useState<AlertVerdict | null>(null);

  const canSubmit = reason.trim().length > 0 && evidence.trim().length > 0 && !!verdict && !submitting;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit || !verdict) return;
    onSubmit(reason.trim(), evidence.trim(), verdict);
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
          <button onClick={onClose} className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors flex-shrink-0 ml-3">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="px-6 py-5 space-y-4">
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
