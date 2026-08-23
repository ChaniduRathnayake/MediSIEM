// Read-only reference for the live-demo runbook (Extra_Material/Demo_Attack/DEMO_RUNBOOK.md).
// Deliberately not a "run" button — the underlying scripts need root and raw
// packet capture on separate attacker/victim VMs the backend has no business
// touching; wiring a web button to them would turn this into a standing
// attack-tool endpoint. This panel just makes the commands easy to copy.
import React, { useState } from 'react';
import { Zap, Copy, Check, Info, Monitor, Server, ShieldAlert, ArrowRight } from 'lucide-react';

const CopyBlock: React.FC<{ command: string; label?: string }> = ({ command, label }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard permission denied — nothing meaningful to recover into, the
      // command text is already visible and selectable in the block itself.
    }
  };

  return (
    <div className="rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 overflow-hidden">
      {label && (
        <div className="px-3 py-1.5 border-b border-slate-200 dark:border-slate-800 text-[11px] font-medium text-slate-400 dark:text-slate-500">
          {label}
        </div>
      )}
      <div className="flex items-start justify-between gap-2 px-3 py-2.5">
        <pre className="text-xs font-mono text-slate-700 dark:text-slate-300 whitespace-pre-wrap break-all">{command}</pre>
        <button
          onClick={handleCopy}
          className="flex-shrink-0 flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium text-slate-400 dark:text-slate-500 hover:text-slate-900 dark:hover:text-white hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors"
        >
          {copied ? <><Check className="w-3 h-3 text-emerald-500" /> Copied</> : <><Copy className="w-3 h-3" /> Copy</>}
        </button>
      </div>
    </div>
  );
};

const Step: React.FC<{ n: number; title: string; machine: string; children: React.ReactNode }> = ({ n, title, machine, children }) => (
  <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-5">
    <div className="flex items-center gap-2.5 mb-3">
      <span className="w-6 h-6 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-500 dark:text-cyan-400 text-xs font-bold flex items-center justify-center flex-shrink-0">
        {n}
      </span>
      <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{title}</h3>
      <span className="ml-auto text-[11px] font-medium text-slate-400 dark:text-slate-500 uppercase tracking-wide">{machine}</span>
    </div>
    <div className="space-y-2.5 pl-8.5">{children}</div>
  </div>
);

const PlaybooksPanel: React.FC = () => (
  <div className="p-5 space-y-5 max-w-3xl">
    <div>
      <h2 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
        <Zap className="w-4.5 h-4.5 text-cyan-500 dark:text-cyan-400" />
        Playbooks
      </h2>
      <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
        Reference for running the live-demo pipeline — real Wazuh agents plus a simulated attack, scored live on the SOC feed
      </p>
    </div>

    <div className="flex items-start gap-2.5 p-3.5 rounded-lg bg-amber-500/5 border border-amber-500/20">
      <Info className="w-4 h-4 text-amber-500 dark:text-amber-400 flex-shrink-0 mt-0.5" />
      <p className="text-xs text-amber-700 dark:text-amber-300">
        This is a reference, not a run button. Every command below executes manually, over SSH, on its own lab machine — the
        dashboard cannot and will not trigger any of it. The attack step generates real ARP-spoof / port-scan / SYN-flood
        traffic and needs root; that's not something a web session should ever be able to click.
      </p>
    </div>

    {/* Topology */}
    <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-5">
      <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-3">Topology</h3>
      <div className="flex items-center gap-2 flex-wrap text-xs">
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700">
          <Monitor className="w-3.5 h-3.5 text-cyan-500 dark:text-cyan-400" />
          <div>
            <p className="font-medium text-slate-900 dark:text-white">Windows host</p>
            <p className="text-slate-400 dark:text-slate-500">Wazuh stack · AI server · backend · dashboard</p>
          </div>
        </div>
        <ArrowRight className="w-3.5 h-3.5 text-slate-300 dark:text-slate-600 flex-shrink-0" />
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700">
          <Server className="w-3.5 h-3.5 text-emerald-500 dark:text-emerald-400" />
          <div>
            <p className="font-medium text-slate-900 dark:text-white">Ubuntu VM — victim</p>
            <p className="text-slate-400 dark:text-slate-500">Wazuh agent · capture + scoring</p>
          </div>
        </div>
        <ArrowRight className="w-3.5 h-3.5 text-slate-300 dark:text-slate-600 flex-shrink-0" />
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700">
          <ShieldAlert className="w-3.5 h-3.5 text-red-500 dark:text-red-400" />
          <div>
            <p className="font-medium text-slate-900 dark:text-white">RedHat VM — attacker</p>
            <p className="text-slate-400 dark:text-slate-500">Wazuh agent · simulated attack traffic</p>
          </div>
        </div>
      </div>
      <p className="text-xs text-slate-400 dark:text-slate-500 mt-3">
        Two surfaces update during the demo: this SOC feed (ML-scored CAS alerts from this pipeline) and the Wazuh SIEM tab
        (raw HIDS detections from the victim's own agent) — worth showing side by side.
      </p>
    </div>

    <Step n={0} title="Give the victim a clinical identity" machine="Windows host">
      <p className="text-xs text-slate-500 dark:text-slate-400">
        Optional but recommended — without it, flows from an unrecognized IP score with a flat clinical-criticality term.
        Edit <code className="text-[11px] font-mono text-cyan-600 dark:text-cyan-400">ml-pipeline/device_map.json</code>{' '}
        before step 2, since it's loaded once at startup:
      </p>
      <CopyBlock
        label="ml-pipeline/device_map.json"
        command={`{\n  "<ubuntu-vm-ip>": { "device_type": "ICU Ventilator", "department": "ICU" },\n  "_default": { "device_type": "Unknown Device", "department": "General" }\n}`}
      />
    </Step>

    <Step n={1} title="Bring up the pipeline" machine="Windows host">
      <CopyBlock command="powershell -ExecutionPolicy Bypass -File .\\start-caap-pipeline.ps1" />
      <p className="text-xs text-slate-500 dark:text-slate-400">
        Starts the Flask AI server (:5001), Node backend (:5000), and React dashboard (:5173). Confirm Windows Firewall
        allows inbound TCP 5001 and 9200 from the VM subnet before starting — check from a VM with:
      </p>
      <CopyBlock command={`curl -sk -u admin:<indexer-pass> https://<windows-host-ip>:9200\ncurl -s http://<windows-host-ip>:5001/health`} />
    </Step>

    <Step n={2} title="Start capture + scoring" machine="Ubuntu VM (victim)">
      <CopyBlock
        command={`pip3 install -r "ml-pipeline/requirements.txt"\nip -brief link   # find your interface, e.g. enp0s3\ncd "ml-pipeline"\nchmod +x run_victim_capture.sh\nsudo ./run_victim_capture.sh <interface> <windows-host-ip> admin <indexer-pass>`}
      />
      <p className="text-xs text-slate-500 dark:text-slate-400">Leave this running — it's the capture + scoring process for the whole demo.</p>
    </Step>

    <Step n={3} title="Launch the simulated attack" machine="RedHat VM (attacker)">
      <CopyBlock
        command={`pip3 install -r "ml-pipeline/requirements.txt"\ncd "Extra_Material/Demo_Attack"\nchmod +x run_attack.sh\nsudo ./run_attack.sh <ubuntu-victim-ip> all`}
      />
      <p className="text-xs text-slate-500 dark:text-slate-400">
        To hit every VM device on the lab network in one run instead of a single target, use{' '}
        <code className="text-[11px] font-mono text-cyan-600 dark:text-cyan-400">multi_target_attack_simulator.py</code>{' '}
        (or its <code className="text-[11px] font-mono text-cyan-600 dark:text-cyan-400">run_multi_attack.sh</code> wrapper)
        in the same folder instead.
      </p>
      <p className="text-xs text-slate-500 dark:text-slate-400">
        <code className="text-[11px] font-mono text-cyan-600 dark:text-cyan-400">all</code> cycles ARP spoof → port scan → SYN
        flood → benign — good for a "watch the CAS score rise and fall" narrative. Swap in{' '}
        <code className="text-[11px] font-mono text-cyan-600 dark:text-cyan-400">port_scan</code> or{' '}
        <code className="text-[11px] font-mono text-cyan-600 dark:text-cyan-400">syn_flood</code> for a single punchier moment.
      </p>
    </Step>

    <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-5">
      <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-2">If nothing shows up</h3>
      <ul className="text-xs text-slate-500 dark:text-slate-400 space-y-1.5 list-disc list-inside">
        <li>Node backend logs <code className="text-[11px] font-mono">HAS NO CAS FIELD</code> — check <code className="text-[11px] font-mono">WAZUH_INDEXER_INDEX</code> in <code className="text-[11px] font-mono">backend/.env</code> is <code className="text-[11px] font-mono">caap-alerts</code>.</li>
        <li>Node backend logs <code className="text-[11px] font-mono">Index "caap-alerts" doesn't exist yet</code> — nothing indexed yet; check the victim's <code className="text-[11px] font-mono">flow_consumer.py</code> terminal first.</li>
      </ul>
    </div>
  </div>
);

export default PlaybooksPanel;
