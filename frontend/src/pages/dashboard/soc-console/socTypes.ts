// Shared types for the ported SOC console (Playbooks tab). Mirrors the shape
// life-critical-orchestration/docs/alert-schema.md defines and the standalone
// frontend's own component props — see life-critical-orchestration/frontend/src/{App.jsx,components/*}.
import type { LifeCriticalDecision } from '../../../services/lifeCriticalApi';

export interface StubAlert {
  alert_id: string;
  timestamp: string;
  source: { siem: string; rule_id?: string; rule_description?: string; rule_level?: number };
  threat: {
    category?: string;
    technical_severity?: string;
    cvss_score?: number;
    cas_score?: number;
    cas_breakdown?: { TR?: number; CC?: number; TS?: number; AE?: number; TC?: number };
    indicators?: Record<string, unknown>;
  };
  asset: {
    asset_id: string;
    hostname?: string;
    ip_address?: string;
    asset_type?: string;
    device_category?: string;
    department?: string;
    patient_facing?: boolean;
  };
  clinical_context: {
    criticality_score?: number;
    patient_dependency?: string;
    time_sensitivity?: number;
    shift?: string;
  };
  enrichment_meta?: { enriched_at?: string; enricher_version?: string; confidence?: number };
  // Client-side only, added by the feed merge logic — never sent to the engine.
  _expectedTier?: 1 | 2 | 3;
  _live?: boolean;
  _liveDecision?: LifeCriticalDecision;
  _sortTimestamp?: string;
}
