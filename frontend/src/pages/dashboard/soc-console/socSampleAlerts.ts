// Ported verbatim from life-critical-orchestration/frontend/src/data/{tier1,tier2,tier3}-cases.json
// via sampleAlerts.js — the same 12 stub alerts the standalone SOC console ships with,
// so the Playbooks tab's alert feed isn't empty before any real MediSIEM alert has been
// pushed to the engine. Clicking one classifies it for real via POST /decide (see
// SocConsole.tsx) — these are inputs, not canned decisions.
import type { StubAlert } from './socTypes';

function withExpected(alerts: Omit<StubAlert, '_expectedTier'>[], expectedTier: 1 | 2 | 3): StubAlert[] {
  return alerts.map((a) => ({ ...a, _expectedTier: expectedTier }));
}

const tier1Alerts: Omit<StubAlert, '_expectedTier'>[] = [
  {
    alert_id: 'alert-2026-05-03-1001',
    timestamp: '2026-05-03T08:14:33Z',
    source: { siem: 'wazuh', rule_id: '5712', rule_description: 'SSHD brute force attempt from external IP', rule_level: 10 },
    threat: { category: 'brute_force', technical_severity: 'high', cvss_score: 7.2, indicators: { source_ip: '203.0.113.45', destination_port: 22, failed_attempts: 47 } },
    asset: { asset_id: 'ADM-LAPTOP-014', hostname: 'admin-laptop-14.hospital.local', ip_address: '10.0.20.114', asset_type: 'workstation', device_category: 'laptop', department: 'Administration', patient_facing: false },
    clinical_context: { criticality_score: 2, patient_dependency: 'none', time_sensitivity: 1.0, shift: 'day' },
    enrichment_meta: { enriched_at: '2026-05-03T08:14:34Z', enricher_version: 'stub-1.0.0', confidence: 1.0 },
  },
  {
    alert_id: 'alert-2026-05-03-1002',
    timestamp: '2026-05-03T11:42:09Z',
    source: { siem: 'wazuh', rule_id: '31151', rule_description: 'Suspicious binary execution detected', rule_level: 9 },
    threat: { category: 'malware_execution', technical_severity: 'medium', cvss_score: 5.4, indicators: { process_name: 'svch0st.exe', user: 'cafe-staff-02' } },
    asset: { asset_id: 'CAF-PC-002', hostname: 'cafeteria-pc-02.hospital.local', ip_address: '10.0.30.52', asset_type: 'workstation', device_category: 'desktop', department: 'Infrastructure', patient_facing: false },
    clinical_context: { criticality_score: 1, patient_dependency: 'none', time_sensitivity: 1.0, shift: 'day' },
    enrichment_meta: { enriched_at: '2026-05-03T11:42:10Z', enricher_version: 'stub-1.0.0', confidence: 1.0 },
  },
  {
    alert_id: 'alert-2026-05-03-1003',
    timestamp: '2026-05-03T14:22:17Z',
    source: { siem: 'wazuh', rule_id: '100502', rule_description: 'Outbound connection to known C2 infrastructure', rule_level: 7 },
    threat: { category: 'c2_communication', technical_severity: 'low', cvss_score: 3.5, indicators: { destination_ip: '198.51.100.77', destination_port: 443, threat_intel_ref: 'ti-mal-2087' } },
    asset: { asset_id: 'PRINT-SRV-01', hostname: 'print-server-01.hospital.local', ip_address: '10.0.40.10', asset_type: 'server', device_category: 'print_server', department: 'Infrastructure', patient_facing: false },
    clinical_context: { criticality_score: 3, patient_dependency: 'low', time_sensitivity: 2.0, shift: 'day' },
    enrichment_meta: { enriched_at: '2026-05-03T14:22:18Z', enricher_version: 'stub-1.0.0', confidence: 1.0 },
  },
  {
    alert_id: 'alert-2026-05-03-1004',
    timestamp: '2026-05-03T16:55:48Z',
    source: { siem: 'wazuh', rule_id: '5710', rule_description: 'Possible privilege escalation attempt', rule_level: 11 },
    threat: { category: 'privilege_escalation', technical_severity: 'high', cvss_score: 7.8, indicators: { user: 'training-user-03', target_account: 'local-admin' } },
    asset: { asset_id: 'TRAIN-PC-007', hostname: 'training-room-pc-07.hospital.local', ip_address: '10.0.50.107', asset_type: 'workstation', device_category: 'desktop', department: 'Administration', patient_facing: false },
    clinical_context: { criticality_score: 4, patient_dependency: 'low', time_sensitivity: 1.0, shift: 'evening' },
    enrichment_meta: { enriched_at: '2026-05-03T16:55:49Z', enricher_version: 'stub-1.0.0', confidence: 1.0 },
  },
];

const tier2Alerts: Omit<StubAlert, '_expectedTier'>[] = [
  {
    alert_id: 'alert-2026-05-03-2001',
    timestamp: '2026-05-03T09:03:11Z',
    source: { siem: 'wazuh', rule_id: '92052', rule_description: 'Multiple authentication failures from internal source', rule_level: 10 },
    threat: { category: 'brute_force', technical_severity: 'high', cvss_score: 7.5, indicators: { source_ip: '10.0.5.99', destination_port: 22, failed_attempts: 12 } },
    asset: { asset_id: 'ICU-VENT-003', hostname: 'icu-ventilator-03.hospital.local', ip_address: '10.0.5.23', asset_type: 'medical_device', device_category: 'ventilator', department: 'ICU', patient_facing: true },
    clinical_context: { criticality_score: 10, patient_dependency: 'life_critical', time_sensitivity: 5.0, shift: 'day' },
    enrichment_meta: { enriched_at: '2026-05-03T09:03:12Z', enricher_version: 'stub-1.0.0', confidence: 1.0 },
  },
  {
    alert_id: 'alert-2026-05-03-2002',
    timestamp: '2026-05-03T10:17:44Z',
    source: { siem: 'wazuh', rule_id: '31104', rule_description: 'Unusual network protocol usage on medical device', rule_level: 9 },
    threat: { category: 'anomalous_traffic', technical_severity: 'medium', cvss_score: 6.4, indicators: { destination_ip: '10.0.5.40', protocol: 'smb', device_protocol_expected: 'hl7' } },
    asset: { asset_id: 'ICU-PUMP-008', hostname: 'icu-infusion-pump-08.hospital.local', ip_address: '10.0.5.40', asset_type: 'medical_device', device_category: 'infusion_pump', department: 'ICU', patient_facing: true },
    clinical_context: { criticality_score: 9, patient_dependency: 'life_critical', time_sensitivity: 5.0, shift: 'day' },
    enrichment_meta: { enriched_at: '2026-05-03T10:17:45Z', enricher_version: 'stub-1.0.0', confidence: 1.0 },
  },
  {
    alert_id: 'alert-2026-05-03-2003',
    timestamp: '2026-05-03T12:45:02Z',
    source: { siem: 'wazuh', rule_id: '100201', rule_description: 'Outbound connection to suspicious domain', rule_level: 8 },
    threat: { category: 'suspicious_communication', technical_severity: 'medium', cvss_score: 5.9, indicators: { destination_domain: 'stats-cdn.example.net', connection_count: 3 } },
    asset: { asset_id: 'OR-MONITOR-002', hostname: 'or-monitor-02.hospital.local', ip_address: '10.0.6.15', asset_type: 'medical_device', device_category: 'patient_monitor', department: 'Ward', patient_facing: true },
    clinical_context: { criticality_score: 7, patient_dependency: 'high', time_sensitivity: 4.0, shift: 'day' },
    enrichment_meta: { enriched_at: '2026-05-03T12:45:03Z', enricher_version: 'stub-1.0.0', confidence: 1.0 },
  },
  {
    alert_id: 'alert-2026-05-03-2004',
    timestamp: '2026-05-03T13:20:38Z',
    source: { siem: 'wazuh', rule_id: '554', rule_description: 'File integrity monitoring: unauthorised binary modification', rule_level: 10 },
    threat: { category: 'tampering', technical_severity: 'high', cvss_score: 7.9, indicators: { modified_path: '/opt/dialysis/control.bin', modified_by: 'unknown' } },
    asset: { asset_id: 'DIAL-UNIT-004', hostname: 'dialysis-unit-04.hospital.local', ip_address: '10.0.7.34', asset_type: 'medical_device', device_category: 'dialysis_machine', department: 'ICU', patient_facing: true },
    clinical_context: { criticality_score: 9, patient_dependency: 'life_critical', time_sensitivity: 5.0, shift: 'day' },
    enrichment_meta: { enriched_at: '2026-05-03T13:20:39Z', enricher_version: 'stub-1.0.0', confidence: 1.0 },
  },
  {
    alert_id: 'alert-2026-05-03-2005',
    timestamp: '2026-05-03T15:11:55Z',
    source: { siem: 'wazuh', rule_id: '5503', rule_description: 'Unusual port scan activity from internal device', rule_level: 9 },
    threat: { category: 'reconnaissance', technical_severity: 'medium', cvss_score: 5.4, indicators: { source_ip: '10.0.8.12', ports_scanned: 178, scan_window_seconds: 90 } },
    asset: { asset_id: 'ER-DEFIB-001', hostname: 'er-defib-01.hospital.local', ip_address: '10.0.8.12', asset_type: 'medical_device', device_category: 'defibrillator', department: 'Ward', patient_facing: true },
    clinical_context: { criticality_score: 6, patient_dependency: 'medium', time_sensitivity: 4.0, shift: 'evening' },
    enrichment_meta: { enriched_at: '2026-05-03T15:11:56Z', enricher_version: 'stub-1.0.0', confidence: 1.0 },
  },
];

const tier3Alerts: Omit<StubAlert, '_expectedTier'>[] = [
  {
    alert_id: 'alert-2026-05-03-3001',
    timestamp: '2026-05-03T07:48:22Z',
    source: { siem: 'wazuh', rule_id: '87105', rule_description: 'Ransomware encryption behaviour detected', rule_level: 15 },
    threat: { category: 'ransomware', technical_severity: 'critical', cvss_score: 9.8, indicators: { files_modified_per_minute: 412, extensions_observed: ['.locked', '.encrypted'], ransom_note_path: '/tmp/READ_ME_NOW.txt' } },
    asset: { asset_id: 'RAD-LINAC-001', hostname: 'rad-linac-01.hospital.local', ip_address: '10.0.9.5', asset_type: 'medical_device', device_category: 'linear_accelerator', department: 'Radiology', patient_facing: true },
    clinical_context: { criticality_score: 10, patient_dependency: 'life_critical', time_sensitivity: 5.0, shift: 'day' },
    enrichment_meta: { enriched_at: '2026-05-03T07:48:23Z', enricher_version: 'stub-1.0.0', confidence: 1.0 },
  },
  {
    alert_id: 'alert-2026-05-03-3002',
    timestamp: '2026-05-03T11:32:41Z',
    source: { siem: 'wazuh', rule_id: '61603', rule_description: 'Active exploitation of remote code execution vulnerability', rule_level: 14 },
    threat: { category: 'active_exploitation', technical_severity: 'critical', cvss_score: 9.6, indicators: { cve: 'CVE-2025-49801', exploit_pattern_match: true, shell_spawned: true } },
    asset: { asset_id: 'ICU-VENT-007', hostname: 'icu-ventilator-07.hospital.local', ip_address: '10.0.5.27', asset_type: 'medical_device', device_category: 'ventilator', department: 'ICU', patient_facing: true },
    clinical_context: { criticality_score: 9, patient_dependency: 'life_critical', time_sensitivity: 5.0, shift: 'day' },
    enrichment_meta: { enriched_at: '2026-05-03T11:32:42Z', enricher_version: 'stub-1.0.0', confidence: 1.0 },
  },
  {
    alert_id: 'alert-2026-05-03-3003',
    timestamp: '2026-05-03T17:09:15Z',
    source: { siem: 'wazuh', rule_id: '100403', rule_description: 'Lateral movement detected: medical subnet -> medical subnet', rule_level: 13 },
    threat: { category: 'lateral_movement', technical_severity: 'critical', cvss_score: 9.1, indicators: { source_asset: 'ICU-VENT-007', destination_asset: 'OR-ANAES-002', method: 'credential_reuse' } },
    asset: { asset_id: 'OR-ANAES-002', hostname: 'or-anaesthesia-02.hospital.local', ip_address: '10.0.6.22', asset_type: 'medical_device', device_category: 'anaesthesia_machine', department: 'Ward', patient_facing: true },
    clinical_context: { criticality_score: 6, patient_dependency: 'high', time_sensitivity: 4.0, shift: 'evening' },
    enrichment_meta: { enriched_at: '2026-05-03T17:09:16Z', enricher_version: 'stub-1.0.0', confidence: 1.0 },
  },
];

export const socSampleAlerts: StubAlert[] = [
  ...withExpected(tier1Alerts, 1),
  ...withExpected(tier2Alerts, 2),
  ...withExpected(tier3Alerts, 3),
];
