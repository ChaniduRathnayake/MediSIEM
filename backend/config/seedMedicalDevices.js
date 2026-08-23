// Default hospital medical device inventory, loaded into the `MedicalDevice`
// Mongo collection once on first server startup — starter data for a fresh
// install only, managed from the admin Devices tab after that. `key` matches
// a Wazuh agent's name or IP (lowercase) so alerts resolve to this device's
// device_type/department for CAAP scoring — see config/deviceInventory.js.
const SEED_MEDICAL_DEVICES = [
  { key: 'icu-vent-04', deviceName: 'ICU Ventilator 04', deviceType: 'ICU Ventilator', department: 'ICU', manufacturer: 'Draeger', model: 'Evita V500', criticality: 'critical', location: 'ICU Bay 4' },
  { key: 'icu-vent-05', deviceName: 'ICU Ventilator 05', deviceType: 'ICU Ventilator', department: 'ICU', manufacturer: 'Draeger', model: 'Evita V500', criticality: 'critical', location: 'ICU Bay 5' },
  { key: 'inf-pump-12', deviceName: 'Infusion Pump 12', deviceType: 'Infusion Pump', department: 'ICU', manufacturer: 'B. Braun', model: 'Infusomat Space', criticality: 'high', location: 'ICU Bay 2' },
  { key: 'inf-pump-13', deviceName: 'Infusion Pump 13', deviceType: 'Infusion Pump', department: 'ICU', manufacturer: 'B. Braun', model: 'Infusomat Space', criticality: 'high', location: 'ICU Bay 3' },
  { key: 'patient-mon-icu2', deviceName: 'ICU Patient Monitor 2', deviceType: 'Patient Monitor', department: 'ICU', manufacturer: 'Philips', model: 'IntelliVue MX750', criticality: 'high', location: 'ICU Bay 2' },
  { key: 'bed-monitor-icu3', deviceName: 'ICU Bedside Monitor 3', deviceType: 'Bedside Monitor', department: 'ICU', manufacturer: 'GE Healthcare', model: 'CARESCAPE B650', criticality: 'high', location: 'ICU Bay 3' },
  { key: 'nurse-station-icu', deviceName: 'ICU Nurse Station', deviceType: 'Workstation', department: 'ICU', manufacturer: 'Dell', model: 'OptiPlex 7010', criticality: 'medium', location: 'ICU Nurse Station' },

  { key: 'cardiac-mon-7', deviceName: 'Cardiac Monitor 7', deviceType: 'Cardiac Monitor', department: 'Cardiology', manufacturer: 'Philips', model: 'IntelliVue MX450', criticality: 'high', location: 'Cardiology Ward' },
  { key: 'ecg-cardio-02', deviceName: 'ECG Machine 2', deviceType: 'ECG Machine', department: 'Cardiology', manufacturer: 'GE Healthcare', model: 'MAC 2000', criticality: 'high', location: 'Cardiology Lab' },

  { key: 'ct-mri-01', deviceName: 'CT/MRI System 01', deviceType: 'CT/MRI System', department: 'Radiology', manufacturer: 'Siemens Healthineers', model: 'MAGNETOM Altea', criticality: 'high', location: 'Radiology Suite 1' },
  { key: 'xray-portable-01', deviceName: 'Portable X-Ray 01', deviceType: 'Portable X-Ray', department: 'Radiology', manufacturer: 'Carestream', model: 'DRX-Revolution', criticality: 'medium', location: 'Radiology' },
  { key: 'ultrasound-03', deviceName: 'Ultrasound System 03', deviceType: 'Ultrasound System', department: 'Radiology', manufacturer: 'GE Healthcare', model: 'Voluson E10', criticality: 'medium', location: 'Radiology Suite 3' },
  { key: 'pacs-workstation-01', deviceName: 'PACS Workstation 01', deviceType: 'Workstation', department: 'Radiology', manufacturer: 'HP', model: 'Z2 Tower G9', criticality: 'elevated', location: 'Radiology' },

  { key: 'workstation-er', deviceName: 'ER Workstation', deviceType: 'Workstation', department: 'Emergency', manufacturer: 'Dell', model: 'OptiPlex 7010', criticality: 'low', location: 'Emergency Dept' },
  { key: 'defib-er-01', deviceName: 'Defibrillator 01', deviceType: 'Defibrillator', department: 'Emergency', manufacturer: 'Zoll', model: 'X Series', criticality: 'critical', location: 'Emergency Dept' },

  { key: 'nurse-station-3', deviceName: 'Nurse Station 3', deviceType: 'Workstation', department: 'General Ward', manufacturer: 'Dell', model: 'OptiPlex 7010', criticality: 'low', location: 'Ward 3 Nurse Station' },
  { key: 'bp-monitor-ward4', deviceName: 'Blood Pressure Monitor Ward 4', deviceType: 'Blood Pressure Monitor', department: 'General Ward', manufacturer: 'Omron', model: 'HBP-1320', criticality: 'medium', location: 'Ward 4' },
  { key: 'pulse-ox-ward2', deviceName: 'Pulse Oximeter Ward 2', deviceType: 'Pulse Oximeter', department: 'General Ward', manufacturer: 'Masimo', model: 'Radical-7', criticality: 'medium', location: 'Ward 2' },

  { key: 'anesthesia-or2', deviceName: 'Anesthesia Machine OR2', deviceType: 'Anesthesia Machine', department: 'Surgery', manufacturer: 'GE Healthcare', model: 'Aisys CS2', criticality: 'critical', location: 'Operating Room 2' },
  { key: 'surgical-robot-or1', deviceName: 'Surgical Robot OR1', deviceType: 'Surgical Robot', department: 'Surgery', manufacturer: 'Intuitive Surgical', model: 'da Vinci Xi', criticality: 'critical', location: 'Operating Room 1' },

  { key: 'dialysis-01', deviceName: 'Dialysis Machine 01', deviceType: 'Dialysis Machine', department: 'Nephrology', manufacturer: 'Fresenius Medical Care', model: '5008S', criticality: 'critical', location: 'Dialysis Unit' },

  { key: 'nicu-incubator-01', deviceName: 'Neonatal Incubator 01', deviceType: 'Neonatal Incubator', department: 'NICU', manufacturer: 'Drägerwerk', model: 'Caleo', criticality: 'critical', location: 'NICU Bay 1' },
  { key: 'nicu-vent-02', deviceName: 'Neonatal Ventilator 02', deviceType: 'Neonatal Ventilator', department: 'NICU', manufacturer: 'Vyaire Medical', model: 'VN500', criticality: 'critical', location: 'NICU Bay 2' },

  { key: 'infusion-onc-04', deviceName: 'Infusion Pump Oncology 04', deviceType: 'Infusion Pump', department: 'Oncology', manufacturer: 'B. Braun', model: 'Infusomat Space', criticality: 'high', location: 'Oncology Ward' },
  { key: 'chemo-pump-01', deviceName: 'Chemotherapy Pump 01', deviceType: 'Chemotherapy Pump', department: 'Oncology', manufacturer: 'BD', model: 'Alaris PK', criticality: 'critical', location: 'Oncology Ward' },

  { key: 'lab-analyzer-01', deviceName: 'Lab Analyzer 01', deviceType: 'Lab Analyzer', department: 'Laboratory', manufacturer: 'Roche', model: 'cobas 8000', criticality: 'elevated', location: 'Laboratory' },
  { key: 'pharmacy-dispenser-01', deviceName: 'Automated Dispensing Cabinet 01', deviceType: 'Automated Dispensing Cabinet', department: 'Pharmacy', manufacturer: 'Omnicell', model: 'XT Cabinet', criticality: 'high', location: 'Pharmacy' },

  { key: 'workstation-admin-01', deviceName: 'Admin Workstation 01', deviceType: 'Workstation', department: 'Administration', manufacturer: 'Dell', model: 'OptiPlex 7010', criticality: 'low', location: 'Administration' },

  // ── Expanded coverage (added 2026-08-23) — more onboarded devices means fewer
  // live alerts fall back to DEFAULT_DEVICE ("Unknown Device", medium criticality)
  // in config/deviceInventory.js, which directly sharpens CAAP's clinical
  // criticality (CC) dimension of the CAS score across the fleet.
  { key: 'icu-vent-06', deviceName: 'ICU Ventilator 06', deviceType: 'ICU Ventilator', department: 'ICU', manufacturer: 'Draeger', model: 'Evita V500', criticality: 'critical', location: 'ICU Bay 6' },
  { key: 'icu-vent-07', deviceName: 'ICU Ventilator 07', deviceType: 'ICU Ventilator', department: 'ICU', manufacturer: 'Medtronic', model: 'Puritan Bennett 980', criticality: 'critical', location: 'ICU Bay 7' },
  { key: 'inf-pump-14', deviceName: 'Infusion Pump 14', deviceType: 'Infusion Pump', department: 'ICU', manufacturer: 'B. Braun', model: 'Infusomat Space', criticality: 'high', location: 'ICU Bay 6' },
  { key: 'inf-pump-15', deviceName: 'Infusion Pump 15', deviceType: 'Infusion Pump', department: 'ICU', manufacturer: 'Baxter', model: 'Sigma Spectrum', criticality: 'high', location: 'ICU Bay 7' },
  { key: 'syringe-pump-icu1', deviceName: 'Syringe Pump ICU 1', deviceType: 'Syringe Pump', department: 'ICU', manufacturer: 'B. Braun', model: 'Perfusor Space', criticality: 'high', location: 'ICU Bay 1' },
  { key: 'patient-mon-icu5', deviceName: 'ICU Patient Monitor 5', deviceType: 'Patient Monitor', department: 'ICU', manufacturer: 'Philips', model: 'IntelliVue MX750', criticality: 'high', location: 'ICU Bay 5' },
  { key: 'crrt-icu-01', deviceName: 'CRRT Machine 01', deviceType: 'CRRT Machine', department: 'ICU', manufacturer: 'Baxter', model: 'PrisMax', criticality: 'critical', location: 'ICU Bay 2' },

  { key: 'echo-cardio-01', deviceName: 'Echocardiogram Machine 1', deviceType: 'Echocardiogram Machine', department: 'Cardiology', manufacturer: 'GE Healthcare', model: 'Vivid E95', criticality: 'high', location: 'Cardiology Lab' },
  { key: 'holter-monitor-01', deviceName: 'Holter Monitor 1', deviceType: 'Holter Monitor', department: 'Cardiology', manufacturer: 'Philips', model: 'DigiTrak XT', criticality: 'medium', location: 'Cardiology Ward' },
  { key: 'cath-lab-01', deviceName: 'Cath Lab Imaging System', deviceType: 'Cath Lab System', department: 'Cardiology', manufacturer: 'Siemens Healthineers', model: 'Artis icono', criticality: 'critical', location: 'Cath Lab' },

  { key: 'ct-scanner-02', deviceName: 'CT Scanner 02', deviceType: 'CT Scanner', department: 'Radiology', manufacturer: 'Siemens Healthineers', model: 'SOMATOM go.Top', criticality: 'high', location: 'Radiology Suite 2' },
  { key: 'mammography-01', deviceName: 'Mammography System 01', deviceType: 'Mammography System', department: 'Radiology', manufacturer: 'Hologic', model: '3Dimensions', criticality: 'medium', location: 'Radiology' },
  { key: 'fluoroscopy-01', deviceName: 'Fluoroscopy System 01', deviceType: 'Fluoroscopy System', department: 'Radiology', manufacturer: 'Philips', model: 'Zenition 70', criticality: 'high', location: 'Radiology Suite 4' },

  { key: 'ecg-er-01', deviceName: 'ECG Machine ER', deviceType: 'ECG Machine', department: 'Emergency', manufacturer: 'GE Healthcare', model: 'MAC 2000', criticality: 'high', location: 'Emergency Dept' },
  { key: 'vent-er-01', deviceName: 'Emergency Ventilator 01', deviceType: 'Ventilator', department: 'Emergency', manufacturer: 'Medtronic', model: 'Puritan Bennett 840', criticality: 'critical', location: 'Emergency Dept' },
  { key: 'triage-workstation-01', deviceName: 'Triage Workstation 01', deviceType: 'Workstation', department: 'Emergency', manufacturer: 'Dell', model: 'OptiPlex 7010', criticality: 'low', location: 'Emergency Triage' },

  { key: 'pulse-ox-ward3', deviceName: 'Pulse Oximeter Ward 3', deviceType: 'Pulse Oximeter', department: 'General Ward', manufacturer: 'Masimo', model: 'Radical-7', criticality: 'medium', location: 'Ward 3' },
  { key: 'bp-monitor-ward5', deviceName: 'Blood Pressure Monitor Ward 5', deviceType: 'Blood Pressure Monitor', department: 'General Ward', manufacturer: 'Omron', model: 'HBP-1320', criticality: 'medium', location: 'Ward 5' },
  { key: 'iv-pump-ward2', deviceName: 'IV Pump Ward 2', deviceType: 'Infusion Pump', department: 'General Ward', manufacturer: 'B. Braun', model: 'Infusomat Space', criticality: 'medium', location: 'Ward 2' },

  { key: 'or-monitor-3', deviceName: 'OR Patient Monitor 3', deviceType: 'Patient Monitor', department: 'Surgery', manufacturer: 'Philips', model: 'IntelliVue MX550', criticality: 'high', location: 'Operating Room 3' },
  { key: 'electrosurgical-unit-01', deviceName: 'Electrosurgical Unit 01', deviceType: 'Electrosurgical Unit', department: 'Surgery', manufacturer: 'Medtronic', model: 'Valleylab FT10', criticality: 'high', location: 'Operating Room 1' },
  { key: 'anesthesia-or3', deviceName: 'Anesthesia Machine OR3', deviceType: 'Anesthesia Machine', department: 'Surgery', manufacturer: 'GE Healthcare', model: 'Aisys CS2', criticality: 'critical', location: 'Operating Room 3' },

  { key: 'dialysis-02', deviceName: 'Dialysis Machine 02', deviceType: 'Dialysis Machine', department: 'Nephrology', manufacturer: 'Fresenius Medical Care', model: '5008S', criticality: 'critical', location: 'Dialysis Unit' },

  { key: 'nicu-incubator-03', deviceName: 'Neonatal Incubator 03', deviceType: 'Neonatal Incubator', department: 'NICU', manufacturer: 'Drägerwerk', model: 'Caleo', criticality: 'critical', location: 'NICU Bay 3' },
  { key: 'nicu-monitor-01', deviceName: 'Neonatal Monitor 01', deviceType: 'Neonatal Monitor', department: 'NICU', manufacturer: 'Philips', model: 'IntelliVue MX800', criticality: 'high', location: 'NICU Bay 1' },

  { key: 'chemo-pump-02', deviceName: 'Chemotherapy Pump 02', deviceType: 'Chemotherapy Pump', department: 'Oncology', manufacturer: 'BD', model: 'Alaris PK', criticality: 'critical', location: 'Oncology Ward' },
  { key: 'infusion-onc-05', deviceName: 'Infusion Pump Oncology 05', deviceType: 'Infusion Pump', department: 'Oncology', manufacturer: 'B. Braun', model: 'Infusomat Space', criticality: 'high', location: 'Oncology Ward' },

  { key: 'lab-analyzer-02', deviceName: 'Lab Analyzer 02', deviceType: 'Lab Analyzer', department: 'Laboratory', manufacturer: 'Abbott', model: 'Alinity ci', criticality: 'elevated', location: 'Laboratory' },
  { key: 'blood-gas-analyzer-01', deviceName: 'Blood Gas Analyzer 01', deviceType: 'Blood Gas Analyzer', department: 'Laboratory', manufacturer: 'Radiometer', model: 'ABL90 FLEX', criticality: 'high', location: 'Laboratory' },

  { key: 'pharmacy-dispenser-02', deviceName: 'Automated Dispensing Cabinet 02', deviceType: 'Automated Dispensing Cabinet', department: 'Pharmacy', manufacturer: 'Omnicell', model: 'XT Cabinet', criticality: 'high', location: 'Pharmacy' },
  { key: 'med-cart-01', deviceName: 'Smart Medication Cart 01', deviceType: 'Smart Medication Cart', department: 'Pharmacy', manufacturer: 'Omnicell', model: 'Anywhere RN', criticality: 'medium', location: 'Pharmacy' },

  { key: 'workstation-admin-02', deviceName: 'Admin Workstation 02', deviceType: 'Workstation', department: 'Administration', manufacturer: 'Dell', model: 'OptiPlex 7010', criticality: 'low', location: 'Administration' },

  { key: 'fetal-monitor-01', deviceName: 'Fetal Monitor 01', deviceType: 'Fetal Monitor', department: 'Maternity', manufacturer: 'Philips', model: 'Avalon FM50', criticality: 'high', location: 'Labor & Delivery' },
  { key: 'fetal-monitor-02', deviceName: 'Fetal Monitor 02', deviceType: 'Fetal Monitor', department: 'Maternity', manufacturer: 'GE Healthcare', model: 'Novii', criticality: 'high', location: 'Labor & Delivery' },

  { key: 'ventilator-resp-01', deviceName: 'Ventilator Resp 01', deviceType: 'Ventilator', department: 'Respiratory Therapy', manufacturer: 'Medtronic', model: 'Puritan Bennett 980', criticality: 'critical', location: 'Respiratory Therapy Unit' },
  { key: 'oxygen-concentrator-01', deviceName: 'Oxygen Concentrator 01', deviceType: 'Oxygen Concentrator', department: 'Respiratory Therapy', manufacturer: 'Philips', model: 'EverFlo', criticality: 'medium', location: 'Respiratory Therapy Unit' },

  { key: 'endoscopy-tower-01', deviceName: 'Endoscopy Tower 01', deviceType: 'Endoscopy Tower', department: 'Endoscopy', manufacturer: 'Olympus', model: 'EVIS X1', criticality: 'high', location: 'Endoscopy Suite' },

  { key: 'blood-bank-fridge-01', deviceName: 'Blood Bank Refrigerator 01', deviceType: 'Blood Bank Refrigerator', department: 'Blood Bank', manufacturer: 'Helmer Scientific', model: 'iB161', criticality: 'high', location: 'Blood Bank' },

  { key: 'autoclave-01', deviceName: 'Autoclave 01', deviceType: 'Autoclave', department: 'Sterile Processing', manufacturer: 'Getinge', model: 'HS66', criticality: 'medium', location: 'Sterile Processing' },

  { key: 'oct-scanner-01', deviceName: 'OCT Scanner 01', deviceType: 'OCT Scanner', department: 'Ophthalmology', manufacturer: 'Zeiss', model: 'CIRRUS HD-OCT', criticality: 'medium', location: 'Ophthalmology Clinic' },
];

export default SEED_MEDICAL_DEVICES;
