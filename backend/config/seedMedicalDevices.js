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
  { key: 'pacs-workstation-01', deviceName: 'PACS Workstation 01', deviceType: 'Workstation', department: 'Radiology', manufacturer: 'HP', model: 'Z2 Tower G9', criticality: 'medium', location: 'Radiology' },

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

  { key: 'lab-analyzer-01', deviceName: 'Lab Analyzer 01', deviceType: 'Lab Analyzer', department: 'Laboratory', manufacturer: 'Roche', model: 'cobas 8000', criticality: 'medium', location: 'Laboratory' },
  { key: 'pharmacy-dispenser-01', deviceName: 'Automated Dispensing Cabinet 01', deviceType: 'Automated Dispensing Cabinet', department: 'Pharmacy', manufacturer: 'Omnicell', model: 'XT Cabinet', criticality: 'high', location: 'Pharmacy' },

  { key: 'workstation-admin-01', deviceName: 'Admin Workstation 01', deviceType: 'Workstation', department: 'Administration', manufacturer: 'Dell', model: 'OptiPlex 7010', criticality: 'low', location: 'Administration' },
];

export default SEED_MEDICAL_DEVICES;
