# Data

Stub datasets for development and testing. No real patient data is ever stored
or processed in this project.

## Contents

```
data/
├── sample-alerts/
│   ├── tier1-cases.json   # Non-critical asset alerts (e.g. cafeteria PC)
│   ├── tier2-cases.json   # Life-critical asset alerts, standard risk
│   └── tier3-cases.json   # Life-critical asset alerts, extreme risk
└── README.md              # this file
```

## Format

All sample alerts conform to the enriched-alert schema documented in
`docs/alert-schema.md`. They represent the output of the enrichment module
(real or stubbed) — i.e. what the decision engine actually receives.

## Sources

Sample alerts are synthesised from publicly reported healthcare cyber-incident
case studies. No real hospital logs are used.

## Status

⚪ Sample data not yet generated. Target: Day 1 of PP1 plan.
