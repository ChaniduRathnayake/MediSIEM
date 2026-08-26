// Loads all 12 stub alerts from the bundled JSON files and flattens them
// into a single array tagged with the expected tier (for the picker UI).
//
// The "expected tier" comes from which file the alert lived in — useful
// for visually grouping the picker, not used in any logic.

import tier1 from "./tier1-cases.json";
import tier2 from "./tier2-cases.json";
import tier3 from "./tier3-cases.json";

function withExpected(group, expectedTier) {
  return group.alerts.map((a) => ({ ...a, _expectedTier: expectedTier }));
}

export const sampleAlerts = [
  ...withExpected(tier1, 1),
  ...withExpected(tier2, 2),
  ...withExpected(tier3, 3),
];