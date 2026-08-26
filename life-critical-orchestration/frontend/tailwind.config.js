/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Consolas', 'monospace'],
      },
      colors: {
        // SOC console palette
        soc: {
          bg:        '#0b0f14',  // page background — near-black with a blue tint
          panel:     '#111821',  // card / panel background
          border:    '#1f2a37',  // subtle borders
          muted:     '#64748b',  // secondary text
          text:      '#e2e8f0',  // primary text
          accent:    '#22d3ee',  // cyan — links, focus rings
        },
        tier: {
          1: '#22c55e',   // green — Tier 1, routine
          2: '#f59e0b',   // amber — Tier 2, monitored
          3: '#ef4444',   // red   — Tier 3, clinician
        },
      },
    },
  },
  plugins: [],
};