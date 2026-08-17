// Alert beep via the Web Audio API. Browsers block audio until a user gesture happens —
// true at login, but not for the wallboard kiosk tab — so resume opportunistically on any
// interaction, so a single stray click/keypress unlocks every beep after it.
let ctx: AudioContext | null = null;
let unlockListenersAttached = false;

function attemptResume() {
  ctx?.resume().catch(() => {});
}

function attachUnlockListeners() {
  if (unlockListenersAttached || typeof document === 'undefined') return;
  unlockListenersAttached = true;
  const opts = { capture: true, passive: true } as const;
  ['pointerdown', 'keydown', 'touchstart'].forEach((evt) =>
    document.addEventListener(evt, attemptResume, opts)
  );
}

function getContext(): AudioContext | null {
  if (typeof window === 'undefined') return null;
  const AudioCtor = window.AudioContext || (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!AudioCtor) return null;
  if (!ctx) ctx = new AudioCtor();
  attachUnlockListeners();
  return ctx;
}

function beep(audioCtx: AudioContext, freq: number, startAt: number, duration: number, peakGain: number) {
  const osc = audioCtx.createOscillator();
  const gain = audioCtx.createGain();
  osc.type = 'sine';
  osc.frequency.value = freq;
  osc.connect(gain);
  gain.connect(audioCtx.destination);

  // Short attack/decay envelope so it reads as a "ping", not a click or a buzz.
  gain.gain.setValueAtTime(0, startAt);
  gain.gain.linearRampToValueAtTime(peakGain, startAt + 0.02);
  gain.gain.exponentialRampToValueAtTime(0.001, startAt + duration);

  osc.start(startAt);
  osc.stop(startAt + duration);
}

// Two ascending tones — reads as "urgent" without being harsh or long.
export function playAlertSound(): void {
  const audioCtx = getContext();
  if (!audioCtx) return;
  if (audioCtx.state === 'suspended') attemptResume();
  try {
    const now = audioCtx.currentTime;
    beep(audioCtx, 880, now, 0.12, 0.15);
    beep(audioCtx, 1174.66, now + 0.12, 0.16, 0.15);
  } catch {
    // A missed beep is never worth surfacing as an error.
  }
}

// A lower, quieter tone for HIGH (not CRITICAL) alerts — distinct by ear from playAlertSound().
export function playSecondaryAlertSound(): void {
  const audioCtx = getContext();
  if (!audioCtx) return;
  if (audioCtx.state === 'suspended') attemptResume();
  try {
    beep(audioCtx, 587.33, audioCtx.currentTime, 0.14, 0.09);
  } catch {
    // See playAlertSound()'s catch.
  }
}
