// Short two-tone alert beep via the Web Audio API — no binary asset to
// source, license, or bundle. A single shared AudioContext is reused (and
// lazily created on first use, since browsers block audio until a user
// gesture has happened somewhere on the page — true for the admin/user
// dashboards, where login is itself a gesture, but NOT for the wallboard:
// that's a kiosk tab meant to be opened cold on a wall-mounted monitor with
// nobody there to click anything, so the context can be created already
// "unlocked" from a prior page yet still sit permanently `suspended` here.
// Resume it opportunistically on ANY interaction the page does get, so a
// single stray click/keypress is enough to unlock every beep after it.
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
    // Autoplay/policy restrictions or an unsupported browser — a missed
    // beep is never worth surfacing as an error to the user.
  }
}
