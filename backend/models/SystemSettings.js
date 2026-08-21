import mongoose, { Schema } from 'mongoose';

// ─── Schema ────────────────────────────────────────────────────────────────────
// Singleton — there is only ever one settings document (same pattern as
// PasswordPolicy.js). Holds every integration credential that used to only be
// configurable via backend/.env (SMTP, Slack/Teams webhooks, LLM/threat-intel
// API keys) so an admin can wire them up from the dashboard instead of
// editing server-side config and restarting the process.
//
// Every credential field is `select: false` — never returned by a normal
// query, never echoed back in a GET response. Routes that need the real
// value must explicitly `.select('+field')`; the settings route itself only
// ever exposes `*Configured: boolean` flags derived from these, same as how
// User.password already works.
const SystemSettingsSchema = new Schema(
  {
    smtp: {
      host: { type: String, default: '' },
      port: { type: Number, default: 587 },
      secure: { type: Boolean, default: false },
      user: { type: String, default: '' },
      pass: { type: String, default: '', select: false },
      fromAddress: { type: String, default: '' },
    },
    // Who receives an email when an Immediate-CAS alert fires — separate
    // from smtp.user, since the SMTP account sending mail isn't necessarily
    // who should be paged.
    notifyEmailRecipients: { type: [String], default: [] },
    slackWebhookUrl: { type: String, default: '', select: false },
    teamsWebhookUrl: { type: String, default: '', select: false },
    // AI-assistant provider — Google Gemini (Generative Language API), called
    // directly over REST in services/geminiClient.js rather than an SDK dependency.
    googleApiKey: { type: String, default: '', select: false },
    abuseIpdbApiKey: { type: String, default: '', select: false },
    mfaRequiredForAdmin: { type: Boolean, default: false },
    // Login lockout policy — was hardcoded in routes/auth.js; now
    // admin-tunable from the same Settings → Integrations panel instead of
    // requiring a code change + restart to adjust.
    lockout: {
      maxAttempts: { type: Number, default: 5, min: 3, max: 20 },
      lockDurationMinutes: { type: Number, default: 15, min: 1, max: 1440 },
    },
    notifyOnImmediateCas: { type: Boolean, default: false },
    notifyChannels: {
      email: { type: Boolean, default: false },
      slack: { type: Boolean, default: false },
      teams: { type: Boolean, default: false },
    },
    // Optional overrides for the CAS scoring weight vector — every field
    // undefined by default, so nothing changes for existing deployments
    // until an admin actively edits something in Settings -> CAS Weights.
    // Falls through to shared/cas_config.json's AHP-justified default (and
    // its named scenario profiles) when unset — see
    // backend/services/caapService.js's resolveCasWeights(). Route-level
    // validation (routes/settings.js) requires each fully-specified profile
    // to sum to 1.00 +/- 0.01; the schema itself stays permissive (Mixed)
    // since the same 5-key shape needs to live both at `default` and per
    // scenario key, which Mongoose's static schema syntax can't express
    // cleanly without one sub-schema per scenario.
    casWeights: {
      default: { type: Schema.Types.Mixed, default: undefined },
      scenarios: { type: Schema.Types.Mixed, default: undefined },
    },
    updatedBy: {
      id: String,
      name: String,
    },
  },
  {
    timestamps: true,
  }
);

SystemSettingsSchema.set('toJSON', {
  transform(_doc, ret) {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

export default mongoose.model('SystemSettings', SystemSettingsSchema);
