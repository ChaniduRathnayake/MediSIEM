// Must be the first import: services imported below (alertPipeline.js ->
// wazuhIndexerService.js/caapService.js) read process.env at module top-level,
// so dotenv has to populate it before those modules are evaluated. ESM
// evaluates sibling imports in file order, so this only works as line 1.
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import mongoose from 'mongoose';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import authRoutes from './routes/auth.js';
import userRoutes from './routes/users.js';
import wazuhRoutes from './routes/wazuh.js';
import auditLogRoutes from './routes/auditLog.js';
import deviceRoutes from './routes/devices.js';
import deviceGroupRoutes from './routes/deviceGroups.js';
import medicalDeviceRoutes from './routes/medicalDevices.js';
import complianceRoutes from './routes/compliance.js';
import alertRoutes from './routes/alerts.js';
import ruleRoutes from './routes/rules.js';
import passwordPolicyRoutes from './routes/passwordPolicy.js';
import threatIntelRoutes from './routes/threatIntel.js';
import detectionPerformanceRoutes from './routes/detectionPerformance.js';
import { startPipeline } from './services/alertPipeline.js';
import { initCveIntel } from './services/cveIntelService.js';
import MedicalDevice from './models/MedicalDevice.js';
import DetectionRule from './models/DetectionRule.js';
import SEED_MEDICAL_DEVICES from './config/seedMedicalDevices.js';

// First-run only, same idempotent pattern as the medical device seed below —
// gives every fresh install one working example of the deviceCriticality/CAS
// fields in action instead of an empty rules list. Admins can edit/disable it
// like any other rule from the Rules tab; this only ever creates it once.
const LIFE_CRITICAL_RULE_NAME = 'Life-critical device — elevated risk';
async function seedLifeCriticalRule() {
  const exists = await DetectionRule.findOne({ name: LIFE_CRITICAL_RULE_NAME });
  if (exists) return;
  await DetectionRule.create({
    name: LIFE_CRITICAL_RULE_NAME,
    description:
      'Flags alerts against a device tagged "critical" in the medical device inventory (ICU ventilators, ' +
      'infusion pumps, defibrillators, ...) once CAS reaches HIGH or above — surfaces device criticality ' +
      'as its own escalation signal, independent of whatever CAS alone would have triggered.',
    enabled: true,
    conditions: [
      { field: 'deviceCriticality', operator: 'equals', value: 'critical' },
      { field: 'CAS', operator: 'gte', value: 6 },
    ],
    createdBy: { id: 'system', name: 'MediSIEM (seeded)' },
  });
  console.log(`🌱  Seeded default detection rule: "${LIFE_CRITICAL_RULE_NAME}"`);
}

// ─── MongoDB Connection ────────────────────────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/medisiem';
mongoose.connect(MONGO_URI)
  .then(async () => {
    console.log('✅  MongoDB connected');
    // First-run only: seed the starter medical device inventory so the CAAP
    // pipeline and the admin Devices tab have real data out of the box.
    // Once devices exist, this is a no-op — the inventory then lives in Mongo,
    // managed from the admin UI (onboard / edit / tag / decommission).
    const existingCount = await MedicalDevice.countDocuments();
    if (existingCount === 0) {
      await MedicalDevice.insertMany(SEED_MEDICAL_DEVICES);
      console.log(`🌱  Seeded ${SEED_MEDICAL_DEVICES.length} starter medical devices`);
    }
    await seedLifeCriticalRule();
  })
  .catch((err) => {
    console.error('❌  MongoDB connection failed:', err.message);
    process.exit(1);
  });

const app = express();
const PORT = process.env.PORT || 5000;
// CORS_ORIGINS env var (comma-separated) lets a real deployment lock this
// down to its actual frontend origin(s) instead of shipping with the dev
// defaults baked in.
const CORS_ORIGINS = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map((o) => o.trim())
  : ['http://localhost:5173', 'http://localhost:3000'];

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(helmet());
app.use(cors({
  origin: CORS_ORIGINS,
  credentials: true,
}));
app.use(express.json({ limit: '1mb' })); // cap request body size — defense against payload-size DoS

// Light global guard against scripted abuse; the auth routes layer their
// own stricter limiter (see routes/auth.js) on top of this.
app.use('/api', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
}));

// ─── Routes ──────────────────────────────────────────────────────────────────
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/wazuh', wazuhRoutes);
app.use('/api/audit-log', auditLogRoutes);
app.use('/api/devices', deviceRoutes);
app.use('/api/device-groups', deviceGroupRoutes);
app.use('/api/medical-devices', medicalDeviceRoutes);
app.use('/api/compliance', complianceRoutes);
app.use('/api/alerts', alertRoutes);
app.use('/api/rules', ruleRoutes);
app.use('/api/password-policy', passwordPolicyRoutes);
app.use('/api/threat-intel', threatIntelRoutes);
app.use('/api/detection-performance', detectionPerformanceRoutes);

// ─── Health Check ────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'MediSIEM API is running', timestamp: new Date().toISOString() });
});

// ─── 404 Handler ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ─── Error Handler ───────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── HTTP server + Socket.IO (for live alert push to the dashboard) ───────────
const httpServer = createServer(app);
const io = new SocketIOServer(httpServer, {
  cors: { origin: CORS_ORIGINS, credentials: true },
});

io.on('connection', (socket) => {
  console.log(`🔌  Dashboard client connected: ${socket.id}`);
  socket.on('disconnect', () => console.log(`🔌  Dashboard client disconnected: ${socket.id}`));
});

httpServer.listen(PORT, () => {
  console.log(`✅  MediSIEM API running on http://localhost:${PORT}`);
  // Start polling the Indexer → CAAP enrichment (pass-through) → live push.
  startPipeline(io);
  // Best-effort CISA KEV fetch for real Active-Exploitation scoring — never
  // blocks startup, degrades to the MITRE-technique heuristic if unreachable.
  initCveIntel();
});
