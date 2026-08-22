// Must be the first import — modules below read process.env at top-level.
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
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
import reportRoutes from './routes/reports.js';
import ruleRoutes from './routes/rules.js';
import passwordPolicyRoutes from './routes/passwordPolicy.js';
import threatIntelRoutes from './routes/threatIntel.js';
import detectionPerformanceRoutes from './routes/detectionPerformance.js';
import settingsRoutes from './routes/settings.js';
import assistantRoutes from './routes/assistant.js';
import { startPipeline } from './services/alertPipeline.js';
import { initCveIntel } from './services/cveIntelService.js';
import MedicalDevice from './models/MedicalDevice.js';
import DetectionRule from './models/DetectionRule.js';
import SEED_MEDICAL_DEVICES from './config/seedMedicalDevices.js';
import JWT_SECRET from './config/jwt.js';

// First-run only — gives every fresh install one working example rule instead of an empty list.
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

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/medisiem';
mongoose.connect(MONGO_URI)
  .then(async () => {
    console.log('✅  MongoDB connected');
    // First-run only — a no-op once devices exist in Mongo.
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
const CORS_ORIGINS = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map((o) => o.trim())
  : ['http://localhost:5173', 'http://localhost:3000'];

app.use(helmet());
app.use(cors({
  origin: CORS_ORIGINS,
  credentials: true,
}));
app.use(express.json({ limit: '1mb' })); // defense against payload-size DoS
app.use(mongoSanitize()); // strips '$'/'.' keys — defense against NoSQL operator injection

// Auth routes layer their own stricter limiter on top of this.
app.use('/api', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
}));

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/wazuh', wazuhRoutes);
app.use('/api/audit-log', auditLogRoutes);
app.use('/api/devices', deviceRoutes);
app.use('/api/device-groups', deviceGroupRoutes);
app.use('/api/medical-devices', medicalDeviceRoutes);
app.use('/api/compliance', complianceRoutes);
app.use('/api/alerts', alertRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/rules', ruleRoutes);
app.use('/api/password-policy', passwordPolicyRoutes);
app.use('/api/threat-intel', threatIntelRoutes);
app.use('/api/detection-performance', detectionPerformanceRoutes);
app.use('/api/settings', settingsRoutes);
app.use('/api/assistant', assistantRoutes);

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'MediSIEM API is running', timestamp: new Date().toISOString() });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

const httpServer = createServer(app);
const io = new SocketIOServer(httpServer, {
  cors: { origin: CORS_ORIGINS, credentials: true },
});

// Every live alert is broadcast to every connected socket, so an unauthenticated
// connection would leak the whole feed — require the same JWT the REST API uses.
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('Not authorised.'));
  try {
    jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    next();
  } catch {
    next(new Error('Not authorised.'));
  }
});

io.on('connection', (socket) => {
  console.log(`🔌  Dashboard client connected: ${socket.id}`);
  socket.on('disconnect', () => console.log(`🔌  Dashboard client disconnected: ${socket.id}`));
});

// Lets route handlers (e.g. the @mention notification in routes/alerts.js) emit over the
// same socket set, without threading `io` through every import.
app.set('io', io);

httpServer.listen(PORT, () => {
  console.log(`✅  MediSIEM API running on http://localhost:${PORT}`);
  startPipeline(io);
  initCveIntel(); // best-effort CISA KEV fetch, never blocks startup
});
