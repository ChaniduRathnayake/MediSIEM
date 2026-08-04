import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import authRoutes from './routes/auth.js';
import userRoutes from './routes/users.js';
import alertRoutes from './routes/alerts.js';
import { startPipeline } from './services/alertPipeline.js';

dotenv.config();

// ─── MongoDB Connection ────────────────────────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/medisiem';
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅  MongoDB connected'))
  .catch((err) => {
    console.error('❌  MongoDB connection failed:', err.message);
    process.exit(1);
  });

const app = express();
const PORT = process.env.PORT || 5000;
const CORS_ORIGINS = ['http://localhost:5173', 'http://localhost:3000'];

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({
  origin: CORS_ORIGINS,
  credentials: true,
}));
app.use(express.json());

// ─── Routes ──────────────────────────────────────────────────────────────────
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/alerts', alertRoutes);

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
  // Start pulling from Wazuh → CAAP → live push once the server is up.
  startPipeline(io);
});
