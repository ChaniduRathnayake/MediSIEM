import mongoose, { Schema } from 'mongoose';

// Persists AbuseIPDB lookups made by services/ipReputationService.js so the
// cache survives process restarts (an in-memory Map previously lost every
// entry on redeploy, forcing a fresh AbuseIPDB call — and free-tier quota
// burn — for every source IP after every restart).
//
// `checkedAt` carries a TTL index matching the service's CACHE_TTL_MS (1
// hour) so Mongo expires stale entries itself rather than the service
// having to prune them.
const IpReputationCacheSchema = new Schema(
  {
    ip: {
      type: String,
      required: true,
      unique: true,
    },
    score: {
      type: Number,
      required: true,
    },
    checkedAt: {
      type: Date,
      required: true,
      default: Date.now,
      expires: 60 * 60, // seconds — mirrors CACHE_TTL_MS in ipReputationService.js
    },
  },
  {
    timestamps: false,
  }
);

export default mongoose.model('IpReputationCache', IpReputationCacheSchema);
