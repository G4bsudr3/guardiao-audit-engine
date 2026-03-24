import express from 'express';
import crypto from 'node:crypto';
import { Queue } from 'bullmq';
import IORedis from 'ioredis';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const API_KEY = process.env.AUDIT_SERVICE_API_KEY;

const ALLOWED_MODELS = [
  'claude-sonnet-4-6',
  'claude-opus-4-6',
  'claude-haiku-4-5-20251001',
  'claude-sonnet-4-5-20241022',
];
const DEFAULT_MODEL = process.env.DEFAULT_MODEL || 'claude-sonnet-4-6';

if (!API_KEY) {
  console.error('FATAL: AUDIT_SERVICE_API_KEY is not set');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Redis + BullMQ queue
// ---------------------------------------------------------------------------
const redis = new IORedis(REDIS_URL, { maxRetriesPerRequest: null });

const auditQueue = new Queue('security-audit', {
  connection: redis,
  defaultJobOptions: {
    attempts: 2,
    backoff: { type: 'exponential', delay: 60_000 },
    removeOnComplete: { age: 7 * 86_400 },   // keep 7 days
    removeOnFail: { age: 30 * 86_400 },       // keep 30 days
    timeout: 45 * 60_000,                      // 45 min hard cap
  },
});

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json({ limit: '10kb' }));

// Timing-safe API key comparison
function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key || typeof key !== 'string') {
    return res.status(401).json({ error: 'Unauthorized: missing x-api-key' });
  }
  const a = Buffer.from(key);
  const b = Buffer.from(API_KEY);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'Unauthorized: invalid x-api-key' });
  }
  next();
}

// Simple in-memory rate limiter per API key (max 10 audits per minute)
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 10;

function rateLimit(req, res, next) {
  const now = Date.now();
  const key = 'global'; // single key since there's one API key
  let entry = rateLimitMap.get(key);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    entry = { windowStart: now, count: 0 };
    rateLimitMap.set(key, entry);
  }
  entry.count++;
  if (entry.count > RATE_LIMIT_MAX) {
    return res.status(429).json({ error: `Rate limit exceeded (max ${RATE_LIMIT_MAX} per minute)` });
  }
  next();
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Health check (no auth)
app.get('/api/health', async (_req, res) => {
  try {
    const waiting = await auditQueue.getWaitingCount();
    const active = await auditQueue.getActiveCount();
    res.json({ status: 'ok', queue: { waiting, active } });
  } catch (err) {
    res.status(503).json({ status: 'error', error: err.message });
  }
});

// Trigger a new audit
app.post('/api/audit', requireApiKey, rateLimit, async (req, res) => {
  const { repo_url, lovable_project_id, aplicacao_id, security_analysis_id, model } = req.body;

  if (!repo_url || typeof repo_url !== 'string') {
    return res.status(400).json({ error: 'repo_url is required' });
  }
  if (!lovable_project_id || typeof lovable_project_id !== 'string') {
    return res.status(400).json({ error: 'lovable_project_id is required' });
  }

  // Strict URL validation: must be https://github.com/owner/repo[.git]
  let parsedUrl;
  try {
    parsedUrl = new URL(repo_url);
  } catch {
    return res.status(400).json({ error: 'repo_url is not a valid URL' });
  }
  if (parsedUrl.hostname !== 'github.com' || parsedUrl.protocol !== 'https:') {
    return res.status(400).json({ error: 'repo_url must be a GitHub HTTPS URL (https://github.com/owner/repo)' });
  }
  if (parsedUrl.username || parsedUrl.password) {
    return res.status(400).json({ error: 'repo_url must not contain credentials' });
  }
  const pathSegments = parsedUrl.pathname.replace(/\.git$/, '').split('/').filter(Boolean);
  if (pathSegments.length < 2) {
    return res.status(400).json({ error: 'repo_url must contain owner and repo' });
  }

  // Validate model against allowlist
  const safeModel = (model && ALLOWED_MODELS.includes(model)) ? model : DEFAULT_MODEL;

  const job = await auditQueue.add('audit', {
    repo_url: `https://github.com/${pathSegments[0]}/${pathSegments[1]}`, // normalized
    lovable_project_id,
    aplicacao_id: aplicacao_id || null,
    security_analysis_id: security_analysis_id || null,
    model: safeModel,
    requested_at: new Date().toISOString(),
  });

  const waiting = await auditQueue.getWaitingCount();

  res.status(202).json({
    job_id: job.id,
    status: 'queued',
    position: waiting,
  });
});

// Poll job status
app.get('/api/audit/:jobId', requireApiKey, async (req, res) => {
  const job = await auditQueue.getJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({ error: 'Job not found' });
  }

  const state = await job.getState();
  const progress = job.progress || 0;

  res.json({
    job_id: job.id,
    status: state,
    progress,
    data: {
      repo_url: job.data.repo_url,
      lovable_project_id: job.data.lovable_project_id,
      model: job.data.model,
    },
    started_at: job.processedOn ? new Date(job.processedOn).toISOString() : null,
    finished_at: job.finishedOn ? new Date(job.finishedOn).toISOString() : null,
    result: job.returnvalue || null,
    error: job.failedReason || null,
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`[audit-engine] API listening on port ${PORT}`);
  // Sanitize Redis URL to avoid logging password
  const safeRedisUrl = REDIS_URL.replace(/:([^@]+)@/, ':***@');
  console.log(`[audit-engine] Redis: ${safeRedisUrl}`);
});
