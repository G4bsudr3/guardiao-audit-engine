import express from 'express';
import { Queue } from 'bullmq';
import IORedis from 'ioredis';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const API_KEY = process.env.AUDIT_SERVICE_API_KEY;

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
app.use(express.json());

function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key || key !== API_KEY) {
    return res.status(401).json({ error: 'Unauthorized: invalid or missing x-api-key' });
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
app.post('/api/audit', requireApiKey, async (req, res) => {
  const { repo_url, lovable_project_id, aplicacao_id, security_analysis_id, model } = req.body;

  if (!repo_url) {
    return res.status(400).json({ error: 'repo_url is required' });
  }
  if (!lovable_project_id) {
    return res.status(400).json({ error: 'lovable_project_id is required' });
  }

  // Basic URL validation
  if (!/^https:\/\/github\.com\/.+\/.+/i.test(repo_url)) {
    return res.status(400).json({ error: 'repo_url must be a valid GitHub HTTPS URL' });
  }

  const job = await auditQueue.add('audit', {
    repo_url,
    lovable_project_id,
    aplicacao_id: aplicacao_id || null,
    security_analysis_id: security_analysis_id || null,
    model: model || process.env.DEFAULT_MODEL || 'claude-sonnet-4-6',
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
  console.log(`[audit-engine] Redis: ${REDIS_URL}`);
});
