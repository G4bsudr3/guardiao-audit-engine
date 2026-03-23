import { Worker } from 'bullmq';
import IORedis from 'ioredis';
import { cloneRepo, cleanupRepo } from './clone.js';
import { runAuditPass, runReviewPass } from './claude.js';
import { submitResults } from './submit.js';

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

// ---------------------------------------------------------------------------
// Progress steps
// ---------------------------------------------------------------------------
const PROGRESS = {
  queued: 0,
  cloning: 5,
  auditing_pass1: 15,
  auditing_pass2: 60,
  submitting: 90,
  completed: 100,
};

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------
const redis = new IORedis(REDIS_URL, { maxRetriesPerRequest: null });

const worker = new Worker('security-audit', processAudit, {
  connection: redis,
  concurrency: 1, // one audit at a time
  limiter: { max: 1, duration: 5_000 },
});

async function processAudit(job) {
  const {
    repo_url,
    lovable_project_id,
    aplicacao_id,
    security_analysis_id,
    model,
  } = job.data;

  const startTime = Date.now();
  console.log(`\n${'='.repeat(60)}`);
  console.log(`[worker] Starting job ${job.id}`);
  console.log(`[worker] Repo: ${repo_url}`);
  console.log(`[worker] Model: ${model}`);
  console.log(`${'='.repeat(60)}\n`);

  try {
    // --- Step 1: Clone ---
    await job.updateProgress(PROGRESS.cloning);
    await job.log('Cloning repository...');
    const repoPath = await cloneRepo(repo_url, job.id);
    await job.log(`Clone complete: ${repoPath}`);

    // --- Step 2: Audit Pass 1 ---
    await job.updateProgress(PROGRESS.auditing_pass1);
    await job.log('Starting Pass 1: comprehensive audit...');
    const pass1Vulns = await runAuditPass(repoPath, model);
    await job.log(`Pass 1 found ${pass1Vulns.length} vulnerabilities`);

    // If Pass 1 found nothing, skip Pass 2
    if (pass1Vulns.length === 0) {
      console.log('[worker] No vulnerabilities found in Pass 1. Skipping Pass 2.');
      await job.log('No vulnerabilities found. Skipping review pass.');

      await job.updateProgress(PROGRESS.submitting);
      await submitResults({
        security_analysis_id,
        lovable_project_id,
        aplicacao_id,
        vulnerabilities: [],
        metadata: buildMetadata(job, startTime, 0, 0, model),
      }, job.id);

      await cleanupRepo(job.id);
      await job.updateProgress(PROGRESS.completed);

      return { total: 0, status: 'completed', pass1_count: 0, pass2_count: 0 };
    }

    // --- Step 3: Review Pass 2 ---
    await job.updateProgress(PROGRESS.auditing_pass2);
    await job.log('Starting Pass 2: review and validation...');
    const confirmedVulns = await runReviewPass(repoPath, pass1Vulns, model);
    await job.log(`Pass 2 confirmed ${confirmedVulns.length} of ${pass1Vulns.length} findings`);

    // --- Step 4: Submit ---
    await job.updateProgress(PROGRESS.submitting);
    await job.log('Submitting results to Guardiao...');
    await submitResults({
      security_analysis_id,
      lovable_project_id,
      aplicacao_id,
      vulnerabilities: confirmedVulns,
      metadata: buildMetadata(job, startTime, pass1Vulns.length, confirmedVulns.length, model),
    }, job.id);
    await job.log('Results submitted successfully');

    // --- Step 5: Cleanup ---
    await cleanupRepo(job.id);
    await job.updateProgress(PROGRESS.completed);

    const summary = buildSummary(confirmedVulns);
    console.log(`[worker] Job ${job.id} completed. ${confirmedVulns.length} vulnerabilities confirmed.`);
    console.log(`[worker] Summary: ${JSON.stringify(summary)}`);

    return {
      total: confirmedVulns.length,
      status: 'completed',
      pass1_count: pass1Vulns.length,
      pass2_count: confirmedVulns.length,
      summary,
    };

  } catch (err) {
    console.error(`[worker] Job ${job.id} failed: ${err.message}`);
    await job.log(`ERROR: ${err.message}`);

    // Always cleanup, even on failure
    await cleanupRepo(job.id);
    throw err; // BullMQ handles retry
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildMetadata(job, startTime, pass1Count, pass2Count, model) {
  return {
    job_id: job.id,
    repo_url: job.data.repo_url,
    audit_duration_seconds: Math.round((Date.now() - startTime) / 1000),
    pass1_count: pass1Count,
    pass2_count: pass2Count,
    model,
    engine_version: '1.0.0',
  };
}

function buildSummary(vulns) {
  const counts = { critica: 0, alta: 0, media: 0, baixa: 0, info: 0 };
  for (const v of vulns) {
    const c = normalizeCriticidade(v.criticidade || v.severity || 'Info');
    if (c === 'Crítica') counts.critica++;
    else if (c === 'Alta') counts.alta++;
    else if (c === 'Média') counts.media++;
    else if (c === 'Baixa') counts.baixa++;
    else counts.info++;
  }
  return counts;
}

function normalizeCriticidade(value) {
  const lower = (value || '').toLowerCase();
  if (lower.includes('crít') || lower.includes('crit') || lower === 'critical') return 'Crítica';
  if (lower.includes('alta') || lower === 'high') return 'Alta';
  if (lower.includes('méd') || lower.includes('med') || lower === 'medium') return 'Média';
  if (lower.includes('baixa') || lower === 'low') return 'Baixa';
  return 'Info';
}

// ---------------------------------------------------------------------------
// Event handlers
// ---------------------------------------------------------------------------
worker.on('completed', (job, result) => {
  console.log(`[worker] Job ${job.id} completed: ${JSON.stringify(result)}`);
});

worker.on('failed', (job, err) => {
  console.error(`[worker] Job ${job?.id} failed permanently: ${err.message}`);
  // TODO: send Slack notification on permanent failure
});

worker.on('error', (err) => {
  console.error(`[worker] Worker error: ${err.message}`);
});

console.log('[worker] Audit worker started. Waiting for jobs...');
