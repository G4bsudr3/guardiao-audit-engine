import fs from 'node:fs/promises';
import path from 'node:path';

const CALLBACK_URL = process.env.GUARDIAO_CALLBACK_URL;
const CRON_SECRET = process.env.GUARDIAO_CRON_SECRET;
const FAILED_DIR = process.env.FAILED_SUBMISSIONS_DIR || '/data/failed-submissions';
const MAX_RETRIES = 3;
const RETRY_DELAYS = [1_000, 5_000, 25_000]; // exponential-ish

/**
 * Submit confirmed vulnerabilities to the Guardiao ingest endpoint.
 * Retries on failure; saves to disk as last resort.
 */
export async function submitResults(payload, jobId) {
  if (!CALLBACK_URL) throw new Error('GUARDIAO_CALLBACK_URL is not configured');
  if (!CRON_SECRET) throw new Error('GUARDIAO_CRON_SECRET is not configured');

  const body = JSON.stringify(payload);

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      console.log(`[submit] Attempt ${attempt + 1}/${MAX_RETRIES} -> ${CALLBACK_URL}`);

      const res = await fetch(CALLBACK_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-cron-secret': CRON_SECRET,
        },
        body,
        signal: AbortSignal.timeout(30_000), // 30s per request
      });

      if (!res.ok) {
        const errBody = await res.text().catch(() => 'no body');
        throw new Error(`HTTP ${res.status}: ${errBody}`);
      }

      const result = await res.json();
      console.log(`[submit] Success: ${result.inserted_count || 0} vulnerabilities ingested`);
      return result;

    } catch (err) {
      console.error(`[submit] Attempt ${attempt + 1} failed: ${err.message}`);

      if (attempt < MAX_RETRIES - 1) {
        const delay = RETRY_DELAYS[attempt];
        console.log(`[submit] Retrying in ${delay / 1000}s...`);
        await sleep(delay);
      }
    }
  }

  // All retries exhausted — save to disk for manual recovery
  await saveFailedSubmission(payload, jobId);
  throw new Error(`Failed to submit after ${MAX_RETRIES} attempts. Saved to ${FAILED_DIR}`);
}

/**
 * Save a failed submission to disk for later replay.
 */
async function saveFailedSubmission(payload, jobId) {
  try {
    await fs.mkdir(FAILED_DIR, { recursive: true });
    const filePath = path.join(FAILED_DIR, `job-${jobId}-${Date.now()}.json`);
    await fs.writeFile(filePath, JSON.stringify(payload, null, 2), 'utf-8');
    console.error(`[submit] Saved failed submission to ${filePath}`);
  } catch (err) {
    console.error(`[submit] Could not save failed submission: ${err.message}`);
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
