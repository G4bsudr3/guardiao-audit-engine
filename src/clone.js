import { execa } from 'execa';
import fs from 'node:fs/promises';
import path from 'node:path';

const WORK_DIR = process.env.WORK_DIR || '/workdir';
const GITHUB_PAT = process.env.GITHUB_PAT;
const CLONE_DEPTH = parseInt(process.env.CLONE_DEPTH || '1', 10);
const MAX_REPO_SIZE_MB = parseInt(process.env.MAX_REPO_SIZE_MB || '500', 10);

/**
 * Parse and validate a GitHub HTTPS URL.
 * Returns { owner, repo } or throws.
 */
function parseGitHubUrl(repoUrl) {
  let parsed;
  try {
    parsed = new URL(repoUrl);
  } catch {
    throw new Error(`Invalid URL: ${repoUrl}`);
  }

  if (parsed.hostname !== 'github.com') {
    throw new Error(`Invalid hostname: ${parsed.hostname} (expected github.com)`);
  }
  if (parsed.protocol !== 'https:') {
    throw new Error(`Invalid protocol: ${parsed.protocol} (expected https:)`);
  }
  if (parsed.username || parsed.password) {
    throw new Error('URL must not contain credentials');
  }

  const segments = parsed.pathname.replace(/\.git$/, '').split('/').filter(Boolean);
  if (segments.length < 2) {
    throw new Error('URL must contain owner and repo (https://github.com/owner/repo)');
  }

  const owner = segments[0];
  const repo = segments[1];

  // Prevent path traversal
  if (/[^a-zA-Z0-9._-]/.test(owner) || /[^a-zA-Z0-9._-]/.test(repo)) {
    throw new Error('Owner/repo contain invalid characters');
  }

  return { owner, repo };
}

/**
 * Clone a GitHub repository into an isolated working directory.
 * Returns the absolute path to the cloned repo.
 */
export async function cloneRepo(repoUrl, jobId) {
  if (!GITHUB_PAT) {
    throw new Error('GITHUB_PAT is not configured');
  }

  const { owner, repo } = parseGitHubUrl(repoUrl);

  // Build authenticated URL safely
  const authedUrl = `https://${GITHUB_PAT}@github.com/${owner}/${repo}.git`;

  const jobDir = path.join(WORK_DIR, `audit-${jobId}`);
  await fs.mkdir(jobDir, { recursive: true });

  const repoPath = path.join(jobDir, repo);

  console.log(`[clone] Cloning github.com/${owner}/${repo} (depth ${CLONE_DEPTH}) into ${repoPath}`);

  try {
    await execa('git', [
      'clone',
      '--depth', String(CLONE_DEPTH),
      '--single-branch',
      authedUrl,
      repoPath,
    ], {
      timeout: 5 * 60_000, // 5 min timeout for clone
      env: { GIT_TERMINAL_PROMPT: '0' }, // never prompt for credentials
    });
  } catch (err) {
    // Sanitize error to prevent GITHUB_PAT leaking in logs/stack traces
    const sanitized = (err.message || '').replaceAll(GITHUB_PAT, '***');
    throw new Error(`Git clone failed (exit ${err.exitCode ?? 'unknown'}): ${sanitized}`);
  }

  // Check repo size
  const sizeBytes = await getDirSize(repoPath);
  const sizeMB = Math.round(sizeBytes / (1024 * 1024));
  console.log(`[clone] Repo size: ${sizeMB} MB`);

  if (sizeMB > MAX_REPO_SIZE_MB) {
    console.warn(`[clone] WARNING: Repo is ${sizeMB} MB (limit: ${MAX_REPO_SIZE_MB} MB)`);
  }

  return repoPath;
}

/**
 * Remove the entire job working directory.
 */
export async function cleanupRepo(jobId) {
  const jobDir = path.join(WORK_DIR, `audit-${jobId}`);
  try {
    await fs.rm(jobDir, { recursive: true, force: true });
    console.log(`[clone] Cleaned up ${jobDir}`);
  } catch (err) {
    console.error(`[clone] Cleanup failed for ${jobDir}: ${err.message}`);
  }
}

/**
 * Recursively calculate directory size in bytes.
 */
async function getDirSize(dirPath) {
  let total = 0;
  try {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      if (entry.name === '.git') continue; // skip .git for size calculation
      if (entry.isDirectory()) {
        total += await getDirSize(fullPath);
      } else {
        const stat = await fs.stat(fullPath);
        total += stat.size;
      }
    }
  } catch {
    // ignore permission errors
  }
  return total;
}
