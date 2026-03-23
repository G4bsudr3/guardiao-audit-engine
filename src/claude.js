import { execa } from 'execa';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROMPTS_DIR = path.join(__dirname, 'prompts');

const AUDIT_TIMEOUT = parseInt(process.env.AUDIT_TIMEOUT_MINUTES || '25', 10) * 60_000;
const REVIEW_TIMEOUT = parseInt(process.env.REVIEW_TIMEOUT_MINUTES || '15', 10) * 60_000;

/**
 * Run Claude Code CLI with a prompt against a repo directory.
 * Returns the parsed JSON array of vulnerabilities.
 */
async function runClaude(repoPath, prompt, { model, timeout, maxTurns }) {
  console.log(`[claude] Running (model=${model}, maxTurns=${maxTurns}, timeout=${timeout / 60000}min)`);

  const { stdout } = await execa('claude', [
    '-p', prompt,
    '--output-format', 'json',
    '--max-turns', String(maxTurns),
    '--model', model,
  ], {
    cwd: repoPath,
    timeout,
    env: {
      ...process.env,
      // Claude Code CLI uses ANTHROPIC_API_KEY from env automatically
    },
    // Capture all output, don't let it go to parent stderr
    reject: true,
  });

  return extractJson(stdout);
}

/**
 * Extract a JSON array from Claude's output.
 * Claude Code with --output-format json wraps the response in a JSON structure.
 * We need to extract the vulnerability array from it.
 */
function extractJson(raw) {
  // --output-format json returns { result: "...", ... }
  // The "result" field contains the text output which should be a JSON array
  try {
    const wrapper = JSON.parse(raw);
    const text = wrapper.result || wrapper.content || raw;

    // If text is already an array, return it
    if (Array.isArray(text)) return text;

    // Try to parse the text as JSON
    if (typeof text === 'string') {
      // Strip markdown code fences if present
      const cleaned = text
        .replace(/^```(?:json)?\s*\n?/m, '')
        .replace(/\n?```\s*$/m, '')
        .trim();

      const parsed = JSON.parse(cleaned);
      return Array.isArray(parsed) ? parsed : [parsed];
    }

    return [];
  } catch {
    // Fallback: try to find a JSON array anywhere in the raw output
    const match = raw.match(/\[[\s\S]*\]/);
    if (match) {
      try {
        return JSON.parse(match[0]);
      } catch {
        // ignore
      }
    }
    console.error('[claude] Failed to parse JSON from output. Raw length:', raw.length);
    return [];
  }
}

/**
 * Validate that a vulnerability object has the required fields.
 */
function isValidVuln(v) {
  return (
    v &&
    typeof v === 'object' &&
    typeof (v.nome || v.titulo) === 'string' &&
    typeof (v.criticidade || v.severity) === 'string'
  );
}

/**
 * Run Pass 1: Comprehensive security audit.
 */
export async function runAuditPass(repoPath, model) {
  const promptTemplate = await fs.readFile(path.join(PROMPTS_DIR, 'audit.md'), 'utf-8');

  const vulns = await runClaude(repoPath, promptTemplate, {
    model,
    timeout: AUDIT_TIMEOUT,
    maxTurns: 50,
  });

  const valid = vulns.filter(isValidVuln);
  console.log(`[claude] Pass 1 complete: ${valid.length} vulnerabilities found (${vulns.length} raw)`);
  return valid;
}

/**
 * Run Pass 2: Review and validate findings from Pass 1.
 */
export async function runReviewPass(repoPath, pass1Vulns, model) {
  const promptTemplate = await fs.readFile(path.join(PROMPTS_DIR, 'review.md'), 'utf-8');

  // Inject Pass 1 results into the review prompt
  const prompt = promptTemplate.replace(
    '<<PASS_1_RESULTS>>',
    JSON.stringify(pass1Vulns, null, 2),
  );

  const vulns = await runClaude(repoPath, prompt, {
    model,
    timeout: REVIEW_TIMEOUT,
    maxTurns: 30,
  });

  const valid = vulns.filter(isValidVuln);
  console.log(`[claude] Pass 2 complete: ${valid.length} confirmed (from ${pass1Vulns.length} candidates)`);
  return valid;
}
