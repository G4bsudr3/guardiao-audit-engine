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
 * Streams stderr to console for real-time progress.
 * Returns { vulns, cost_usd, duration_ms, num_turns, input_tokens, output_tokens }.
 */
async function runClaude(repoPath, prompt, { model, timeout, maxTurns }) {
  console.log(`[claude] Running (model=${model}, maxTurns=${maxTurns}, timeout=${timeout / 60000}min)`);

  // Build a clean env: only pass what Claude CLI needs, not secrets like GITHUB_PAT
  const cleanEnv = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    NODE_ENV: process.env.NODE_ENV,
  };

  // Support both direct Anthropic API and AWS Bedrock
  if (process.env.CLAUDE_CODE_USE_BEDROCK === '1') {
    cleanEnv.CLAUDE_CODE_USE_BEDROCK = '1';
    cleanEnv.AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;
    cleanEnv.AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY;
    cleanEnv.AWS_REGION = process.env.AWS_REGION;
    if (process.env.AWS_SESSION_TOKEN) cleanEnv.AWS_SESSION_TOKEN = process.env.AWS_SESSION_TOKEN;
  } else {
    cleanEnv.ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
  }

  const subprocess = execa('claude', [
    '-p', prompt,
    '--output-format', 'stream-json',
    '--verbose',
    '--max-turns', String(maxTurns),
    '--model', model,
    '--allowedTools', 'Read,Glob,Grep',
  ], {
    cwd: repoPath,
    timeout,
    env: cleanEnv,
    reject: true,
    buffer: true,
  });

  // Stream stderr for real-time progress
  if (subprocess.stderr) {
    subprocess.stderr.on('data', (chunk) => {
      const line = chunk.toString().trim();
      if (line) console.log(`[claude:stderr] ${line}`);
    });
  }

  // Collect stdout lines for stream-json parsing
  const lines = [];
  if (subprocess.stdout) {
    subprocess.stdout.on('data', (chunk) => {
      const text = chunk.toString();
      for (const line of text.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        lines.push(trimmed);

        // Log interesting events in real-time
        try {
          const event = JSON.parse(trimmed);
          if (event.type === 'assistant' && event.message?.content) {
            for (const block of event.message.content) {
              if (block.type === 'tool_use') {
                console.log(`[claude] Tool: ${block.name} ${block.input?.file_path || block.input?.command || block.input?.pattern || ''}`);
              }
              if (block.type === 'text' && block.text?.length < 200) {
                console.log(`[claude] ${block.text.substring(0, 150)}`);
              }
            }
          }
          if (event.type === 'result') {
            console.log(`[claude] Finished: ${event.num_turns} turns, cost=$${event.total_cost_usd?.toFixed(4) || '0'}, duration=${Math.round((event.duration_ms || 0) / 1000)}s`);
          }
        } catch {
          // Not JSON, ignore
        }
      }
    });
  }

  await subprocess;

  return extractFromStreamJson(lines);
}

/**
 * Extract vulnerabilities + stats from stream-json output.
 */
function extractFromStreamJson(lines) {
  let resultText = '';
  let stats = { cost_usd: 0, duration_ms: 0, num_turns: 0, input_tokens: 0, output_tokens: 0 };

  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const event = JSON.parse(lines[i]);
      if (event.type === 'result') {
        if (!resultText && event.result) resultText = event.result;
        stats.cost_usd = event.total_cost_usd || 0;
        stats.duration_ms = event.duration_ms || 0;
        stats.num_turns = event.num_turns || 0;
        stats.input_tokens = event.usage?.input_tokens || 0;
        stats.output_tokens = event.usage?.output_tokens || 0;
        break;
      }
    } catch {
      // ignore
    }
  }

  if (!resultText) {
    console.error('[claude] No result event found in stream output');
    return { vulns: [], ...stats };
  }

  return { vulns: extractJson(resultText), ...stats };
}

/**
 * Extract a JSON array from Claude's text result.
 */
function extractJson(text) {
  try {
    if (Array.isArray(text)) return text;

    if (typeof text === 'string') {
      const cleaned = text
        .replace(/^```(?:json)?\s*\n?/m, '')
        .replace(/\n?```\s*$/m, '')
        .trim();

      const parsed = JSON.parse(cleaned);
      return Array.isArray(parsed) ? parsed : [parsed];
    }

    return [];
  } catch {
    const match = (typeof text === 'string' ? text : '').match(/\[[\s\S]*\]/);
    if (match) {
      try {
        return JSON.parse(match[0]);
      } catch {
        // ignore
      }
    }
    console.error('[claude] Failed to parse JSON from result. Length:', String(text).length);
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
 * Returns { vulns, cost_usd, duration_ms, num_turns, input_tokens, output_tokens }
 */
export async function runAuditPass(repoPath, model) {
  const promptTemplate = await fs.readFile(path.join(PROMPTS_DIR, 'audit.md'), 'utf-8');

  const result = await runClaude(repoPath, promptTemplate, {
    model,
    timeout: AUDIT_TIMEOUT,
    maxTurns: 50,
  });

  const valid = result.vulns.filter(isValidVuln);
  console.log(`[claude] Pass 1 complete: ${valid.length} vulnerabilities found (${result.vulns.length} raw), cost=$${result.cost_usd.toFixed(4)}`);
  return { ...result, vulns: valid };
}

/**
 * Run Pass 2: Review and validate findings from Pass 1.
 * Returns { vulns, cost_usd, duration_ms, num_turns, input_tokens, output_tokens }
 */
export async function runReviewPass(repoPath, pass1Vulns, model) {
  const promptTemplate = await fs.readFile(path.join(PROMPTS_DIR, 'review.md'), 'utf-8');

  const prompt = promptTemplate.replace(
    '<<PASS_1_RESULTS>>',
    JSON.stringify(pass1Vulns, null, 2),
  );

  const result = await runClaude(repoPath, prompt, {
    model,
    timeout: REVIEW_TIMEOUT,
    maxTurns: 30,
  });

  const valid = result.vulns.filter(isValidVuln);
  console.log(`[claude] Pass 2 complete: ${valid.length} confirmed (from ${pass1Vulns.length} candidates), cost=$${result.cost_usd.toFixed(4)}`);
  return { ...result, vulns: valid };
}
