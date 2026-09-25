/**
 * CYVRIX V4.1 — thin CI client for GitHub Actions (JavaScript action).
 *
 * One job: ask CYVRIX to analyze THIS repository at THIS commit, then wait
 * for the server-computed result. The Action:
 *
 * - receives ONLY a scoped CYVRIX API key (needs `scans:read` +
 *   `scans:create`; nothing else exists for it to do),
 * - NEVER receives credentials that can approve, authorize, execute, roll
 *   back, or administer anything (no such scope exists),
 * - binds the request to the exact commit SHA of the checkout (github.sha),
 * - NEVER declares its own security result: it polls
 *   GET /api/v1/scans/{id}/status and exits on the SERVER-computed
 *   `result` (PASS/FAIL) or fails closed on ERROR/UNKNOWN/timeout,
 * - fails CLOSED: CYVRIX unreachable, timeout, or an unreadable state is
 *   a FAILED CI step (INCONCLUSIVE), never a silent PASS.
 *
 * Idempotent: an Idempotency-Key derived from (repository, commit) means
 * a retried workflow cannot create duplicate scans.
 */

const GATEWAY = process.env.CYVRIX_API_URL || 'http://localhost:8000';
const API_KEY = process.env.CYVRIX_API_KEY || '';
const OWNER = (process.env.GITHUB_REPOSITORY || '').split('/')[0];
const REPO = (process.env.GITHUB_REPOSITORY || '').split('/')[1];
const SHA = (process.env.GITHUB_SHA || '').toLowerCase();
const EVENT = process.env.CYVRIX_EVENT || 'ci';

const POLL_INTERVAL_MS = 5000;
const POLL_TIMEOUT_MS = 15 * 60 * 1000;

function die(message) {
  process.stderr.write(`cyvrix-ci: ${message}\n`);
  process.exit(1);
}

async function apiCall(path, options) {
  const response = await fetch(`${GATEWAY}${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      'Content-Type': 'application/json',
      ...(options && options.headers ? options.headers : {}),
    },
  });
  return response;
}

async function main() {
  if (!API_KEY) {
    die('CYVRIX_API_KEY is not set — refusing to run (fail closed)');
  }
  if (!OWNER || !REPO || !/^[0-9a-f]{40}$/.test(SHA)) {
    die(`cannot determine repository/commit (repo=${OWNER}/${REPO} sha=${SHA ? SHA.slice(0, 8) : 'none'})`);
  }

  // Resolve the repository id through the public API (scoped read). We do
  // not accept a repository id from workflow input: it is looked up so the
  // commit binding is against the platform's own record of the repository.
  const reposResponse = await apiCall('/api/v1/repositories?limit=200', {});
  if (!reposResponse.ok) {
    die(`cannot list repositories (HTTP ${reposResponse.status}) — fail closed`);
  }
  const reposBody = await reposResponse.json();
  const match = (reposBody.items || []).find(
    (r) => r.owner === OWNER && r.name === REPO,
  );
  if (!match) {
    die(`repository ${OWNER}/${REPO} is not active in CYVRIX — fail closed`);
  }

  // Submit the commit-bound analysis request.
  const idempotencyKey = `ci-${OWNER}-${REPO}-${SHA}`.replace(/[^A-Za-z0-9_.:-]/g, '').slice(0, 200);
  const submit = await apiCall('/api/v1/scans', {
    method: 'POST',
    body: JSON.stringify({ repository_id: match.id, commit_sha: SHA }),
    headers: { 'Idempotency-Key': idempotencyKey },
  });
  if (submit.status === 409) {
    // An analysis is already running for this repository — poll it rather
    // than declaring anything ourselves.
    const conflict = await submit.json().catch(() => ({}));
    if (conflict.code === 'SCAN_IN_PROGRESS' && conflict.details && conflict.details.scan_id) {
      return poll(conflict.details.scan_id);
    }
    die(`submission conflict: ${conflict.code || submit.status} — fail closed`);
  }
  if (!submit.ok) {
    const body = await submit.json().catch(() => ({}));
    die(`submission refused: ${body.code || submit.status} — fail closed`);
  }
  const { scan_id } = await submit.json();
  return poll(scan_id);
}

async function poll(scanId) {
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const response = await apiCall(`/api/v1/scans/${scanId}/status`, {});
    if (!response.ok) {
      die(`status check failed (HTTP ${response.status}) — fail closed (INCONCLUSIVE)`);
    }
    const job = await response.json();

    if (job.commit_binding === 'MISMATCH') {
      die(`COMMIT_MISMATCH: repository advanced past ${SHA.slice(0, 8)} — result not attributable to this commit (INCONCLUSIVE)`);
    }
    if (job.result === 'PASS') {
      process.stdout.write(`cyvrix-ci: analysis completed for ${SHA.slice(0, 8)} (result=${job.result})\n`);
      // Findings are visible in the console; CI gates on pipeline success.
      process.exit(0);
    }
    if (job.result === 'FAIL') {
      die(`analysis failed (${job.error_reason || 'unspecified'}) — INCONCLUSIVE for CI`);
    }
    process.stdout.write(`cyvrix-ci: job ${job.status} (binding=${job.commit_binding})\n`);
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  die('timeout waiting for CYVRIX analysis — fail closed (INCONCLUSIVE)');
}

main().catch((error) => die(error && error.message ? error.message : 'unexpected failure'));
