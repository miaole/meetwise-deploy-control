import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import fs from 'node:fs';
import {
  accountDigest,
  buildVerifierIdentity,
  buildUnsignedReceipt,
  canonical,
  networkRequestDecision,
  signReceipt,
  validateCredentialInputs,
  validateReceiptShape,
  validateRedirect,
  verifyReceiptSignature,
} from './verify-preview-e2e.mjs';

let assertions = 0;
function check(name, condition) {
  assert.equal(Boolean(condition), true, name);
  assertions += 1;
}
function rejects(name, fn, expected) {
  assert.throws(fn, expected, name);
  assertions += 1;
}

const context = {
  schemaVersion: 1,
  origin: 'https://preview-tail1234.tail1234.ts.net',
  probeNonce: 'a'.repeat(64),
  manifestSha256: 'b'.repeat(64),
  rootStatus: 200,
  loginStatus: 200,
  manifestStatus: 200,
  rootUrl: 'https://preview-tail1234.tail1234.ts.net/',
  loginUrl: 'https://preview-tail1234.tail1234.ts.net/login',
  manifestUrl: 'https://preview-tail1234.tail1234.ts.net/preview-release-manifest.json',
  rootSha256: 'c'.repeat(64),
  blackboxSha256: 'd'.repeat(64),
};

const workflow = fs.readFileSync(new URL('../.github/workflows/verify.yml', import.meta.url), 'utf8');
const verifierSource = fs.readFileSync(new URL('./verify-preview-e2e.mjs', import.meta.url), 'utf8');
const packageLock = JSON.parse(fs.readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8'));
check('workflow keeps the verifier environment protected and read-only', workflow.includes('environment: preview-verifier') && workflow.includes('contents: read') && !workflow.includes('docker'));
check('workflow pins checkout, setup-node and artifact actions', workflow.includes('actions/checkout@11d5960a326750d5838078e36cf38b85af677262') && workflow.includes('actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020') && workflow.includes('actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'));
check('workflow passes all four fixed account secret names only to the E2E step', ['PREVIEW_C_EMAIL', 'PREVIEW_C_PASSWORD', 'PREVIEW_B_EMAIL', 'PREVIEW_B_PASSWORD'].every((name) => workflow.includes(`secrets.${name}`)) && !workflow.includes('123456'));
check('workflow pins Playwright package and package-lock integrity', packageLock.packages?.['node_modules/playwright']?.version === '1.61.1' && packageLock.packages?.['node_modules/playwright']?.integrity?.startsWith('sha512-') && packageLock.packages?.['node_modules/playwright-core']?.version === '1.61.1');
check('workflow runs the behavior proof before the real browser E2E', workflow.includes('Run verifier behavior proof before browser E2E') && workflow.indexOf('Run verifier behavior proof before browser E2E') < workflow.indexOf('Real browser B/C login and read-only E2E'));
check('workflow signs and uploads only the exact E2E receipt after the browser step', workflow.indexOf('id: e2e') < workflow.indexOf('path: ${{ steps.e2e.outputs.receipt_path }}') && workflow.includes('scripts/verify-preview-e2e.mjs'));
check('browser verifier blocks service workers and websocket traffic', verifierSource.includes("serviceWorkers: 'block'") && verifierSource.includes('routeWebSocket') && verifierSource.includes('socket.close()'));
check('browser verifier has a single-origin read-only request policy', verifierSource.includes('networkRequestDecision') && verifierSource.includes("return route.abort('blockedbyclient')"));
check('browser verifier verifies the privacy page and explicitly omits export bodies', verifierSource.includes("pagePlan('/privacy', ['隐私与数据边界'])") && !verifierSource.includes("'/api/privacy/export'") && verifierSource.includes('privacy export is intentionally omitted'));
check('browser verifier requires secure httpOnly session cookies and role cookies', verifierSource.includes('token.httpOnly !== true') && verifierSource.includes('token.secure !== true') && verifierSource.includes('roleCookie.secure !== true'));

check('fixed C/B account identities are accepted', validateCredentialInputs({
  cEmail: 'previewc@meetwise.com', cPassword: 'candidate-password',
  bEmail: 'previewb@meetwise.com', bPassword: 'recruiter-password',
}));
check('account receipt identity is a digest, not an email', /^[a-f0-9]{64}$/.test(accountDigest('previewc@meetwise.com')));
rejects('email drift fails closed', () => validateCredentialInputs({
  cEmail: 'other@example.test', cPassword: 'candidate-password',
  bEmail: 'previewb@meetwise.com', bPassword: 'recruiter-password',
}), /credential_account_mismatch/);
rejects('short password fails closed', () => validateCredentialInputs({
  cEmail: 'previewc@meetwise.com', cPassword: '123456',
  bEmail: 'previewb@meetwise.com', bPassword: 'recruiter-password',
}), /credential_password_length_invalid/);

const redirect = validateRedirect(`${context.origin}/login?next=%2Fdashboard`, context.origin);
check('protected redirect is exact and same origin', redirect.origin === context.origin && redirect.pathname === '/login' && redirect.search === '?next=%2Fdashboard');
rejects('localhost redirect is rejected', () => validateRedirect('http://localhost:3000/login?next=%2Fdashboard', context.origin), /protected_redirect_localhost/);
rejects('cross-origin redirect is rejected', () => validateRedirect('https://evil.example/login?next=%2Fdashboard', context.origin), /protected_redirect_target_invalid/);

check('network policy permits same-origin reads', networkRequestDecision({ origin: context.origin, method: 'GET', requestUrl: `${context.origin}/dashboard` }) === 'continue');
check('network policy permits only the same-origin login POST', networkRequestDecision({ origin: context.origin, method: 'POST', requestUrl: `${context.origin}/login` }) === 'continue');
check('network policy rejects same-origin non-login writes', networkRequestDecision({ origin: context.origin, method: 'POST', requestUrl: `${context.origin}/api/interviews` }) === 'abort');
check('network policy rejects cross-origin reads', networkRequestDecision({ origin: context.origin, method: 'GET', requestUrl: 'https://evil.example/' }) === 'abort');
check('network policy rejects malformed URLs', networkRequestDecision({ origin: context.origin, method: 'GET', requestUrl: 'not a url' }) === 'abort');

const page = (path, bodyHash, markerHash, negativeHash) => ({
  path,
  status: 200,
  headers: { 'content-type': 'text/html' },
  bodyHash,
  bodyStored: false,
  markerHashes: [markerHash],
  negativeMarkerHashes: [negativeHash],
});
const candidate = {
  role: 'candidate',
  accountEmailSha256: accountDigest('previewc@meetwise.com'),
  loginPath: '/dashboard',
  sessionCookie: { httpOnly: true, secure: true, roleCookie: 'candidate' },
  pages: [page('/dashboard', 'e'.repeat(64), '1'.repeat(64), '2'.repeat(64)), page('/settings', '3'.repeat(64), '4'.repeat(64), '5'.repeat(64))],
  roleBoundary: { status: 'verified', path: '/recruiter/jobs', markerHashes: ['6'.repeat(64)] },
  api: { status: 'unproven', reason: 'privacy export is intentionally omitted because Playwright API responses may buffer personal data' },
  sse: { status: 'unproven', reason: 'no stable persisted interview-or-quiz id is permitted for the short verifier' },
  worker: { status: 'unproven', reason: 'no business object is created by the short verifier' },
  semanticAssertionCount: 7,
};
const recruiter = {
  role: 'recruiter',
  accountEmailSha256: accountDigest('previewb@meetwise.com'),
  loginPath: '/recruiter/jobs',
  sessionCookie: { httpOnly: true, secure: true, roleCookie: 'recruiter' },
  pages: [page('/recruiter/jobs', '7'.repeat(64), '8'.repeat(64), '9'.repeat(64)), page('/settings', 'a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64))],
  roleBoundary: { status: 'unproven', reason: 'no safe recruiter-to-candidate negative write-free contract is available' },
  api: { status: 'unproven', reason: 'privacy export is intentionally omitted because Playwright API responses may buffer personal data' },
  sse: { status: 'unproven', reason: 'no stable persisted interview-or-quiz id is permitted for the short verifier' },
  worker: { status: 'unproven', reason: 'no business object is created by the short verifier' },
  semanticAssertionCount: 6,
};
const verifierIdentity = buildVerifierIdentity({
  repository: 'miaole/meetwise-deploy-control',
  workflow: 'verify-meetwise-public-origin',
  ref: 'refs/heads/main',
  sha: '1'.repeat(40),
  runId: '42',
  sourceSha256: '4'.repeat(64),
  workflowSha256: '5'.repeat(64),
  packageLockSha256: '6'.repeat(64),
});
const unsigned = buildUnsignedReceipt({ context, redirect, accounts: { candidate, recruiter }, checkedAt: '2026-08-20T00:00:00.000Z', verifierIdentity });
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const signed = signReceipt(unsigned, privateKey.export({ type: 'pkcs8', format: 'pem' }));
check('receipt has v2 identity binding and explicit pages-only status', signed.schemaVersion === 2 && signed.e2e.status === 'passed_pages_only' && signed.e2e.scope === 'browser_auth_pages_only' && signed.e2e.complete === false && signed.e2e.accounts.candidate.sse.status === 'unproven');
check('receipt signature verifies over canonical unsigned fields', verifyReceiptSignature(signed, publicKey.export({ type: 'spki', format: 'pem' })));
check('receipt contains no raw account or credential values', !JSON.stringify(signed).includes('previewc@meetwise.com') && !JSON.stringify(signed).includes('candidate-password') && !JSON.stringify(signed).includes('recruiter-password'));
check('receipt does not claim worker/SSE/API completion', signed.e2e.accounts.candidate.worker.status === 'unproven' && signed.e2e.accounts.recruiter.sse.status === 'unproven' && signed.e2e.accounts.candidate.api.status === 'unproven');
check('receipt carries caller-bound verifier source, workflow and lockfile digests', signed.verifier.repository === 'miaole/meetwise-deploy-control' && signed.verifier.ref === 'refs/heads/main' && signed.verifier.commit.length === 40 && signed.verifier.sourceSha256.length === 64 && signed.verifier.workflowSha256.length === 64 && signed.verifier.packageLockSha256.length === 64);
rejects('receipt rejects unknown top-level keys', () => validateReceiptShape({ ...signed, extra: true }), /receipt_keys_invalid/);
rejects('receipt rejects unknown nested account keys', () => validateReceiptShape({ ...signed, e2e: { ...signed.e2e, accounts: { ...signed.e2e.accounts, candidate: { ...signed.e2e.accounts.candidate, extra: true } } } }), /receipt_candidate_keys_invalid/);
rejects('receipt rejects unknown nested page keys', () => validateReceiptShape({ ...signed, e2e: { ...signed.e2e, accounts: { ...signed.e2e.accounts, candidate: { ...signed.e2e.accounts.candidate, pages: [{ ...signed.e2e.accounts.candidate.pages[0], extra: true }] } } } }), /receipt_candidate_page_0_keys_invalid/);
rejects('receipt rejects non-allowlisted response headers', () => validateReceiptShape({ ...signed, e2e: { ...signed.e2e, accounts: { ...signed.e2e.accounts, candidate: { ...signed.e2e.accounts.candidate, pages: [{ ...signed.e2e.accounts.candidate.pages[0], headers: { 'content-type': 'text/html', authorization: 'redacted' } }] } } } }), /receipt_candidate_page_0_headers_keys_invalid/);
rejects('receipt rejects control characters in unproven reasons', () => validateReceiptShape({ ...signed, e2e: { ...signed.e2e, accounts: { ...signed.e2e.accounts, recruiter: { ...signed.e2e.accounts.recruiter, worker: { status: 'unproven', reason: 'bad\nreason' } } } } }), /receipt_recruiter_worker_reason_invalid/);
check('canonical ordering is stable', canonical({ b: 1, a: 2 }) === '{"a":2,"b":1}');

const tampered = {
  ...signed,
  e2e: {
    ...signed.e2e,
    accounts: {
      ...signed.e2e.accounts,
      candidate: { ...signed.e2e.accounts.candidate, semanticAssertionCount: signed.e2e.accounts.candidate.semanticAssertionCount + 1 },
    },
  },
};
check('shape-valid tampering fails the receipt signature', !verifyReceiptSignature(tampered, publicKey.export({ type: 'spki', format: 'pem' })));

console.log(`PASS verify-preview-e2e proof: ${assertions} assertions`);
