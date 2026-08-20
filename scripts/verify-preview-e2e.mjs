/**
 * Protected-control-repository verifier for the preview user journey.
 *
 * This file intentionally contains no application source and never checks out
 * or executes the candidate repository.  It uses a pinned Playwright runtime
 * to submit the existing Web login Server Action, then performs only GET/HEAD
 * checks with the resulting browser session.  Response bodies are hashed in
 * memory and discarded; no export/API body is requested by this verifier.
 */
import fs from 'node:fs';
import { createHash, createPrivateKey, sign, verify } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const ORIGIN_RE = /^https:\/\/[a-z0-9-]+\.tail[a-z0-9]+\.ts\.net$/;
const HEX64 = /^[a-f0-9]{64}$/;
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const FIXED_C_EMAIL = 'previewc@meetwise.com';
const FIXED_B_EMAIL = 'previewb@meetwise.com';
const CONTROL_REPOSITORY = 'miaole/meetwise-deploy-control';
const CONTROL_WORKFLOW = 'verify-meetwise-public-origin';
const SAFE_HEADER_NAMES = ['content-type', 'cache-control'];
const PAGE_PATHS = new Set(['/dashboard', '/interviews', '/jobs', '/resume', '/settings', '/privacy', '/recruiter/jobs', '/recruiter/talent']);

export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function fail(code) {
  throw new Error(code);
}

export function accountDigest(email) {
  if (!EMAIL_RE.test(email)) fail('credential_email_invalid');
  return sha256(email);
}

export function validateCredentialInputs({ cEmail, cPassword, bEmail, bPassword }) {
  if (cEmail !== FIXED_C_EMAIL || bEmail !== FIXED_B_EMAIL) fail('credential_account_mismatch');
  for (const password of [cPassword, bPassword]) {
    if (typeof password !== 'string' || password.length < 8 || password.length > 128) fail('credential_password_length_invalid');
  }
  return true;
}

export function validateRedirect(location, origin) {
  if (typeof location !== 'string' || location.includes('localhost')) fail('protected_redirect_localhost');
  let url;
  try { url = new URL(location, origin); } catch { fail('protected_redirect_url_invalid'); }
  if (url.origin !== origin || url.pathname !== '/login' || url.search !== '?next=%2Fdashboard') fail('protected_redirect_target_invalid');
  return { origin: url.origin, pathname: url.pathname, search: url.search };
}

export function networkRequestDecision({ origin, method, requestUrl }) {
  let url;
  try { url = new URL(requestUrl); } catch { return 'abort'; }
  if (url.origin !== origin) return 'abort';
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return 'continue';
  if (method === 'POST' && url.pathname === '/login') return 'continue';
  return 'abort';
}

function publicHeaders(headers) {
  const selected = {};
  for (const name of SAFE_HEADER_NAMES) {
    const value = headers[name] ?? headers[name.toLowerCase()];
    if (value !== undefined) {
      const normalized = String(value);
      if (!/^[\x20-\x7e]{1,256}$/.test(normalized)) fail('response_header_invalid');
      selected[name] = normalized;
    }
  }
  return selected;
}

async function responseEvidence(response, { markers = [], forbiddenMarkers = [] } = {}) {
  const headers = publicHeaders(await response.allHeaders());
  const evidence = { status: response.status(), headers, bodyHash: null, bodyStored: false };
  const body = await response.body();
  if (body.byteLength > 2_000_000) fail('protected_response_too_large');
  const text = body.toString('utf8');
  if (markers.some((marker) => !text.includes(marker))) fail('protected_page_marker_missing');
  if (forbiddenMarkers.some((marker) => text.includes(marker))) fail('protected_page_forbidden_sentinel');
  evidence.bodyHash = sha256(body);
  evidence.markerHashes = markers.map((marker) => sha256(marker));
  evidence.negativeMarkerHashes = forbiddenMarkers.map((marker) => sha256(marker));
  return evidence;
}

function pagePlan(path, markers, forbiddenMarkers = []) {
  if (!PAGE_PATHS.has(path)) fail('protected_page_path_not_allowlisted');
  if (![...markers, ...forbiddenMarkers].every((marker) => typeof marker === 'string' && marker.length > 0 && marker.length <= 256 && !/[\r\n]/.test(marker))) fail('protected_page_marker_invalid');
  return { path, markers, forbiddenMarkers };
}

async function protectedPageEvidence(request, origin, plan) {
  const response = await request.get(`${origin}${plan.path}`, {
    maxRedirects: 0,
    timeout: 20_000,
    headers: { accept: 'text/html' },
  });
  const evidence = await responseEvidence(response, plan);
  if (evidence.status !== 200) fail('protected_page_status_invalid');
  return { path: plan.path, ...evidence };
}

function pagePlansFor(role, email) {
  if (role === 'candidate') return [
    pagePlan('/dashboard', ['继续打磨你的面试表现', email], ['账户信息暂不可用']),
    pagePlan('/interviews', ['面试 · 知面'], ['面试列表暂不可用']),
    pagePlan('/jobs', ['岗位广场'], ['岗位列表暂不可用']),
    pagePlan('/resume', ['简历 · 知面'], ['简历列表暂不可用']),
    pagePlan('/settings', ['账户设置', `邮箱:${email}`], ['账户信息暂不可用']),
    pagePlan('/privacy', ['隐私与数据边界']),
  ];
  return [
    pagePlan('/recruiter/jobs', ['招聘方 · 岗位', '我的岗位'], ['岗位列表暂不可用']),
    pagePlan('/recruiter/talent', ['人才库'], ['人才库暂不可用']),
    pagePlan('/settings', ['账户设置', `邮箱:${email}`], ['账户信息暂不可用']),
    pagePlan('/privacy', ['隐私与数据边界']),
  ];
}

function pagePlanForCandidateRoleBoundary() {
  return pagePlan('/recruiter/jobs', ['招聘方 · 岗位', '岗位列表暂不可用']);
}

async function roleBoundaryEvidence(request, origin, role) {
  if (role !== 'candidate') return { status: 'unproven', reason: 'no safe recruiter-to-candidate negative write-free contract is available' };
  const evidence = await protectedPageEvidence(request, origin, pagePlanForCandidateRoleBoundary());
  return { status: 'verified', path: evidence.path, markerHashes: evidence.markerHashes };
}

function unprovenApiEvidence() {
  return { status: 'unproven', reason: 'privacy export is intentionally omitted because Playwright API responses may buffer personal data' };
}

function unprovenSseEvidence() {
  return { status: 'unproven', reason: 'no stable persisted interview-or-quiz id is permitted for the short verifier' };
}

function unprovenWorkerEvidence() {
  return { status: 'unproven', reason: 'no business object is created by the short verifier' };
}

async function noCookieRedirect(browser, origin) {
  const context = await browser.newContext({ serviceWorkers: 'block' });
  try {
    const response = await context.request.get(`${origin}/dashboard`, { maxRedirects: 0, timeout: 20_000, headers: { accept: 'text/html' } });
    const location = response.headers().location;
    if (response.status() !== 307 && response.status() !== 308) fail('protected_redirect_status_invalid');
    return validateRedirect(location, origin);
  } finally {
    await context.close();
  }
}

async function loginAndProbe(browser, origin, role, email, password, plans) {
  if (role !== 'candidate' && role !== 'recruiter') fail('login_role_invalid');
  const context = await browser.newContext({ serviceWorkers: 'block' });
  if (typeof context.routeWebSocket === 'function') {
    await context.routeWebSocket('**/*', (route) => route.close());
  }
  context.on('websocket', (socket) => { try { socket.close(); } catch { /* browser teardown */ } });
  // The verifier is intentionally read-only after login.  The only permitted
  // POST is the login Server Action submitted by the page form itself.
  await context.route('**/*', async (route) => {
    const request = route.request();
    const method = request.method();
    if (networkRequestDecision({ origin, method, requestUrl: request.url() }) === 'continue') return route.continue();
    return route.abort('blockedbyclient');
  });
  const page = await context.newPage();
  try {
    await page.goto(`${origin}/login`, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    await page.locator('input[name="email"]').fill(email);
    await page.locator('input[name="password"]').fill(password);
    const expectedPath = role === 'candidate' ? '/dashboard' : '/recruiter/jobs';
    await Promise.all([
      page.waitForURL((url) => url.origin === origin && url.pathname === expectedPath, { timeout: 30_000 }),
      page.locator('button[name="mode"][value="login"]').click(),
    ]);
    if (page.url().includes('localhost')) fail('login_redirect_localhost');
    const cookies = await context.cookies(origin);
    const token = cookies.find((cookie) => cookie.name === 'mw_token');
    const roleCookie = cookies.find((cookie) => cookie.name === 'mw_role');
    if (!token || token.httpOnly !== true || token.secure !== true || !roleCookie || roleCookie.secure !== true || roleCookie.value !== role) fail('login_cookie_contract_invalid');
    const pages = [];
    for (const plan of plans) pages.push(await protectedPageEvidence(context.request, origin, plan));
    const roleBoundary = await roleBoundaryEvidence(context.request, origin, role);
    const semanticAssertionCount = pages.reduce((count, page) => count + page.markerHashes.length + page.negativeMarkerHashes.length, 0) + (roleBoundary.status === 'verified' ? roleBoundary.markerHashes.length : 0);
    return {
      role,
      accountEmailSha256: accountDigest(email),
      loginPath: expectedPath,
      sessionCookie: { httpOnly: token.httpOnly, secure: token.secure, roleCookie: roleCookie.value },
      pages,
      roleBoundary,
      api: unprovenApiEvidence(),
      sse: unprovenSseEvidence(),
      worker: unprovenWorkerEvidence(),
      semanticAssertionCount,
    };
  } finally {
    await context.close();
  }
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label}_shape_invalid`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) fail(`${label}_keys_invalid`);
}

function digest(value, label) {
  if (!HEX64.test(value ?? '')) fail(`${label}_digest_invalid`);
}

function safeStatus(status, label) {
  if (status !== 200) fail(`${label}_status_invalid`);
}

function safeReason(reason, label) {
  if (typeof reason !== 'string' || reason.length < 1 || reason.length > 256 || /[\u0000-\u001f\u007f]/.test(reason)) fail(`${label}_reason_invalid`);
}

function validateHeaderMap(headers, label) {
  exactKeys(headers, Object.keys(headers).filter((key) => SAFE_HEADER_NAMES.includes(key)), label);
  for (const [name, value] of Object.entries(headers)) {
    if (!SAFE_HEADER_NAMES.includes(name) || typeof value !== 'string' || !/^[\x20-\x7e]{1,256}$/.test(value)) fail(`${label}_value_invalid`);
  }
}

function validatePageReceipt(page, label) {
  exactKeys(page, ['path', 'status', 'headers', 'bodyHash', 'bodyStored', 'markerHashes', 'negativeMarkerHashes'], label);
  if (!PAGE_PATHS.has(page.path)) fail(`${label}_path_invalid`);
  safeStatus(page.status, label);
  validateHeaderMap(page.headers, `${label}_headers`);
  digest(page.bodyHash, `${label}_body`);
  if (page.bodyStored !== false || !Array.isArray(page.markerHashes) || !Array.isArray(page.negativeMarkerHashes) || page.markerHashes.length === 0) fail(`${label}_semantic_invalid`);
  for (const marker of [...page.markerHashes, ...page.negativeMarkerHashes]) digest(marker, `${label}_marker`);
}

function validateAccountReceipt(account, label, expectedRole, expectedLoginPath) {
  exactKeys(account, ['role', 'accountEmailSha256', 'loginPath', 'sessionCookie', 'pages', 'roleBoundary', 'api', 'sse', 'worker', 'semanticAssertionCount'], label);
  if (account.role !== expectedRole || account.loginPath !== expectedLoginPath) fail(`${label}_identity_invalid`);
  digest(account.accountEmailSha256, `${label}_account`);
  exactKeys(account.sessionCookie, ['httpOnly', 'secure', 'roleCookie'], `${label}_session`);
  if (account.sessionCookie.httpOnly !== true || account.sessionCookie.secure !== true || account.sessionCookie.roleCookie !== expectedRole) fail(`${label}_session_invalid`);
  if (!Array.isArray(account.pages) || account.pages.length < 1) fail(`${label}_pages_invalid`);
  account.pages.forEach((page, index) => validatePageReceipt(page, `${label}_page_${index}`));
  exactKeys(account.roleBoundary, account.roleBoundary.status === 'verified' ? ['status', 'path', 'markerHashes'] : ['status', 'reason'], `${label}_role_boundary`);
  if (account.roleBoundary.status === 'verified') {
    if (account.roleBoundary.path !== '/recruiter/jobs' || !Array.isArray(account.roleBoundary.markerHashes) || account.roleBoundary.markerHashes.length < 1) fail(`${label}_role_boundary_invalid`);
    account.roleBoundary.markerHashes.forEach((marker) => digest(marker, `${label}_role_boundary_marker`));
  } else if (account.roleBoundary.status !== 'unproven') fail(`${label}_role_boundary_unproven_invalid`);
  if (account.roleBoundary.status === 'unproven') safeReason(account.roleBoundary.reason, `${label}_role_boundary`);
  for (const [name, value] of [['api', account.api], ['sse', account.sse], ['worker', account.worker]]) {
    exactKeys(value, ['status', 'reason'], `${label}_${name}`);
    if (value.status !== 'unproven') fail(`${label}_${name}_invalid`);
    safeReason(value.reason, `${label}_${name}`);
  }
  if (!Number.isInteger(account.semanticAssertionCount) || account.semanticAssertionCount < 1) fail(`${label}_semantic_count_invalid`);
}

export function buildVerifierIdentity({ repository, workflow, ref, sha, commit, runId, sourceSha256, workflowSha256, packageLockSha256 }) {
  const resolvedCommit = commit ?? sha;
  if ((commit !== undefined && sha !== undefined && commit !== sha) || repository !== CONTROL_REPOSITORY || workflow !== CONTROL_WORKFLOW || ref !== 'refs/heads/main' || !/^[a-f0-9]{40}$/.test(resolvedCommit ?? '') || !/^[0-9]+$/.test(runId ?? '')) fail('verifier_identity_invalid');
  for (const [name, value] of [['source', sourceSha256], ['workflow', workflowSha256], ['package_lock', packageLockSha256]]) digest(value, `verifier_${name}`);
  return { repository, workflow, ref, commit: resolvedCommit, runId, sourceSha256, workflowSha256, packageLockSha256 };
}

export function validateReceiptShape(receipt) {
  const signed = Object.prototype.hasOwnProperty.call(receipt ?? {}, 'signature');
  exactKeys(receipt, ['schemaVersion', 'origin', 'probeNonce', 'checkedAt', 'manifestSha256', 'rootStatus', 'loginStatus', 'manifestStatus', 'rootUrl', 'loginUrl', 'manifestUrl', 'rootSha256', 'blackboxSha256', 'signingKeyId', 'verifier', 'e2e', ...(signed ? ['signature'] : [])], 'receipt');
  if (receipt.schemaVersion !== 2 || !ORIGIN_RE.test(receipt.origin ?? '') || !HEX64.test(receipt.probeNonce ?? '') || !HEX64.test(receipt.manifestSha256 ?? '') || new Date(receipt.checkedAt).toISOString() !== receipt.checkedAt) fail('receipt_identity_invalid');
  safeStatus(receipt.rootStatus, 'receipt_root');
  safeStatus(receipt.loginStatus, 'receipt_login');
  safeStatus(receipt.manifestStatus, 'receipt_manifest');
  if (receipt.rootUrl !== `${receipt.origin}/` || receipt.loginUrl !== `${receipt.origin}/login` || receipt.manifestUrl !== `${receipt.origin}/preview-release-manifest.json`) fail('receipt_url_invalid');
  digest(receipt.rootSha256, 'receipt_root');
  digest(receipt.blackboxSha256, 'receipt_blackbox');
  if (receipt.signingKeyId !== 'probe-receipt-ed25519-v2') fail('receipt_signing_key_invalid');
  if (signed && (!/^[A-Za-z0-9+/]+={0,2}$/.test(receipt.signature ?? '') || Buffer.from(receipt.signature, 'base64').length !== 64)) fail('receipt_signature_invalid');
  exactKeys(receipt.verifier, ['repository', 'workflow', 'ref', 'commit', 'runId', 'sourceSha256', 'workflowSha256', 'packageLockSha256'], 'receipt_verifier');
  buildVerifierIdentity(receipt.verifier);
  exactKeys(receipt.e2e, ['status', 'scope', 'complete', 'noCookieProtectedRedirect', 'accounts', 'sensitiveResponseBodies'], 'receipt_e2e');
  if (receipt.e2e.status !== 'passed_pages_only' || receipt.e2e.scope !== 'browser_auth_pages_only' || receipt.e2e.complete !== false || receipt.e2e.sensitiveResponseBodies !== 'not_stored') fail('receipt_e2e_status_invalid');
  exactKeys(receipt.e2e.noCookieProtectedRedirect, ['origin', 'pathname', 'search'], 'receipt_redirect');
  if (receipt.e2e.noCookieProtectedRedirect.origin !== receipt.origin || receipt.e2e.noCookieProtectedRedirect.pathname !== '/login' || receipt.e2e.noCookieProtectedRedirect.search !== '?next=%2Fdashboard') fail('receipt_redirect_invalid');
  exactKeys(receipt.e2e.accounts, ['candidate', 'recruiter'], 'receipt_accounts');
  validateAccountReceipt(receipt.e2e.accounts.candidate, 'receipt_candidate', 'candidate', '/dashboard');
  validateAccountReceipt(receipt.e2e.accounts.recruiter, 'receipt_recruiter', 'recruiter', '/recruiter/jobs');
  return receipt;
}

export function buildUnsignedReceipt({ context, redirect, accounts, checkedAt, verifierIdentity }) {
  if (!context || context.schemaVersion !== 1 || !ORIGIN_RE.test(context.origin ?? '') || !HEX64.test(context.probeNonce ?? '') || !HEX64.test(context.manifestSha256 ?? '') || context.rootStatus !== 200 || context.loginStatus !== 200 || context.manifestStatus !== 200 || context.rootUrl !== `${context.origin}/` || context.loginUrl !== `${context.origin}/login` || context.manifestUrl !== `${context.origin}/preview-release-manifest.json` || !HEX64.test(context.rootSha256 ?? '') || !HEX64.test(context.blackboxSha256 ?? '')) fail('probe_context_invalid');
  const receipt = {
    schemaVersion: 2,
    origin: context.origin,
    probeNonce: context.probeNonce,
    checkedAt,
    manifestSha256: context.manifestSha256,
    rootStatus: context.rootStatus,
    loginStatus: context.loginStatus,
    manifestStatus: context.manifestStatus,
    rootUrl: context.rootUrl,
    loginUrl: context.loginUrl,
    manifestUrl: context.manifestUrl,
    rootSha256: context.rootSha256,
    blackboxSha256: context.blackboxSha256,
    signingKeyId: 'probe-receipt-ed25519-v2',
    verifier: verifierIdentity,
    e2e: {
      status: 'passed_pages_only',
      scope: 'browser_auth_pages_only',
      complete: false,
      noCookieProtectedRedirect: redirect,
      accounts,
      sensitiveResponseBodies: 'not_stored',
    },
  };
  validateReceiptShape(receipt);
  return receipt;
}

export function signReceipt(unsigned, privateKeyPem) {
  if (!privateKeyPem) fail('probe_signing_key_missing');
  validateReceiptShape(unsigned);
  const receipt = { ...unsigned, signature: sign(null, Buffer.from(canonical(unsigned)), createPrivateKey(privateKeyPem)).toString('base64') };
  validateReceiptShape(receipt);
  return receipt;
}

export function verifyReceiptSignature(receipt, publicKeyPem) {
  validateReceiptShape(receipt);
  const { signature, ...unsigned } = receipt;
  return verify(null, Buffer.from(canonical(unsigned)), publicKeyPem, Buffer.from(signature, 'base64'));
}

async function run() {
  const contextPath = process.env.PROBE_CONTEXT_PATH;
  const context = contextPath ? JSON.parse(fs.readFileSync(contextPath, 'utf8')) : null;
  const origin = process.env.REQUESTED_ORIGIN;
  if (!context || context.origin !== origin || context.probeNonce !== process.env.PROBE_NONCE || context.manifestSha256 !== process.env.EXPECTED_MANIFEST_SHA256 || !ORIGIN_RE.test(origin ?? '') || !HEX64.test(context.probeNonce ?? '') || !HEX64.test(context.manifestSha256 ?? '') || context.rootStatus !== 200 || context.loginStatus !== 200 || context.manifestStatus !== 200 || !HEX64.test(context.rootSha256 ?? '') || !HEX64.test(context.blackboxSha256 ?? '')) fail('probe_context_invalid');
  validateCredentialInputs({
    cEmail: process.env.PREVIEW_C_EMAIL,
    cPassword: process.env.PREVIEW_C_PASSWORD,
    bEmail: process.env.PREVIEW_B_EMAIL,
    bPassword: process.env.PREVIEW_B_PASSWORD,
  });
  const { chromium } = await import('playwright');
  const browser = await chromium.launch({ headless: true });
  try {
    const redirect = await noCookieRedirect(browser, origin);
    const candidateEmail = process.env.PREVIEW_C_EMAIL;
    const recruiterEmail = process.env.PREVIEW_B_EMAIL;
    const candidate = await loginAndProbe(browser, origin, 'candidate', candidateEmail, process.env.PREVIEW_C_PASSWORD, pagePlansFor('candidate', candidateEmail));
    const recruiter = await loginAndProbe(browser, origin, 'recruiter', recruiterEmail, process.env.PREVIEW_B_PASSWORD, pagePlansFor('recruiter', recruiterEmail));
    const verifierIdentity = buildVerifierIdentity({
      repository: process.env.GITHUB_REPOSITORY,
      workflow: process.env.GITHUB_WORKFLOW,
      ref: process.env.GITHUB_REF,
      sha: process.env.GITHUB_SHA,
      runId: process.env.GITHUB_RUN_ID,
      sourceSha256: sha256(fs.readFileSync(new URL('./verify-preview-e2e.mjs', import.meta.url))),
      workflowSha256: sha256(fs.readFileSync(new URL('../.github/workflows/verify.yml', import.meta.url))),
      packageLockSha256: sha256(fs.readFileSync(new URL('../package-lock.json', import.meta.url))),
    });
    const unsigned = buildUnsignedReceipt({ context, redirect, accounts: { candidate, recruiter }, checkedAt: new Date().toISOString(), verifierIdentity });
    const receipt = signReceipt(unsigned, process.env.PROBE_SIGNING_KEY);
    const artifactPath = `${process.env.RUNNER_TEMP}/receipt.json`;
    const fd = fs.openSync(artifactPath, 'wx', 0o600);
    try { fs.writeFileSync(fd, `${JSON.stringify(receipt)}\n`); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `receipt_path=${artifactPath}\n`);
  } finally {
    await browser.close();
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  run().catch(() => { process.stderr.write('preview_e2e_verification_failed\n'); process.exit(1); });
}
