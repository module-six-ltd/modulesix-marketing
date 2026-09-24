// functions/_middleware.js
//
// Blocks everything on this origin that is not front end.
//
// modulesix.co.uk is a Pages project built from the repository root. The 9 Aug
// Pages exposure note recorded that this repo "tracks zero non-front-end files,
// so there is nothing to expose by construction". That stopped being true when
// patch-ms-calibrate-nod.py was committed, and .DS_Store was tracked at the root
// the whole time. Both were publicly downloadable from modulesix.co.uk.
//
// Untracking them was not enough on its own. Cloudflare revalidates a cached
// object against the origin, gets a 404 for a file that no longer exists, and
// hands out the stale copy rather than evicting it. That is the same mechanism
// that kept serving the retired Activate exam banks after they were deleted, and
// a cache purge did not hold there. Functions answer before static asset
// resolution AND before the cache is consulted, so this returns a real 404.
//
// Do not try to do this with _redirects. Pages matches an existing static asset
// BEFORE it consults _redirects, so a 404 rule there can never block a file that
// exists. That was tried on the Calibrate origin and verified ineffective live.
//
// _routes.json uses a precise include list and an EMPTY exclude list, on purpose.
// Exclude takes precedence over include in Pages, and a broad exclude is exactly
// what left the whole competency library readable on Calibrate after that origin
// had already been audited and fixed.
//
// Deny lists rot. The structural fix is to stop building Pages from the repo root
// and point the build output at a folder holding only front-end files.

const BLOCKED_PREFIXES = ['/.git/', '/.github/', '/.wrangler/', '/functions/', '/node_modules/'];

// Removed from the build, but the edge may still hold a cached copy.
const REMOVED_BUT_CACHED = [
  '/patch-ms-calibrate-nod.py',
  '/.ds_store',
  '/courses/.ds_store',
];

// MS-DAT-001 and MS-DAT-002 became MS-LEG-004 and MS-LEG-003 on 31 August 2026.
// A retired reference is redirected, never deleted: recorded consents name
// MS-DAT-002 and MS-DPA-001, and those citations have to resolve.
const RETIRED_DOCS = {
  '/assets/docs/ms-dat-001_privacy_notice_first_edition.pdf':
    '/assets/docs/MS-LEG-004_Privacy_Notice_First_Edition.pdf',
  '/assets/docs/ms-dat-002_data_processing_agreement_first_edition.pdf':
    '/assets/docs/MS-LEG-003_Data_Processing_Agreement_First_Edition.pdf',
};

// MS-LEG-005 and MS-LEG-006 are internal control records. They are produced to a
// customer's data protection officer, an auditor or the ICO on request, and they
// are never served. MS-LEG-006 describes the security architecture.
const NEVER_SERVED = [
  '/assets/docs/ms-leg-005_record_of_processing_activities_first_edition.pdf',
  '/assets/docs/ms-leg-006_security_and_data_protection_procedures_first_edition.pdf',
];

// Earlier editions of a document still in force. Blocked rather than redirected:
// the next edition is different wording, and sending somebody who asked for the
// First Edition to the Second would show them terms they may never have agreed
// to. The superseded text is kept in ipp-docs/superseded and produced on request.
const SUPERSEDED_DOCS = [
  '/assets/docs/ms-leg-001_terms_of_service_for_individuals_first_edition.pdf',
  '/assets/docs/ms-leg-002_terms_of_service_for_organisations_first_edition.pdf',
];

const BLOCKED_EXACT = [
  ...NEVER_SERVED,
  ...SUPERSEDED_DOCS,
  ...REMOVED_BUT_CACHED,
  '/package.json',
  '/package-lock.json',
  '/readme.md',
];

const BLOCKED_EXTENSIONS = ['.py', '.md', '.sql', '.toml', '.lock', '.mjs', '.yml', '.yaml', '.env', '.bak', '.ts'];

// ── MAINTENANCE MODE, EDGE LAYER ─────────────────────────────────────────────
//
// The worker returns 503 for the whole API during a maintenance window. Without
// this block, a page on this origin still LOADS during that window and then
// fails every call it makes, which reads as a broken site rather than a planned
// one. Nineteen pages in the estate carry maintenance-banner.js and show
// something sensible; the other hundred and five do not.
//
// WHAT THIS IS AND IS NOT.
//
// This is a DISPLAY decision, not a security control. The control is in the
// worker: it holds the API closed and verifies the bypass cookie's HMAC against
// a secret this Pages project does not have and should not be given, because a
// secret in fourteen places is a secret that never gets rotated. So the check
// below is a presence-and-shape check on the cookie. Forge it and you get a
// static page whose every API call still returns 503, which is worth nothing.
//
// Saying that plainly matters. The old ?ms6bypass= flag was exactly this kind of
// check, and the defect recorded against it was not that it was weak — its own
// comment called it "purely UX convenience" and was right — it was that
// wrangler.toml described it as the maintenance bypass token, so a control that
// was never a boundary was documented as one.
//
// The state comes from the worker rather than from a per-project variable, so
// there is one switch for the estate.
//
// FAILS OPEN. If site-status cannot be reached, serve the page. An origin that
// takes itself offline because it could not ask whether it should be offline is
// a worse outage than the one this exists to schedule.

const STATUS_BASE = 'https://api.modulesix.io/public/site-status';

/*
 * THE URL CHANGES EVERY 20 SECONDS, AND THAT IS THE WHOLE POINT.
 *
 * Two live rehearsals on 14 August 2026 failed here, the second one after the
 * caching had already been pulled in-process and cache: 'no-store' added to the
 * read. The worker published maintenance_active:true, the middleware ran, and it
 * was told the estate was online for over seventy seconds. reason came back 'off'
 * both times, which is the value for a SUCCESSFUL read, so nothing threw and
 * nothing timed out: something between this file and the worker was answering
 * with a copy taken before the window opened.
 *
 * Rather than keep guessing which layer, the URL now carries a bucket number that
 * changes every 20 seconds. A cache can only answer with a copy of THIS url, and
 * this url did not exist 20 seconds ago, so no cache anywhere — edge, zone, tiered,
 * or one nobody has told me about — can be more than 20 seconds stale. It stops
 * being a question about Cloudflare's behaviour and becomes arithmetic.
 *
 * It also stays cacheable WITHIN each bucket, so the perf argument for caching
 * survives intact: a burst of traffic in the same 20 seconds still shares one
 * origin read.
 */
function statusUrl(nowMs) {
  return `${STATUS_BASE}?t=${Math.floor(nowMs / 20000)}`;
}
const BYPASS_COOKIE = 'ms6_bypass';

// Matches the cookie the worker mints: <expiry>.<64 hex>. Shape only. The
// signature is checked by the worker, which has the key.
const BYPASS_SHAPE = /^\d{10,15}\.[0-9a-f]{64}$/;

function hasBypassCookie(request) {
  const header = request.headers.get('Cookie');
  if (!header) return false;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== BYPASS_COOKIE) continue;
    return BYPASS_SHAPE.test(part.slice(eq + 1).trim());
  }
  return false;
}

// Two seconds, and it matters more than it looks. Without a deadline this
// subrequest sits in front of EVERY page load on this origin, so a worker that
// is slow rather than down would make the shop slow rather than down, with the
// cause two hops away from where anyone would look. A timeout turns "the API is
// struggling" into "the site serves normally", which is the same fail-open
// choice as the catch below and for the same reason.
//
// Implemented as a race rather than with AbortSignal.timeout. The first version
// used AbortSignal.timeout, and its own comment said that if the runtime did not
// support it the fetch would throw and this would fail open. That is exactly
// what happened on the first live rehearsal, 14 August 2026: the worker
// published maintenance_active:true, the middleware was demonstrably running
// (its deny list still returned 404), and the shop served normally throughout.
// A Pages project honours a compatibility date set when it was created, and this
// one predates that API. Promise.race with setTimeout has worked since the
// beginning and cannot be turned off by a date.
const STATUS_TIMEOUT_MS = 2000;

// FAILING OPEN SILENTLY IS WHY THAT TOOK A REHEARSAL TO FIND.
//
// Failing open is right: an origin that takes itself offline because it could
// not ask whether it should be offline is a worse outage than the planned one.
// But a control that fails open and says nothing is indistinguishable from one
// that is working, which is this estate's most-repeated defect and this file
// managed to reproduce it within an hour of being written.
//
// So every outcome other than "the mode is off" is named, and the name is put on
// the response as x-ms6-maint. Silence now means healthy. Anything else can be
// read with curl -I from anywhere, without a deploy and without guessing.
// THE CACHE IS OURS NOW, NOT CLOUDFLARE'S.
//
// The second live rehearsal, 14 August 2026, went: worker publishing
// maintenance_active:true, middleware demonstrably running, shop serving 200, and
// the header reading nothing at all. Nothing is the value for reason 'off', which
// means the subrequest SUCCEEDED and came back saying the estate was online. It
// was being answered from Cloudflare's edge cache with a copy taken before the
// window opened, and cf: { cacheTtl: 60 } is what put it there.
//
// So the caching moved in here, where it can be reasoned about. Module scope in a
// Pages Function is per isolate, exactly like the worker's own flag cache, and
// the fetch now carries cache: 'no-store' so no layer between here and the worker
// can answer it with something older than this file believes.
//
// The perf reason for caching at all has not gone away: this runs in front of
// every page load on the origin, and an uncached read would put a subrequest on
// the hottest path permanently for a feature used a handful of times a year. 20
// seconds is the same number the worker uses, so the two layers move together and
// the whole estate is offline within twenty seconds rather than sixty.
//
// The failed read is cached for less, because a status endpoint having a bad
// moment must not turn every page load into a retry against it.
const TTL_MS = 20_000;
const ERROR_TTL_MS = 5_000;

let cached = { status: null, reason: 'off' };
let cachedUntil = 0;

async function maintenance(nowMs) {
  if (nowMs < cachedUntil) return cached;

  const result = await readStatus(nowMs);
  cached = result;
  cachedUntil = nowMs + (result.reason === 'off' || result.reason === 'live' ? TTL_MS : ERROR_TTL_MS);
  return result;
}

async function readStatus(nowMs) {
  let timer;
  try {
    const timeout = new Promise((resolve) => {
      timer = setTimeout(() => resolve('__timeout__'), STATUS_TIMEOUT_MS);
    });
    const res = await Promise.race([
      fetch(statusUrl(nowMs), { cache: 'no-store', headers: { 'cache-control': 'no-cache' } }),
      timeout,
    ]);

    if (res === '__timeout__') return { status: null, reason: 'timeout' };
    if (!res.ok) return { status: null, reason: `status-${res.status}` };

    const s = await res.json();
    if (!s || typeof s !== 'object') return { status: null, reason: 'unreadable' };
    return s.maintenance_active
      ? { status: s, reason: 'live' }
      : { status: null, reason: 'off' };
  } catch (e) {
    // The name only. A message can carry a URL or a header value, and this goes
    // onto a response header that anybody can read.
    return { status: null, reason: `error-${(e && e.name) || 'unknown'}` };
  } finally {
    clearTimeout(timer);
  }
}

// Exported so the gate can prove the cache does what the comment claims, and can
// reset it between assertions rather than carrying state across them.
export function _resetMaintenanceCache() {
  cached = { status: null, reason: 'off' };
  cachedUntil = 0;
}

export const _MAINT_TTL_MS = TTL_MS;
export const _MAINT_ERROR_TTL_MS = ERROR_TTL_MS;

function maintenancePage(status) {
  const msg = (status.maintenance_message
    || 'We are carrying out planned maintenance. We will be back shortly.')
    .replace(/[<>&]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]));
  const lifts = status.maintenance_lifts
    ? `<p class="t">Expected back at ${new Date(status.maintenance_lifts).toUTCString()}</p>`
    : '';
  // No JavaScript and no external asset. A maintenance page that depends on this
  // origin serving its own CSS is a maintenance page that can fail for the same
  // reason the site did. The refresh brings a waiting visitor back by itself.
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<meta http-equiv="refresh" content="120">
<title>Planned maintenance | Module Six</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:#f8fafc;color:#0f172a;font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:34rem;padding:2.5rem;text-align:center}
h1{font-size:1.5rem;margin:0 0 1rem}
p{margin:0 0 .75rem;color:#475569}
.t{font-size:.875rem;color:#64748b}
</style></head><body><main>
<h1>Planned maintenance</h1>
<p>${msg}</p>
${lifts}
<p class="t">This page refreshes by itself.</p>
</main></body></html>`;
}

export async function onRequest(context) {
  const path = new URL(context.request.url).pathname.toLowerCase();

  const blocked =
    BLOCKED_PREFIXES.some((p) => path.startsWith(p)) ||
    BLOCKED_EXACT.includes(path) ||
    BLOCKED_EXTENSIONS.some((e) => path.endsWith(e));

  const retiredTo = RETIRED_DOCS[path];

  if (retiredTo) {

    return new Response(null, { status: 301, headers: { Location: retiredTo, 'Cache-Control': 'public, max-age=3600' } });

  }


  if (blocked) {
    return new Response('Not found', {
      status: 404,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'X-Robots-Tag': 'noindex' },
    });
  }

  /*
   * ?__maint — say exactly what this file just saw.
   *
   * Added after the second live rehearsal, because x-ms6-maint had a hole in it
   * that took two windows to notice: silence means 'off', and 'off' is a
   * SUCCESSFUL read. So "the status endpoint told me the estate is online" and
   * "the estate really is online" produce identical output, and the first of
   * those was the actual fault, twice.
   *
   * The header stays as it is, because it is what you get without asking. This
   * is what you get when you ask, and it is the difference between another live
   * window and one curl.
   *
   * Read-only, uncacheable, discloses nothing that /public/site-status does not
   * already publish unauthenticated. It reports what THIS origin saw, which is
   * the whole point: the endpoint being right has never been the question.
   */
  if (new URL(context.request.url).searchParams.has('__maint')) {
    const now = Date.now();
    const fresh = await readStatus(now);
    return new Response(JSON.stringify({
      origin: new URL(context.request.url).host,
      askedAt: new Date(now).toISOString(),
      url: statusUrl(now),
      reason: fresh.reason,
      maintenanceActive: !!fresh.status,
      publishedMessage: fresh.status ? fresh.status.maintenance_message : null,
      publishedLifts: fresh.status ? fresh.status.maintenance_lifts : null,
      bypassCookiePresent: hasBypassCookie(context.request),
      statusCacheMs: TTL_MS,
      timeoutMs: STATUS_TIMEOUT_MS,
    }, null, 2), {
      status: 200,
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
    });
  }

  // Checked before the bypass so a normal day costs one in-process cached read
  // and nothing else.
  const { status, reason } = await maintenance(Date.now());

  if (status && hasBypassCookie(context.request)) {
    return withReason(await context.next(), 'bypass');
  }

  if (status) {
    return new Response(maintenancePage(status), {
      // 503, not 200. It is the status that tells a crawler and a monitor this
      // is temporary. A 200 during an outage is how a search engine caches the
      // outage page as the site.
      status: 503,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'retry-after': '300',
        'x-ms6-maint': 'live',
      },
    });
  }
  return withReason(await context.next(), reason);
}

/*
 * Stamp the outcome onto the response, but only when it is not the healthy one.
 *
 * 'off' is silence, so an ordinary day carries no extra header and nothing is
 * disclosed. Every other value means this control could not do its job, and
 * naming it is the difference between an hour of guessing and one curl -I.
 *
 * Nothing here is secret: it says whether one public endpoint answered.
 */
function withReason(res, reason) {
  if (!reason || reason === 'off') return res;
  const out = new Response(res.body, res);
  out.headers.set('x-ms6-maint', reason);
  return out;
}
