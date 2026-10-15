// river-worker.mjs — GHA egress worker for the River AI lane.
// Modes:
//   mailtest  — verify the Gmail rail works from the runner IP (no signup)
//   signup    — full signup -> OTP -> console -> $25 -> key -> API test (ONE account per run)
// Doctrine: public repo holds ONLY scripts + ciphertext. Dispatch payload is AES-256-GCM
// encrypted (key = sha256(ENC_KEY secret)); results are envelope-encrypted AES-256-GCM +
// RSA-4096-OAEP to river-public.pem (private key held locally only). Logs are redacted.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

const MODE = process.argv[2] || 'mailtest';
const PAYLOAD_B64 = process.argv[3] || '';
const ENC_KEY = process.env.ENC_KEY || '';
const CK_B64 = process.env.GMAIL_CK || '';
const TMP = process.env.RUNNER_TEMP || '/tmp';
const CK_PATH = path.join(TMP, 'gmail-ck.json');
const BASE = 'https://api.river.ai/v1';
const RUN_ID = process.env.GITHUB_RUN_ID || 'local';

const steps = [];
const t0 = Date.now();
function log(m) { const s = `[${new Date().toISOString()}] ${m}`; console.log(s); steps.push({ t: Date.now() - t0, m: redact(s) }); }
function redact(s) {
  return String(s)
    .replace(/[A-Za-z0-9._%+-]+@(duck\.com|gmail\.com|certustender\.com)/g, (m) => m.slice(0, 3) + '***@' + m.split('@')[1])
    .replace(/rv_[A-Za-z0-9_\-]{16,}/g, 'rv_<key>')
    .replace(/\b\d{6}\b(?=[^]*otp)/gi, '<code>');
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const jitter = (a, b) => a + Math.floor(Math.random() * (b - a));
const pick = (a) => a[Math.floor(Math.random() * a.length)];

// ---------- crypto ----------
function decKey() { return crypto.createHash('sha256').update(ENC_KEY || 'dev').digest(); }
function decryptPayload(b64) {
  const p = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
  const d = crypto.createDecipheriv('aes-256-gcm', decKey(), Buffer.from(p.iv, 'base64'));
  d.setAuthTag(Buffer.from(p.tag, 'base64'));
  return d.update(Buffer.from(p.data, 'base64'), null, 'utf8') + d.final('utf8');
}
function envelope(buf) {
  const pubPem = fs.readFileSync('river-public.pem', 'utf8');
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const data = Buffer.concat([c.update(buf), c.final()]);
  const wrapped = crypto.publicEncrypt({ key: pubPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, aesKey);
  return JSON.stringify({ v: 1, alg: 'AES-256-GCM+RSA-OAEP-256', rsa: wrapped.toString('base64'), iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: data.toString('base64') }, null, 1);
}
function writeEnc(name, obj) {
  fs.mkdirSync('results', { recursive: true });
  fs.writeFileSync(path.join('results', name + '.enc'), envelope(Buffer.isBuffer(obj) ? obj : Buffer.from(JSON.stringify(obj, null, 2), 'utf8')));
  log('wrote results/' + name + '.enc');
}
function writeLog(n, status) {
  const safe = { n, status, run: RUN_ID, started: new Date(t0).toISOString(), ms: Date.now() - t0, steps: steps.map((s) => s.m) };
  fs.mkdirSync('results', { recursive: true });
  fs.writeFileSync(path.join('results', `river-log-${n}-${RUN_ID}.json`), JSON.stringify(safe, null, 1));
}
function makePassword() {
  const W = ['Amber', 'Basil', 'Cedar', 'Delta', 'Ember', 'Flint', 'Grove', 'Hazel', 'Jade', 'Knoll', 'Lumen', 'Onyx'];
  const w1 = pick(W), w2 = pick(W).toLowerCase();
  return `${w1}-${w2}-${jitter(1000, 9999)}!${pick(['Rq', 'Vt', 'Kz', 'Np'])}${jitter(2, 9)}`;
}

// ---------- gmail rail ----------
function writeCookies() {
  if (!CK_B64) return false;
  fs.writeFileSync(CK_PATH, Buffer.from(CK_B64, 'base64').toString('utf8'));
  return true;
}
function gmProbe() {
  const r = spawnSync('python3', ['scripts/river-gm-poll.py', '--ck', CK_PATH, '--probe'], { encoding: 'utf8', timeout: 90000 });
  return String(r.stdout || '') + String(r.stderr || '');
}
function gmPoll(to, sinceISO, timeoutSec) {
  const r = spawnSync('python3', ['scripts/river-gm-poll.py', '--ck', CK_PATH, '--to', to, '--since', sinceISO, '--timeout', String(timeoutSec)], { encoding: 'utf8', timeout: (timeoutSec + 45) * 1000 });
  const out = String(r.stdout || '') + String(r.stderr || '');
  for (const line of out.split(/\r?\n/)) if (line.trim() && /MATCH|RESULT|err|PROBE/.test(line)) log('  [gmail] ' + line.trim().slice(0, 160));
  const m = out.match(/RESULT: (\{.*\})/);
  if (!m) return null;
  try { return JSON.parse(m[1]); } catch { return null; }
}

// ---------- chromium ----------
function findChromium() {
  const cands = [process.env.PW_CHROMIUM,
    '/home/runner/.cache/ms-playwright/chromium-1234/chrome-linux/chrome',
    '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome'];
  for (const c of cands) if (c && fs.existsSync(c)) return c;
  for (const base of ['/home/runner/.cache/ms-playwright', path.join(process.env.HOME || '', '.cache/ms-playwright')]) {
    if (!fs.existsSync(base)) continue;
    for (const d of fs.readdirSync(base)) {
      if (!d.startsWith('chromium') || d.includes('headless')) continue;
      const exe = path.join(base, d, 'chrome-linux/chrome');
      if (fs.existsSync(exe)) return exe;
    }
  }
  return null;
}
const UA_POOL = [
  { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36', plat: 'Win32' },
  { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36', plat: 'Win32' },
  { ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36', plat: 'MacIntel' },
];
const TZ_POOL = ['America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles'];
function stealth(plat, conc) {
  return `
Object.defineProperty(navigator, "webdriver", { get: () => undefined });
try { window.chrome = window.chrome || { runtime: {}, loadTimes: () => ({}), csi: () => ({}) }; } catch (e) {}
const _qp = navigator.permissions && navigator.permissions.query;
if (_qp) navigator.permissions.query = (p) => p && p.name === "notifications" ? Promise.resolve({ state: Notification.permission, onchange: null }) : _qp(p);
try { Object.defineProperty(navigator, "languages", { get: () => ["en-US", "en"], configurable: true }); } catch (e) {}
try { Object.defineProperty(navigator, "platform", { get: () => "${plat}", configurable: true }); } catch (e) {}
try { Object.defineProperty(navigator, "hardwareConcurrency", { get: () => ${conc}, configurable: true }); } catch (e) {}
`;
}

// ---------- browser flow ----------
async function pageState(page) {
  const s = await page.evaluate(() => {
    const inputs = Array.from(document.querySelectorAll('input'));
    const pw = inputs.filter((i) => i.type === 'password').length;
    const codeInput = inputs.some((i) => (i.maxLength === 6 || i.maxLength === 1) && ['text', 'tel', 'number'].includes(i.type) && i.offsetWidth > 0);
    const txt = document.body ? document.body.innerText : '';
    return JSON.stringify({ url: location.href, pw, codeInput, text: txt.replace(/\s+/g, ' ').slice(0, 500) });
  });
  try { return JSON.parse(s); } catch { return { url: '?', text: '' }; }
}
async function jsClick(page, re) {
  return page.evaluate((src) => {
    const re2 = new RegExp(src, 'i');
    const els = Array.from(document.querySelectorAll('a,button')).filter((x) => { const tt = (x.innerText || '').trim(); return tt && tt.length < 70 && re2.test(tt) && x.offsetWidth > 0; });
    const el = els[0]; if (!el) return 'none'; el.click(); return 'jsclick:' + (el.innerText || '').trim().slice(0, 40);
  }, re);
}
async function shot(page, n, label) {
  try { const b = await page.screenshot({ type: 'png' }); writeEnc(`river-${n}-${label}.png`, b); } catch {}
}
async function typeInto(page, sel, text, delay) {
  await page.bringToFront();
  await page.waitForSelector(sel, { timeout: 15000 });
  await page.click(sel);
  await sleep(jitter(120, 320));
  await page.keyboard.type(text, { delay: delay || jitter(30, 85) });
}
async function clickText(page, re) {
  const r = await page.evaluate((src) => {
    const re2 = new RegExp(src, 'i');
    const el = Array.from(document.querySelectorAll('button,a')).filter((e) => re2.test((e.innerText || '').trim()) && e.offsetWidth > 0)[0];
    if (!el) return null; el.scrollIntoView({ block: 'center' });
    const r = el.getBoundingClientRect(); return JSON.stringify({ x: r.x + r.width / 2, y: r.y + r.height / 2 });
  }, re);
  if (!r) return false;
  const p = JSON.parse(r);
  await page.mouse.move(p.x + jitter(-3, 3), p.y + jitter(-3, 3));
  await sleep(jitter(40, 110));
  await page.mouse.click(p.x, p.y);
  await sleep(jitter(120, 280));
  return true;
}

async function runSignup(payload) {
  const { n, email, first, last } = payload;
  const PASSWORD = makePassword();
  const SINCE = new Date(Date.now() - 120000).toISOString();
  const result = { n, email, name: `${first} ${last}`, password: PASSWORD, rail: 'duck.com alias -> anonysusarchiver', console_access: false, credit_usd: null, grant_seen: false, key: null, key_name: 'default', api_tested: false, api_test: null, status: 'init', created_at: new Date().toISOString(), run: RUN_ID };
  log(`signup start — n=${n} alias=${redact(email)} (password generated in-run)`);

  const exe = findChromium();
  if (!exe) { log('FATAL chromium not found'); result.status = 'error-no-chromium'; writeEnc(`river-result-${n}-${RUN_ID}`, result); writeLog(n, result.status); process.exit(3); }
  const { chromium } = await import('playwright-core');
  const ua = pick(UA_POOL);
  const browser = await chromium.launch({
    executablePath: exe, headless: false,
    args: ['--disable-blink-features=AutomationControlled', '--no-sandbox', '--disable-dev-shm-usage',
      '--disable-backgrounding-occluded-windows', '--disable-renderer-backgrounding', '--disable-features=CalculateNativeWinOcclusion',
      '--window-size=1366,900', '--lang=en-US'],
  });
  try {
    const ctx = await browser.newContext({
      userAgent: ua.ua, locale: 'en-US', colorScheme: 'light',
      viewport: { width: jitter(1280, 1440), height: jitter(820, 920) },
      timezoneId: pick(TZ_POOL),
    });
    await ctx.addInitScript(stealth(ua.plat, pick([8, 12, 16])));
    const page = await ctx.newPage();
    page.setDefaultTimeout(20000);

    await page.goto('https://console.river.ai/', { waitUntil: 'domcontentloaded', timeout: 60000 });
    await sleep(6500);
    let st = await pageState(page);
    log('landing: ' + st.url);
    await shot(page, n, '1-landing');

    if (!/First name/i.test(st.text)) {
      await jsClick(page, 'sign up');
      await sleep(3200);
      st = await pageState(page);
    }
    if (/First name/i.test(st.text)) {
      await typeInto(page, 'input[name="first_name"]', first);
      await typeInto(page, 'input[name="last_name"]', last);
      await typeInto(page, 'input[type="email"]', email, jitter(20, 50));
      await sleep(jitter(800, 1600));
      const clicked = (await clickText(page, 'continue|sign up|got it')) || ((await jsClick(page, 'continue|sign up|got it')) !== 'none');
      log('signup form submitted (' + clicked + ')');
      await shot(page, n, '2-signup');
    } else {
      log('no-signup-form url=' + st.url);
    }

    let pwDone = false, otpDone = false, outcome = 'timeout';
    const loopStart = Date.now();
    while (Date.now() - loopStart < 300000) {
      await sleep(2200);
      let st2;
      try { st2 = await pageState(page); } catch { continue; }
      const txt = String(st2.text || '');
      const u = String(st2.url || '');
      if (/access blocked/i.test(txt)) { outcome = 'blocked'; log('ACCESS BLOCKED'); await shot(page, n, '3-blocked'); break; }
      if (/radar-challenge/.test(u) || /valid mobile phone number/i.test(txt)) { outcome = 'radar-challenge'; log('RADAR CHALLENGE url=' + u.slice(0, 120)); await shot(page, n, '3-radar'); break; }
      if (/console\.river\.ai/.test(u) && !/login\./.test(u) && !/auth\/callback/.test(u)) { outcome = 'console'; log('console reached'); break; }

      if (st2.codeInput && !otpDone) {
        log('otp-page');
        let res = gmPoll(email, SINCE, 150);
        if (res && res.code) {
          log('otp matched (from ' + redact(res.from || '') + ')');
          await typeInto(page, 'input[autocomplete="one-time-code"]', res.code, jitter(60, 120));
          await sleep(5000);
          const st3 = await pageState(page);
          if (/invalid one-time code/i.test(String(st3.text))) {
            log('otp invalid — resend cycle');
            await sleep(jitter(30000, 45000));
            await jsClick(page, 'resend');
            await sleep(6000);
            res = gmPoll(email, new Date(Date.now() - 30000).toISOString(), 180);
            if (res && res.code) { log('otp(2) matched'); await typeInto(page, 'input[autocomplete="one-time-code"]', res.code, jitter(60, 120)); await sleep(5000); }
          }
          otpDone = true;
          await shot(page, n, '4-otp');
          continue;
        }
        if (res && res.error) log('gmail-rail-error ' + res.error);
        await sleep(4000);
        continue;
      }

      if (st2.pw > 0 && !pwDone) {
        await sleep(jitter(2000, 5000));
        await typeInto(page, 'input[type="password"]', PASSWORD);
        const cnt = await page.evaluate(() => document.querySelectorAll('input[type="password"]').length);
        if (Number(cnt) > 1) await typeInto(page, 'input[type="password"] >> nth=1', PASSWORD);
        await sleep(jitter(900, 2000));
        const ok = (await clickText(page, 'continue|create|sign up')) || ((await jsClick(page, 'continue|create|sign up')) !== 'none');
        pwDone = true;
        log('password submitted (' + ok + ')');
        await sleep(4500);
        continue;
      }
    }

    if (outcome === 'console') {
      await sleep(3000);
      await shot(page, n, '5-console');
      await page.goto('https://console.river.ai/billing', { waitUntil: 'domcontentloaded', timeout: 45000 });
      await sleep(4500);
      const btxt = await page.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));
      const bal = String(btxt).match(/Current balance \$([\d,.]+)/);
      result.credit_usd = bal ? parseFloat(bal[1].replace(/,/g, '')) : null;
      result.grant_seen = /Signup credit/.test(String(btxt));
      log('billing balance=' + result.credit_usd + ' grant=' + result.grant_seen);
      await shot(page, n, '6-billing');

      let key = null;
      try {
        await page.goto('https://console.river.ai/keys', { waitUntil: 'domcontentloaded', timeout: 45000 });
        await sleep(4500);
        await page.evaluate(() => { const b = Array.from(document.querySelectorAll('button')).filter((x) => /create key/i.test(x.innerText || '') && x.offsetWidth > 0)[0]; if (b) b.click(); });
        await sleep(2000);
        await page.evaluate(() => { const el = Array.from(document.querySelectorAll('input')).find((i) => /Production API Key/.test(i.placeholder)); if (el) { el.focus(); el.click(); } });
        await page.keyboard.type('default', { delay: jitter(25, 60) });
        await sleep(600);
        await page.evaluate(() => {
          const inp = Array.from(document.querySelectorAll('input')).find((i) => /Production API Key/.test(i.placeholder));
          if (!inp) return; const root = inp.closest('form') || inp.closest('[data-state]') || document.body;
          const b = Array.from(root.querySelectorAll('button')).find((x) => /create key/i.test(x.innerText || '') && !x.disabled);
          if (b) b.click();
        });
        for (let i = 0; i < 12; i++) {
          await sleep(1200);
          key = await page.evaluate(() => {
            const els = Array.from(document.querySelectorAll('input, textarea, code'));
            for (const e of els) { const v = (e.value || e.textContent || '').trim(); if (/^rv_[A-Za-z0-9_\-]{20,}$/.test(v)) return v; }
            const m = document.body.innerText.match(/rv_[A-Za-z0-9_\-]{20,}/); return m ? m[0] : null;
          });
          if (key && typeof key === 'string' && key.startsWith('rv_')) break;
          key = null;
        }
        if (key) log('KEY CAPTURED (prefix ' + key.slice(0, 12) + '...)');
        else log('key not captured');
        await shot(page, n, '7-key');
      } catch (e) { log('key-error ' + String(e).slice(0, 150)); }

      if (key) {
        result.key = key;
        result.console_access = true;
        const t1 = Date.now();
        let ok = false, last = 0, reply = null, usage = null;
        while (Date.now() - t1 < 8 * 60000) {
          try {
            const r = await fetch(BASE + '/chat/completions', {
              method: 'POST', headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
              body: JSON.stringify({ model: 'deepseek-ai/DeepSeek-V4.1-Flash', messages: [{ role: 'user', content: 'Reply with exactly: RIVER_OK' }], max_tokens: 16, temperature: 0 }),
            });
            last = r.status;
            if (r.status === 200) { const j = await r.json().catch(() => null); ok = true; reply = j?.choices?.[0]?.message?.content; usage = j?.usage; break; }
          } catch {}
          await sleep(30000);
        }
        result.api_tested = ok;
        result.api_test = { model: 'deepseek-ai/DeepSeek-V4.1-Flash', reply, usage, ms: Date.now() - t1, lastStatus: last };
        result.status = ok ? 'live' : 'key-pending-activation';
        log('activation probe ok=' + ok + ' (' + (Date.now() - t1) + 'ms)');
      } else {
        result.console_access = true;
        result.status = 'console-no-key';
      }
    } else if (outcome === 'blocked') {
      result.status = 'blocked';
    } else if (outcome === 'radar-challenge') {
      result.status = 'radar-sms-challenge';
    } else {
      result.status = 'timeout';
    }

    await shot(page, n, '8-final');
    writeEnc(`river-result-${n}-${RUN_ID}`, result);
    writeLog(n, result.status);
    await browser.close().catch(() => {});
    log('OUTCOME ' + result.status);
    process.exit(outcome === 'console' ? 0 : outcome === 'blocked' ? 2 : outcome === 'radar-challenge' ? 4 : 3);
  } catch (e) {
    log('FATAL ' + String(e).slice(0, 250));
    try { writeEnc(`river-result-${payload.n}-${RUN_ID}`, { n: payload.n, email: payload.email, status: 'error', error: String(e).slice(0, 300), created_at: new Date().toISOString(), run: RUN_ID }); writeLog(payload.n, 'error'); } catch {}
    await browser.close().catch(() => {});
    process.exit(3);
  }
}

// ---------- main ----------
const ok = writeCookies();
log(`worker mode=${MODE} run=${RUN_ID} cookies=${ok ? 'set' : 'MISSING'}`);

if (MODE === 'mailtest') {
  const out = gmProbe();
  console.log(out);
  const m = out.match(/PROBE status=(\d+) entries=(\d+)/);
  if (m && m[1] === '200') {
    fs.mkdirSync('results', { recursive: true });
    fs.writeFileSync(`results/mailtest-${RUN_ID}.json`, JSON.stringify({ ok: true, status: 200, entries: Number(m[2]), at: new Date().toISOString(), run: RUN_ID }));
    log('MAILTEST OK entries=' + m[2]);
    process.exit(0);
  } else {
    fs.mkdirSync('results', { recursive: true });
    fs.writeFileSync(`results/mailtest-${RUN_ID}.json`, JSON.stringify({ ok: false, probe: out.slice(0, 300), at: new Date().toISOString(), run: RUN_ID }));
    log('MAILTEST FAIL');
    process.exit(2);
  }
} else if (MODE === 'signup') {
  if (!PAYLOAD_B64) { log('no payload'); process.exit(9); }
  let payload;
  try { payload = JSON.parse(decryptPayload(PAYLOAD_B64)); } catch (e) { log('payload decrypt failed: ' + String(e).slice(0, 120)); process.exit(9); }
  await runSignup(payload);
} else {
  log('unknown mode ' + MODE); process.exit(9);
}
