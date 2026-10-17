// tuta-signup.mjs — GHA egress worker: Tuta mailbox factory (one account per run).
// Payload (AES-256-GCM, key=sha256(ENC_KEY)): {username, password?}. Result envelope-encrypted to river-public.pem.
// Flow (validated 2026-10-18): plan -> Free -> form -> Create Account -> clock captcha (dual-signal ray-scan,
// up to 4 rounds incl. wrong-answer retries) -> Recovery Kit (code polled 20s) -> acknowledge -> mailbox.
// The worker launches its own chromium (playwright cache) with --remote-debugging-port=9222 and drives it via CDP.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';

const PAYLOAD_B64 = process.argv[2] || '';
const ENC_KEY = process.env.ENC_KEY || '';
const RUN_ID = process.env.GITHUB_RUN_ID || 'local';
const PORT = 9222;
const CDP_URL = `http://127.0.0.1:${PORT}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const steps = [];
const t0 = Date.now();
function log(m) { const s = `[${new Date().toISOString()}] ${m}`; console.log(s.slice(0, 400)); steps.push({ t: Date.now() - t0, m: redact(String(s)) }); }
function redact(s) {
  return String(s)
    .replace(/[A-Za-z0-9._%+-]+@tutamail\.com/g, (m) => m.slice(0, 3) + '***@tutamail.com')
    .replace(/\b[0-9a-f]{4}( [0-9a-f]{4}){15}\b/gi, '<recovery>');
}

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
  fs.writeFileSync(path.join('results', name + '.enc'), envelope(Buffer.from(JSON.stringify(obj, null, 2), 'utf8')));
  log('wrote results/' + name + '.enc');
}
function writeLog(status) {
  fs.mkdirSync('results', { recursive: true });
  fs.writeFileSync(path.join('results', `tuta-log-${RUN_ID}.json`), JSON.stringify({ status, run: RUN_ID, started: new Date(t0).toISOString(), ms: Date.now() - t0, steps: steps.map((s) => s.m) }, null, 1));
}

// ---------- payload ----------
let USERNAME = '';
let PASSWORD = '';
try {
  const p = JSON.parse(decryptPayload(PAYLOAD_B64));
  USERNAME = p.username || '';
  PASSWORD = p.password || '';
} catch (e) { log('payload decrypt failed: ' + String(e.message).slice(0, 80)); }
if (!USERNAME) { log('no username in payload — abort'); writeLog('no-username'); process.exit(2); }
if (!PASSWORD) {
  const W = ['Amber', 'Basil', 'Cedar', 'Delta', 'Ember', 'Flint', 'Grove', 'Hazel'];
  PASSWORD = `${W[Math.floor(Math.random() * 4)].toUpperCase()}-Tuta-${Math.random().toString(36).slice(2, 6)}!${Math.random().toString(36).slice(2, 5)}`;
}

// ---------- chromium bootstrap ----------
function findChromium() {
  const cands = [process.env.PW_CHROMIUM,
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
const CHROME = findChromium();
if (!CHROME) { log('chromium not found'); writeLog('no-chromium'); process.exit(3); }
log('chromium: ' + CHROME);
const proc = spawn(CHROME, [
  `--remote-debugging-port=${PORT}`, '--user-data-dir=/tmp/tuta-prof',
  '--window-size=1280,950', '--no-first-run', '--no-default-browser-check',
  '--no-sandbox', '--disable-dev-shm-usage', '--lang=en-US', 'about:blank',
], { detached: true, stdio: 'ignore' });
proc.unref();

let up = false;
for (let i = 0; i < 40 && !up; i++) {
  try { const v = await (await fetch(`${CDP_URL}/json/version`)).json(); if (v.webSocketDebuggerUrl) up = true; } catch { await sleep(800); }
}
if (!up) { log('chromium CDP never came up'); writeLog('no-cdp'); process.exit(3); }
log('chromium up');

// ---------- CDP plumbing ----------
const ver = await (await fetch(`${CDP_URL}/json/version`)).json();
const bws = new WebSocket(ver.webSocketDebuggerUrl);
await new Promise((res, rej) => { bws.onopen = res; bws.onerror = rej; });
let bid = 0; const bpend = new Map();
const bsend = (method, params = {}) => new Promise((res, rej) => { const i = ++bid; bpend.set(i, { res, rej }); bws.send(JSON.stringify({ id: i, method, params })); });
bws.onmessage = (ev2) => { const m = JSON.parse(ev2.data); if (m.id && bpend.has(m.id)) { const { res, rej } = bpend.get(m.id); bpend.delete(m.id); m.error ? rej(new Error(m.error.message)) : res(m.result); } };
const created = await bsend('Target.createTarget', { url: 'https://app.tuta.com/signup' });
const targetId = created.targetId;
await sleep(10000);

let page = null;
for (let i = 0; i < 12 && !page; i++) {
  const l = await (await fetch(`${CDP_URL}/json/list`)).json();
  page = l.find((t) => t.id === targetId);
  if (!page) await sleep(1000);
}
if (!page) { log('no target'); writeLog('no-target'); process.exit(4); }
const cdp = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((res, rej) => { cdp.onopen = res; cdp.onerror = rej; });
let id = 0; const pend = new Map();
const send = (method, params = {}) => new Promise((res, rej) => { const i = ++id; pend.set(i, { res, rej }); cdp.send(JSON.stringify({ id: i, method, params })); });
cdp.onmessage = (ev2) => { const m = JSON.parse(ev2.data); if (m.id && pend.has(m.id)) { const { res, rej } = pend.get(m.id); pend.delete(m.id); m.error ? rej(new Error(m.error.message)) : res(m.result); } };
const ev = async (expression) => {
  const r = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (r.exceptionDetails) throw new Error('eval: ' + (r.exceptionDetails.text || 'err'));
  return r.result ? r.result.value : undefined;
};
const text = () => ev('document.body ? document.body.innerText : ""');
const waitText = async (re, ms) => { const t1 = Date.now(); while (Date.now() - t1 < ms) { const t = await text().catch(() => ''); if (re.test(t)) return true; await sleep(700); } return false; };
const mouse = (type, x, y, extra = {}) => send('Input.dispatchMouseEvent', { type, x, y, ...extra });
const tclick = async (sel) => {
  const r = await ev(`(()=>{const b=${sel};if(!b)return null;b.scrollIntoView({block:'center'});const rr=b.getBoundingClientRect();return {x:Math.round(rr.x+rr.width/2),y:Math.round(rr.y+rr.height/2)}})()`);
  if (!r) return false;
  await mouse('mouseMoved', r.x - 70, r.y - 40);
  for (let i = 1; i <= 5; i++) { await sleep(40); await mouse('mouseMoved', r.x - 70 + (70 * i) / 5, r.y - 40 + (40 * i) / 5); }
  await sleep(100);
  await mouse('mousePressed', r.x, r.y, { button: 'left', clickCount: 1 });
  await sleep(70);
  await mouse('mouseReleased', r.x, r.y, { button: 'left', clickCount: 1 });
  return true;
};
const btnByText = (re) => `[...document.querySelectorAll('button')].find(b=>new RegExp(${JSON.stringify(re)},'i').test((b.innerText||'').trim()))`;

const result = { username: USERNAME, email: USERNAME + '@tutamail.com', password: PASSWORD, status: 'start', run: RUN_ID, started_at: new Date(t0).toISOString(), rounds: [] };
const fail = (why) => {
  result.error = why; result.status = result.status.startsWith('LIVE') ? result.status : 'fail:' + why;
  writeEnc(`tuta-result-${USERNAME}-${RUN_ID}`, result);
  log('FAIL ' + why);
  writeLog(result.status);
  process.exit(1);
};

try {
  // 1) plan
  if (!(await waitText(/Free[\s\S]*1 GB storage|Continue/i, 45000))) fail('plan screen missing');
  await ev(`(()=>{const rs=[...document.querySelectorAll('.buyOptionBox-v2 input[type=radio]')];if(rs[2]&&!rs[2].checked)rs[2].click();return rs.length})()`);
  await sleep(600);
  await tclick(btnByText('^continue$'));
  result.status = 'plan-continued';

  // 2) form
  if (!(await waitText(/Create Account[\s\S]*Set password|Repeat password/i, 40000))) fail('form missing');
  let avail = false;
  for (let attempt = 0; attempt < 4 && !avail; attempt++) {
    await ev(`(()=>{const ins=[...document.querySelectorAll('input')];const set=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;const fire=(el,v)=>{set.call(el,v);el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}))};fire(ins[0],${JSON.stringify(USERNAME)});fire(ins[1],${JSON.stringify(PASSWORD)});fire(ins[2],${JSON.stringify(PASSWORD)});const cbs=ins.filter(i=>i.type==='checkbox');cbs.forEach(c=>{if(!c.checked)c.click()});return 1})()`);
    const t1 = Date.now();
    while (Date.now() - t1 < 14000) {
      const t = await text().catch(() => '');
      if (/Email address is available/i.test(t)) { avail = true; break; }
      if (/not available|already taken|taken/i.test(t)) break;
      await sleep(700);
    }
    if (!avail) { USERNAME = `${USERNAME.split('.')[0]}.${USERNAME.split('.')[1] || 'x'}${Math.floor(Math.random() * 900 + 100)}`; result.username = USERNAME; result.email = USERNAME + '@tutamail.com'; result.renamed = true; }
  }
  if (!avail) fail('username never available');
  result.status = 'form-filled';
  await tclick(btnByText('create account'));
  result.status = 'submitted';

  // 3) captcha
  let solved = false;
  for (let round = 1; round <= 4 && !solved; round++) {
    if (!(await waitText(/Enter the time of the displayed clock/i, 60000))) fail('captcha dialog missing');
    await sleep(1000);
    const solRaw = await ev(`(${solverSrc()})()`);
    let sol = null; try { sol = JSON.parse(solRaw); } catch {}
    result.rounds.push({ round, sol: sol ? { answer: sol.answer, mAng: sol.mAng, hAng: sol.hAng, mMax: sol.mMax, hMax: sol.hMax, conf: sol.confidence, err: sol.error } : String(solRaw).slice(0, 140) });
    if (!sol || !sol.answer) fail('solver error: ' + String(solRaw).slice(0, 160));
    const fill = await ev(`(()=>{const set=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;const el=[...document.querySelectorAll('input')].find(i=>i.type==='text'&&i.offsetParent&&(i.value===''||/^[0-9:. ]{0,7}$/.test(i.value)));if(!el)return 'no-field';set.call(el,'');el.dispatchEvent(new Event('input',{bubbles:true}));set.call(el,${JSON.stringify(sol.answer)});el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));return el.value})()`);
    result.rounds[result.rounds.length - 1].filled = fill;
    await sleep(400);
    await tclick(btnByText('^ok$'));
    const t2 = Date.now(); let outcome = null;
    while (Date.now() - t2 < 50000) {
      const t = await text().catch(() => '');
      if (/Save Your Key|Copy Recovery Code/i.test(t)) { outcome = 'kit'; break; }
      if (/answer is wrong|Unfortunately/i.test(t)) { outcome = 'wrong'; break; }
      await sleep(900);
    }
    result.rounds[result.rounds.length - 1].outcome = outcome || 'timeout';
    if (outcome === 'kit') { solved = true; break; }
    await tclick(btnByText('^ok$'));
    await sleep(3000);
  }
  if (!solved) fail('captcha not solved after rounds');
  result.status = 'captcha-solved';

  // 4) recovery kit
  let code = null; const tc = Date.now();
  while (Date.now() - tc < 20000 && !code) {
    const t = await text().catch(() => '');
    const m = t.match(/[0-9a-f]{4}(?:\s+[0-9a-f]{4}){15}/i) || t.match(/(?:[0-9a-f]{4}\s+){6,}[0-9a-f]{4}/i);
    if (m) code = m[0]; else await sleep(700);
  }
  result.recovery = code;
  if (!code) fail('recovery code not found');
  await ev(`(()=>{const cbs=[...document.querySelectorAll('input[type=checkbox]')];cbs.forEach(c=>{if(!c.checked)c.click()});return 1})()`);
  await sleep(400);
  await tclick(btnByText("let'?s get started"));
  result.status = 'recovery-saved';

  // 5) mailbox + review
  const arrived = await waitText(/Inbox|New email/i, 60000);
  if (!arrived) fail('mailbox did not load');
  await sleep(3000);
  const t3 = await text();
  const review = /short review|One last step/i.test(t3);
  result.review = review ? 'pending-banner' : 'no-banner';
  result.inbox = (t3.match(/Inbox\s+(\d+)/i) || [])[1] | 0;
  result.status = 'LIVE' + (review ? '(review)' : '(clean)');
  result.url = await ev('location.href');
} catch (e) { result.error = result.error || String(e && e.message).slice(0, 200); }

result.ms = Date.now() - t0;
writeEnc(`tuta-result-${USERNAME}-${RUN_ID}`, result);
log('status=' + result.status + ' ms=' + result.ms);
writeLog(result.status);
process.exit(result.status.startsWith('LIVE') ? 0 : 1);

function solverSrc() {
  return `() => {
  const img = [...document.querySelectorAll('img')].find(i => (i.src || '').startsWith('data:image/png'));
  if (!img) return JSON.stringify({ error: 'no-img' });
  const W = img.naturalWidth, H = img.naturalHeight;
  const c = document.createElement('canvas'); c.width = W; c.height = H;
  const x = c.getContext('2d'); x.drawImage(img, 0, 0);
  const d = x.getImageData(0, 0, W, H).data;
  const cx = W / 2, cy = H / 2;
  const lum = (px, py) => { const i = (py * W + px) * 4; return d[i] * 0.299 + d[i + 1] * 0.587 + d[i + 2] * 0.114; };
  const rays = [];
  for (let a = 0; a < 360; a++) {
    const rad = a * Math.PI / 180;
    const dx = Math.sin(rad), dy = -Math.cos(rad);
    let run = 0, best = 0, bestSt = -1, curSt = -1;
    for (let r = 70; r < 340; r += 2) {
      const px = Math.round(cx + dx * r), py = Math.round(cy + dy * r);
      if (px < 0 || py < 0 || px >= W || py >= H) { run = 0; continue; }
      if (lum(px, py) < 110) { if (run === 0) curSt = r; run += 2; if (run > best) { best = run; bestSt = curSt; } }
      else run = 0;
    }
    if (best >= 40 && bestSt <= 90) rays.push({ a, best });
  }
  if (!rays.length) return JSON.stringify({ error: 'no hand rays' });
  const sorted = rays.slice().sort((p, q) => p.a - q.a);
  const clusters = [];
  for (const r of sorted) {
    const last = clusters[clusters.length - 1];
    if (last && (r.a - last.lastA) <= 5) { last.members.push(r); last.lastA = r.a; }
    else clusters.push({ members: [r], lastA: r.a });
  }
  if (clusters.length > 1) {
    const f = clusters[0], l = clusters[clusters.length - 1];
    if (f.members[0].a <= 5 && l.lastA >= 355) { l.members = l.members.concat(f.members); clusters.shift(); }
  }
  const cmean = (mem) => { let s = 0, c2 = 0; for (const m of mem) { const rad = m.a * Math.PI / 180; s += Math.sin(rad); c2 += Math.cos(rad); } let ang = Math.atan2(s, c2) * 180 / Math.PI; if (ang < 0) ang += 360; return ang; };
  const stats = clusters.map(cl => ({ ang: cmean(cl.members), max: Math.max(...cl.members.map(m => m.best)), n: cl.members.length })).sort((p, q) => q.max - p.max);
  if (stats.length < 1) return JSON.stringify({ error: 'no clusters' });
  const minuteC = stats[0];
  let hourC = null;
  for (let i = 1; i < stats.length; i++) {
    const s = stats[i];
    let dd = Math.abs(s.ang - minuteC.ang); if (dd > 180) dd = 360 - dd;
    if (dd > 18 && s.max >= 50) { hourC = s; break; }
  }
  if (!hourC) return JSON.stringify({ error: 'no hour cluster', stats: stats.slice(0, 6) });
  const minute = Math.round(minuteC.ang / 6) % 60;
  let hour = Math.round((hourC.ang - minute * 0.5) / 30) % 12; if (hour <= 0) hour += 12;
  return JSON.stringify({
    answer: String(hour).padStart(2, '0') + ':' + String(minute).padStart(2, '0'),
    mAng: Math.round(minuteC.ang), hAng: Math.round(hourC.ang), mMax: minuteC.max, hMax: hourC.max,
    confidence: minuteC.max > 120 && hourC.max > 60 ? 'high' : minuteC.max > 80 ? 'medium' : 'low',
    stats: stats.slice(0, 5).map(s => ({ ang: Math.round(s.ang), max: s.max, n: s.n })),
  });
}`;
}
