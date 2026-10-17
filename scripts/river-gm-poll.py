# river-gm-poll.py — IMAP edition (app-password rail; Rule-2 compliant, no browser cookies).
# Polls the anonysusarchiver Gmail for a forwarded verification mail addressed to <--to> and extracts
# the 6-digit code (phrased match wins: "verification code is NNNNNN"; newest message in the window wins).
# Usage: python3 river-gm-poll.py --to alias@certustender.com --since ISO --timeout 150
#        python3 river-gm-poll.py --probe
#   (--ck <file> is accepted for backwards compatibility and IGNORED.)
# Env: GMAIL_APP_PW (required), GMAIL_USER (default anonysusarchiver@gmail.com)
# Final line: RESULT: {...} | RESULT: null | RESULT: {"error": ...}; probe prints: PROBE status=200 entries=N
import json, re, sys, time, argparse, os, imaplib, email
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from email.header import decode_header

ap = argparse.ArgumentParser()
ap.add_argument('--ck', default='')      # legacy, ignored
ap.add_argument('--to', default='')
ap.add_argument('--since', default='')
ap.add_argument('--timeout', type=int, default=120)
ap.add_argument('--probe', action='store_true')
a = ap.parse_args()

USER = os.environ.get('GMAIL_USER', 'anonysusarchiver@gmail.com')
PW = os.environ.get('GMAIL_APP_PW', '')
if not PW:
    print('RESULT: {"error":"no GMAIL_APP_PW"}'); sys.exit(2)

def connect():
    m = imaplib.IMAP4_SSL('imap.gmail.com', 993)
    m.login(USER, PW)
    return m

def hdr_str(v):
    try:
        parts = decode_header(v or '')
        out = ''
        for txt, enc in parts:
            out += txt.decode(enc or 'utf-8', 'ignore') if isinstance(txt, bytes) else str(txt)
        return out
    except Exception:
        return str(v or '')

def msg_text(msg):
    txt = ''
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ('text/plain', 'text/html'):
                try:
                    txt += part.get_payload(decode=True).decode('utf-8', 'ignore') + '\n'
                except Exception:
                    pass
    else:
        try:
            txt = msg.get_payload(decode=True).decode('utf-8', 'ignore')
        except Exception:
            pass
    plain = re.sub(r'<[^>]+>', ' ', txt).replace('\u00a0', ' ')
    return ' '.join(plain.split())

def parse_msg(raw, target):
    msg = email.message_from_bytes(raw)
    frm = hdr_str(msg.get('From', ''))
    subj = hdr_str(msg.get('Subject', ''))
    date = msg.get('Date', '')
    tos = hdr_str(msg.get('To', '')) + ' ' + hdr_str(msg.get('Delivered-To', '')) + ' ' + hdr_str(msg.get('X-Forwarded-To', ''))
    ts = 0
    try:
        ts = parsedate_to_datetime(date).timestamp()
    except Exception:
        pass
    text = msg_text(msg)
    phrased = re.findall(r'verification code is\s*(\d{6})', text, re.I)
    codes = re.findall(r'\b\d{6}\b', text)
    link = re.search(r'https?://[^\s"\']*(?:verify|confirm|token|login)[^\s"\']*', text)
    blob = (frm + ' ' + subj + ' ' + text[:600]).lower()
    relevant = bool(re.search(r'river|workos|console\.river', blob, re.I)) or (target.lower() in tos.lower())
    return {'ts': ts, 'from': frm[:120], 'title': subj[:160], 'to': tos[:160],
            'code': (phrased[-1] if phrased else (codes[-1] if codes else None)),
            'codes': codes[:6], 'link': link.group(0) if link else None,
            'relevant': relevant, 'mid': (msg.get('Message-ID') or '').strip()}

def search_ids(m, target, since_imap):
    ids = []
    # Gmail extended search first (fast, server-side): to:<addr> newer_than:1d
    try:
        typ, data = m.search(None, 'X-GM-RAW', '"to:%s newer_than:1d"' % target)
        if typ == 'OK' and data and data[0]:
            ids = data[0].split()
    except Exception:
        pass
    if not ids:
        try:
            typ, data = m.search(None, 'TO', '"%s"' % target, 'SINCE', since_imap)
            if typ == 'OK' and data and data[0]:
                ids = data[0].split()
        except Exception:
            pass
    return ids

def probe():
    m = connect()
    m.select('INBOX', readonly=True)
    typ, data = m.status('INBOX', '(UNSEEN)')
    n = 0
    if typ == 'OK' and data:
        mm = re.search(rb'UNSEEN\s+(\d+)', data[0])
        if mm:
            n = int(mm.group(1))
    print('PROBE status=200 entries=%d' % n)
    m.logout()

def main():
    if a.probe:
        try:
            probe()
        except Exception as e:
            print('PROBE status=0 entries=0 err=' + str(e)[:100]); sys.exit(1)
        return
    if not a.to:
        print('RESULT: {"error":"no --to"}'); sys.exit(1)
    since_epoch = None
    if a.since:
        try:
            since_epoch = datetime.fromisoformat(a.since.replace('Z', '+00:00')).timestamp()
        except Exception:
            try:
                since_epoch = float(a.since)
            except Exception:
                pass
    since_imap = datetime.fromtimestamp(since_epoch or (time.time() - 7200), tz=timezone.utc).strftime('%d-%b-%Y')
    t0 = time.time()
    seen = set()
    m = connect()
    try:
        m.select('"[Gmail]/All Mail"', readonly=True)
    except Exception:
        m.select('INBOX', readonly=True)
    while time.time() - t0 < a.timeout:
        try:
            ids = search_ids(m, a.to, since_imap)
            best = None
            for i in ids[-12:]:
                mid = i.decode() if isinstance(i, bytes) else str(i)
                if mid in seen:
                    continue
                typ, d = m.fetch(mid, '(BODY.PEEK[])')
                for part in d:
                    if isinstance(part, tuple) and part[1]:
                        info = parse_msg(part[1], a.to)
                        seen.add(mid)
                        if info['code'] and info['relevant']:
                            if since_epoch and info['ts'] and info['ts'] < since_epoch - 120:
                                continue
                            if not best or info['ts'] >= best['ts']:
                                best = info
            if best:
                print('MATCH', best['from'][:60], '|', best['title'][:90], '|', best['ts'], flush=True)
                out = {'code': best['code'], 'codes': best['codes'], 'link': best['link'], 'from': best['from'],
                       'title': best['title'], 'modified': best['ts'], 'to': best['to']}
                print('RESULT: ' + json.dumps(out))
                m.logout(); return
        except Exception as e:
            print('imap err ' + str(e)[:120], flush=True)
            try:
                m.logout()
            except Exception:
                pass
            try:
                m = connect()
                try:
                    m.select('"[Gmail]/All Mail"', readonly=True)
                except Exception:
                    m.select('INBOX', readonly=True)
            except Exception:
                pass
        time.sleep(8)
    print('RESULT: null')
    try:
        m.logout()
    except Exception:
        pass

main()
