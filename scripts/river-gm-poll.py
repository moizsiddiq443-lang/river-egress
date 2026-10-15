# river-gm-poll.py — GHA port: poll the anonysusarchiver Gmail rail for River/WorkOS mail,
# extract the 6-digit verification code (newest phrased match wins; resends stack in-thread).
# Usage: python3 river-gm-poll.py --ck /tmp/gmail-ck.json --to alias@duck.com --since ISO --timeout 150
#        python3 river-gm-poll.py --ck /tmp/gmail-ck.json --probe
# Prints log lines; final line: RESULT: {...} or RESULT: null; probe prints: PROBE status=200 entries=20
import json, re, sys, time, argparse
from curl_cffi import requests as creq

ap = argparse.ArgumentParser()
ap.add_argument('--ck', default='/tmp/gmail-ck.json')
ap.add_argument('--to', default='')
ap.add_argument('--since', default='')
ap.add_argument('--timeout', type=int, default=120)
ap.add_argument('--probe', action='store_true')
a = ap.parse_args()

allc = json.load(open(a.ck, encoding='utf8'))
scoped = [c for c in allc if c.get('domain') in ('mail.google.com', '.google.com')]
s = creq.Session(impersonate='chrome', timeout=25)
s.headers.update({'Cookie': '; '.join(f"{c['name']}={c['value']}" for c in scoped), 'Accept-Language': 'en-US,en;q=0.9'})

def entries():
    r = s.get('https://mail.google.com/mail/feed/atom', allow_redirects=False)
    if r.status_code != 200:
        return None
    out = []
    for m in re.finditer(r'(?s)<entry>(.*?)</entry>', r.text):
        blk = m.group(1)
        th = re.search(r'tag:gmail\.google\.com,2004:(\d+)', blk)
        email = re.search(r'<email>([^<]+)</email>', blk)
        title = re.search(r'<title>(.*?)</title>', blk, re.S)
        summary = re.search(r'<summary>(.*?)</summary>', blk, re.S)
        modified = re.search(r'<modified>([^<]+)</modified>', blk)
        out.append({'thread': th.group(1) if th else None, 'email': email.group(1) if email else '',
                    'title': (title.group(1) if title else ''), 'summary': (summary.group(1) if summary else ''),
                    'modified': modified.group(1) if modified else ''})
    return out

def msg_text(thread_id):
    r = s.get(f'https://mail.google.com/mail/u/0/?ui=2&ik=0&view=pt&permthid=thread-f%3A{thread_id}&search=all', allow_redirects=False)
    if r.status_code != 200:
        return ''
    txt = re.sub(r'(?s)<[^>]+>', ' ', r.text).replace('\u00a0', ' ')
    return ' '.join(txt.split())

if a.probe:
    try:
        es = entries()
    except Exception as e:
        print('PROBE status=0 entries=0 err=' + str(e)[:80]); sys.exit(1)
    if es is None:
        print('PROBE status=401 entries=0'); sys.exit(1)
    print(f'PROBE status=200 entries={len(es)}')
    sys.exit(0)

if not a.to:
    print('RESULT: {"error":"no --to"}'); sys.exit(1)

t0 = time.time()
seen = set()
while time.time() - t0 < a.timeout:
    es = None
    try:
        es = entries()
    except Exception as e:
        print('feed err', str(e)[:120], flush=True)
    if es is None:
        print('RESULT: {"error":"feed_unavailable"}')
        sys.exit(2)
    target = a.to.lower()
    for e in es:
        blob = (e['email'] + ' ' + e['title'] + ' ' + e['summary']).lower()
        relevant = re.search(r'river|workos|console\.river', blob, re.I) and (target in blob or target.split('@')[0] in blob or 'duck.com' in blob)
        fresh = (not a.since) or (e['modified'] and e['modified'] >= a.since)
        if relevant and fresh and e['thread'] and e['thread'] not in seen:
            seen.add(e['thread'])
            txt = msg_text(e['thread'])
            phrased = re.findall(r'verification code is\s*(\d{6})', txt, re.I)
            codes = re.findall(r'\b\d{6}\b', txt)
            code = phrased[-1] if phrased else (codes[-1] if codes else None)
            link = re.search(r'https?://[^\s"\']*(?:verify|confirm|token|login)[^\s"\']*', txt)
            print('MATCH', e['email'], '|', e['title'][:90], '|', e['modified'], '| phrased codes:', phrased, flush=True)
            if code or link:
                print('RESULT: ' + json.dumps({'code': code, 'codes': codes[:6],
                                               'link': link.group(0) if link else None, 'from': e['email'],
                                               'title': e['title'][:120], 'modified': e['modified']}))
                sys.exit(0)
    time.sleep(8)
print('RESULT: null')
