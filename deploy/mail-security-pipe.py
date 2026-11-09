#!/usr/bin/env python3
"""Postfix pipe adapter: acknowledge only durable per-recipient acceptance."""
import argparse
import base64
import json
from pathlib import Path
import sys
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None


def main():
    p = argparse.ArgumentParser()
    for name in ('queue-id', 'sender', 'recipient', 'ip'): p.add_argument('--' + name, required=True)
    args = p.parse_args()
    raw = sys.stdin.buffer.read(64 * 1024 * 1024 + 1)
    if not raw or len(raw) > 64 * 1024 * 1024: return 75
    try:
        secret = Path('/etc/masspanel/rspamd-export-secret').read_text().strip()
        if not secret: raise ValueError()
        meta = {'queue_id': args.queue_id, 'sender': '' if args.sender == '<>' else args.sender.lower(),
                'recipient': args.recipient.lower(), 'ip': args.ip or '127.0.0.1'}
        headers = {'Content-Type': 'message/rfc822', 'X-MassPanel-Envelope': json.dumps(meta),
                   'Authorization': 'Basic ' + base64.b64encode(('masspanel:' + secret).encode()).decode()}
        request = Request('http://127.0.0.1:8100/api/mail-security/ingest/scan', data=raw, headers=headers, method='POST')
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=100) as response:
            result = json.loads(response.read(65536))
        if result.get('accepted') is not True: raise ValueError()
        return 0
    except Exception:
        print('Temporary mail security failure; message remains in Postfix queue.', file=sys.stderr)
        return 75


if __name__ == '__main__': sys.exit(main())
