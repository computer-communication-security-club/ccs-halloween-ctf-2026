#!/usr/bin/env python3
"""Bounded concurrent read-only smoke check; not a submissions load benchmark."""
import argparse
import concurrent.futures
import json
import math
import ssl
import threading
import time
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--url', default='https://ctf.sict-ccs.club')
parser.add_argument('--clients', type=int, default=100)
parser.add_argument('--requests-per-client', type=int, default=10)
args = parser.parse_args()
if not 1 <= args.clients <= 100 or not 1 <= args.requests_per_client <= 10:
    parser.error('Use 1-100 clients and 1-10 requests per client')

context = ssl.create_default_context()
barrier = threading.Barrier(args.clients)
paths = ['/', '/api/readyz', '/api/v1/integrations/client/config']


def client(index):
    durations, errors = [], []
    barrier.wait(timeout=30)
    for iteration in range(args.requests_per_client):
        path = paths[(index + iteration) % len(paths)]
        start = time.perf_counter()
        try:
            request = urllib.request.Request(
                args.url.rstrip('/') + path,
                headers={'User-Agent': 'CCS-rCTF-deployment-smoke-test'},
            )
            with urllib.request.urlopen(request, timeout=15, context=context) as response:
                data = response.read()
                assert response.status == 200, response.status
                if path == '/api/readyz':
                    assert data.strip() == b'ok', 'Unexpected readiness response'
                elif path.endswith('/config'):
                    assert json.loads(data)['kind'] == 'goodClientConfig'
                else:
                    assert b'<html' in data.lower(), 'Missing HTML'
        except Exception as error:
            errors.append({'path': path, 'error': str(error)})
        durations.append(time.perf_counter() - start)
        time.sleep(0.1)
    return durations, errors


started = time.perf_counter()
with concurrent.futures.ThreadPoolExecutor(max_workers=args.clients) as pool:
    results = list(pool.map(client, range(args.clients)))
durations = sorted(value for values, _ in results for value in values)
errors = [error for _, items in results for error in items]
elapsed = time.perf_counter() - started
print(json.dumps({
    'url': args.url,
    'clients': args.clients,
    'requests': len(durations),
    'failed': len(errors),
    'elapsed_seconds': round(elapsed, 2),
    'requests_per_second': round(len(durations) / elapsed, 2),
    'p95_ms': round(durations[math.ceil(len(durations) * 0.95) - 1] * 1000, 2),
    'errors': errors[:10],
    'scope': 'Homepage, readiness (Postgres/Redis), and public config; no registration or submissions',
}, indent=2))
raise SystemExit(bool(errors))
