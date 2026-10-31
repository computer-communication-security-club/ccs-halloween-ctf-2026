#!/usr/bin/env python3
"""Seed demo data exclusively into the named local preview Compose project."""
import json
import subprocess
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = 'http://localhost:8080'
ACCESS = ROOT / '.local/preview-access.json'

def request(path, data=None, token=None, method=None):
    headers = {'Content-Type': 'application/json', 'Origin': ORIGIN}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(ORIGIN + '/api' + path,
        data=json.dumps(data).encode() if data is not None else None,
        headers=headers, method=method)
    with urllib.request.urlopen(req) as response:
        result = json.load(response)
    if not result['kind'].startswith('good'):
        raise RuntimeError(result['kind'])
    return result.get('data')

if ACCESS.exists():
    access = json.loads(ACCESS.read_text())
    auth = request('/v1/auth/login', {'teamToken': access['teamToken']})['authToken']
else:
    result = request('/v2/auth/register', {'name': 'Midnight Debuggers', 'email': 'preview@example.invalid'})
    auth = result['authToken']
    access = {'teamToken': result['teamToken'], 'login_url': ORIGIN + '/login?token=' + result['teamToken']}
    ACCESS.parent.mkdir(exist_ok=True, mode=0o700)
    ACCESS.touch(mode=0o600)
    ACCESS.write_text(json.dumps(access, indent=2) + '\n')

subprocess.run(['docker', 'compose', '-f', str(ROOT / 'compose.preview.yml'),
    'exec', '-T', 'rctf', 'rctf', 'user', 'promote', 'preview@example.invalid'], check=True)
# Reauthenticate after the CLI invalidates cached permissions.
auth = request('/v1/auth/login', {'teamToken': access['teamToken']})['authToken']
for i, (slug, name, category, points, teaser) in enumerate([
    ('pumpkin-patch', 'Pumpkin Patch', 'pwn', 100, 'Something is growing just beyond the buffer.'),
    ('ghost-in-the-shell', 'Ghost in the Shell', 'web', 150, 'An abandoned endpoint still answers after midnight.'),
    ('witches-cipher', "The Witch’s Cipher", 'crypto', 200, 'A spellbook, a secret, and one suspiciously familiar pattern.'),
    ('dead-signal', 'Dead Signal', 'rev', 250, 'The program is silent. Its instructions are not.'),
    ('graveyard-shift', 'Graveyard Shift', 'forensics', 300, 'Some files refuse to stay deleted.'),
    ('trick-or-treat', 'Trick or Treat', 'misc', 50, 'Your first stop in the haunted neighborhood.'),
]):
    request('/v2/admin/challs/preview-' + slug, {'data': {
        'name': name, 'category': category, 'author': 'CCS preview',
        'description': teaser + '\n\n**Theme preview only.** This is sample data, not an event challenge.\n\nSubmit `ccsCTF{preview_' + slug.replace('-', '_') + '}` to try the solve flow.',
        'flag': 'ccsCTF{preview_' + slug.replace('-', '_') + '}',
        'points': {'min': points, 'max': points}, 'hidden': False,
        'releaseTime': None, 'tags': ['Preview'], 'sortWeight': i,
    }}, auth, 'PUT')
print('Six local sample challenges ready. Preview login saved to .local/preview-access.json.')
