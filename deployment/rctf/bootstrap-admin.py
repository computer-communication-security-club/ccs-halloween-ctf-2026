#!/usr/bin/env python3
"""Create the first organizer via a loopback-only rCTF API, then promote it."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def request(base, path, body=None, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    req = urllib.request.Request(
        base + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        try:
            kind = json.load(error).get('kind', 'unknown')
        except (ValueError, AttributeError):
            kind = 'unreadable response'
        raise RuntimeError(f'API {path}: HTTP {error.code}, {kind}') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--email', required=True)
    parser.add_argument('--name', default='CCS Organizers')
    parser.add_argument('--permissions', help='Comma-separated rCTF permissions; defaults to full admin')
    parser.add_argument('--output', default='/opt/rctf/admin-access.json',
                        help='Private credential file; must not already exist')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run as root on the rCTF server')
    os.chdir('/opt/rctf')
    os.umask(0o077)
    access = Path(args.output).resolve()
    if access.exists():
        parser.error('Credential file already exists; refusing to overwrite credentials')
    container = 'ccs-rctf-admin-bootstrap-' + uuid.uuid4().hex[:8]
    # The standard public service keeps registrations disabled throughout.
    with tempfile.TemporaryDirectory(prefix='.admin-bootstrap-', dir='/opt/rctf') as temp:
        config = Path(temp)
        shutil.copytree('rctf.d', config, dirs_exist_ok=True)
        (config / '99-bootstrap.json').write_text(json.dumps({'registrationsEnabled': True}))
        # The API runs as UID 1001. The parent /opt/rctf remains root-only.
        config.chmod(0o755)
        for item in config.iterdir():
            if item.is_file():
                item.chmod(0o644)
        try:
            run('docker', 'compose', 'run', '-d', '--no-deps', '--name', container,
                '-p', '127.0.0.1::80', '-v', f'{config}:/app/rctf.d:ro',
                '-e', 'RCTF_INSTANCE_TYPE=frontend', '-e', 'RCTF_DATABASE_MIGRATE=never',
                'rctf')
            binding = run('docker', 'port', container, '80/tcp').splitlines()[0]
            if not binding.startswith('127.0.0.1:'):
                raise RuntimeError('Bootstrap API must bind only to loopback')
            base = 'http://' + binding
            for _ in range(60):
                try:
                    with urllib.request.urlopen(base + '/api/readyz', timeout=2) as response:
                        if response.status == 200:
                            break
                except (OSError, urllib.error.URLError):
                    pass
                time.sleep(1)
            else:
                raise RuntimeError('Bootstrap API did not become ready')
            registration = request(base, '/api/v2/auth/register', {
                'email': args.email, 'name': args.name,
            })
            if registration['kind'] != 'goodRegisterV2':
                raise RuntimeError('Registration did not issue a team token')
            tokens = registration['data']
            # Save before promotion so any later error cannot lose account access.
            credentials = {
                'email': args.email,
                'name': args.name,
                'login_url': 'https://ctf.sict-ccs.club/login?' + urllib.parse.urlencode({
                    'token': tokens['teamToken'],
                }),
                'team_token': tokens['teamToken'],
                'admin_url': 'https://ctf.sict-ccs.club/admin',
            }
            with access.open('x') as stream:
                json.dump(credentials, stream, indent=2)
                stream.write('\n')
            promotion = ['docker', 'compose', 'exec', '-T', 'rctf', 'rctf', 'user', 'promote', args.email]
            if args.permissions:
                promotion.extend(['--perms', args.permissions])
            run(*promotion)
            login = request('http://127.0.0.1:8080', '/api/v1/auth/login', {
                'teamToken': tokens['teamToken'],
            })
            result = request('http://127.0.0.1:8080', '/api/v1/admin/challs',
                             token=login['data']['authToken'])
            if not result.get('kind', '').startswith('good'):
                raise RuntimeError('Admin API validation failed')
            print('Admin created and authenticated API access verified.')
            print(f'Credentials saved to {access} (root-only).')
        finally:
            subprocess.run(['docker', 'rm', '-f', container], capture_output=True, check=False)


if __name__ == '__main__':
    main()
