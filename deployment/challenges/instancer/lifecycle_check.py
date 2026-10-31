"""Run inside the instance-manager container; creates only disposable test teams."""
import asyncio
import copy
import json
import os
import sys
from pathlib import Path
import time
import urllib.error
import urllib.request
import uuid

from aiodocker import Docker

POLICY = json.loads(Path('/etc/ccs/policy.json').read_text())
CHALLENGE = sys.argv[1] if len(sys.argv) > 1 else 'shelloween'
PREFIX = 'ccs-verify-' + uuid.uuid4().hex
TEAMS = [PREFIX + '-a', PREFIX + '-b']


def call(method, team, *, create=False, ttl=20000, expected=200, mutate=None):
    form = {'rctfAuthToken': os.environ['AUTH_TOKEN'], 'teamId': team,
            'challengeIntegrationId': CHALLENGE}
    if create:
        form.update(copy.deepcopy(POLICY['challenges'][CHALLENGE]))
    if create or method == 'PATCH':
        form['timeoutMilliseconds'] = ttl
    if mutate:
        mutate(form)
    try:
        with urllib.request.urlopen(urllib.request.Request(
                'http://127.0.0.1:1337/v1/instances/', method=method,
                data=json.dumps(form).encode(), headers={'Content-Type': 'application/json'}), timeout=20) as response:
            assert response.status == expected
            return json.load(response)
    except urllib.error.HTTPError as error:
        assert error.code == expected, f'Unexpected API status: {error.code}'
        return None


async def resources(docker, team):
    filters = {'label': ['io.es3n1n.managed_by=ccs-instancer',
                         'io.es3n1n.instancer.team_id=' + team]}
    containers = await docker.containers.list(all=True, filters=filters)
    networks = await docker.networks.list(filters=filters)
    volumes = (await docker.volumes.list(filters=filters)).get('Volumes') or []
    return containers, networks, volumes


async def main():
    async with Docker() as docker:
        try:
            call('PUT', TEAMS[0], create=True, expected=422,
                 mutate=lambda f: f.update(rctfAuthToken='invalid-test-token'))
            call('PUT', TEAMS[0], create=True, expected=422,
                 mutate=lambda f: f['config']['services']['chall'].update(privileged=True))
            call('PUT', TEAMS[0], create=True, ttl=60000)
            call('PUT', TEAMS[1], create=True, ttl=20000)
            a, an, _ = await resources(docker, TEAMS[0])
            b, bn, _ = await resources(docker, TEAMS[1])
            assert len(a) == len(b) == 1
            assert an and bn and not ({n['Id'] for n in an} & {n['Id'] for n in bn})
            details = await a[0].show()
            host = details['HostConfig']
            assert host['ReadonlyRootfs'] and not host['Privileged']
            assert host['Memory'] == (512 if CHALLENGE == 'the-cursed-mayo' else 256) * 1024 * 1024
            assert host['PidsLimit'] == 128
            if CHALLENGE == 'the-cursed-mayo':
                assert host['NanoCpus'] == 1000000000
                assert host['Tmpfs']['/tmp'] == 'size=64m,mode=1777'
            assert host['Dns'] == ['127.0.0.1']
            labels = details['Config']['Labels']
            assert any(k.startswith('traefik.tcp.routers.') for k in labels)
            call('PATCH', TEAMS[0], ttl=60000)
            call('PATCH', TEAMS[0], ttl=POLICY['ttl_seconds'] * 1000 + 1, expected=422)
            call('DELETE', TEAMS[0])
            assert not any(await resources(docker, TEAMS[0]))
            assert (await resources(docker, TEAMS[1]))[0]
            print('Authentication, config allowlist, isolation, limits, renewal and explicit cleanup passed', flush=True)
            deadline = time.monotonic() + 40
            while any(await resources(docker, TEAMS[1])):
                if time.monotonic() > deadline:
                    raise TimeoutError('Expiry did not remove every test resource')
                await asyncio.sleep(2)
            print('Automatic expiry removed test containers, networks and volumes', flush=True)
        finally:
            for team in TEAMS:
                if any(await resources(docker, team)):
                    call('DELETE', team)


if __name__ == '__main__':
    asyncio.run(main())
