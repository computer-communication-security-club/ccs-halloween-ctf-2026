#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Validate the committed seed and safely test private fragment rendering."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
WORLD = ROOT / 'src/world'
manifest = json.loads((ROOT / 'src/world-manifest.json').read_text())
for item in manifest['files']:
    path = WORLD / item['path']
    assert path.is_file(), f'Missing seed file: {item["path"]}'
    assert hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256'], f'Seed checksum mismatch: {item["path"]}'
for forbidden in ['players', 'playerdata', 'stats', 'advancements', 'session.lock']:
    assert not (WORLD / forbidden).exists(), f'Unexpected player state: {forbidden}'
print(f'Seed manifest passed: {len(manifest["files"])} files')

for fake_flag in ['ccsCTF{rendering_test_123456}', 'ccsCTF{A&B$#^%!*._-@?987654321}']:
    with tempfile.TemporaryDirectory(prefix='sict-render-') as temp:
        temp = Path(temp)
        world = temp / 'world with spaces'
        shutil.copytree(WORLD, world)
        flag_file = temp / 'flag.txt'
        flag_file.write_text(fake_flag + '\n')
        proc = subprocess.run(['bash', str(ROOT / 'src/prepare-world.sh'), str(world), str(flag_file)],
                              capture_output=True, text=True, timeout=30)
        assert proc.returncode == 0, proc.stderr
        assert fake_flag not in proc.stdout + proc.stderr, 'Renderer disclosed its input'
        fragments = []
        for number in range(1, 5):
            claim = (world / f'datapacks/sict-campus/data/sict/function/ctf/claim{number}.mcfunction').read_text()
            fragments.append(re.search(r'"text":"\d/4: ([^"]*)"', claim).group(1))
        assert ''.join(fragments) == fake_flag, 'Rendered fragments do not reconstruct input'
        assert not list(world.rglob('*.sict-render-backup')), 'Renderer left intermediate secret-bearing backups'
        assert not any('@@FRAGMENT_' in p.read_text() for p in world.rglob('*')
                       if p.suffix in ('.mcfunction', '.json')), 'Unresolved fragment template'
print('Fragment rendering passed, including shell/sed special characters')

with tempfile.TemporaryDirectory(prefix='sict-invalid-') as temp:
    temp = Path(temp)
    shutil.copytree(WORLD, temp / 'world')
    (temp / 'flag.txt').write_text('invalid\nsecond line\n')
    proc = subprocess.run(['bash', str(ROOT / 'src/prepare-world.sh'), str(temp / 'world'), str(temp / 'flag.txt')],
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode != 0, 'Invalid flag was accepted'
print('Invalid flag rejected')
