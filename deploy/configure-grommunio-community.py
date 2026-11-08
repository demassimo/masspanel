#!/usr/bin/env python3
"""Apply the operator's local AGPL Community capacity customization.

This changes the source default, not signed certificates or commercial support.
Upstream copyright/license notices and certificate validation are preserved.
"""
import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
from urllib.request import urlopen


def patch_capacity(source, users):
    if type(users) is not int or not 5 <= users <= 100000:
        raise ValueError('Choose a capacity between 5 and 100000.')
    tree = ast.parse(source)
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_defaultLicense']
    if len(functions) != 1:
        raise ValueError('Unrecognized upstream source: _defaultLicense is missing or ambiguous.')
    function = functions[0]
    calls = [n for n in ast.walk(function) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == 'GrommunioLicense']
    fields = [k.value for n in calls for k in n.keywords if k.arg == 'users']
    if len(fields) != 1 or not isinstance(fields[0], ast.Constant) or type(fields[0].value) is not int:
        raise ValueError('Unrecognized upstream capacity expression; no change made.')
    value = fields[0]
    lines = source.splitlines(keepends=True)
    line = lines[value.lineno - 1]
    lines[value.lineno - 1] = line[:value.col_offset] + str(users) + line[value.end_col_offset:]
    result = ''.join(lines)
    compile(result, 'license.py', 'exec')
    return result


def settings(source):
    values = {'emsmdb_max_obh_per_session': 1000, 'emsmdb_max_cxh_per_user': 300}
    for key, value in values.items():
        source = re.sub(r'^\s*' + re.escape(key) + r'\s*=.*\n?', '', source, flags=re.M)
        source = source.rstrip() + f'\n{key} = {value}\n'
    return source


def corresponding_source(before, after):
    version = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', 'grommunio-admin-api'], text=True).strip()
    match = re.search(r'\.m([a-f0-9]{7,40})(?:-|\+|$)', version)
    if not match:
        raise ValueError('Cannot identify the installed upstream revision; prepare its corresponding source before modifying it.')
    revision = match[1]
    url = 'https://codeload.github.com/grommunio/admin-api/tar.gz/' + revision
    with urlopen(url, timeout=60) as response: content = response.read(64 * 1024 * 1024 + 1)
    if len(content) > 64 * 1024 * 1024: raise ValueError('Unexpected upstream source archive size.')
    result = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(content), mode='r:gz') as original, tarfile.open(fileobj=result, mode='w:gz') as modified:
        candidates = [m for m in original.getmembers() if m.name.endswith('/tools/license.py') and m.isfile()]
        if len(candidates) != 1: raise ValueError('Upstream source is missing tools/license.py.')
        upstream = original.extractfile(candidates[0]).read().decode()
        if patch_capacity(upstream, 5) != patch_capacity(before, 5):
            raise ValueError('Installed source differs from the identified revision; review its complete source before modifying it.')
        for member in original.getmembers():
            if member == candidates[0]:
                data = after.encode(); member.size = len(data); modified.addfile(member, io.BytesIO(data))
            else:
                modified.addfile(member, original.extractfile(member) if member.isfile() else None)
        script = Path(__file__).read_bytes()
        member = tarfile.TarInfo('masspanel-configure-grommunio-community.py'); member.size = len(script); member.mode = 0o644
        modified.addfile(member, io.BytesIO(script))
    return content, result.getvalue(), {'package_version': version, 'source_url': url,
                                      'source_sha256': hashlib.sha256(content).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--users', type=int, required=True)
    parser.add_argument('--restart', action='store_true', help='Restart the admin API and Gromox HTTP service.')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run as root.')
    target = Path('/usr/share/grommunio-admin-api/tools/license.py')
    before = target.read_text()
    after = patch_capacity(before, args.users)
    upstream_archive, modified_archive, provenance = corresponding_source(before, after)
    backup = Path('/var/backups/masspanel/grommunio-community')
    backup.mkdir(parents=True, mode=0o700, exist_ok=True)
    digest = hashlib.sha256(before.encode()).hexdigest()
    original = backup / (digest + '-license.py')
    if not original.exists():
        shutil.copy2(target, original)
    # Source archives come from the identified upstream revision, never from
    # runtime directories that may contain deployment passwords or private data.
    temp = target.with_suffix('.py.masspanel-tmp')
    temp.write_text(after)
    shutil.copystat(target, temp)
    os.replace(temp, target)
    config = Path('/etc/gromox/exchange_emsmdb.cfg')
    if config.exists():
        shutil.copy2(config, backup / 'exchange_emsmdb.cfg.before')
    config.write_text(settings(config.read_text() if config.exists() else ''))
    shutil.chown(config, user='root', group='gromoxcf')
    config.chmod(0o640)
    manifest = {'customization': 'Local Community capacity; not a commercial license',
                'users': args.users, 'upstream_sha256': digest,
                'patched_sha256': hashlib.sha256(after.encode()).hexdigest(), **provenance}
    (backup / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    source_dir = Path('/usr/share/masspanel/source/grommunio-community-customization')
    source_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(target, source_dir / 'license.py')
    (source_dir / 'license.py.before').write_text(before)
    (source_dir / 'admin-api-upstream.tar.gz').write_bytes(upstream_archive)
    (source_dir / 'admin-api-modified.tar.gz').write_bytes(modified_archive)
    (source_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    (source_dir / 'admin-api-modified.tar.gz').chmod(0o644)
    shutil.copy2(Path(__file__), source_dir / Path(__file__).name)
    (source_dir / 'NOTICE.txt').write_text('Grommunio admin-api license.py: AGPL-3.0-or-later; copyright grommunio GmbH.\nModified default Community capacity by the local MassPanel operator.\nCertificate validation is unchanged. No commercial support entitlement is granted.\n')
    if args.restart:
        subprocess.run(['systemctl', 'restart', 'grommunio-admin-api', 'gromox-http'], check=True)
    print(f'Local Community capacity set to {args.users}; EMSMDB limits set to 1000 / 300.')


if __name__ == '__main__':
    main()
