#!/usr/bin/env python3
"""Install pinned imapsync with a Gromox APPEND compatibility adjustment.

Gromox accepts custom keywords through STORE, but rejects them on large APPENDs.
Keep the original flags for --syncflagsaftercopy and send only system flags in
APPEND. No message content is rewritten. Upstream NLPL notices remain intact.
"""
import hashlib
import os
from pathlib import Path
import subprocess
from urllib.request import urlopen

COMMIT = '8895966244fb161cc68f2c8427a8f6326a7f2ab0'
SHA256 = '89faed96f7c389723ddd7e78a00421b90d5b85bf79407fcf1b11209f3d4d7416'
URL = f'https://raw.githubusercontent.com/imapsync/imapsync/{COMMIT}/imapsync'
ORIGINAL = '$new_id = $mysync->{ imap2 }->append_string( $h2_fold, ${ $string_ref }, $h1_flags, $h1_date ) ;'
REPLACEMENT = r'''# MassPanel: Gromox custom keywords are restored by STORE after APPEND.
                # Do not change $h1_flags: it is still used by syncflagsaftercopy.
                my $append_flags = join q{ }, grep { /^(?:\\(?:Seen|Answered|Flagged|Draft|Deleted)|\$Forwarded)$/i } split /\s+/, $h1_flags ;
                $new_id = $mysync->{ imap2 }->append_string( $h2_fold, ${ $string_ref }, $append_flags, $h1_date ) ;'''


def patch_source(content):
    source = content.decode('utf-8')
    if hashlib.sha256(content).hexdigest() != SHA256 or source.count(ORIGINAL) != 1:
        raise ValueError('Unexpected imapsync source; installation stopped.')
    return source.replace(ORIGINAL, REPLACEMENT)


def main():
    if os.geteuid() != 0: raise SystemExit('Run as root.')
    packages = ['libauthen-ntlm-perl', 'libcrypt-ssleay-perl', 'libdigest-hmac-perl',
                'libfile-tail-perl', 'libio-socket-ssl-perl', 'libio-tee-perl',
                'libmail-imapclient-perl', 'libterm-readkey-perl', 'libtest-mockobject-perl',
                'libunicode-string-perl', 'liburi-perl', 'libwww-perl', 'libjson-perl',
                'libencode-imaputf7-perl', 'libregexp-common-perl', 'libsys-meminfo-perl',
                'libfile-copy-recursive-perl', 'libdata-uniqid-perl', 'libreadonly-perl',
                'libtest-pod-perl', 'nftables']
    subprocess.run(['apt-get', 'install', '-y', '--no-install-recommends', *packages],
                   env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'}, check=True)
    with urlopen(URL, timeout=60) as response: original = response.read(2 * 1024 * 1024)
    patched = patch_source(original)
    directory = Path('/usr/share/masspanel/source/imapsync')
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'imapsync.upstream').write_bytes(original)
    (directory / 'imapsync').write_text(patched)
    (directory / 'NOTICE.txt').write_text('imapsync 2.314 by Gilles LAMIRAL. License: NLPL.\nNo limits to do anything with this work and this license.\nMassPanel modification: restrict APPEND flags, preserve original flags through STORE.\nSource: ' + URL + '\nSHA256: ' + SHA256 + '\n')
    subprocess.run(['/usr/bin/perl', '-c', str(directory / 'imapsync')], check=True)
    target = Path('/usr/local/libexec/masspanel-imapsync')
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix('.new'); temp.write_text(patched); temp.chmod(0o755); os.replace(temp, target)
    print('Installed pinned imapsync with Gromox flag compatibility. Use --syncflagsaftercopy --nofilterflags.')


if __name__ == '__main__': main()
