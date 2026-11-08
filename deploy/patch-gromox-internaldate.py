#!/usr/bin/env python3
"""Patch the identified Gromox source revision before a reviewed local build.

IMAP INTERNALDATE must use the store's delivery timestamp, including the value
supplied to APPEND. The Received header is message content, not that timestamp.
This modifies only the transient midb response digest; stored messages and their
headers are untouched. Upstream copyright and licensing notices are retained.
"""
import argparse
import hashlib
from pathlib import Path

REVISION = '01cda79696b5ce97c4283a1868dc4dddfa7b3987'
SOURCE_SHA256 = '44c2220cfa692267d342fab3475ec441ef07f31d1ffc3d3e1a8f08d059bca38c'
QUERY = '" folder_id, keywords FROM messages WHERE mid_string=?"'
ANCHOR = '\tdigest["keywords"]  = pstmt.col_text(9);\n\treturn folder_id;'
REPLACEMENT = '''\tdigest["keywords"]  = pstmt.col_text(9);
\t// MassPanel: INTERNALDATE is the stored delivery time, not a MIME header.
\t// This overlays only the response digest; the RFC822 bytes stay unchanged.
\tauto received_nt = pstmt.col_uint64(10);
\tif (received_nt != 0) {
\t\tauto received_time = rop_util_nttime_to_unix(received_nt);
\t\tstruct tm received_tm{};
\t\tif (gmtime_r(&received_time, &received_tm) != nullptr) {
\t\t\tstatic constexpr const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
\t\t\tauto received_text = fmt::format("{:02} {} {:04} {:02}:{:02}:{:02} +0000",
\t\t\t\treceived_tm.tm_mday, months[received_tm.tm_mon], received_tm.tm_year + 1900,
\t\t\t\treceived_tm.tm_hour, received_tm.tm_min, received_tm.tm_sec);
\t\t\tdigest["received"] = base64_encode(received_text);
\t\t}
\t}
\treturn folder_id;'''


def patch_source(source):
    start = source.index('static uint64_t me_get_digest(')
    end = source.index('\n/**', start)
    function = source[start:end]
    if function.count(QUERY) != 1 or function.count(ANCHOR) != 1:
        raise ValueError('Unexpected upstream source; no patch applied.')
    function = function.replace(QUERY, '" folder_id, keywords, received FROM messages WHERE mid_string=?"').replace(ANCHOR, REPLACEMENT)
    return source[:start] + function + source[end:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_tree', type=Path)
    args = parser.parse_args()
    path = args.source_tree / 'exch/midb/mail_engine.cpp'
    original = path.read_text()
    if hashlib.sha256(original.encode()).hexdigest() != SOURCE_SHA256:
        raise SystemExit('Source does not match the reviewed Gromox revision; no patch applied.')
    modified = patch_source(original)
    backup = path.with_suffix('.cpp.masspanel-original')
    if backup.exists(): raise SystemExit('A previous backup exists; review before patching again.')
    backup.write_text(original)
    path.write_text(modified)
    print('Patched midb INTERNALDATE metadata. Build and test before installing.')
    print('Original source SHA256:', hashlib.sha256(original.encode()).hexdigest())


if __name__ == '__main__': main()
