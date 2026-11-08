# Gromox IMAP INTERNALDATE correction

Some Gromox builds derive IMAP INTERNALDATE from a Received header instead of
the delivery timestamp supplied to APPEND. Missing or different Received headers
can therefore change dates during an otherwise successful migration.

The optional `deploy/patch-gromox-internaldate.py` script accepts only the reviewed
`exch/midb/mail_engine.cpp` SHA-256 from upstream revision
`01cda79696b5ce97c4283a1868dc4dddfa7b3987`. It overlays the transient midb digest
with the stored delivery time. It does not change MIME headers, message bodies,
database timestamps, or authentication behavior. An unexpected revision fails
closed and requires another source review.

## Build and validation

Use the complete upstream source tree for that revision. Retain every upstream
copyright and license file. Install the development dependencies required by
its configure script, then run:

```sh
python3 patch-gromox-internaldate.py /path/to/gromox-source
cd /path/to/gromox-source
autoreconf -fiv
./configure --without-php --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=/usr/lib/x86_64-linux-gnu
make -j2 include/gromox/paths.h midb
```

These paths match the tested Ubuntu 24.04 packages. Compare runtime paths and
linked libraries against the installed package before deployment. Back up the
original `/usr/libexec/gromox/midb`, stop its service before replacement, start
it, and allow existing IMAP backend connections to reconnect (or restart IMAP
on a staged server). Keep a rollback copy and restore it if validation fails.
Do not replace unrelated libraries or services from this build.

Validate APPEND followed by FETCH using messages with no Received header,
a different Received date, and a large body. Check INTERNALDATE against the
supplied timestamp and SHA-256 of the fetched body against the original bytes.
Also rerun migration flag/keyword and source-to-destination metadata checks.
Upstream package updates may replace the binary; repeat validation after updates.

When distributing the modified binary, provide the complete corresponding
source tree, patch script, build instructions and retained notices. The optional
Nginx source route serves that archive at `/masspanel-gromox-source.tar.gz`.
The deployment must actually install the archive; the route alone is not a
source offer. The modified file is GPL-2.0-only WITH linking exception; preserve
all other component-specific license notices in the complete tree as well.
