# MassPanel licence transition

The project owner confirmed ownership of, or permission to relicense, the
original MassPanel code on **8 November 2026**. This revision applies the
[MassPanel Hosting License 1.0](../../LICENSE) to that code, with the exceptions
listed in [LICENSING.md](../../LICENSING.md).

## Version boundary

The transition is the commit introducing the root licence whose first line is
`MassPanel Hosting License 1.0`. Locate it with:

```sh
git log --reverse --format='%H %s' -S 'MassPanel Hosting License 1.0' -- LICENSE
```

The preceding default-branch revision, `8cee97f`, and earlier AGPL releases
retain their existing rights. Migration-branch revisions `0f27f66` and `040eac2`
also remain available under their original terms. Earlier tags, public releases and deployed source archives
are not rewritten. The unchanged former root licence is preserved at
[licenses/AGPL-3.0-or-later.txt](../../licenses/AGPL-3.0-or-later.txt).

## Permissions

| Activity | Terms for original MassPanel code in this revision |
| --- | --- |
| Use, inspect and modify MassPanel | Allowed |
| Sell hosting and hosted customer/reseller accounts | Allowed |
| Charge for genuine installation, migration, development and support | Allowed |
| Distribute source or copies for free | Allowed with the licence, corresponding source and notices |
| Sell copies, installers, rebranded versions or activation entitlements | Requires separate written authorization |
| Sell separately licensed upstream software | Its own licence governs; the MassPanel restriction does not apply |
| Use or sell earlier AGPL versions | Prior AGPL rights remain intact |

## Source and upstream obligations

MassPanel is described as source-available. Grommunio and other open-source
components retain their own licences, notices and source offers. The Grommunio
integration modules and generated WordPress plugin are explicitly marked as
AGPL-3.0-or-later. Upstream-derived patch material and modified upstream output
retain their applicable licences. Source downloads remain free.

The current licence URL is `/masspanel-license`, and the panel page is
`/licences`. The legacy `/masspanel-open-source-license` and `/open-source`
URLs remain compatible; visible labels describe the installed licence. Existing deployments continue to
serve the notices and exact source for their installed version until updated.

This changes licensing documentation and labels, not the 20-domain product
tier, Unlimited activation behavior, customer data or migration cutover state.

The [GNU licensing FAQ](https://www.gnu.org/licenses/gpl-faq.en.html) explains
copyright holders' ability to offer their work under different terms. The
[Open Source Definition](https://opensource.org/osd) permits software resale;
the new restricted licence must therefore not be described as OSI-approved.
