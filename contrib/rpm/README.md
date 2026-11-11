# Fedora / COPR packaging

`amivuln.spec` is the draft spec for a COPR project and for the eventual
Fedora official review. It uses the Fedora cargo macros, so the SRPM needs a
vendored dependency tarball alongside the source.

## Build an SRPM

    cargo vendor vendor | tail -n 5   # shows the config.toml snippet
    tar --zstd -cf vendor-0.0.13.tar.zst vendor
    rpmbuild -bs contrib/rpm/amivuln.spec

## Upload to COPR

1. Log in to <https://copr.fedorainfracloud.org> and create a project with
   the `fedora-rawhide` and `fedora-44` chroots.
2. Upload the SRPM from the step above; the build uses the spec in the SRPM.

## Fedora official review

The official package should be regenerated with `rust2rpm` once the review
opens. Request a review through a Fedora Bugzilla ticket in the
`Package Review` component and follow the Fedora packaging policy (the spec
above is a starting point, not the reviewed artifact).
