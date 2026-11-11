# Nix packaging

`amivuln.nix` builds amivuln from the published release source. Test it
locally, then use it as the basis for a `pkgs/by-name` PR in nixpkgs:

    nix-build -E "with import <nixpkgs> {}; callPackage ./contrib/nix/amivuln.nix {}"

The `cargoLock.lockFile` points at the repository's `Cargo.lock`; a nixpkgs
PR copies that lock file beside the derivation under
`pkgs/by-name/am/amivuln/`.
