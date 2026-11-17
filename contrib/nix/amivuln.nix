// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
{
  lib,
  rustPlatform,
  fetchurl,
  installShellFiles,
}: let
  version = "0.5.0";
in
  rustPlatform.buildRustPackage {
    pname = "amivuln";
    inherit version;

    src = fetchurl {
      url = "https://github.com/nubian-ibex/amivuln/releases/download/v${version}/source.tar.gz";
      hash = "sha256-W1Sdou41eTbnpmoQuJ+5318fn4fbW/e1VAU4uf1bjCw=";
    };
    sourceRoot = "amivuln-${version}";

    # The release tarball ships its own Cargo.lock; nixpkgs by-name wants a
    # copy beside the derivation, which ../Cargo.lock satisfies in this repo.
    cargoLock.lockFile = ../Cargo.lock;

    nativeBuildInputs = [installShellFiles];
    postInstall = ''
      installManPage contrib/man/*.1
      installShellCompletion \
        --bash contrib/completions/amivuln.bash \
        --zsh contrib/completions/_amivuln \
        --fish contrib/completions/amivuln.fish
    '';

    doCheck = true;

    meta = {
      description = "Backport-aware CVE check for binaries, services and packages on this host";
      homepage = "https://github.com/nubian-ibex/amivuln";
      license = with lib.licenses; [mit asl20];
      mainProgram = "amivuln";
      platforms = lib.platforms.linux;
    };
  }
