// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Draft spec for COPR and the Fedora review request. The final Fedora
// package should be regenerated with rust2rpm; this spec keeps COPR and
// manual SRPM builds working. The version is bumped at every release
// (release-plz only knows Cargo.toml; keep this file in sync).
Name:           amivuln
Version:        0.3.0
Release:        1%{?dist}
Summary:        Backport-aware CVE check for binaries, services and packages on this host

License:        MIT OR Apache-2.0
URL:            https://github.com/nubian-ibex/amivuln
Source0:        %{url}/releases/download/v%{version}/source.tar.gz
Source1:        vendor-%{version}.tar.zst
Source2:        %{url}/raw/v%{version}/README.md

BuildRequires:  cargo-rpm-macros >= 26
BuildRequires:  gcc

%description
amivuln answers: which CVEs apply to this binary, service or package on this
host, taking distribution backports into account? It never executes the
target, sends only the package name and version off the host and reports the
patch status from each advisory source it consulted.

%prep
%autosetup -n amivuln-%{version} -p1 -a0
%cargo_prep -v vendor

%build
%cargo_build

%install
%cargo_install
install -Dpm 0644 contrib/man/amivuln.1 %{buildroot}%{_mandir}/man1/amivuln.1
install -Dpm 0644 contrib/man/amivuln-tui.1 %{buildroot}%{_mandir}/man1/amivuln-tui.1
install -Dpm 0644 contrib/completions/amivuln.bash %{buildroot}%{_datadir}/bash-completion/completions/amivuln
install -Dpm 0644 contrib/completions/_amivuln %{buildroot}%{_datadir}/zsh/site-functions/_amivuln
install -Dpm 0644 contrib/completions/amivuln.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/amivuln.fish

%check
%cargo_test

%files
%license LICENSE-MIT LICENSE-APACHE
%doc README.md
%{_bindir}/amivuln
%{_mandir}/man1/amivuln.1*
%{_mandir}/man1/amivuln-tui.1*
%{_datadir}/bash-completion/completions/amivuln
%{_datadir}/zsh/site-functions/_amivuln
%{_datadir}/fish/vendor_completions.d/amivuln.fish

%changelog
* Fri Nov 13 2026 amivuln contributors <noreply@github.com> - 0.3.0-1
- Update to 0.3.0

* Fri Nov 13 2026 amivuln contributors <noreply@github.com> - 0.2.0-1
- Update to 0.2.0

* Fri Nov 13 2026 amivuln contributors <noreply@github.com> - 0.1.0-1
- Update to 0.1.0

* Tue Nov 11 2026 amivuln contributors <noreply@github.com> - 0.0.13-1
- Initial package
