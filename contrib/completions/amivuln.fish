# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_amivuln_global_optspecs
    string join \n f/format= output= fail-on= fail-on-epss= strict offline no-cache config= color= distro= file= package= pid= purl= baseline= vex= packages-from= sbom= container= mitigations flatpak q/quiet all h/help V/version
end

function __fish_amivuln_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_amivuln_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_amivuln_using_subcommand
    set -l cmd (__fish_amivuln_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c amivuln -n "__fish_amivuln_needs_command" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_needs_command" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_needs_command" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_needs_command" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_needs_command" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_needs_command" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_needs_command" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_needs_command" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_needs_command" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_needs_command" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_needs_command" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_needs_command" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_needs_command" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_needs_command" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_needs_command" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_needs_command" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_needs_command" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_needs_command" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_needs_command" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_needs_command" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_needs_command" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_needs_command" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_needs_command" -l all -d 'Check every installed package'
complete -c amivuln -n "__fish_amivuln_needs_command" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c amivuln -n "__fish_amivuln_needs_command" -s V -l version -d 'Print version'
complete -c amivuln -n "__fish_amivuln_needs_command" -a "check" -d 'Check packages, files, versions or purls'
complete -c amivuln -n "__fish_amivuln_needs_command" -a "cve" -d 'Is this host affected by a CVE? Scans every installed package'
complete -c amivuln -n "__fish_amivuln_needs_command" -a "pending" -d 'Which updates close the most risk? Ranks the updates that fix affected findings'
complete -c amivuln -n "__fish_amivuln_needs_command" -a "services" -d 'Check every running systemd service. Services that are not packaged are listed, not fatal'
complete -c amivuln -n "__fish_amivuln_needs_command" -a "restart" -d 'Which running processes still use files an update replaced? Exit 1 when a restart is needed'
complete -c amivuln -n "__fish_amivuln_needs_command" -a "mcp" -d 'Serve read-only tools to AI agents over the Model Context Protocol on stdio'
complete -c amivuln -n "__fish_amivuln_needs_command" -a "tui" -d 'Interactive terminal UI (feature `tui`). Without the feature, exits 64'
complete -c amivuln -n "__fish_amivuln_needs_command" -a "db" -d 'Build, fetch, verify or inspect the offline advisory database'
complete -c amivuln -n "__fish_amivuln_needs_command" -a "config" -d 'Show, create or validate the configuration'
complete -c amivuln -n "__fish_amivuln_needs_command" -a "cache" -d 'Inspect or clear the on-disk cache'
complete -c amivuln -n "__fish_amivuln_needs_command" -a "completions" -d 'Print shell completions'
complete -c amivuln -n "__fish_amivuln_needs_command" -a "version" -d 'Print version and build information'
complete -c amivuln -n "__fish_amivuln_needs_command" -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l all -d 'Check every installed package'
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand check" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand cve" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand pending" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand services" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand restart" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand mcp" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand tui" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -f -a "build" -d 'Snapshot the local cache into a signed-ready `tar.zst` archive'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -f -a "pull" -d 'Verify an archive and install it as the offline database'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -f -a "verify" -d 'Check an archive: manifest, database checksum and, with `--key`/`--sig`, the signature'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -f -a "info" -d 'Print the manifest of an archive (after checking its integrity)'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and not __fish_seen_subcommand_from build pull verify info help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l archive -d 'Where to write the archive' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from build" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l key -d 'Minisign public key; the signature over the manifest is checked' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l sig -d 'Minisign signature over `manifest.json`' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l force -d 'Install even when the archive is older than the installed database'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from pull" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l key -d 'Minisign public key' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l sig -d 'Minisign signature over `manifest.json`' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from verify" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from info" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from help" -f -a "build" -d 'Snapshot the local cache into a signed-ready `tar.zst` archive'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from help" -f -a "pull" -d 'Verify an archive and install it as the offline database'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from help" -f -a "verify" -d 'Check an archive: manifest, database checksum and, with `--key`/`--sig`, the signature'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from help" -f -a "info" -d 'Print the manifest of an archive (after checking its integrity)'
complete -c amivuln -n "__fish_amivuln_using_subcommand db; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -f -a "show" -d 'Print the effective configuration'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -f -a "init" -d 'Write a commented default configuration file'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -f -a "validate" -d 'Load the configuration and report problems'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and not __fish_seen_subcommand_from show init validate help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from show" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l path -d 'Where to write; defaults to the user configuration path' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from init" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from validate" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "show" -d 'Print the effective configuration'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "init" -d 'Write a commented default configuration file'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "validate" -d 'Load the configuration and report problems'
complete -c amivuln -n "__fish_amivuln_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -f -a "info" -d 'Show where the cache lives and how big it is'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -f -a "clear" -d 'Delete every cached response'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and not __fish_seen_subcommand_from info clear help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from info" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from clear" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from help" -f -a "info" -d 'Show where the cache lives and how big it is'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from help" -f -a "clear" -d 'Delete every cached response'
complete -c amivuln -n "__fish_amivuln_using_subcommand cache; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand completions" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -s f -l format -d 'Output format: summary, detail, json, sarif, markdown, csv, prometheus, cyclonedx or openvex' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l output -d 'Write the result to FILE instead of stdout, replacing it atomically' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l fail-on -d 'Exit 1 when a finding reaches this level: none, low, medium, high, critical or kev' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l fail-on-epss -d 'Exit 1 when an affected finding has at least this EPSS score (0.0 to 1.0)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l config -d 'Configuration file (skips the default search path)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l color -d 'Colors: auto, always or never (`NO_COLOR` is honored)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l distro -d 'Treat the host as another distro: `fedora:44` or `arch`' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l file -d 'Treat this path as a target (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l package -d 'Treat this value as an installed package name or `name@version` (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l pid -d 'Check the executable of this running process (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l purl -d 'Treat this value as a package URL (repeatable)' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l baseline -d 'A previous `-f json` report; only new findings violate --fail-on' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l vex -d '`OpenVEX` documents stating that a product is not affected (repeatable)' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l packages-from -d 'Check the packages listed in FILE (one `name@version` per line) instead of the installed ones; for example a list exported from another host' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l sbom -d 'Check the OS packages listed in a `CycloneDX` JSON SBOM (rpm, deb and alpm purls). Other components are listed as unresolved, grouped by type' -r -F
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l container -d 'Scan a container\'s installed packages (repeatable): the rootfs is exported with podman or docker, nothing inside the container runs. The container\'s own `os-release` decides the ecosystem' -r
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l json -d 'Machine-readable output'
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l strict -d 'Count findings without a distro statement as violations of --fail-on'
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l offline -d 'Never use the network; answer from the cache only'
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l no-cache -d 'Do not keep a cache on disk for this run'
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l mitigations -d 'Also look up the mitigation Red Hat publishes for each affected CVE (what to do while the fix is not installed). Sends the CVE ids to access.redhat.com'
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -l flatpak -d 'Also check the components of the installed Flatpak runtimes (system and user installations), read from each runtime\'s manifest.json. Nothing is run. The NVD answers per component, at its own pace: without `sources.nvd.api_key_file` a first run takes several minutes'
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -s q -l quiet -d 'Only print errors'
complete -c amivuln -n "__fish_amivuln_using_subcommand version" -s h -l help -d 'Print help'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and not __fish_seen_subcommand_from check cve pending services restart mcp tui db config cache completions version help" -f -a "check" -d 'Check packages, files, versions or purls'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and not __fish_seen_subcommand_from check cve pending services restart mcp tui db config cache completions version help" -f -a "cve" -d 'Is this host affected by a CVE? Scans every installed package'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and not __fish_seen_subcommand_from check cve pending services restart mcp tui db config cache completions version help" -f -a "pending" -d 'Which updates close the most risk? Ranks the updates that fix affected findings'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and not __fish_seen_subcommand_from check cve pending services restart mcp tui db config cache completions version help" -f -a "services" -d 'Check every running systemd service. Services that are not packaged are listed, not fatal'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and not __fish_seen_subcommand_from check cve pending services restart mcp tui db config cache completions version help" -f -a "restart" -d 'Which running processes still use files an update replaced? Exit 1 when a restart is needed'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and not __fish_seen_subcommand_from check cve pending services restart mcp tui db config cache completions version help" -f -a "mcp" -d 'Serve read-only tools to AI agents over the Model Context Protocol on stdio'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and not __fish_seen_subcommand_from check cve pending services restart mcp tui db config cache completions version help" -f -a "tui" -d 'Interactive terminal UI (feature `tui`). Without the feature, exits 64'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and not __fish_seen_subcommand_from check cve pending services restart mcp tui db config cache completions version help" -f -a "db" -d 'Build, fetch, verify or inspect the offline advisory database'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and not __fish_seen_subcommand_from check cve pending services restart mcp tui db config cache completions version help" -f -a "config" -d 'Show, create or validate the configuration'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and not __fish_seen_subcommand_from check cve pending services restart mcp tui db config cache completions version help" -f -a "cache" -d 'Inspect or clear the on-disk cache'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and not __fish_seen_subcommand_from check cve pending services restart mcp tui db config cache completions version help" -f -a "completions" -d 'Print shell completions'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and not __fish_seen_subcommand_from check cve pending services restart mcp tui db config cache completions version help" -f -a "version" -d 'Print version and build information'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and not __fish_seen_subcommand_from check cve pending services restart mcp tui db config cache completions version help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and __fish_seen_subcommand_from db" -f -a "build" -d 'Snapshot the local cache into a signed-ready `tar.zst` archive'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and __fish_seen_subcommand_from db" -f -a "pull" -d 'Verify an archive and install it as the offline database'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and __fish_seen_subcommand_from db" -f -a "verify" -d 'Check an archive: manifest, database checksum and, with `--key`/`--sig`, the signature'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and __fish_seen_subcommand_from db" -f -a "info" -d 'Print the manifest of an archive (after checking its integrity)'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "show" -d 'Print the effective configuration'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "init" -d 'Write a commented default configuration file'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "validate" -d 'Load the configuration and report problems'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and __fish_seen_subcommand_from cache" -f -a "info" -d 'Show where the cache lives and how big it is'
complete -c amivuln -n "__fish_amivuln_using_subcommand help; and __fish_seen_subcommand_from cache" -f -a "clear" -d 'Delete every cached response'
