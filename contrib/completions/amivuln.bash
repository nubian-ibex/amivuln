_amivuln() {
    local i cur prev opts cmd
    COMPREPLY=()
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    prev="$3"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]:0:COMP_CWORD}"
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="amivuln"
                ;;
            amivuln,cache)
                cmd="amivuln__subcmd__cache"
                ;;
            amivuln,check)
                cmd="amivuln__subcmd__check"
                ;;
            amivuln,completions)
                cmd="amivuln__subcmd__completions"
                ;;
            amivuln,config)
                cmd="amivuln__subcmd__config"
                ;;
            amivuln,cve)
                cmd="amivuln__subcmd__cve"
                ;;
            amivuln,db)
                cmd="amivuln__subcmd__db"
                ;;
            amivuln,help)
                cmd="amivuln__subcmd__help"
                ;;
            amivuln,mcp)
                cmd="amivuln__subcmd__mcp"
                ;;
            amivuln,pending)
                cmd="amivuln__subcmd__pending"
                ;;
            amivuln,restart)
                cmd="amivuln__subcmd__restart"
                ;;
            amivuln,services)
                cmd="amivuln__subcmd__services"
                ;;
            amivuln,tui)
                cmd="amivuln__subcmd__tui"
                ;;
            amivuln,version)
                cmd="amivuln__subcmd__version"
                ;;
            amivuln__subcmd__cache,clear)
                cmd="amivuln__subcmd__cache__subcmd__clear"
                ;;
            amivuln__subcmd__cache,help)
                cmd="amivuln__subcmd__cache__subcmd__help"
                ;;
            amivuln__subcmd__cache,info)
                cmd="amivuln__subcmd__cache__subcmd__info"
                ;;
            amivuln__subcmd__cache__subcmd__help,clear)
                cmd="amivuln__subcmd__cache__subcmd__help__subcmd__clear"
                ;;
            amivuln__subcmd__cache__subcmd__help,help)
                cmd="amivuln__subcmd__cache__subcmd__help__subcmd__help"
                ;;
            amivuln__subcmd__cache__subcmd__help,info)
                cmd="amivuln__subcmd__cache__subcmd__help__subcmd__info"
                ;;
            amivuln__subcmd__config,help)
                cmd="amivuln__subcmd__config__subcmd__help"
                ;;
            amivuln__subcmd__config,init)
                cmd="amivuln__subcmd__config__subcmd__init"
                ;;
            amivuln__subcmd__config,show)
                cmd="amivuln__subcmd__config__subcmd__show"
                ;;
            amivuln__subcmd__config,validate)
                cmd="amivuln__subcmd__config__subcmd__validate"
                ;;
            amivuln__subcmd__config__subcmd__help,help)
                cmd="amivuln__subcmd__config__subcmd__help__subcmd__help"
                ;;
            amivuln__subcmd__config__subcmd__help,init)
                cmd="amivuln__subcmd__config__subcmd__help__subcmd__init"
                ;;
            amivuln__subcmd__config__subcmd__help,show)
                cmd="amivuln__subcmd__config__subcmd__help__subcmd__show"
                ;;
            amivuln__subcmd__config__subcmd__help,validate)
                cmd="amivuln__subcmd__config__subcmd__help__subcmd__validate"
                ;;
            amivuln__subcmd__db,build)
                cmd="amivuln__subcmd__db__subcmd__build"
                ;;
            amivuln__subcmd__db,help)
                cmd="amivuln__subcmd__db__subcmd__help"
                ;;
            amivuln__subcmd__db,info)
                cmd="amivuln__subcmd__db__subcmd__info"
                ;;
            amivuln__subcmd__db,pull)
                cmd="amivuln__subcmd__db__subcmd__pull"
                ;;
            amivuln__subcmd__db,verify)
                cmd="amivuln__subcmd__db__subcmd__verify"
                ;;
            amivuln__subcmd__db__subcmd__help,build)
                cmd="amivuln__subcmd__db__subcmd__help__subcmd__build"
                ;;
            amivuln__subcmd__db__subcmd__help,help)
                cmd="amivuln__subcmd__db__subcmd__help__subcmd__help"
                ;;
            amivuln__subcmd__db__subcmd__help,info)
                cmd="amivuln__subcmd__db__subcmd__help__subcmd__info"
                ;;
            amivuln__subcmd__db__subcmd__help,pull)
                cmd="amivuln__subcmd__db__subcmd__help__subcmd__pull"
                ;;
            amivuln__subcmd__db__subcmd__help,verify)
                cmd="amivuln__subcmd__db__subcmd__help__subcmd__verify"
                ;;
            amivuln__subcmd__help,cache)
                cmd="amivuln__subcmd__help__subcmd__cache"
                ;;
            amivuln__subcmd__help,check)
                cmd="amivuln__subcmd__help__subcmd__check"
                ;;
            amivuln__subcmd__help,completions)
                cmd="amivuln__subcmd__help__subcmd__completions"
                ;;
            amivuln__subcmd__help,config)
                cmd="amivuln__subcmd__help__subcmd__config"
                ;;
            amivuln__subcmd__help,cve)
                cmd="amivuln__subcmd__help__subcmd__cve"
                ;;
            amivuln__subcmd__help,db)
                cmd="amivuln__subcmd__help__subcmd__db"
                ;;
            amivuln__subcmd__help,help)
                cmd="amivuln__subcmd__help__subcmd__help"
                ;;
            amivuln__subcmd__help,mcp)
                cmd="amivuln__subcmd__help__subcmd__mcp"
                ;;
            amivuln__subcmd__help,pending)
                cmd="amivuln__subcmd__help__subcmd__pending"
                ;;
            amivuln__subcmd__help,restart)
                cmd="amivuln__subcmd__help__subcmd__restart"
                ;;
            amivuln__subcmd__help,services)
                cmd="amivuln__subcmd__help__subcmd__services"
                ;;
            amivuln__subcmd__help,tui)
                cmd="amivuln__subcmd__help__subcmd__tui"
                ;;
            amivuln__subcmd__help,version)
                cmd="amivuln__subcmd__help__subcmd__version"
                ;;
            amivuln__subcmd__help__subcmd__cache,clear)
                cmd="amivuln__subcmd__help__subcmd__cache__subcmd__clear"
                ;;
            amivuln__subcmd__help__subcmd__cache,info)
                cmd="amivuln__subcmd__help__subcmd__cache__subcmd__info"
                ;;
            amivuln__subcmd__help__subcmd__config,init)
                cmd="amivuln__subcmd__help__subcmd__config__subcmd__init"
                ;;
            amivuln__subcmd__help__subcmd__config,show)
                cmd="amivuln__subcmd__help__subcmd__config__subcmd__show"
                ;;
            amivuln__subcmd__help__subcmd__config,validate)
                cmd="amivuln__subcmd__help__subcmd__config__subcmd__validate"
                ;;
            amivuln__subcmd__help__subcmd__db,build)
                cmd="amivuln__subcmd__help__subcmd__db__subcmd__build"
                ;;
            amivuln__subcmd__help__subcmd__db,info)
                cmd="amivuln__subcmd__help__subcmd__db__subcmd__info"
                ;;
            amivuln__subcmd__help__subcmd__db,pull)
                cmd="amivuln__subcmd__help__subcmd__db__subcmd__pull"
                ;;
            amivuln__subcmd__help__subcmd__db,verify)
                cmd="amivuln__subcmd__help__subcmd__db__subcmd__verify"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        amivuln)
            opts="-f -q -h -V --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --all --help --version check cve pending services restart mcp tui db config cache completions version help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__cache)
            opts="-f -q -h --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help info clear help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__cache__subcmd__clear)
            opts="-f -q -h --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__cache__subcmd__help)
            opts="info clear help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__cache__subcmd__help__subcmd__clear)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__cache__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__cache__subcmd__help__subcmd__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__cache__subcmd__info)
            opts="-f -q -h --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__check)
            opts="-f -q -h --all --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__completions)
            opts="-f -q -h --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help bash zsh fish elvish powershell"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__config)
            opts="-f -q -h --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help show init validate help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__config__subcmd__help)
            opts="show init validate help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__config__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__config__subcmd__help__subcmd__init)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__config__subcmd__help__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__config__subcmd__help__subcmd__validate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__config__subcmd__init)
            opts="-f -q -h --path --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --path)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__config__subcmd__show)
            opts="-f -q -h --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__config__subcmd__validate)
            opts="-f -q -h --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__cve)
            opts="-f -q -h --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__db)
            opts="-f -q -h --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help build pull verify info help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__db__subcmd__build)
            opts="-f -q -h --archive --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --archive)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__db__subcmd__help)
            opts="build pull verify info help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__db__subcmd__help__subcmd__build)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__db__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__db__subcmd__help__subcmd__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__db__subcmd__help__subcmd__pull)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__db__subcmd__help__subcmd__verify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__db__subcmd__info)
            opts="-f -q -h --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__db__subcmd__pull)
            opts="-f -q -h --force --key --sig --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sig)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__db__subcmd__verify)
            opts="-f -q -h --key --sig --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sig)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help)
            opts="check cve pending services restart mcp tui db config cache completions version help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__cache)
            opts="info clear"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__cache__subcmd__clear)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__cache__subcmd__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__check)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__completions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__config)
            opts="show init validate"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__config__subcmd__init)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__config__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__config__subcmd__validate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__cve)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__db)
            opts="build pull verify info"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__db__subcmd__build)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__db__subcmd__info)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__db__subcmd__pull)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__db__subcmd__verify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__mcp)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__pending)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__restart)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__services)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__tui)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__help__subcmd__version)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__mcp)
            opts="-f -q -h --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__pending)
            opts="-f -q -h --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__restart)
            opts="-f -q -h --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__services)
            opts="-f -q -h --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__tui)
            opts="-f -q -h --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        amivuln__subcmd__version)
            opts="-f -q -h --json --format --output --fail-on --fail-on-epss --strict --offline --no-cache --config --color --distro --file --package --pid --purl --baseline --vex --packages-from --sbom --container --flatpak --mitigations --explain --quiet --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fail-on-epss)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --color)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --distro)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --package)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --purl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --vex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --packages-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --container)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _amivuln -o nosort -o bashdefault -o default amivuln
else
    complete -F _amivuln -o bashdefault -o default amivuln
fi
