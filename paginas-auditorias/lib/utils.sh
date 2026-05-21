#!/usr/bin/env bash
# ============================================================================
# utils.sh — Core Utilities & Pre-flight Checks
# Part of PaginasAudit Cyber Audit Installer
# ----------------------------------------------------------------------------
# Provides:
#   - Privilege escalation detection + auto-sudo
#   - OS/architecture detection (Kali, Debian, Ubuntu, Arch, etc.)
#   - Package manager abstraction (apt, apt-get, snap, pip3, npm)
#   - Network connectivity tests
#   - Disk space / resource checks
#   - Function composition helpers (retry, timeout, run-and-log)
# ============================================================================

[[ -n "${__UTILS_LOADED:-}" ]] && return 0
readonly __UTILS_LOADED=true

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/colors.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logging.sh"

# ---- Privilege Check ------------------------------------------------------

# require_root — exit if not running as root (or can sudo)
require_root() {
    if [[ $EUID -eq 0 ]]; then
        return 0
    fi
    if command -v sudo &>/dev/null; then
        # Try passwordless sudo first
        if sudo -n true 2>/dev/null; then
            log_debug "Escalando con sudo (passwordless)"
            return 0
        fi
        # Ask the user
        echo ""
        warn "Este instalador requiere permisos de superusuario (root)."
        hint "Se usará sudo — ingrese su contraseña cuando se solicite."
        echo ""
        if sudo -v 2>/dev/null; then
            log_debug "sudo autenticado correctamente"
            return 0
        fi
    fi
    error "No se pudo obtener acceso root. Ejecute: sudo $0"
    log_fatal "Requerido: acceso root"
}

# is_root — returns 0 if running as root
is_root() { [[ $EUID -eq 0 ]]; }

# sudo_exec <cmd...> — run with sudo if not root
sudo_exec() {
    if is_root; then
        "$@"
    else
        sudo "$@"
    fi
}

# ---- OS Detection ---------------------------------------------------------

# OS type constants
declare -A OS_INFO=()
os_detect() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_INFO[ID]="${ID:-unknown}"
        OS_INFO[NAME]="${NAME:-Unknown}"
        OS_INFO[VERSION_ID]="${VERSION_ID:-unknown}"
        OS_INFO[VERSION_CODENAME]="${VERSION_CODENAME:-unknown}"
    elif [[ -f /etc/debian_version ]]; then
        OS_INFO[ID]="debian"
        OS_INFO[NAME]="Debian"
        OS_INFO[VERSION_ID]="$(cat /etc/debian_version)"
        OS_INFO[VERSION_CODENAME]=""
    elif [[ "$(uname -s)" == "Darwin" ]]; then
        OS_INFO[ID]="macos"
        OS_INFO[NAME]="macOS"
        OS_INFO[VERSION_ID]="$(sw_vers -productVersion 2>/dev/null || echo unknown)"
    else
        OS_INFO[ID]="unknown"
        OS_INFO[NAME]="Unknown OS"
        OS_INFO[VERSION_ID]=""
    fi

    # Determine OS family
    case "${OS_INFO[ID]}" in
        kali)     OS_INFO[FAMILY]="debian" ;;
        debian)   OS_INFO[FAMILY]="debian" ;;
        ubuntu)   OS_INFO[FAMILY]="debian" ;;
        linuxmint) OS_INFO[FAMILY]="debian" ;;
        pop)      OS_INFO[FAMILY]="debian" ;;
        arch)     OS_INFO[FAMILY]="arch" ;;
        manjaro)  OS_INFO[FAMILY]="arch" ;;
        fedora)   OS_INFO[FAMILY]="fedora" ;;
        centos)   OS_INFO[FAMILY]="fedora" ;;
        rhel)     OS_INFO[FAMILY]="fedora" ;;
        opensuse*) OS_INFO[FAMILY]="suse" ;;
        macos)    OS_INFO[FAMILY]="macos" ;;
        *)        OS_INFO[FAMILY]="unknown" ;;
    esac

    export OS_INFO
}

os_detect

# os_is_kali — true if Kali Linux
os_is_kali() { [[ "${OS_INFO[ID]}" == "kali" ]]; }

# os_family_debian — true if Debian-based
os_family_debian() { [[ "${OS_INFO[FAMILY]}" == "debian" ]]; }

# os_print — pretty-print OS info
os_print() {
    echo "  ${FG_BWHT}Sistema:${RST}     ${OS_INFO[NAME]} ${OS_INFO[VERSION_ID]}"
    echo "  ${FG_BWHT}Familia:${RST}    ${OS_INFO[FAMILY]}"
    echo "  ${FG_BWHT}Arquitectura:${RST} $(uname -m)"
    echo "  ${FG_BWHT}Kernel:${RST}     $(uname -r)"
}

# os_check_compat — warns if not on a supported Linux distro
os_check_compat() {
    if os_family_debian; then
        log_info "Sistema compatible: ${OS_INFO[NAME]} ${OS_INFO[VERSION_ID]}"
        return 0
    fi
    warn "Sistema no completamente probado: ${OS_INFO[NAME]}"
    warn "Algunas herramientas pueden no estar disponibles en los repositorios oficiales."
    hint "Se recomienda Kali Linux, Debian 11+ o Ubuntu 22.04+"
    if ! confirm "¿Continuar de todas formas?" "n"; then
        log_info "Instalación cancelada por el usuario — sistema no compatible"
        exit 0
    fi
}

# ---- Package Manager Abstraction ------------------------------------------

# pkg_update — update package lists
pkg_update() {
    log_info "Actualizando índices de paquetes..."
    if os_family_debian; then
        sudo_exec apt-get update -qq 2>&1 | log_debug || true
    elif [[ "${OS_INFO[FAMILY]}" == "arch" ]]; then
        sudo_exec pacman -Sy --noconfirm 2>&1 | log_debug || true
    elif [[ "${OS_INFO[FAMILY]}" == "fedora" ]]; then
        sudo_exec dnf check-update -q 2>&1 | log_debug || true
    else
        log_warn "No se pudo actualizar paquetes — OS no soportado"
    fi
    log_ok "Índices actualizados"
}

# pkg_install <packages...> — install via system package manager
pkg_install() {
    local pkgs=("$@")
    log_info "Instalando paquetes: ${pkgs[*]}"

    if os_family_debian; then
        DEBIAN_FRONTEND=noninteractive sudo_exec apt-get install -y -qq "${pkgs[@]}" 2>&1 | log_debug || {
            log_error "Falló instalación de: ${pkgs[*]}"
            return 1
        }
    elif [[ "${OS_INFO[FAMILY]}" == "arch" ]]; then
        sudo_exec pacman -S --noconfirm --needed "${pkgs[@]}" 2>&1 | log_debug || {
            log_error "Falló instalación de: ${pkgs[*]}"
            return 1
        }
    elif [[ "${OS_INFO[FAMILY]}" == "fedora" ]]; then
        sudo_exec dnf install -y "${pkgs[@]}" 2>&1 | log_debug || {
            log_error "Falló instalación de: ${pkgs[*]}"
            return 1
        }
    else
        log_error "No hay gestor de paquetes para ${OS_INFO[FAMILY]}"
        return 1
    fi

    log_ok "Paquetes instalados: ${pkgs[*]}"
    return 0
}

# pip_install <package> — install via pip3
pip_install() {
    local pkg="$1"
    log_info "Instalando paquete Python: ${pkg}"
    sudo_exec pip3 install --quiet "$pkg" 2>&1 | log_debug || {
        log_error "Falló pip install: ${pkg}"
        return 1
    }
    log_ok "Paquete Python instalado: ${pkg}"
    return 0
}

# npm_global <package> — install global npm package
npm_global() {
    local pkg="$1"
    log_info "Instalando paquete npm global: ${pkg}"
    sudo_exec npm install -g --quiet "$pkg" 2>&1 | log_debug || {
        log_error "Falló npm install -g: ${pkg}"
        return 1
    }
    log_ok "npm package instalado: ${pkg}"
    return 0
}

# snap_install <package> [classic]
snap_install() {
    local pkg="$1"
    local mode="${2:-}"
    log_info "Instalando snap: ${pkg}"
    if [[ "$mode" == "classic" ]]; then
        sudo_exec snap install "$pkg" --classic 2>&1 | log_debug || return 1
    else
        sudo_exec snap install "$pkg" 2>&1 | log_debug || return 1
    fi
    log_ok "Snap instalado: ${pkg}"
    return 0
}

# cargo_install <package> — install via cargo (Rust)
cargo_install() {
    local pkg="$1"
    log_info "Instalando crate: ${pkg}"
    if ! command -v cargo &>/dev/null; then
        log_info "Instalando cargo (Rust)..."
        pkg_install cargo 2>/dev/null || {
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y 2>&1 | log_debug
            source "$HOME/.cargo/env" 2>/dev/null || true
        }
    fi
    cargo install "$pkg" 2>&1 | log_debug || {
        log_error "Falló cargo install: ${pkg}"
        return 1
    }
    log_ok "Crate instalado: ${pkg}"
    return 0
}

# go_install <package> — install via go install
go_install() {
    local pkg="$1"
    log_info "Instalando paquete Go: ${pkg}"
    if ! command -v go &>/dev/null; then
        pkg_install golang-go 2>/dev/null || pkg_install golang 2>/dev/null || true
    fi
    go install "${pkg}@latest" 2>&1 | log_debug || {
        log_error "Falló go install: ${pkg}"
        return 1
    }
    log_ok "Go package instalado: ${pkg}"
    return 0
}

# gh_release <repo> <asset_pattern> — download latest GitHub release asset
gh_release() {
    local repo="$1"
    local pattern="$2"
    local dest="${3:-/tmp}"
    log_info "Descargando ${repo} — ${pattern}"

    local url
    url=$(curl -s "https://api.github.com/repos/${repo}/releases/latest" \
        | grep "browser_download_url.*${pattern}" \
        | head -1 \
        | cut -d: -f2- \
        | tr -d ' "' 2>/dev/null) || true

    if [[ -z "$url" ]]; then
        log_error "No se encontró release para ${repo}/${pattern}"
        return 1
    fi

    cd "$dest" && curl -sL -O "$url" 2>&1 | log_debug || {
        log_error "Falló descarga de ${url}"
        return 1
    }
    log_ok "Descargado: ${url##*/}"
    echo "${dest}/${url##*/}"
}

# ---- Tool Verification ----------------------------------------------------

# Which? — returns 0 if command exists
cmd_exists() {
    command -v "$1" &>/dev/null
}

# ver <tool> — get version of installed tool
tool_version() {
    local tool="$1"
    local ver=""
    case "$tool" in
        nmap)          ver=$(nmap --version 2>/dev/null | head -1 | grep -oP '[\d\.]+' | head -1) ;;
        nikto)         ver=$(nikto -Version 2>/dev/null | grep -oP '[\d\.]+' | head -1) ;;
        sqlmap)        ver=$(sqlmap --version 2>/dev/null | grep -oP '[\d\.]+' | head -1) ;;
        whatweb)       ver=$(whatweb --version 2>/dev/null | grep -oP '[\d\.]+' | head -1) ;;
        zaproxy)       ver=$(zap-cli --version 2>/dev/null | grep -oP '[\d\.]+' | head -1) ;;
        wireshark)     ver=$(wireshark --version 2>/dev/null | grep -oP '[\d\.]+' | head -1) ;;
        tcpdump)       ver=$(tcpdump --version 2>/dev/null | grep -oP '[\d\.]+' | head -1) ;;
        python3)       ver=$(python3 --version 2>/dev/null | grep -oP '[\d\.]+' | head -1) ;;
        node)          ver=$(node --version 2>/dev/null | sed 's/v//') ;;
        docker)        ver=$(docker --version 2>/dev/null | grep -oP '[\d\.]+' | head -1) ;;
        *)             ver=$($tool --version 2>/dev/null | head -1) ;;
    esac
    [[ -z "$ver" ]] && ver=$($tool -v 2>/dev/null | head -1)
    [[ -z "$ver" ]] && ver=$($tool version 2>/dev/null | head -1)
    echo "${ver:-unknown}"
}

# ---- Network Checks -------------------------------------------------------

# net_test — ping test to internet host
net_test() {
    local host="${1:-8.8.8.8}"
    if ping -c1 -W2 "$host" &>/dev/null; then
        log_debug "Connectividad a Internet: OK (${host})"
        return 0
    fi
    log_warn "Sin conectividad a ${host}"
    return 1
}

# net_test_dns — check DNS resolution
net_test_dns() {
    local domain="${1:-google.com}"
    if host "$domain" &>/dev/null || nslookup "$domain" &>/dev/null || dig "$domain" &>/dev/null; then
        log_debug "Resolución DNS: OK"
        return 0
    fi
    log_warn "Sin resolución DNS"
    return 1
}

# net_test_all — comprehensive network check
net_test_all() {
    log_section "VERIFICACIÓN DE RED"
    net_test || true
    net_test_dns || true
    # Test GitHub reachability
    if curl -sI https://github.com &>/dev/null; then
        log_ok "GitHub accesible"
    else
        log_warn "GitHub no accesible — algunas descargas pueden fallar"
    fi
    return 0
}

# ---- Resource Checks ------------------------------------------------------

# disk_check <path> [min_gb]
disk_check() {
    local path="${1:-/}"
    local min_gb="${2:-5}"
    local avail
    avail=$(df -BG "$path" | awk 'NR==2 {gsub(/G/,""); print $4}')
    if [[ "${avail%.*}" -ge "$min_gb" ]]; then
        log_debug "Disco disponible: ${avail}G en ${path}"
        return 0
    fi
    log_warn "Espacio bajo en disco: ${avail}G disponible en ${path} (mín: ${min_gb}G)"
    return 1
}

# mem_check [min_mb]
mem_check() {
    local min_mb="${1:-1024}"
    local total
    total=$(free -m | awk '/^Mem:/ {print $2}')
    if [[ "$total" -ge "$min_mb" ]]; then
        log_debug "Memoria RAM: ${total}MB"
        return 0
    fi
    log_warn "Poca memoria RAM: ${total}MB (mín: ${min_mb}MB)"
    return 1
}

# ---- Execution Helpers ----------------------------------------------------

# retry <cmd...> — retry up to N times
retry() {
    local n="${RETRY_MAX:-3}"
    local delay="${RETRY_DELAY:-2}"
    local attempts=0
    while true; do
        attempts=$(( attempts + 1 ))
        if "$@"; then
            return 0
        fi
        if [[ $attempts -ge $n ]]; then
            log_error "Se agotaron los reintentos (${n}) para: $*"
            return 1
        fi
        log_warn "Reintentando (${attempts}/${n}) en ${delay}s..."
        sleep "$delay"
    done
}

# timed_run <timeout_seconds> <cmd...> — run with timeout
timed_run() {
    local timeout_sec="$1"; shift
    if command -v timeout &>/dev/null; then
        timeout "$timeout_sec" "$@" 2>&1 || {
            local rc=$?
            [[ $rc -eq 124 ]] && log_warn "Timeout (${timeout_sec}s): $*"
            return $rc
        }
    else
        "$@"  # fallback: run without timeout
    fi
}

# run_with_log <log_label> <cmd...> — run and log output
run_with_log() {
    local label="$1"; shift
    log_info "Ejecutando: $*"
    "$@" 2>&1 | while IFS= read -r line; do
        log_debug "[${label}] ${line}"
    done
    local rc=${PIPESTATUS[0]}
    log_cmd "$*" "$rc"
    return $rc
}

# ---- Backup / Restore -----------------------------------------------------

# backup_file <file> — create timestamped backup
backup_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        log_debug "No existe, no se respalda: ${file}"
        return 0
    fi
    local backup="${file}.$(date '+%Y%m%d-%H%M%S').bak"
    cp "$file" "$backup" && log_info "Respaldo creado: ${backup}" || {
        log_error "Falló respaldo de: ${file}"
        return 1
    }
}

# ---- Temp Directory -------------------------------------------------------

# make_temp_dir — create and register temp directory
make_temp_dir() {
    local prefix="${1:-PaginasAudit}"
    local dir
    dir="$(mktemp -d "/tmp/${prefix}.XXXXXX")" || {
        log_fatal "No se pudo crear directorio temporal"
    }
    log_debug "Directorio temporal: ${dir}"
    echo "$dir"
}

# cleanup_temp <dir> — remove temp directory
cleanup_temp() {
    local dir="$1"
    if [[ -d "$dir" ]]; then
        rm -rf "$dir" 2>/dev/null && log_debug "Temp eliminado: ${dir}" || true
    fi
}
