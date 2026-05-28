#!/usr/bin/env bash
# ============================================================================
# 01-assessment.sh — Fase 1: Assessment de Ciberseguridad
# ----------------------------------------------------------------------------
# Escaneo activo, DAST (OWASP ZAP / Burp Suite), revisión de superficie de red
# con Nmap, y análisis dinámico de aplicaciones web.
# ============================================================================

[[ -n "${__MODULE_ASSESSMENT_LOADED:-}" ]] && return 0
readonly __MODULE_ASSESSMENT_LOADED=true

MODULE_ASSESSMENT_NAME="Assessment"
MODULE_ASSESSMENT_DESC="Escaneo activo, DAST y revisión de superficie de red"

# ---- Phase Banner ---------------------------------------------------------

assessment_banner() {
    clear 2>/dev/null || true
    echo ""
    __echo "${FG_RED}${BLD}"  "  ╔══════════════════════════════════════════════════════════════╗"
    __echo "${FG_RED}${BLD}"  "  ║         FASE 1: ASSESSMENT DE CIBERSEGURIDAD                  ║"
    __echo "${FG_RED}${BLD}"  "  ╠══════════════════════════════════════════════════════════════╣"
    __echo "${FG_RED}"        "  ║  Escaneo activo · DAST · Superficie de red                    ║"
    __echo "${FG_RED}${BLD}"  "  ╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  ${FG_BBLK}OWASP ZAP / Burp Suite → Interceptar tráfico web y automatizar"
    echo "  búsqueda de vulnerabilidades comunes (XSS, SQLi)"
    echo ""
    echo "  Nmap → Mapear puertos y descubrir servicios en el servidor host"
    echo "  Nikto + WhatWeb → Fingerprinting y escaneo web"
    echo "  Nuclei → Escaneo automatizado con templates YAML${RST}"
    echo ""
}

# ---- Tool Install Functions -----------------------------------------------

assessment_install_nmap() {
    log_section "Instalando Nmap"
    info "Escáner de puertos y detección de servicios"
    pkg_install nmap
    verify_tool "nmap" "Assessment" "nmap"
}

assessment_install_nikto() {
    log_section "Instalando Nikto"
    info "Escáner de vulnerabilidades web"
    pkg_install nikto
    verify_tool "nikto" "Assessment" "nikto"
}

assessment_install_sqlmap() {
    log_section "Instalando SQLmap"
    info "Detección y explotación automatizada de SQL Injection"
    pkg_install sqlmap
    verify_tool "sqlmap" "Assessment" "sqlmap"
}

assessment_install_whatweb() {
    log_section "Instalando WhatWeb"
    info "Identificación de tecnologías web"
    pkg_install whatweb
    verify_tool "whatweb" "Assessment" "whatweb"
}

assessment_install_wpscan() {
    log_section "Instalando WPScan"
    info "Escáner de vulnerabilidades WordPress"
    if cmd_exists wpscan; then
        log_ok "WPScan ya está instalado"
        verify_tool "wpscan" "Assessment" "wpscan"
        return 0
    fi
    log_info "Instalando WPScan via Ruby gem..."
    sudo_exec gem install wpscan 2>&1 | log_debug
    verify_tool "wpscan" "Assessment" "wpscan"
}

assessment_install_dirb() {
    log_section "Instalando Dirb"
    info "Fuzzing de directorios web"
    pkg_install dirb
    verify_tool "dirb" "Assessment" "dirb"
}

assessment_install_gobuster() {
    log_section "Instalando Gobuster"
    info "Fuerza bruta de directorios y subdominios"
    pkg_install gobuster
    verify_tool "gobuster" "Assessment" "gobuster"
}

assessment_install_zaproxy() {
    log_section "Instalando OWASP ZAP"
    info "Proxy de interceptación y DAST automatizado"
    pkg_install zaproxy
    verify_tool "zaproxy" "Assessment" "zap-cli"
}

assessment_install_burpsuite() {
    log_section "Instalando Burp Suite Community"
    info "Suite de pruebas de penetración web con interceptación"

    if cmd_exists burpsuite; then
        log_ok "Burp Suite ya está instalado"
        verify_tool "burpsuite" "Assessment" "burpsuite"
        return 0
    fi

    # Try to install via apt or download manually
    if pkg_install burpsuite 2>/dev/null; then
        verify_tool "burpsuite" "Assessment" "burpsuite"
        return 0
    fi

    # Fallback: download from official source
    warn "Burp Suite no disponible en repositorios. Descargando Community Edition..."
    local tmp_dir
    tmp_dir=$(make_temp_dir "burpsuite")
    cd "$tmp_dir" || return 1

    local burp_url="https://portswigger.net/burp/releases/download?product=community&type=linux"
    wget -q --show-progress -O burpsuite.sh "$burp_url" 2>&1 | log_debug || {
        log_error "Falló descarga de Burp Suite"
        cleanup_temp "$tmp_dir"
        return 1
    }

    sudo_exec mkdir -p /opt/burpsuite
    sudo_exec mv burpsuite.sh /opt/burpsuite/
    sudo_exec chmod +x /opt/burpsuite/burpsuite.sh
    sudo_exec ln -sf /opt/burpsuite/burpsuite.sh /usr/local/bin/burpsuite
    cleanup_temp "$tmp_dir"

    log_ok "Burp Suite Community instalado en /opt/burpsuite/"
    verify_tool "burpsuite" "Assessment" "burpsuite"
}

assessment_install_dnsrecon() {
    log_section "Instalando DNSRecon"
    info "Enumeración y reconocimiento DNS"
    pkg_install dnsrecon
    verify_tool "dnsrecon" "Assessment" "dnsrecon"
}

assessment_install_dnsenum() {
    log_section "Instalando DNSEnum"
    info "Enumeración de registros DNS"
    pkg_install dnsenum
    verify_tool "dnsenum" "Assessment" "dnsenum"
}

assessment_install_whois() {
    log_section "Instalando Whois"
    info "Consultas de registro de dominios"
    pkg_install whois
    verify_tool "whois" "Assessment" "whois"
}

assessment_install_sslscan() {
    log_section "Instalando SSLScan"
    info "Evaluación de configuración SSL/TLS"
    pkg_install sslscan
    verify_tool "sslscan" "Assessment" "sslscan"
}

assessment_install_testssl() {
    log_section "Instalando testssl.sh"
    info "Suite de testing de SSL/TLS"
    pkg_install testssl.sh
    verify_tool "testssl" "Assessment" "testssl.sh"
}

assessment_install_nuclei() {
    log_section "Instalando Nuclei"
    info "Escáner de vulnerabilidades basado en templates YAML (ProjectDiscovery)"

    # Nuclei requires Go
    if ! cmd_exists go; then
        log_info "Instalando Go primero..."
        pkg_install golang-go
    fi

    if cmd_exists nuclei; then
        verify_tool "nuclei" "Assessment" "nuclei"
        return 0
    fi

    go_install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
    nuclei -update-templates 2>&1 | log_debug || true
    verify_tool "nuclei" "Assessment" "nuclei"
}

assessment_install_httpx() {
    log_section "Instalando httpx"
    info "Sondeo HTTP proactivo (ProjectDiscovery)"
    if cmd_exists httpx; then
        verify_tool "httpx" "Assessment" "httpx"
        return 0
    fi
    go_install "github.com/projectdiscovery/httpx/cmd/httpx"
    verify_tool "httpx" "Assessment" "httpx"
}

assessment_install_subfinder() {
    log_section "Instalando Subfinder"
    info "Descubrimiento de subdominios pasivo"
    if cmd_exists subfinder; then
        verify_tool "subfinder" "Assessment" "subfinder"
        return 0
    fi
    go_install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    verify_tool "subfinder" "Assessment" "subfinder"
}

assessment_install_amass() {
    log_section "Instalando Amass"
    info "Mapeo de superficie de ataque (OWASP)"
    if cmd_exists amass; then
        verify_tool "amass" "Assessment" "amass"
        return 0
    fi
    go_install "github.com/owasp-amass/amass/v4/..."
    verify_tool "amass" "Assessment" "amass"
}

assessment_install_hydra() {
    log_section "Instalando Hydra"
    info "Fuerza bruta de autenticación"
    pkg_install hydra
    verify_tool "hydra" "Assessment" "hydra"
}

assessment_install_john() {
    log_section "Instalando John the Ripper"
    info "Crackeo de hashes de contraseñas"
    pkg_install john
    verify_tool "john" "Assessment" "john"
}

assessment_install_hashcat() {
    log_section "Instalando Hashcat"
    info "Crackeo de hashes acelerado por GPU"
    pkg_install hashcat
    verify_tool "hashcat" "Assessment" "hashcat"
}

assessment_install_curl() {
    log_section "Verificando cURL"
    pkg_install curl
    verify_tool "curl" "Assessment" "curl"
}

assessment_install_wget() {
    log_section "Verificando Wget"
    pkg_install wget
    verify_tool "wget" "Assessment" "wget"
}

# ---- Generic Install Dispatcher -------------------------------------------

# Map tool name to install function
assessment_install_tool() {
    local tool="$1"
    case "$tool" in
        nmap)       assessment_install_nmap ;;
        nikto)      assessment_install_nikto ;;
        sqlmap)     assessment_install_sqlmap ;;
        whatweb)    assessment_install_whatweb ;;
        wpscan)     assessment_install_wpscan ;;
        dirb)       assessment_install_dirb ;;
        gobuster)   assessment_install_gobuster ;;
        zaproxy)    assessment_install_zaproxy ;;
        burpsuite)  assessment_install_burpsuite ;;
        dnsrecon)   assessment_install_dnsrecon ;;
        dnsenum)    assessment_install_dnsenum ;;
        whois)      assessment_install_whois ;;
        sslscan)    assessment_install_sslscan ;;
        testssl)    assessment_install_testssl ;;
        nuclei)     assessment_install_nuclei ;;
        httpx)      assessment_install_httpx ;;
        subfinder)  assessment_install_subfinder ;;
        amass)      assessment_install_amass ;;
        hydra)      assessment_install_hydra ;;
        john)       assessment_install_john ;;
        hashcat)    assessment_install_hashcat ;;
        curl)       assessment_install_curl ;;
        wget)       assessment_install_wget ;;
        *)          log_warn "Fase Assessment: herramienta desconocida '${tool}'"; return 1 ;;
    esac
}

# ---- Phase Installation ---------------------------------------------------

assessment_install_all() {
    assessment_banner

    log_section "FASE 1: ASSESSMENT DE CIBERSEGURIDAD"
    log_info "Iniciando instalación de herramientas de Assessment..."

    local tools=()
    mapfile -t tools < <(tools_by_phase "Assessment")

    local total=${#tools[@]}
    local current=0

    for tool in "${tools[@]}"; do
        current=$(( current + 1 ))

        # Check if already installed
        if $SKIP_INSTALLED && tool_installed "$tool"; then
            local ver
            ver=$(tool_version "$(tool_bin "$tool")")
            log_ok "✓ ${tool} v${ver} — ya instalado, saltando"
            verify_tool "$tool" "Assessment" "$(tool_bin "$tool")"
            continue
        fi

        log_info "[${current}/${total}] Instalando ${tool}..."

        # Install dependencies first
        local dep="${TOOL_DEPS[$tool]:-}"
        if [[ -n "$dep" ]] && $AUTO_INSTALL_DEPS; then
            if ! tool_installed "$dep"; then
                log_info "Dependencia requerida: ${dep}. Instalando primero..."
                # Recursive install for dependency
                assessment_install_tool "$dep" || true
            fi
        fi

        assessment_install_tool "$tool" || {
            log_error "Falló instalación de ${tool}"
        }
    done

    log_ok "Fase Assessment completada"
}

# ---- Interactive Selection -------------------------------------------------

assessment_menu() {
    while true; do
        assessment_banner

        local tools=()
        mapfile -t tools < <(tools_by_phase "Assessment")
        local menu_items=()

        # Build menu: all + individual tools
        menu_items+=("all" "Instalar TODAS las herramientas de Assessment")
        for tool in "${tools[@]}"; do
            local status
            if tool_installed "$tool"; then
                status="✓ INSTALADO"
            else
                status="✗ PENDIENTE"
            fi
            menu_items+=("$tool" "${TOOL_DESC[$tool]} [${status}]")
        done
        menu_items+=("back" "Volver al menú principal")

        local choice
        choice=$(ui_menu "Fase 1: Assessment" "Seleccione una opción:" 20 "${menu_items[@]}")

        case "$choice" in
            "")
                return 0
                ;;
            "all")
                if ui_confirm "Assessment" "¿Instalar TODAS las herramientas de Assessment?"; then
                    assessment_install_all
                    ui_msg "Assessment" "Instalación de Fase Assessment completada."
                fi
                ;;
            "back")
                return 0
                ;;
            *)
                if ui_confirm "Assessment" "¿Instalar ${choice}?"; then
                    assessment_install_tool "$choice"
                fi
                ;;
        esac
    done
}

# ---- Auto-Execute ---------------------------------------------------------
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    assessment_menu
fi
