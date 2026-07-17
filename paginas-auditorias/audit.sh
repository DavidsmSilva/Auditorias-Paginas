#!/usr/bin/env bash
# ============================================================================
# audit.sh — PaginasAudit Cyber Audit Installer
# ============================================================================
# Instalador modular de herramientas de ciberseguridad para Kali Linux.
# Organizado en 6 fases: Assessment, Malware, Brand Protection, IR, SAST, SCA+SBOM
#
# Uso:
#   ./audit.sh                    → Menú interactivo (TUI con dialog)
#   ./audit.sh --help             → Ayuda completa
#   ./audit.sh --list-tools       → Listar todas las herramientas
#   ./audit.sh --install-all      → Instalar TODO
#   ./audit.sh --install-phase N  → Instalar fase N (1-6)
#   ./audit.sh --install-tool X   → Instalar herramienta específica
#   ./audit.sh --verify           → Verificar instalación únicamente
#   ./audit.sh --report           → Generar reporte de verificación
#   ./audit.sh --version          → Mostrar versión
#   ./audit.sh --audit URL        → Auditoría automática contra URL
#   ./audit.sh --audit URL DIR    → Auditoría con directorio de salida
# ============================================================================

set -euo pipefail
IFS=$'\n\t'

# ---- Config ---------------------------------------------------------------
VERSION="2.1.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SCRIPT_DIR

# ---- Modes ----------------------------------------------------------------
# --mode bounty: activa guías de explotación en reportes HTML (bug bounty)
# --mode opsec:  activa chequeo OPSEC pre-vuelo (anonymity check)
BOUNTY_MODE=false
OPSEC_MODE=false
export BOUNTY_MODE OPSEC_MODE

# ---- Source Libraries -----------------------------------------------------
source "${SCRIPT_DIR}/lib/colors.sh"
source "${SCRIPT_DIR}/lib/logging.sh"
source "${SCRIPT_DIR}/lib/ui.sh"
source "${SCRIPT_DIR}/lib/utils.sh"
source "${SCRIPT_DIR}/lib/verify.sh"
source "${SCRIPT_DIR}/config/tools.db"

# ---- Load Settings --------------------------------------------------------
SETTINGS_FILE="${SCRIPT_DIR}/config/settings.cfg"
SKIP_INSTALLED=true
AUTO_INSTALL_DEPS=true

if [[ -f "$SETTINGS_FILE" ]]; then
    # Source settings, filtering out comments and empty lines
    source "$SETTINGS_FILE" 2>/dev/null || true
fi

# Export some settings as readonly for modules
export SKIP_INSTALLED
export AUTO_INSTALL_DEPS

# ---- Signal Handling ------------------------------------------------------
cleanup_on_exit() {
    local exit_code=$?
    echo ""
    if [[ $exit_code -ne 0 && $exit_code -ne 130 ]]; then
        __echo "${FG_BRED}" "  ╔══════════════════════════════════════════════════════════════╗"
        __echo "${FG_BRED}" "  ║  ✖  ERROR: El instalador terminó inesperadamente           ║"
        __echo "${FG_BRED}" "  ║     Revise el log para más detalles                        ║"
        __echo "${FG_BRED}" "  ╚══════════════════════════════════════════════════════════════╝"
        [[ -n "$LOG_FILE" ]] && echo "  Log: ${LOG_FILE}"
    fi
    exit "$exit_code"
}

interrupt_handler() {
    echo ""
    __echo "${FG_YLW}" "  ╔══════════════════════════════════════════════════════════════╗"
    __echo "${FG_YLW}" "  ║  ⚑  Instalación interrumpida por el usuario               ║"
    __echo "${FG_YLW}" "  ╚══════════════════════════════════════════════════════════════╝"
    exit 130
}

trap cleanup_on_exit EXIT
trap interrupt_handler INT TERM

# ---- Pre-flight -----------------------------------------------------------

pre_flight() {
    echo ""
    banner "${VERSION}"

    log_section "PRE-FLIGHT CHECK"

    # Root check
    if ! is_root; then
        require_root
        warn "NOTA: Algunas herramientas requerirán sudo durante la instalación."
        echo ""
    fi

    # OS detection
    os_print
    echo ""

    # Compatibility check
    os_check_compat
    echo ""

    # Network checks
    if ! net_test_all; then
        warn "Problemas de conectividad detectados. Algunas descargas pueden fallar."
        if ! confirm "¿Continuar de todas formas?" "n"; then
            exit 0
        fi
    fi
    echo ""

    # Disk check
    disk_check "/" 5 || {
        warn "Espacio en disco bajo — se recomienda al menos 5GB libres."
        if ! confirm "¿Continuar?" "n"; then
            exit 0
        fi
    }
    echo ""

    # Resource check
    mem_check 1024 || {
        warn "Memoria baja — algunas herramientas pueden funcionar lentamente."
    }
    echo ""

    # Initialize logging
    log_init "${SCRIPT_DIR}/logs" "${LOG_LEVEL:-INFO}" "${LOG_JSON:-false}"
    log_info "Pre-flight completado — Sistema: ${OS_INFO[NAME]} ${OS_INFO[VERSION_ID]}"

    # Check for dialog
    if ! command -v dialog &>/dev/null; then
        warn "dialog no está instalado. Se usará modo texto (fallback)."
        hint "Para mejor experiencia: sudo apt install dialog"
        echo ""
    fi
}

# ---- Dependency Installation ----------------------------------------------

install_core_deps() {
    log_section "INSTALANDO DEPENDENCIAS BASE"

    info "Verificando dependencias del sistema..."

    local core_pkgs=(
        "dialog"
        "curl"
        "wget"
        "git"
        "ca-certificates"
        "gnupg"
        "unzip"
        "zip"
        "tar"
        "gzip"
        "python3"
        "python3-pip"
        "python3-venv"
        "ruby"
        "ruby-dev"
        "build-essential"
        "libpcap-dev"
        "libssl-dev"
        "libffi-dev"
    )

    local to_install=()
    for pkg in "${core_pkgs[@]}"; do
        if ! dpkg -s "$pkg" &>/dev/null 2>&1; then
            to_install+=("$pkg")
        fi
    done

    if [[ ${#to_install[@]} -gt 0 ]]; then
        info "Instalando dependencias base: ${to_install[*]}"
        pkg_update
        pkg_install "${to_install[@]}"
    else
        log_ok "Todas las dependencias base ya están instaladas."
    fi

    # WeasyPrint deps for PDF reports — NOT fatal if they fail (optional feature)
    # libgdk-pixbuf name changed in Debian Bookworm+ (Kali 2026.1+)
    local weasy_deps=(
        "libpango-1.0-0"
        "libharfbuzz0b"
        "libpangoft2-1.0-0"
        "libcairo2"
    )
    # Detect correct gdk-pixbuf package name
    if dpkg -s libgdk-pixbuf-2.0-0 &>/dev/null 2>&1; then
        : # already installed
    elif apt-cache show libgdk-pixbuf-2.0-0 &>/dev/null 2>&1; then
        weasy_deps+=("libgdk-pixbuf-2.0-0")
    else
        weasy_deps+=("libgdk-pixbuf2.0-0")  # fallback to old name
    fi
    local weasy_to_install=()
    for pkg in "${weasy_deps[@]}"; do
        if ! dpkg -s "$pkg" &>/dev/null 2>&1; then
            weasy_to_install+=("$pkg")
        fi
    done
    if [[ ${#weasy_to_install[@]} -gt 0 ]]; then
        info "Instalando dependencias para reportes PDF (WeasyPrint)..."
        pkg_install "${weasy_to_install[@]}" || log_warn "Algunas dependencias de WeasyPrint no se instalaron — reportes PDF se saltarán"
    else
        log_info "Dependencias de WeasyPrint ya disponibles."
    fi

    # Ensure pip and npm basics
    if ! cmd_exists pip3 && cmd_exists python3; then
        log_info "Instalando pip3..."
        pkg_install python3-pip
    fi

    # Fresh package cache before npm/nodejs install (may have been skipped if core pkgs were present)
    pkg_update

    # Install nodejs first, then npm separately — and make it NON-FATAL
    if ! cmd_exists node; then
        log_info "Instalando nodejs..."
        pkg_install nodejs || log_warn "nodejs no se pudo instalar — algunas herramientas requerirán Node.js"
    fi

    if ! cmd_exists npm; then
        log_info "Instalando npm..."
        pkg_install npm || log_warn "npm no se pudo instalar — funciones npm no estarán disponibles"
    fi

    # 🔒 Supply chain hardening: apply npm global security config
    if cmd_exists npm; then
        echo ""
        npm_verify_apt_origin
        npm_harden_global
        echo ""
    fi

    # Install python-docx for professional DOCX report generation
    info "Verificando python-docx para reportes DOCX..."
    if python3 -c "import docx" 2>/dev/null; then
        log_info "python-docx ya disponible."
    else
        log_info "Instalando python-docx vía pip..."
        if cmd_exists pip3; then
            sudo_exec pip3 install --quiet python-docx 2>&1 | log_debug && \
                log_ok "python-docx instalado correctamente." || \
                log_warn "No se pudo instalar python-docx — los reportes DOCX se saltarán."
        else
            log_warn "pip3 no disponible — no se puede instalar python-docx"
        fi
    fi

    # Install weasyprint for professional PDF report generation (HTML → PDF)
    info "Verificando weasyprint para reportes PDF..."
    if python3 -c "import weasyprint" 2>/dev/null; then
        log_info "weasyprint ya disponible."
    else
        log_info "Instalando weasyprint vía pip..."
        if cmd_exists pip3; then
            sudo_exec pip3 install --quiet weasyprint 2>&1 | log_debug && \
                log_ok "weasyprint instalado correctamente." || \
                log_warn "No se pudo instalar weasyprint — los reportes PDF se saltarán."
        else
            log_warn "pip3 no disponible — no se puede instalar weasyprint"
        fi
    fi

    log_ok "Dependencias base listas"
}

# ---- Module Loading -------------------------------------------------------

# Source all phase modules
load_modules() {
    local modules=(
        "${SCRIPT_DIR}/modules/00-automated-audit.sh"
        "${SCRIPT_DIR}/modules/01-assessment.sh"
        "${SCRIPT_DIR}/modules/02-malware.sh"
        "${SCRIPT_DIR}/modules/03-brand-protection.sh"
        "${SCRIPT_DIR}/modules/04-incident-response.sh"
        "${SCRIPT_DIR}/modules/05-sast.sh"
        "${SCRIPT_DIR}/modules/06-sca-sbom.sh"
        "${SCRIPT_DIR}/modules/07-exploit-guides.sh"
    )

    for mod in "${modules[@]}"; do
        if [[ -f "$mod" ]]; then
            source "$mod"
            log_debug "Módulo cargado: ${mod}"
        else
            log_warn "Módulo no encontrado: ${mod}"
        fi
    done
}

# ---- Audit URL Interactive Wrapper ---------------------------------------

audit_url_interactive() {
    # Ensure module is loaded
    if ! declare -F audit_menu &>/dev/null; then
        log_warn "Módulo de auditoría automática no cargado. Cargando..."
        [[ -f "${SCRIPT_DIR}/modules/00-automated-audit.sh" ]] && source "${SCRIPT_DIR}/modules/00-automated-audit.sh"
    fi

    if declare -F audit_menu &>/dev/null; then
        audit_menu
    else
        error "Módulo 00-automated-audit.sh no encontrado."
        error "Asegúrese de que el archivo existe en modules/"
        ui_msg "Error" "Módulo de auditoría automática no disponible.\n\nVerifique que modules/00-automated-audit.sh existe."
    fi
}

# ---- Main Menu ------------------------------------------------------------

main_menu() {
    while true; do
        clear 2>/dev/null || true
        banner "$VERSION"

        echo ""
        __echo "${FG_BWHT}${BLD}" "  ╔══════════════════════════════════════════════════════════════╗"
        __echo "${FG_BWHT}${BLD}" "  ║            PaginasAudit — CYBER AUDIT TOOLKIT                    ║"
        __echo "${FG_BWHT}${BLD}" "  ║        Instalador de Herramientas de Auditoría               ║"
        __echo "${FG_BWHT}${BLD}" "  ╚══════════════════════════════════════════════════════════════╝"
        echo ""

        local menu_items=(
            "A" "🎯  AUDITAR URL — Auditoría automática completa contra un sitio web"
            "─" "────────────────────────────────────────────────────────────"
            "1" "Fase 1: Assessment — Escaneo activo, DAST, Nmap, ZAP, SQLmap..."
            "2" "Fase 2: Malware Analysis — Dependencias, webshells, integridad..."
            "3" "Fase 3: Brand Protection — Typosquatting, fugas, reputación..."
            "4" "Fase 4: Incident Response — Forense, tráfico, backups..."
            "5" "Fase 5: SAST — Semgrep, TruffleHog, Gitleaks, Bandit, Ruff..."
            "6" "Fase 6: SCA + SBOM — Trivy, Dep-Check, Syft, Grype, OSV..."
            "─" "────────────────────────────────────────────────────────────"
            "I" "⚠  INSTALAR TODO — Las 6 fases completas"
            "V" "✓  Verificar instalación y generar reporte"
            "S" "📋  Mostrar resumen de herramientas"
            "H" "📖  Ayuda y documentación"
            "Q" "🚪  Salir"
        )

        local choice
        choice=$(ui_menu "PaginasAudit Cyber Audit" "Seleccione una fase:" 16 "${menu_items[@]}")

        case "$choice" in
            "A"|"a")
                audit_url_interactive
                ;;
            "─")
                # Separator — do nothing
                ;;
            "1")
                assessment_menu
                ;;
            "2")
                malware_menu
                ;;
            "3")
                brand_menu
                ;;
            "4")
                incident_menu
                ;;
            "5")
                sast_menu
                ;;
            "6")
                sca_menu
                ;;
            "I"|"i")
                install_everything
                ;;
            "V"|"v")
                run_verification
                ;;
            "S"|"s")
                show_tool_summary
                ;;
            "H"|"h")
                show_help
                ;;
            "Q"|"q"|"")
                if ui_confirm "PaginasAudit" "¿Salir del instalador?"; then
                    log_info "Instalador finalizado por el usuario"
                    exit 0
                fi
                ;;
        esac
    done
}

# ---- Install Everything ---------------------------------------------------

install_everything() {
    echo ""
    __echo "${FG_RED}${BLD}"  "  ╔══════════════════════════════════════════════════════════════╗"
    __echo "${FG_RED}${BLD}"  "  ║     INSTALACIÓN COMPLETA — TODAS LAS FASES                   ║"
    __echo "${FG_RED}${BLD}"  "  ╚══════════════════════════════════════════════════════════════╝"
    echo ""
    warn "Esto instalará TODAS las herramientas de las 6 fases."
    warn "Tiempo estimado: 20-40 minutos (dependiendo de la conexión)"
    echo ""

    if ! ui_confirm "Instalación Completa" "¿Está seguro de instalar todo el toolkit?"; then
        return 0
    fi

    install_core_deps

    local start_time
    start_time=$(date +%s)

    # Phase 1
    assessment_install_all
    echo ""

    # Phase 2
    malware_install_all
    echo ""

    # Phase 3
    brand_install_all
    echo ""

    # Phase 4
    incident_install_all
    echo ""

    # Phase 5
    sast_install_all
    echo ""

    # Phase 6
    sca_install_all
    echo ""

    local end_time
    end_time=$(date +%s)
    local duration=$(( end_time - start_time ))
    local minutes=$(( duration / 60 ))
    local seconds=$(( duration % 60 ))

    log_ok "Instalación completa en ${minutes}m ${seconds}s"

    # Generate report
    if $GENERATE_REPORT; then
        generate_report "${SCRIPT_DIR}/reports/installation-report"
    fi

    # Summary
    summary

    echo ""
    __echo "${FG_BGRN}${BLD}"  "  ┌──────────────────────────────────────────────────────────────┐"
    __echo "${FG_BGRN}${BLD}"  "  │  ✅  INSTALACIÓN COMPLETA                                   │"
    __echo "${FG_BGRN}${BLD}"  "  │  Las 6 fases han sido instaladas.                           │"
    __echo "${FG_BGRN}${BLD}"  "  │  Use la opción 'Verificar' para generar el reporte.         │"
    __echo "${FG_BGRN}${BLD}"  "  └──────────────────────────────────────────────────────────────┘"
    echo ""

    ui_msg "Instalación Completa" "Todas las herramientas han sido instaladas.\n\nTiempo total: ${minutes}m ${seconds}s\nRevise el reporte en: reports/installation-report.txt"
}

# ---- Verification ---------------------------------------------------------

run_verification() {
    log_section "VERIFICACIÓN DE HERRAMIENTAS"

    info "Iniciando verificación de todas las herramientas instaladas..."
    verify_reset

    local phases=("Assessment" "Malware Analysis" "Brand Protection" "Incident Response" "SAST" "SCA + SBOM")
    for phase in "${phases[@]}"; do
        log_info "Verificando fase: ${phase}"
        local tools
        mapfile -t tools < <(tools_by_phase "$phase")
        for tool in "${tools[@]}"; do
            local bin
            bin=$(tool_bin "$tool")
            verify_tool "$tool" "$phase" "$bin" || true
        done
    done

    echo ""

    if $GENERATE_REPORT; then
        generate_report "${SCRIPT_DIR}/reports/verification-report"
    else
        summary
    fi

    ui_msg "Verificación Completa" "Verificación finalizada.\n\nTotal: ${VERIFY_TOTAL}   ✓ OK: ${VERIFY_PASS}   ✗ Fail: ${VERIFY_FAIL}   - Skip: ${VERIFY_SKIP}\n\nReporte: reports/verification-report.txt"
}

# ---- Tool Summary ---------------------------------------------------------

show_tool_summary() {
    clear 2>/dev/null || true
    echo ""
    __echo "${COLOR_HEADER}" "  ╔══════════════════════════════════════════════════════════════╗"
    __echo "${COLOR_HEADER}" "  ║           PaginasAudit — RESUMEN DE HERRAMIENTAS                 ║"
    __echo "${COLOR_HEADER}" "  ╚══════════════════════════════════════════════════════════════╝"
    echo ""

    local all_phases=("Assessment" "Malware Analysis" "Brand Protection" "Incident Response" "SAST" "SCA + SBOM")

    # First show the summary table
    phase_summary
    echo ""

    for phase in "${all_phases[@]}"; do
        local tools=()
        mapfile -t tools < <(tools_by_phase "$phase")
        local count=${#tools[@]}

        subheader "${phase} (${count} herramientas)"
        echo ""

        for tool in "${tools[@]}"; do
            local desc="${TOOL_DESC[$tool]}"
            local inst_meth="${TOOL_METHOD[$tool]:-apt}"
            local bin
            bin=$(tool_bin "$tool")
            local installed=" "
            local ver=""

            if cmd_exists "$bin"; then
                installed="${FG_GRN}✓${RST}"
                ver=$(tool_version "$bin")
            else
                installed="${FG_RED}✗${RST}"
                ver="—"
            fi

            printf "  ${installed} ${FG_BWHT}%-16s${RST} ${FG_BBLK}%-5s${RST} ${FG_BBLK}%-12s${RST} %s\n" \
                "$tool" "[${inst_meth}]" "v${ver}" "$desc"
        done
        echo ""
    done

    ui_msg "Resumen de Herramientas" "Resumen mostrado arriba.\n\nTotal: $(phase_tool_count_all) herramientas en 6 fases."
}

# ---- Help -----------------------------------------------------------------

show_help() {
    if [[ -f "${SCRIPT_DIR}/README.md" ]]; then
        ui_text "PaginasAudit — Ayuda" "${SCRIPT_DIR}/README.md"
    else
        clear 2>/dev/null || true
        echo ""
        banner "$VERSION"
        echo ""
        __echo "${FG_BWHT}${BLD}"  "  PaginasAudit CYBER AUDIT INSTALLER — MANUAL DE USO"
        __echo "${FG_BWHT}"        "  ══════════════════════════════════════════════"
        echo ""
        echo "  SINOPSIS"
        echo "    ./audit.sh [OPCIÓN]"
        echo ""
        echo "  OPCIONES"
        echo "    (sin opción)   Menú interactivo TUI"
        echo "    --help            Muestra esta ayuda"
        echo "    --version         Muestra la versión"
        echo "    --list-tools      Lista todas las herramientas disponibles"
        echo "    --install-all     Instala todas las herramientas de las 6 fases"
        echo "    --install-phase N Instala la fase N (1-6)"
        echo "    --install-tool NAME  Instala una herramienta específica"
        echo "    --verify          Verifica las herramientas instaladas"
        echo "    --report          Genera reporte de verificación"
        echo "    --audit URL       Ejecuta auditoría automática contra una URL"
        echo "    --audit URL DIR   Auditoría con directorio de salida personalizado"
        echo "    --mode MODE       Activa modo específico:"
        echo "                       bounty  → Guías de explotación en reportes (bug bounty)"
        echo "                       opsec   → Chequeo OPSEC/anonymity pre-vuelo"
        echo "                      Ej: ./audit.sh --mode bounty --audit https://ejemplo.com"
        echo ""
        echo "  FASES (Instalación)"
        echo "    1. Assessment       — 29 herramientas de escaneo, fuzzing y DAST"
        echo "    2. Malware Analysis — 16 herramientas de análisis de malware"
        echo "    3. Brand Protection — 11 herramientas de OSINT y marca"
        echo "    4. Incident Response— 19 herramientas de forense y backup"
        echo "    5. SAST               — 5 herramientas de análisis estático (Semgrep, TruffleHog, Gitleaks, Bandit, Ruff)"
        echo "    6. SCA + SBOM         — 5 herramientas de composición y dependencias (Trivy, Dep-Check, Syft, Grype, OSV)"
        echo ""
        echo "  REPORTES GENERADOS:"
        echo "    · TXT  — Reporte texto plano"
        echo "    · JSON — Reporte estructurado (máquina)"
        echo "    · HTML — Reporte interactivo con filtros y severidad + guías de explotación (modo bounty)"
        echo "    · DOCX — Reporte profesional Word (portada, tabla, gráficos)"
        echo ""
        echo "  AUDITORÍA AUTOMÁTICA (--audit)"
        echo "    Ejecuta las 6 fases contra una URL en una sola corrida:"
        echo "    · Assessment: Nmap + Nikto + WhatWeb + Nuclei + SSL + DNS + Gobuster"
        echo "    · Malware:    YARA + ExifTool + Análisis de cabeceras de seguridad"
        echo "    · Brand:      dnstwist + theHarvester + Sublist3r + HIBP"
        echo "    · IR:         Evaluación de preparación ante incidentes"
        echo "    · SAST:       Semgrep + TruffleHog + Gitleaks + Bandit + Ruff"
        echo "    · SCA+SBOM:   Trivy + Dependency-Check + Syft + Grype + OSV-Scanner"
        echo "    Genera reportes TXT + JSON + HTML interactivo"
        echo ""
        echo "  EJEMPLOS"
        echo "    ./audit.sh                       # Menú interactivo"
        echo "    ./audit.sh                       # Menú interactivo"
        echo "    ./audit.sh --install-all          # Instalar todo"
        echo "    ./audit.sh --install-phase 1      # Solo Assessment"
        echo "    ./audit.sh --install-tool nmap    # Solo Nmap"
        echo "    ./audit.sh --verify              # Verificar instalación"
        echo "    ./audit.sh --report              # Generar reporte"
        echo "    ./audit.sh --audit https://ejemplo.com  # Auditoría automática"
        echo "    ./audit.sh --audit https://ejemplo.com ./audits  # Con directorio"
        echo "    ./audit.sh --mode opsec --audit ...  # Con OPSEC pre-vuelo"
        echo "    ./audit.sh --mode bounty --audit ... # Con guías de explotación"
        echo "    ./audit.sh --clean                   # Limpiar evidencia de auditoría"
        echo ""
        echo "  SEGURIDAD DEL OPERADOR"
        echo "    · Consent log: registro de autorización del target antes de auditar"
        echo "    · OPSEC auto-prompt: verifica VPN, DNS leak, IPv6 pre-auditoría"
        echo "    · Findings vault: protege hallazgos sensibles (permisos 600)"
        echo "    · Cleanup: elimina evidencia de auditoría del disco (--clean)"
        echo ""
        echo "  ESTRUCTURA DE DIRECTORIOS"
        echo "    audit.sh           → Entry point principal"
        echo "    config/            → Configuración y registro de herramientas"
        echo "    lib/               → Librerías compartidas"
        echo "    modules/           → Módulos por fase"
        echo "    logs/              → Logs de instalación"
        echo "    reports/           → Reportes generados"
        echo ""
        echo "  REQUISITOS"
        echo "    - Sistema operativo: Kali Linux, Debian 11+, Ubuntu 22.04+"
        echo "    - Permisos: root o sudo"
        echo "    - Conexión a Internet"
        echo "    - Mínimo: 1GB RAM, 5GB disco libre"
        echo ""
        __echo "${FG_BBLK}"  "  Documentación completa: README.md"
        echo ""
        ui_msg "PaginasAudit — Ayuda" "Manual de uso mostrado arriba."
    fi
}

# ---- CLI Argument Parsing -------------------------------------------------

cli_dispatch() {
    case "${1:-}" in
        --help|-h)
            show_help
            exit 0
            ;;
        --version|-v)
            echo "PaginasAudit Cyber Audit Installer v${VERSION}"
            exit 0
            ;;
        --list-tools|-l)
            show_tool_summary
            exit 0
            ;;
        --install-all|-a)
            pre_flight
            install_core_deps
            load_modules
            install_everything
            exit 0
            ;;
        --install-phase|-p)
            local phase_num="${2:-}"
            if [[ -z "$phase_num" ]]; then
                error "Especifique el número de fase (1-6)"
                exit 1
            fi
            pre_flight
            install_core_deps
            load_modules
            case "$phase_num" in
                1) assessment_install_all ;;
                2) malware_install_all ;;
                3) brand_install_all ;;
                4) incident_install_all ;;
                5) sast_install_all ;;
                6) sca_install_all ;;
                *) error "Fase inválida: ${phase_num}. Use 1-6."; exit 1 ;;
            esac
            exit 0
            ;;
        --install-tool|-t)
            local tool_name="${2:-}"
            if [[ -z "$tool_name" ]]; then
                error "Especifique el nombre de la herramienta"
                exit 1
            fi
            pre_flight
            install_core_deps
            load_modules

            # Find which phase has this tool
            local phase
            phase="${TOOL_PHASE[$tool_name]:-}"
            if [[ -z "$phase" ]]; then
                error "Herramienta desconocida: ${tool_name}"
                hint "Use --list-tools para ver las herramientas disponibles"
                exit 1
            fi

            log_info "Fase detectada: ${phase}"
            case "$phase" in
                "Assessment") assessment_install_tool "$tool_name" ;;
                "Malware Analysis") malware_install_tool "$tool_name" ;;
                "Brand Protection") brand_install_tool "$tool_name" ;;
                "Incident Response") incident_install_tool "$tool_name" ;;
                "SAST") sast_install_tool "$tool_name" ;;
                "SCA + SBOM") sca_install_tool "$tool_name" ;;
            esac
            exit 0
            ;;
        --verify)
            pre_flight
            load_modules
            run_verification
            exit 0
            ;;
        --report|-r)
            pre_flight
            load_modules
            generate_report "${SCRIPT_DIR}/reports/verification-report"
            exit 0
            ;;
        --mode)
            local mode_val="${2:-}"
            if [[ "$mode_val" == "bounty" ]]; then
                BOUNTY_MODE=true
                log_info "🐞 MODO BOUNTY ACTIVADO — Reportes con guías de explotación"
            elif [[ "$mode_val" == "opsec" ]]; then
                OPSEC_MODE=true
                log_info "🛡️ MODO OPSEC ACTIVADO — Chequeo de anonimato pre-vuelo"
            else
                error "Modo inválido: ${mode_val}. Use: bounty | opsec"
                exit 1
            fi
            # Shift args and continue with next command
            shift 2
            cli_dispatch "$@"
            return
            ;;
        --audit)
            pre_flight
            # 🛡️ OPSEC check — automático si está activo, si no, preguntar
            if $OPSEC_MODE && declare -F opsec_check &>/dev/null; then
                opsec_check
            else
                opsec_auto_prompt
            fi
            # 📝 Consentimiento — siempre preguntar antes de auditar
            local audit_url="${2:-}"
            local audit_dir="${3:-${SCRIPT_DIR}/audits}"
            if [[ -z "$audit_url" ]]; then
                error "Especifique la URL a auditar."
                hint "Ejemplo: ./audit.sh --audit https://example.com"
                exit 1
            fi
            consent_prompt "$audit_url"
            install_core_deps
            load_modules
            # Ensure the audit module is loaded
            if declare -F audit_url &>/dev/null; then
                audit_url "$audit_url" "$audit_dir"
                # 🔒 Findings vault — proteger hallazgos después de la auditoría
                if declare -F findings_vault &>/dev/null && [[ -n "${AUDIT_DIR:-}" ]]; then
                    findings_vault "$AUDIT_DIR"
                fi
            else
                error "Módulo de auditoría automática no disponible."
                exit 1
            fi
            exit 0
            ;;
        --clean|-c)
            echo ""
            audit_cleanup
            exit 0
            ;;
        ""|--menu|-m)
            # Default: interactive menu
            ;;
        *)
            error "Opción desconocida: $1"
            echo "  Use --help para ver las opciones disponibles."
            exit 1
            ;;
    esac
}

# ---- Security & Compliance -------------------------------------------------

# consent_prompt — pide confirmación de autorización antes de auditar
consent_prompt() {
    local target="$1"
    echo ""
    __echo "${FG_RED}${BLD}" "  ╔══════════════════════════════════════════════════════════════╗"
    __echo "${FG_RED}${BLD}" "  ║     ⚠  CONSENTIMIENTO REQUERIDO — AUTORIZACIÓN DE AUDITORÍA  ║"
    __echo "${FG_RED}${BLD}" "  ╚══════════════════════════════════════════════════════════════╝"
    echo ""
    log_warn "Está por auditar: ${target}"
    log_warn "Auditar sin autorización es ILEGAL en la mayoría de las jurisdicciones."
    echo ""
    if ! confirm "¿Tiene autorización por escrito del propietario del sitio?" "n"; then
        error "Auditoría cancelada — se requiere autorización del propietario."
        exit 1
    fi
    local ref=""
    read -r -p "  Referencia del cliente/permiso (opcional, Enter para omitir): " ref
    echo ""

    # Save consent log
    local log_dir="${SCRIPT_DIR}/logs"
    mkdir -p "$log_dir"
    local consent_file="${log_dir}/consent.log"
    {
        echo "=== CONSENT LOG ==="
        echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Operator:  $(whoami)@$(hostname 2>/dev/null || echo 'unknown')"
        echo "Target:    ${target}"
        echo "Reference: ${ref:-N/A}"
        echo "SHA256:    $(echo "${target}|$(date +%s)|${ref}" | sha256sum 2>/dev/null | cut -d' ' -f1 || echo 'checksum_unavailable')"
        echo "Output:    ${AUDIT_DIR:-not set at consent time}"
        echo "==================="
        echo ""
    } >> "$consent_file"
    chmod 600 "$consent_file"
    log_ok "Consentimiento registrado en: ${consent_file}"
}

# opsec_auto_prompt — ofrece ejecutar OPSEC check si no está activo
opsec_auto_prompt() {
    if ! $OPSEC_MODE; then
        echo ""
        log_warn "🛡️  No se detectó modo OPSEC activo (--mode opsec)"
        if confirm "¿Ejecutar chequeo de anonimato (VPN, DNS leak, IPv6) antes de continuar?" "y"; then
            OPSEC_MODE=true
            export OPSEC_MODE
            if declare -F opsec_check &>/dev/null; then
                opsec_check
            else
                # Fallback: cargar módulo y reintentar
                load_modules
                if declare -F opsec_check &>/dev/null; then
                    opsec_check
                fi
            fi
        fi
    fi
}

# findings_vault — protege hallazgos sensibles post-auditoría
findings_vault() {
    local audit_dir="$1"
    echo ""
    log_section "🔒 FINDINGS VAULT — Protegiendo datos sensibles"
    if [[ ! -d "$audit_dir" ]]; then
        log_info "Sin directorio de auditoría para proteger."
        return 0
    fi
    local protected=0
    while IFS= read -r -d '' f; do
        chmod 600 "$f" 2>/dev/null && protected=$(( protected + 1 ))
    done < <(find "$audit_dir" -type f \( -name "*-results.*" -o -name "*secret*" -o -name "*credencial*" -o -name "*password*" -o -name "*token*" \) -print0 2>/dev/null)
    # Also protect the entire audit dir from other users
    chmod -R o-rwx "$audit_dir" 2>/dev/null || true
    log_ok "${protected} archivos de hallazgos protegidos (permisos 600, resto del directorio 700)"
}

# audit_cleanup — elimina evidencia de auditorías anteriores
audit_cleanup() {
    echo ""
    log_section "🧹 CLEANUP — Eliminando evidencia de auditoría"
    local audit_dir="${SCRIPT_DIR}/audits"
    if [[ -d "$audit_dir" ]]; then
        local count
        count=$(find "$audit_dir" -type f 2>/dev/null | wc -l)
        if [[ "$count" -gt 0 ]]; then
            log_warn "Se eliminarán ${count} archivos de auditoría en: ${audit_dir}"
            if confirm "¿Está seguro?" "n"; then
                rm -rf "${audit_dir:?}/"* 2>/dev/null
                log_ok "Directorio de auditorías limpiado."
            else
                log_info "Cleanup cancelado."
            fi
        else
            log_info "No hay auditorías para limpiar."
        fi
    fi
    # Clean logs
    if [[ -d "${SCRIPT_DIR}/logs" ]]; then
        rm -f "${SCRIPT_DIR}/logs/"*.log 2>/dev/null
        log_ok "Logs eliminados."
    fi
}

# ---- Main -----------------------------------------------------------------

main() {
    # Parse CLI args first
    cli_dispatch "$@"

    # If we get here, run interactive mode
    pre_flight
    install_core_deps
    load_modules
    main_menu
}

# Bootstrap
main "$@"
