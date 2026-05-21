#!/usr/bin/env bash
# ============================================================================
# audit.sh — PaginasAudit Cyber Audit Installer
# ============================================================================
# Instalador modular de herramientas de ciberseguridad para Kali Linux.
# Organizado en 4 fases: Assessment, Malware, Brand Protection, Incident Response
#
# Uso:
#   ./audit.sh                    → Menú interactivo (TUI con dialog)
#   ./audit.sh --help             → Ayuda completa
#   ./audit.sh --list-tools       → Listar todas las herramientas
#   ./audit.sh --install-all      → Instalar TODO
#   ./audit.sh --install-phase N  → Instalar fase N (1-4)
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
VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SCRIPT_DIR

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

    # Ensure pip and npm basics
    if ! cmd_exists pip3 && cmd_exists python3; then
        log_info "Instalando pip3..."
        pkg_install python3-pip
    fi

    if ! cmd_exists npm; then
        log_info "Instalando npm..."
        pkg_install npm nodejs
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
            "─" "────────────────────────────────────────────────────────────"
            "I" "⚠  INSTALAR TODO — Las 4 fases completas"
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
    warn "Esto instalará TODAS las herramientas de las 4 fases."
    warn "Tiempo estimado: 15-30 minutos (dependiendo de la conexión)"
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
    __echo "${FG_BGRN}${BLD}"  "  │  Las 4 fases han sido instaladas.                           │"
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

    local phases=("Assessment" "Malware Analysis" "Brand Protection" "Incident Response")
    for phase in "${phases[@]}"; do
        log_info "Verificando fase: ${phase}"
        local tools
        tools=($(tools_by_phase "$phase"))
        for tool in "${tools[@]}"; do
            local bin
            bin=$(tool_bin "$tool")
            verify_tool "$tool" "$phase" "$bin"
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

    local all_phases=("Assessment" "Malware Analysis" "Brand Protection" "Incident Response")

    # First show the summary table
    phase_summary
    echo ""

    for phase in "${all_phases[@]}"; do
        local tools
        tools=($(tools_by_phase "$phase"))
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

    ui_msg "Resumen de Herramientas" "Resumen mostrado arriba.\n\nTotal: $(phase_tool_count_all) herramientas en 4 fases."
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
        echo "    --install-all     Instala todas las herramientas de las 4 fases"
        echo "    --install-phase N Instala la fase N (1-4)"
        echo "    --install-tool NAME  Instala una herramienta específica"
        echo "    --verify          Verifica las herramientas instaladas"
        echo "    --report          Genera reporte de verificación"
        echo "    --audit URL       Ejecuta auditoría automática contra una URL"
        echo "    --audit URL DIR   Auditoría con directorio de salida personalizado"
        echo ""
        echo "  FASES (Instalación)"
        echo "    1. Assessment       — 23 herramientas de escaneo y DAST"
        echo "    2. Malware Analysis — 16 herramientas de análisis de malware"
        echo "    3. Brand Protection — 11 herramientas de OSINT y marca"
        echo "    4. Incident Response— 19 herramientas de forense y backup"
        echo ""
        echo "  REPORTES GENERADOS:"
        echo "    · TXT  — Reporte texto plano"
        echo "    · JSON — Reporte estructurado (máquina)"
        echo "    · HTML — Reporte interactivo con filtros y severidad"
        echo "    · DOCX — Reporte profesional Word (portada, tabla, gráficos)"
        echo ""
        echo "  AUDITORÍA AUTOMÁTICA (--audit)"
        echo "    Ejecuta las 4 fases contra una URL en una sola corrida:"
        echo "    · Assessment: Nmap + Nikto + WhatWeb + Nuclei + SSL + DNS + Gobuster"
        echo "    · Malware:    YARA + ExifTool + Análisis de cabeceras de seguridad"
        echo "    · Brand:      dnstwist + theHarvester + Sublist3r + HIBP"
        echo "    · IR:         Evaluación de preparación ante incidentes"
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
                error "Especifique el número de fase (1-4)"
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
                *) error "Fase inválida: ${phase_num}. Use 1-4."; exit 1 ;;
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
        --audit)
            pre_flight
            install_core_deps
            load_modules
            local audit_url="${2:-}"
            local audit_dir="${3:-${SCRIPT_DIR}/audits}"
            if [[ -z "$audit_url" ]]; then
                error "Especifique la URL a auditar."
                hint "Ejemplo: ./audit.sh --audit https://example.com"
                exit 1
            fi
            # Ensure the audit module is loaded
            if declare -F audit_url &>/dev/null; then
                audit_url "$audit_url" "$audit_dir"
            else
                error "Módulo de auditoría automática no disponible."
                exit 1
            fi
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
