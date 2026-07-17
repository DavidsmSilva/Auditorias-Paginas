#!/usr/bin/env bash
# ============================================================================
# 05-sast.sh — Fase 5: SAST — Static Application Security Testing
# ----------------------------------------------------------------------------
# Análisis estático de código fuente: Semgrep, TruffleHog, Gitleaks, Bandit, Ruff.
# Detecta vulnerabilidades, secretos hardcodeados y malas prácticas en el
# código fuente de aplicaciones web escaneadas.
# ============================================================================

[[ -n "${__MODULE_SAST_LOADED:-}" ]] && return 0
readonly __MODULE_SAST_LOADED=true

MODULE_SAST_NAME="SAST"
MODULE_SAST_DESC="Static Application Security Testing — análisis estático de código"

# ---- Banner ----------------------------------------------------------------

sast_banner() {
    clear 2>/dev/null || true
    echo ""
    __echo "${FG_RED}${BLD}"  "  ╔══════════════════════════════════════════════════════════════╗"
    __echo "${FG_RED}${BLD}"  "  ║         FASE 5: SAST — STATIC APPLICATION SECURITY TESTING      ║"
    __echo "${FG_RED}${BLD}"  "  ╠══════════════════════════════════════════════════════════════╣"
    __echo "${FG_RED}"        "  ║  Semgrep · TruffleHog · Gitleaks · Bandit · Ruff               ║"
    __echo "${FG_RED}${BLD}"  "  ╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  ${FG_BBLK}Semgrep → Escaneo SAST multi-lenguaje con reglas OSS y personalizadas"
    echo "  TruffleHog → Detección de secretos y credenciales en repositorios"
    echo "  Gitleaks → Escáner de secretos hardcodeados en repositorios Git"
    echo "  Bandit → Analizador SAST para código Python"
    echo "  Ruff → Linter ultra-rápido en Rust con reglas de seguridad (AST-based)${RST}"
    echo ""
}

# ---- Tool Install Functions ------------------------------------------------

sast_install_semgrep() {
    log_section "Instalando Semgrep"
    info "Escáner SAST multi-lenguaje con reglas OSS y pro (>= 1.157.0)"
    if cmd_exists semgrep; then
        local ver
        ver=$(semgrep --version 2>/dev/null | head -1)
        if [[ "$(printf '%s\n' "1.157.0" "$ver" | sort -V | head -1)" == "1.157.0" ]]; then
            log_ok "Semgrep v${ver} ya instalado y cumple versión mínima"
            verify_tool "semgrep" "SAST" "semgrep"
            return 0
        fi
        log_info "Actualizando Semgrep v${ver} a >= 1.157.0..."
    fi
    # 🔒 CVE-2026-34073: Must be >= 1.157.0
    pip_install "semgrep>=1.157.0"
    verify_tool "semgrep" "SAST" "semgrep"
}

sast_install_trufflehog() {
    log_section "Instalando TruffleHog"
    info "Detección de secretos y credenciales en repositorios"
    if cmd_exists trufflehog; then
        log_ok "TruffleHog ya está instalado"
        verify_tool "trufflehog" "SAST" "trufflehog"
        return 0
    fi
    pip_install "trufflehog"
    verify_tool "trufflehog" "SAST" "trufflehog"
}

sast_install_gitleaks() {
    log_section "Instalando Gitleaks"
    info "Escáner de secretos hardcodeados en repositorios Git"
    if cmd_exists gitleaks; then
        log_ok "Gitleaks ya está instalado"
        verify_tool "gitleaks" "SAST" "gitleaks"
        return 0
    fi
    # Requires Go
    if ! cmd_exists go; then
        log_info "Instalando Go primero..."
        pkg_install golang-go
    fi
    go_install "github.com/gitleaks/gitleaks/v8"
    verify_tool "gitleaks" "SAST" "gitleaks"
}

sast_install_bandit() {
    log_section "Instalando Bandit"
    info "Analizador SAST para Python (PyCQA)"
    if cmd_exists bandit; then
        log_ok "Bandit ya está instalado"
        verify_tool "bandit" "SAST" "bandit"
        return 0
    fi
    pip_install "bandit"
    verify_tool "bandit" "SAST" "bandit"
}

sast_install_ruff() {
    log_section "Instalando Ruff"
    info "Linter ultra-rápido en Rust con reglas de seguridad (AST-based)"
    if cmd_exists ruff; then
        log_ok "Ruff ya está instalado"
        verify_tool "ruff" "SAST" "ruff"
        return 0
    fi
    pip_install "ruff"
    verify_tool "ruff" "SAST" "ruff"
}

# ---- Generic Install Dispatcher -------------------------------------------

sast_install_tool() {
    local tool="$1"
    case "$tool" in
        semgrep)    sast_install_semgrep ;;
        trufflehog) sast_install_trufflehog ;;
        gitleaks)   sast_install_gitleaks ;;
        bandit)     sast_install_bandit ;;
        ruff)       sast_install_ruff ;;
        *)          log_warn "Fase SAST: herramienta desconocida '${tool}'"; return 1 ;;
    esac
}

# ---- Phase Installation ---------------------------------------------------

sast_install_all() {
    sast_banner

    log_section "FASE 5: SAST — STATIC APPLICATION SECURITY TESTING"
    log_info "Iniciando instalación de herramientas SAST..."

    local tools=()
    mapfile -t tools < <(tools_by_phase "SAST")

    local total=${#tools[@]}
    local current=0

    for tool in "${tools[@]}"; do
        current=$(( current + 1 ))

        # Check if already installed
        if $SKIP_INSTALLED && tool_installed "$tool"; then
            local ver
            ver=$(tool_version "$(tool_bin "$tool")")
            log_ok "✓ ${tool} v${ver} — ya instalado, saltando"
            verify_tool "$tool" "SAST" "$(tool_bin "$tool")"
            continue
        fi

        log_info "[${current}/${total}] Instalando ${tool}..."

        # Install dependencies first
        local dep="${TOOL_DEPS[$tool]:-}"
        if [[ -n "$dep" ]] && $AUTO_INSTALL_DEPS; then
            if ! tool_installed "$dep"; then
                log_info "Dependencia requerida: ${dep}. Instalando primero..."
                sast_install_tool "$dep" || true
            fi
        fi

        sast_install_tool "$tool" || {
            log_error "Falló instalación de ${tool}"
        }
    done

    log_ok "Fase SAST completada"
}

# ---- Interactive Selection -------------------------------------------------

sast_menu() {
    while true; do
        sast_banner

        local tools=()
        mapfile -t tools < <(tools_by_phase "SAST")
        local menu_items=()

        # Build menu: all + individual tools
        menu_items+=("all" "Instalar TODAS las herramientas SAST")
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
        choice=$(ui_menu "Fase 5: SAST" "Seleccione una opción:" 14 "${menu_items[@]}")

        case "$choice" in
            "")
                return 0
                ;;
            "all")
                if ui_confirm "SAST" "¿Instalar TODAS las herramientas SAST?"; then
                    sast_install_all
                    ui_msg "SAST" "Instalación de Fase SAST completada."
                fi
                ;;
            "back")
                return 0
                ;;
            *)
                if ui_confirm "SAST" "¿Instalar ${choice}?"; then
                    sast_install_tool "$choice"
                fi
                ;;
        esac
    done
}

# ---- Auto-Execute ---------------------------------------------------------
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    sast_menu
fi
