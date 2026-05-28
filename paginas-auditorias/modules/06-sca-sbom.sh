#!/usr/bin/env bash
# ============================================================================
# 06-sca-sbom.sh — Fase 6: SCA + SBOM — Dependency & Supply Chain Security
# ----------------------------------------------------------------------------
# Análisis de composición de software, generación de SBOM y detección de
# vulnerabilidades en dependencias: Trivy, OWASP Dependency-Check, Syft,
# Grype, OSV-Scanner.
# ============================================================================

[[ -n "${__MODULE_SCA_LOADED:-}" ]] && return 0
readonly __MODULE_SCA_LOADED=true

MODULE_SCA_NAME="SCA + SBOM"
MODULE_SCA_DESC="Software Composition Analysis y generación de SBOM"

# ---- Banner ----------------------------------------------------------------

sca_banner() {
    clear 2>/dev/null || true
    echo ""
    __echo "${FG_RED}${BLD}"  "  ╔══════════════════════════════════════════════════════════════╗"
    __echo "${FG_RED}${BLD}"  "  ║     FASE 6: SCA + SBOM — DEPENDENCY & SUPPLY CHAIN SECURITY    ║"
    __echo "${FG_RED}${BLD}"  "  ╠══════════════════════════════════════════════════════════════╣"
    __echo "${FG_RED}"        "  ║  Trivy · OWASP Dep-Check · Syft · Grype · OSV-Scanner          ║"
    __echo "${FG_RED}${BLD}"  "  ╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  ${FG_BBLK}Trivy → Escáner integral de vulnerabilidades (OS, librerías, IaC)"
    echo "  OWASP Dependency-Check → SCA para Java/.NET/Node.js"
    echo "  Syft → Generador de SBOM (CycloneDX / SPDX)"
    echo "  Grype → Escáner de vulnerabilidades sobre SBOM"
    echo "  OSV-Scanner → Escáner usando base OSV.dev${RST}"
    echo ""
}

# ---- Tool Install Functions ------------------------------------------------

sca_install_trivy() {
    log_section "Instalando Trivy"
    info "Escáner integral de vulnerabilidades (v0.69.3 pinneado)"

    if cmd_exists trivy; then
        local ver
        ver=$(trivy --version 2>/dev/null | head -1 | grep -oP '[\d\.]+' | head -1)
        log_ok "Trivy v${ver} ya instalado"
        verify_tool "trivy" "SCA + SBOM" "trivy"
        return 0
    fi

    # 🔒 CRITICAL: Trivy MUST be pinned to v0.69.3 exactly.
    # v0.69.4 has a compromised supply chain (CVE-2026-33634).
    local version="0.69.3"
    local repo="aquasecurity/trivy"
    local asset_pattern="trivy_${version}_Linux-64bit.deb"
    local tmp_dir
    tmp_dir=$(make_temp_dir "trivy_install")

    log_info "Descargando Trivy v${version} desde GitHub release (PINNEADO)..."
    gh_release "$repo" "$asset_pattern" "$tmp_dir" || {
        log_error "Falló descarga de Trivy v${version}"
        cleanup_temp "$tmp_dir"
        return 1
    }

    local deb_file
    deb_file=$(find "$tmp_dir" -name "*.deb" | head -1)
    if [[ -z "$deb_file" ]]; then
        log_error "No se encontró archivo .deb de Trivy"
        cleanup_temp "$tmp_dir"
        return 1
    fi

    log_info "Instalando paquete DEB: ${deb_file}"
    sudo_exec dpkg -i "$deb_file" 2>&1 | log_debug || {
        log_error "Falló instalación del paquete DEB de Trivy"
        # Try to fix deps
        sudo_exec apt-get install -f -y 2>&1 | log_debug || true
        cleanup_temp "$tmp_dir"
        return 1
    }

    cleanup_temp "$tmp_dir"
    log_ok "Trivy v${version} instalado correctamente (pinneado)"
    verify_tool "trivy" "SCA + SBOM" "trivy"
}

sca_install_dependency_check() {
    log_section "Instalando OWASP Dependency-Check"
    info "SCA para Java/.NET/Node.js — requiere Java Runtime"

    # Check Java dependency
    if ! cmd_exists java; then
        log_info "Java no encontrado. Instalando JRE (requerido para Dependency-Check)..."
        pkg_install default-jre || {
            log_error "No se pudo instalar Java. OWASP Dependency-Check requiere Java."
            log_info "Instale manualmente: sudo apt install default-jre"
            return 1
        }
    fi

    if cmd_exists dependency-check; then
        log_ok "OWASP Dependency-Check ya está instalado"
        verify_tool "dependency-check" "SCA + SBOM" "dependency-check"
        return 0
    fi

    pip_install "dependency-check"
    verify_tool "dependency-check" "SCA + SBOM" "dependency-check"
}

sca_install_syft() {
    log_section "Instalando Syft"
    info "Generador de SBOM (>= 1.42.3)"

    if cmd_exists syft; then
        local ver
        ver=$(syft --version 2>/dev/null | grep -oP '[\d\.]+' | head -1)
        if [[ "$(printf '%s\n' "1.42.3" "$ver" | sort -V | head -1)" == "1.42.3" ]]; then
            log_ok "Syft v${ver} ya instalado y cumple versión mínima"
            verify_tool "syft" "SCA + SBOM" "syft"
            return 0
        fi
        log_info "Actualizando Syft v${ver} a >= 1.42.3..."
    fi

    # 🔒 CVE-2026-33481: Syft must be >= 1.42.3
    # Use official curl installer from Anchore
    log_info "Descargando e instalando Syft via script oficial..."
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
        | sh -s -- -b /usr/local/bin v1.42.3 2>&1 | log_debug || {
        log_error "Falló instalación de Syft"
        return 1
    }

    verify_tool "syft" "SCA + SBOM" "syft"
}

sca_install_grype() {
    log_section "Instalando Grype"
    info "Escáner de vulnerabilidades basado en SBOM (Anchore)"

    if cmd_exists grype; then
        log_ok "Grype ya está instalado"
        verify_tool "grype" "SCA + SBOM" "grype"
        return 0
    fi

    # Use official curl installer from Anchore
    log_info "Descargando e instalando Grype via script oficial..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
        | sh -s -- -b /usr/local/bin 2>&1 | log_debug || {
        log_error "Falló instalación de Grype"
        return 1
    }

    verify_tool "grype" "SCA + SBOM" "grype"
}

sca_install_osv_scanner() {
    log_section "Instalando OSV-Scanner"
    info "Escáner de vulnerabilidades usando la base OSV.dev"

    if cmd_exists osv-scanner; then
        log_ok "OSV-Scanner ya está instalado"
        verify_tool "osv-scanner" "SCA + SBOM" "osv-scanner"
        return 0
    fi

    # Requires Go
    if ! cmd_exists go; then
        log_info "Instalando Go primero..."
        pkg_install golang-go
    fi

    go_install "github.com/google/osv-scanner/cmd/osv-scanner"
    verify_tool "osv-scanner" "SCA + SBOM" "osv-scanner"
}

# ---- Generic Install Dispatcher -------------------------------------------

sca_install_tool() {
    local tool="$1"
    case "$tool" in
        trivy)              sca_install_trivy ;;
        dependency-check)   sca_install_dependency_check ;;
        syft)               sca_install_syft ;;
        grype)              sca_install_grype ;;
        osv-scanner)        sca_install_osv_scanner ;;
        *)                  log_warn "Fase SCA + SBOM: herramienta desconocida '${tool}'"; return 1 ;;
    esac
}

# ---- Phase Installation ---------------------------------------------------

sca_install_all() {
    sca_banner

    log_section "FASE 6: SCA + SBOM — DEPENDENCY & SUPPLY CHAIN SECURITY"
    log_info "Iniciando instalación de herramientas SCA + SBOM..."

    local tools=()
    mapfile -t tools < <(tools_by_phase "SCA + SBOM")

    local total=${#tools[@]}
    local current=0

    for tool in "${tools[@]}"; do
        current=$(( current + 1 ))

        # Check if already installed
        if $SKIP_INSTALLED && tool_installed "$tool"; then
            local ver
            ver=$(tool_version "$(tool_bin "$tool")")
            log_ok "✓ ${tool} v${ver} — ya instalado, saltando"
            verify_tool "$tool" "SCA + SBOM" "$(tool_bin "$tool")"
            continue
        fi

        log_info "[${current}/${total}] Instalando ${tool}..."

        # Install dependencies first
        local dep="${TOOL_DEPS[$tool]:-}"
        if [[ -n "$dep" ]] && $AUTO_INSTALL_DEPS; then
            if ! tool_installed "$dep"; then
                log_info "Dependencia requerida: ${dep}. Instalando primero..."
                # Handle non-tool deps differently
                case "$dep" in
                    default-jre) pkg_install default-jre || true ;;
                    go)          pkg_install golang-go || true ;;
                    curl)        pkg_install curl || true ;;
                    *)           log_info "Dependencia '${dep}' debe instalarse manualmente si es necesario" ;;
                esac
            fi
        fi

        sca_install_tool "$tool" || {
            log_error "Falló instalación de ${tool}"
        }
    done

    log_ok "Fase SCA + SBOM completada"
}

# ---- Interactive Selection -------------------------------------------------

sca_menu() {
    while true; do
        sca_banner

        local tools=()
        mapfile -t tools < <(tools_by_phase "SCA + SBOM")
        local menu_items=()

        # Build menu: all + individual tools
        menu_items+=("all" "Instalar TODAS las herramientas SCA + SBOM")
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
        choice=$(ui_menu "Fase 6: SCA + SBOM" "Seleccione una opción:" 16 "${menu_items[@]}")

        case "$choice" in
            "")
                return 0
                ;;
            "all")
                if ui_confirm "SCA + SBOM" "¿Instalar TODAS las herramientas SCA + SBOM?"; then
                    sca_install_all
                    ui_msg "SCA + SBOM" "Instalación de Fase SCA + SBOM completada."
                fi
                ;;
            "back")
                return 0
                ;;
            *)
                if ui_confirm "SCA + SBOM" "¿Instalar ${choice}?"; then
                    sca_install_tool "$choice"
                fi
                ;;
        esac
    done
}

# ---- Auto-Execute ---------------------------------------------------------
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    sca_menu
fi
