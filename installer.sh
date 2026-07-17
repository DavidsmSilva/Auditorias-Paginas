#!/usr/bin/env bash
# ============================================================================
# installer.sh — PaginasAudit Cyber Audit Installer
# ============================================================================
# One-command:
#   curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash
#
# Instala en /opt/paginas-audit/ y crea /usr/local/bin/paginas-audit
# ============================================================================

set -euo pipefail

# ---- Config ---------------------------------------------------------------
REPO_OWNER="${REPO_OWNER:-DavidsmSilva}"
REPO_NAME="${REPO_NAME:-Auditorias-Paginas}"
REPO_BRANCH="${REPO_BRANCH:-main}"
REPO_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"
RAW_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH}"

# Default: system-wide install
INSTALL_DIR="${INSTALL_DIR:-/opt/paginas-audit}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
BIN_NAME="${BIN_NAME:-paginas-audit}"

# ---- Detect local execution -----------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)" || SCRIPT_DIR=""
LOCAL_MODE=false
if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/paginas-auditorias/audit.sh" ]]; then
    LOCAL_MODE=true
fi

# ---- Colors ---------------------------------------------------------------
RST='\033[0m'; RED='\033[31m'; GRN='\033[32m'; YLW='\033[33m'; BLU='\033[34m'; MAG='\033[35m'; CYN='\033[36m'; BLD='\033[1m'
cecho() { echo -e "${1}${2}${RST}"; }

# ---- Help -----------------------------------------------------------------
show_help() {
    echo ""
    echo "  PAGINASAUDIT — Cyber Audit Toolkit"
    echo "  ${REPO_URL}"
    echo ""
    echo "  USO:"
    echo "    curl -sL ${RAW_URL}/installer.sh | bash"
    echo "    curl -sL ${RAW_URL}/installer.sh | bash -s -- --install-all"
    echo ""
    echo "  OPCIONES:"
    echo "    --help, -h        Esta ayuda"
    echo "    --version, -v     Mostrar versión"
    echo ""
    echo "  VARIABLES DE ENTORNO:"
    echo "    INSTALL_DIR=/opt/paginas-audit   Directorio de instalación"
    echo "    BIN_DIR=/usr/local/bin           Directorio del ejecutable"
    echo "    REPO_BRANCH=develop              Rama específica"
    echo ""
    echo "  EJEMPLOS:"
    echo "    curl -sL ${RAW_URL}/installer.sh | bash"
    echo "    curl -sL ${RAW_URL}/installer.sh | bash -s -- --install-all"
    echo "    paginas-audit --audit https://ejemplo.com"
    echo ""
    exit 0
}

show_version() {
    local ver=""
    if $LOCAL_MODE && [[ -f "$SCRIPT_DIR/paginas-auditorias/.version" ]]; then
        ver="$(cat "$SCRIPT_DIR/paginas-auditorias/.version")"
    elif [[ -f "$INSTALL_DIR/paginas-auditorias/.version" ]]; then
        ver="$(cat "$INSTALL_DIR/paginas-auditorias/.version")"
    else
        ver="2.0.0"
    fi
    echo "PaginasAudit v${ver}"
    exit 0
}

# ---- Banner ---------------------------------------------------------------
show_banner() {
    echo ""
    cecho "$RED$BLD"  "  ██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗ "
    cecho "$RED$BLD"  "  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝ "
    cecho "$YLW$BLD"  "  ███████║ ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗██║  ███╗"
    cecho "$YLW$BLD"  "  ██╔══██║  ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██║   ██║"
    cecho "$GRN$BLD"  "  ██║  ██║   ██║   ██║     ███████╗██║  ██║███████║╚██████╔╝"
    cecho "$GRN$BLD"  "  ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ "
    echo ""
    cecho "$MAG"      "  PaginasAudit — Cyber Audit Toolkit"
    cecho "$BLU"      "  ${REPO_URL}"
    echo ""
}

# ---- Pre-flight -----------------------------------------------------------
pre_flight() {
    # curl
    if ! command -v curl &>/dev/null; then
        if command -v apt-get &>/dev/null; then
            sudo apt-get update -qq && sudo apt-get install -y -qq curl
        elif command -v pacman &>/dev/null; then
            sudo pacman -S --noconfirm curl
        fi
    fi

    # git
    if ! command -v git &>/dev/null; then
        if command -v apt-get &>/dev/null; then
            sudo apt-get update -qq && sudo apt-get install -y -qq git
        elif command -v pacman &>/dev/null; then
            sudo pacman -S --noconfirm git
        fi
    fi

    # Build dependencies (perl for bundle processing)
    if ! command -v perl &>/dev/null; then
        if command -v apt-get &>/dev/null; then
            sudo apt-get install -y -qq perl
        fi
    fi
}

# ---- Clone / Update -------------------------------------------------------
clone_or_update() {
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        cecho "$CYN" "→ Actualizando repositorio en ${INSTALL_DIR}..."
        cd "$INSTALL_DIR"
        git fetch origin "$REPO_BRANCH" 2>&1 | while IFS= read -r line; do
            cecho "$BLU" "  ${line}"
        done

        # Fix tracking branch if needed
        local upstream
        upstream=$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || echo "")
        if [[ "$upstream" != "refs/remotes/origin/${REPO_BRANCH}" ]]; then
            cecho "$YLW" "→ Corrigiendo tracking branch..."
            git branch --set-upstream-to="origin/${REPO_BRANCH}" "$(git rev-parse --abbrev-ref HEAD)" 2>/dev/null || true
        fi

        local behind
        behind=$(git rev-list HEAD..origin/"$REPO_BRANCH" --count 2>/dev/null || echo 0)
        if [[ "$behind" -gt 0 ]]; then
            cecho "$YLW" "→ ${behind} commits detrás. Actualizando..."
            git pull origin "$REPO_BRANCH" 2>&1 | while IFS= read -r line; do
                cecho "$BLU" "  ${line}"
            done
            cecho "$GRN" "✓ Repositorio actualizado"
        else
            cecho "$GRN" "✓ Repositorio ya está actualizado"
        fi
    else
        cecho "$CYN" "→ Clonando repositorio en ${INSTALL_DIR}..."
        mkdir -p "$(dirname "$INSTALL_DIR")"
        git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$INSTALL_DIR" 2>&1 | while IFS= read -r line; do
            cecho "$BLU" "  ${line}"
        done
        cecho "$GRN" "✓ Repositorio clonado en ${INSTALL_DIR}"
    fi

    # Make scripts executable
    chmod +x "${INSTALL_DIR}/build.sh" 2>/dev/null || true
    find "${INSTALL_DIR}/paginas-auditorias/lib" -name '*.sh' -exec chmod +x {} \; 2>/dev/null || true
    find "${INSTALL_DIR}/paginas-auditorias/modules" -name '*.sh' -exec chmod +x {} \; 2>/dev/null || true
    chmod +x "${INSTALL_DIR}/paginas-auditorias/audit.sh" 2>/dev/null || true
}

# ---- Build bundle ---------------------------------------------------------
build_bundle() {
    cecho "$CYN" "→ Generando ejecutable autocontenido..."
    cd "$INSTALL_DIR"

    if [[ ! -f "build.sh" ]]; then
        cecho "$RED" "✖ build.sh no encontrado en ${INSTALL_DIR}"
        return 1
    fi

    bash build.sh "${BIN_DIR}/${BIN_NAME}" 2>&1 | while IFS= read -r line; do
        cecho "$BLU" "  ${line}"
    done

    local rc=${PIPESTATUS[0]}
    if [[ $rc -eq 0 && -x "${BIN_DIR}/${BIN_NAME}" ]]; then
        cecho "$GRN" "✓ Ejecutable generado: ${BIN_DIR}/${BIN_NAME}"
        return 0
    else
        # Fallback: build to temp location and copy
        local tmp_out
        tmp_out=$(mktemp)
        bash build.sh "$tmp_out" 2>/dev/null
        if [[ -x "$tmp_out" ]]; then
            sudo cp "$tmp_out" "${BIN_DIR}/${BIN_NAME}"
            sudo chmod +x "${BIN_DIR}/${BIN_NAME}"
            rm -f "$tmp_out"
            cecho "$GRN" "✓ Ejecutable instalado: ${BIN_DIR}/${BIN_NAME}"
            return 0
        fi
        cecho "$RED" "✖ Falló generación del ejecutable"
        cecho "$YLW" "  Puede ejecutar directamente: bash ${INSTALL_DIR}/build.sh"
        return 1
    fi
}

# ---- Main -----------------------------------------------------------------
main() {
    case "${1:-}" in
        --help|-h)
            show_help
            ;;
        --version|-v)
            show_version
            ;;
    esac

    show_banner

    # Local mode: run directly if we're already in the repo
    if $LOCAL_MODE; then
        cecho "$GRN" "✓ Repositorio detectado localmente"
        cecho "$CYN" "→ Instalando desde ${SCRIPT_DIR}..."

        # Build and install the bundle
        cd "$SCRIPT_DIR"
        sudo mkdir -p "$BIN_DIR"
        bash build.sh "/tmp/paginas-audit-$$" 2>/dev/null
        if [[ -x "/tmp/paginas-audit-$$" ]]; then
            sudo cp "/tmp/paginas-audit-$$" "${BIN_DIR}/${BIN_NAME}"
            sudo chmod +x "${BIN_DIR}/${BIN_NAME}"
            rm -f "/tmp/paginas-audit-$$"
            cecho "$GRN" "✓ Ejecutable instalado: ${BIN_DIR}/${BIN_NAME}"
        else
            cecho "$YLW" "  Ejecute manualmente: bash build.sh && sudo cp paginas-audit ${BIN_DIR}/"
        fi

        echo ""
        cecho "$GRN$BLD" "  ┌──────────────────────────────────────────────────────┐"
        cecho "$GRN$BLD" "  │  ✅  Instalación completada                          │"
        cecho "$GRN$BLD" "  │                                                      │"
        cecho "$GRN$BLD" "  │  ▶️  Uso:                                            │"
        cecho "$GRN$BLD" "  │     ${BIN_NAME} --audit https://ejemplo.com              │"
        cecho "$GRN$BLD" "  │     ${BIN_NAME} --install-all                           │"
        cecho "$GRN$BLD" "  │                                                      │"
        cecho "$GRN$BLD" "  │  📖  Ayuda: ${BIN_NAME} --help                        │"
        cecho "$GRN$BLD" "  └──────────────────────────────────────────────────────┘"
        echo ""
        exit 0
    fi

    # Standard install
    cecho "$CYN" "→ Preparando instalación..."
    echo ""

    pre_flight

    # Update package lists (non-fatal)
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq 2>/dev/null || true
    fi

    clone_or_update

    # Build bundle
    sudo mkdir -p "$BIN_DIR"
    build_bundle

    echo ""
    cecho "$GRN$BLD" "  ┌──────────────────────────────────────────────────────────────┐"
    cecho "$GRN$BLD" "  │  ✅  Instalación lista                                       │"
    cecho "$GRN$BLD" "  │                                                              │"
    cecho "$GRN$BLD" "  │  📁  Código:      ${INSTALL_DIR}          │"
    cecho "$GRN$BLD" "  │  📁  Ejecutable:  ${BIN_DIR}/${BIN_NAME}                    │"
    cecho "$GRN$BLD" "  │                                                              │"
    cecho "$GRN$BLD" "  │  ▶️  Próximos pasos:                                          │"
    cecho "$GRN$BLD" "  │     ${BIN_NAME} --install-all                              │"
    cecho "$GRN$BLD" "  │     ${BIN_NAME} --audit https://ejemplo.com                 │"
    cecho "$GRN$BLD" "  │                                                              │"
    cecho "$GRN$BLD" "  │  📖  Ayuda: ${BIN_NAME} --help                             │"
    cecho "$GRN$BLD" "  └──────────────────────────────────────────────────────────────┘"
    echo ""

    # Open interactive menu
    if command -v "${BIN_DIR}/${BIN_NAME}" &>/dev/null; then
        cecho "$CYN" "→ Abriendo menú interactivo..."
        echo ""
        "${BIN_DIR}/${BIN_NAME}"
    fi
}

main "$@"
