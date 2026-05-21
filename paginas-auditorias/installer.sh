#!/usr/bin/env bash
# ============================================================================
# installer.sh — PaginasAudit Cyber Audit Installer Bootstrap
# ============================================================================
# One-command installer: curl -sL URL | bash
#
# This script clones (or updates) the PaginasAudit Cyber Audit repository
# from GitHub and launches the main installer.
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash
#
#   Or with options:
#   curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash -s -- --install-all
#   curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash -s -- --install-phase 1
# ============================================================================

set -euo pipefail

# ---- Config ---------------------------------------------------------------
REPO_OWNER="${REPO_OWNER:-DavidsmSilva}"
REPO_NAME="${REPO_NAME:-Auditorias-Paginas}"
REPO_BRANCH="${REPO_BRANCH:-main}"
REPO_URL="${REPO_URL:-https://github.com/${REPO_OWNER}/${REPO_NAME}.git}"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/tools/paginas-auditorias}"

# ---- Colors (minimal, no external deps) -----------------------------------
RST='\033[0m'; RED='\033[31m'; GRN='\033[32m'; YLW='\033[33m'; BLU='\033[34m'; MAG='\033[35m'; CYN='\033[36m'; BLD='\033[1m'
cecho() { echo -e "${1}${2}${RST}"; }

# ---- Pre-flight -----------------------------------------------------------

pre_flight() {
    # Check for git
    if ! command -v git &>/dev/null; then
        cecho "$RED" "✖ git no está instalado. Instalando..."
        if command -v apt-get &>/dev/null; then
            sudo apt-get update -qq && sudo apt-get install -y -qq git
        elif command -v pacman &>/dev/null; then
            sudo pacman -S --noconfirm git
        else
            cecho "$RED" "✖ No se pudo instalar git. Instálelo manualmente."
            exit 1
        fi
    fi
    cecho "$GRN" "✓ git detectado: $(git --version)"
}

# ---- Clone / Update -------------------------------------------------------

clone_or_update() {
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        cecho "$CYN" "→ Repositorio existente en ${INSTALL_DIR}. Actualizando..."
        cd "$INSTALL_DIR"
        git fetch origin "$REPO_BRANCH" 2>&1 | while IFS= read -r line; do
            cecho "$BLU" "  ${line}"
        done

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
        cecho "$CYN" "→ Clonando repositorio..."
        mkdir -p "$(dirname "$INSTALL_DIR")"
        git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$INSTALL_DIR" 2>&1 | while IFS= read -r line; do
            cecho "$BLU" "  ${line}"
        done
        cecho "$GRN" "✓ Repositorio clonado en ${INSTALL_DIR}"
    fi

    cd "$INSTALL_DIR"
    chmod +x audit.sh 2>/dev/null || true
    find "${INSTALL_DIR}/lib" -name '*.sh' -exec chmod +x {} \; 2>/dev/null || true
    find "${INSTALL_DIR}/modules" -name '*.sh' -exec chmod +x {} \; 2>/dev/null || true
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
    cecho "$MAG"      "  PaginasAudit Cyber Audit Installer"
    cecho "$BLU"      "  ${REPO_URL}"
    echo ""
}

# ---- Help (pre-install) ---------------------------------------------------

show_help() {
    echo "  USO:"
    echo "    curl -sL URL | bash                             # Menú interactivo"
    echo "    curl -sL URL | bash -s -- --install-all         # Instalar todo"
    echo "    curl -sL URL | bash -s -- --install-phase 1     # Fase específica"
    echo "    curl -sL URL | bash -s -- --install-tool nmap   # Tool específica"
    echo ""
    echo "  VARIABLES DE ENTORNO:"
    echo "    INSTALL_DIR=/opt/tools     Directorio de instalación"
    echo "    REPO_BRANCH=develop        Rama específica"
    echo ""
    echo "  FASES:"
    echo "    1. Assessment       — 23 herramientas (Nmap, ZAP, SQLmap...)"
    echo "    2. Malware Analysis — 13 herramientas (Lynis, ClamAV, YARA...)"
    echo "    3. Brand Protection — 11 herramientas (dnstwist, theHarvester...)"
    echo "    4. Incident Response— 19 herramientas (Wireshark, Volatility, Tripwire...)"
    echo ""
    echo "  REPORTES: TXT + JSON + HTML interactivo + DOCX profesional"
}

# ---- Main -----------------------------------------------------------------

main() {
    show_banner

    # Handle help
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        show_help
        exit 0
    fi

    cecho "$CYN" "  → Preparando instalación..."
    echo ""

    pre_flight
    clone_or_update

    echo ""
    cecho "$GRN$BLD" "  ┌──────────────────────────────────────────────────────────────┐"
    cecho "$GRN$BLD" "  │  ✅  Repositorio listo en:                                    │"
    cecho "$GRN$BLD" "  │      ${INSTALL_DIR}                    │"
    cecho "$GRN$BLD" "  │                                                              │"
    cecho "$GRN$BLD" "  │  Ejecutando auditor...                                       │"
    cecho "$GRN$BLD" "  └──────────────────────────────────────────────────────────────┘"
    echo ""

    # Launch audit.sh passing through any arguments
    cd "$INSTALL_DIR"
    exec bash audit.sh "$@"
}

main "$@"
