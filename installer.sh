#!/usr/bin/env bash
# ============================================================================
# installer.sh — PaginasAudit Cyber Audit Installer
# ============================================================================
# One-command:
#   curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash
#
# With all tools:
#   curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash -s -- --install-all
# ============================================================================

set -euo pipefail

# ---- Config ---------------------------------------------------------------
REPO_OWNER="${REPO_OWNER:-DavidsmSilva}"
REPO_NAME="${REPO_NAME:-Auditorias-Paginas}"
REPO_BRANCH="${REPO_BRANCH:-main}"
REPO_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/tools/${REPO_NAME}}"
RAW_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH}"

# ---- Detect local execution -----------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)" || SCRIPT_DIR=""
LOCAL_MODE=false
if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/paginas-auditorias/audit.sh" ]]; then
    LOCAL_MODE=true
fi

# ---- Colors ---------------------------------------------------------------
RST='\033[0m'; RED='\033[31m'; GRN='\033[32m'; YLW='\033[33m'; BLU='\033[34m'; MAG='\033[35m'; CYN='\033[36m'; BLD='\033[1m'
cecho() { echo -e "${1}${2}${RST}"; }

# ---- Version --------------------------------------------------------------
show_version() {
    local ver
    if $LOCAL_MODE && [[ -f "$SCRIPT_DIR/paginas-auditorias/.version" ]]; then
        ver="$(cat "$SCRIPT_DIR/paginas-auditorias/.version")"
    elif [[ -f "paginas-auditorias/.version" ]]; then
        ver="$(cat "paginas-auditorias/.version")"
    else
        ver="1.0.0"
    fi
    echo "PaginasAudit v${ver}"
    exit 0
}

# ---- Help -----------------------------------------------------------------
show_help() {
    echo "  PAGINASAUDIT — Cyber Audit Toolkit"
    echo "  ${REPO_URL}"
    echo ""
    echo "  USO (one-command):"
    echo "    curl -sL ${RAW_URL}/installer.sh | bash"
    echo "    curl -sL ${RAW_URL}/installer.sh | bash -s -- --install-all"
    echo "    curl -sL ${RAW_URL}/installer.sh | bash -s -- --install-phase 1"
    echo ""
    echo "  OPCIONES DEL INSTALADOR:"
    echo "    --help, -h        Esta ayuda"
    echo "    --version, -v     Mostrar versión"
    echo ""
    echo "  VARIABLES DE ENTORNO:"
    echo "    INSTALL_DIR=/opt/tools     Directorio de instalación (defecto: ~/tools/Auditorias-Paginas)"
    echo "    REPO_BRANCH=develop        Rama específica"
    echo ""
    echo "  FASES DE HERRAMIENTAS:"
    echo "    1  Assessment       — 23 tools (Nmap, ZAP, SQLmap, Nuclei...)"
    echo "    2  Malware Analysis — 13 tools (Lynis, ClamAV, YARA, Radare2...)"
    echo "    3  Brand Protection — 11 tools (dnstwist, theHarvester, SpiderFoot...)"
    echo "    4  Incident Response— 19 tools (Wireshark, Volatility, Tripwire...)"
    echo ""
    echo "  REPORTES: TXT + JSON + HTML interactivo + DOCX profesional"
    echo ""
    echo "  EJEMPLO RÁPIDO:"
    echo "    curl -sL ${RAW_URL}/installer.sh | bash -s -- --install-all"
    echo "    cd ~/tools/Auditorias-Paginas"
    echo "    bash paginas-auditorias/audit.sh --audit https://ejemplo.com"
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
        cecho "$RED" "✖ curl no está instalado. Instalando..."
        if command -v apt-get &>/dev/null; then
            sudo apt-get update -qq && sudo apt-get install -y -qq curl
        elif command -v pacman &>/dev/null; then
            sudo pacman -S --noconfirm curl
        else
            cecho "$RED" "✖ No se pudo instalar curl. Instálelo manualmente."
            exit 1
        fi
    fi
    cecho "$GRN" "✓ curl detectado"

    # git
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
        cecho "$CYN" "→ Actualizando repositorio en ${INSTALL_DIR}..."
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
    chmod +x paginas-auditorias/audit.sh 2>/dev/null || true
    find "${INSTALL_DIR}/paginas-auditorias/lib" -name '*.sh' -exec chmod +x {} \; 2>/dev/null || true
    find "${INSTALL_DIR}/paginas-auditorias/modules" -name '*.sh' -exec chmod +x {} \; 2>/dev/null || true
}

# ---- Main -----------------------------------------------------------------
main() {
    # Handle flags before anything else
    case "${1:-}" in
        --help|-h)
            show_help
            ;;
        --version|-v)
            show_version
            ;;
    esac

    show_banner

    # Local mode: already inside the cloned repo, run audit.sh directly
    if $LOCAL_MODE; then
        cecho "$GRN" "✓ Repositorio detectado localmente"
        echo ""
        cecho "$CYN" "→ Ejecutando auditor..."
        echo ""
        exec bash "$SCRIPT_DIR/paginas-auditorias/audit.sh" "$@"
    fi

    cecho "$CYN" "→ Preparando instalación..."
    echo ""

    pre_flight
    clone_or_update

    echo ""
    cecho "$GRN$BLD" "  ┌──────────────────────────────────────────────────────────────┐"
    cecho "$GRN$BLD" "  │  ✅  Instalación lista                                       │"
    cecho "$GRN$BLD" "  │                                                              │"
    cecho "$GRN$BLD" "  │  📁  ${INSTALL_DIR}                │"
    cecho "$GRN$BLD" "  │                                                              │"
    cecho "$GRN$BLD" "  │  ▶️  Próximos pasos:                                          │"
    cecho "$GRN$BLD" "  │     cd ~/tools/Auditorias-Paginas                             │"
    cecho "$GRN$BLD" "  │     bash paginas-auditorias/audit.sh --audit https://ejemplo  │"
    cecho "$GRN$BLD" "  │                                                              │"
    cecho "$GRN$BLD" "  │  📖  Ayuda: ./audit.sh --help                                │"
    cecho "$GRN$BLD" "  └──────────────────────────────────────────────────────────────┘"
    echo ""

    cd "$INSTALL_DIR"
    exec bash paginas-auditorias/audit.sh "$@"
}

main "$@"
