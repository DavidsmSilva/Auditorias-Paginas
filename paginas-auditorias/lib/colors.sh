#!/usr/bin/env bash
# ============================================================================
# colors.sh — ANSI Color & Formatting Library
# Part of PaginasAudit Cyber Audit Installer
# ----------------------------------------------------------------------------
# Provides:
#   - Named ANSI color codes (foreground + background)
#   - Text formatting: bold, dim, italic, underline, blink, reverse
#   - High-level styled output functions: info, success, warn, error, header
#   - Box/separator drawing utilities
#   - Automatic detection of terminal color support (NO_COLOR, TERM)
# ============================================================================

# ---- Guard (prevents double-sourcing) ------------------------------------
[[ -n "${__COLORS_LOADED:-}" ]] && return 0
readonly __COLORS_LOADED=true

# ---- Color Capability Detection -------------------------------------------
__color_init() {
    # Respect NO_COLOR standard (https://no-color.org/)
    if [[ -n "${NO_COLOR:-}" ]]; then
        __HAVE_COLORS=false
    elif [[ "$TERM" == dumb ]]; then
        __HAVE_COLORS=false
    elif [[ -n "$TERM" && "$TERM" != "" ]]; then
        __HAVE_COLORS=true
    elif command -v tput &>/dev/null && [[ $(tput colors 2>/dev/null || echo 0) -ge 8 ]]; then
        __HAVE_COLORS=true
    else
        __HAVE_COLORS=false
    fi
}

__color_init

# ---- Control Sequences ----------------------------------------------------
if $__HAVE_COLORS; then
    # Reset / Special
    readonly RST='\033[0m'
    readonly BLD='\033[1m'
    readonly DIM='\033[2m'
    readonly ITL='\033[3m'
    readonly UDL='\033[4m'
    readonly BLK='\033[5m'
    readonly REV='\033[7m'
    readonly HID='\033[8m'

    # Standard 16 Foreground Colors
    readonly FG_BLK='\033[30m'
    readonly FG_RED='\033[31m'
    readonly FG_GRN='\033[32m'
    readonly FG_YLW='\033[33m'
    readonly FG_BLU='\033[34m'
    readonly FG_MAG='\033[35m'
    readonly FG_CYN='\033[36m'
    readonly FG_WHT='\033[37m'

    # Bright Foreground Colors
    readonly FG_BBLK='\033[90m'
    readonly FG_BRED='\033[91m'
    readonly FG_BGRN='\033[92m'
    readonly FG_BYLW='\033[93m'
    readonly FG_BBLU='\033[94m'
    readonly FG_BMAG='\033[95m'
    readonly FG_BCYN='\033[96m'
    readonly FG_BWHT='\033[97m'

    # Standard 16 Background Colors
    readonly BG_BLK='\033[40m'
    readonly BG_RED='\033[41m'
    readonly BG_GRN='\033[42m'
    readonly BG_YLW='\033[43m'
    readonly BG_BLU='\033[44m'
    readonly BG_MAG='\033[45m'
    readonly BG_CYN='\033[46m'
    readonly BG_WHT='\033[47m'

    # Bright Background Colors
    readonly BG_BBLK='\033[100m'
    readonly BG_BRED='\033[101m'
    readonly BG_BGRN='\033[102m'
    readonly BG_BYLW='\033[103m'
    readonly BG_BBLU='\033[104m'
    readonly BG_BMAG='\033[105m'
    readonly BG_BCYN='\033[106m'
    readonly BG_BWHT='\033[107m'

    # 256-color helpers
    fg_256() { printf '\033[38;5;%dm' "$1"; }
    bg_256() { printf '\033[48;5;%dm' "$1"; }
else
    readonly RST='' BLD='' DIM='' ITL='' UDL='' BLK='' REV='' HID=''
    readonly FG_BLK='' FG_RED='' FG_GRN='' FG_YLW='' FG_BLU='' FG_MAG='' FG_CYN='' FG_WHT=''
    readonly FG_BBLK='' FG_BRED='' FG_BGRN='' FG_BYLW='' FG_BBLU='' FG_BMAG='' FG_BCYN='' FG_BWHT=''
    readonly BG_BLK='' BG_RED='' BG_GRN='' BG_YLW='' BG_BLU='' BG_MAG='' BG_CYN='' BG_WHT=''
    readonly BG_BBLK='' BG_BRED='' BG_BGRN='' BG_BYLW='' BG_BBLU='' BG_BMAG='' BG_BCYN='' BG_BWHT=''
    fg_256() { :; }
    bg_256() { :; }
fi

# ---- Palette Aliases (semantic, easier to read) ---------------------------
readonly COLOR_INFO="${FG_CYN}"
readonly COLOR_OK="${FG_GRN}"
readonly COLOR_WARN="${FG_YLW}"
readonly COLOR_ERROR="${FG_RED}"
readonly COLOR_HEADER="${FG_BMAG}${BLD}"
readonly COLOR_HINT="${FG_BBLK}${ITL}"
readonly COLOR_ACCENT1="${FG_BBLU}"
readonly COLOR_ACCENT2="${FG_BCYN}"
readonly COLOR_ACCENT3="${FG_BGRN}"

# ---- Styled Output Functions ----------------------------------------------

# __echo [color] [text] — print with ansi, auto-reset
__echo() {
    local color="${1:-}"
    local text="${2:-}"
    echo -e "${color}${text}${RST}"
}

# __printf [color] [format...] — printf with ansi, auto-reset
__printf() {
    local color="${1:-}"
    shift
    printf "${color}$*${RST}"
}

# info  → cyan
info() {
    __echo "${COLOR_INFO}" "  ℹ️  $*"
}

# success → green
success() {
    __echo "${COLOR_OK}" "  ✔️  $*"
}

# warn → yellow
warn() {
    __echo "${COLOR_WARN}" "  ⚠️  $*"
}

# error → red
error() {
    __echo "${COLOR_ERROR}" "  ✖️  $*"
}

# header → bright magenta + bold + underline effect
header() {
    local text="$*"
    local len=${#text}
    local bar
    printf -v bar '%*s' "$len" ''
    bar="${bar// /═}"
    echo ""
    __echo "${COLOR_HEADER}" "  ╔${bar}╗"
    __echo "${COLOR_HEADER}" "  ║ ${text} ║"
    __echo "${COLOR_HEADER}" "  ╚${bar}╝"
    echo ""
}

# subheader → blue
subheader() {
    __echo "${COLOR_ACCENT1}${BLD}" "  ── $* ──"
}

# hint → dim italic
hint() {
    __echo "${COLOR_HINT}" "  → $*"
}

# bullet
bullet() {
    __echo "${COLOR_ACCENT2}" "  • $*"
}

# label: value — useful for summary tables
kv() {
    local key="$1"
    local val="$2"
    printf "  ${FG_BBLU}${BLD}%-20s${RST} ${FG_BWHT}%s${RST}\n" "${key}:" "$val"
}

# separator line
separator() {
    echo -e "  ${FG_BBLK}────────────────────────────────────────────${RST}"
}

# banner — full width header with version
banner() {
    local version="${1:-unknown}"
    echo ""
    __echo "${FG_BRED}${BLD}"  "  ██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗ "
    __echo "${FG_BRED}${BLD}"  "  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝ "
    __echo "${FG_YLW}${BLD}"  "  ███████║ ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗██║  ███╗"
    __echo "${FG_YLW}${BLD}"  "  ██╔══██║  ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██║   ██║"
    __echo "${FG_GRN}${BLD}"  "  ██║  ██║   ██║   ██║     ███████╗██║  ██║███████║╚██████╔╝"
    __echo "${FG_GRN}${BLD}"  "  ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ "
    echo ""
    __echo "${FG_BMAG}"       "  PaginasAudit Cyber Audit Installer v${version}"
    __echo "${FG_BBLK}"       "  ─────────────────────────────────────────────"
    echo ""
}

# Confirm prompt (yes/no)
confirm() {
    local prompt="${1:-Continue?}"
    local default="${2:-n}"
    local opts
    if [[ "$default" == "y" ]]; then
        opts="[Y/n]"
    else
        opts="[y/N]"
    fi
    echo ""
    read -r -p "  ${FG_BYLW}?${RST} ${prompt} ${opts} " reply
    echo ""
    reply="${reply,,}"
    if [[ "$default" == "y" ]]; then
        [[ -z "$reply" || "$reply" == y* ]]
    else
        [[ "$reply" == y* ]]
    fi
}
