#!/usr/bin/env bash
# ============================================================================
# colors.sh — ANSI Color & Formatting Library
# Part of PaginasAudit Cyber Audit Installer
# ----------------------------------------------------------------------------
# Provides:
#   - Named ANSI color codes (foreground + background)
#   - Text formatting: bold, dim, italic, underline, blink, reverse
#   - Box-drawing utilities: box_start, box_line, box_end
#   - Status output: status_ok, status_warn, status_err, status_running
#   - Progress bar: progress_bar
#   - Summary dashboard: summary_row, summary_end
#   - Legacy functions: info, success, warn, error, header, banner
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
    readonly BG_BRED='' BG_BGRN='' BG_BYLW='' BG_BBLU='' BG_BMAG='' BG_BCYN='' BG_BWHT=''
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
readonly COLOR_BOX="${FG_BBLK}"
readonly COLOR_BOX_TITLE="${FG_BWHT}${BLD}"
readonly COLOR_STATUS_OK="${FG_GRN}${BLD}"
readonly COLOR_STATUS_WARN="${FG_YLW}${BLD}"
readonly COLOR_STATUS_ERR="${FG_RED}${BLD}"
readonly COLOR_STATUS_RUN="${FG_BCYN}${BLD}"
readonly COLOR_STATUS_INFO="${FG_CYN}"

# ---- Terminal Helpers ------------------------------------------------------

# __term_width — get terminal width, default 72
__term_width() {
    tput cols 2>/dev/null || echo 72
}

# __term_height — get terminal height, default 24
__term_height() {
    tput lines 2>/dev/null || echo 24
}

# ---- Low-Level Output ------------------------------------------------------

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

# ---- Box-Drawing API -------------------------------------------------------
# All boxes auto-fit to terminal width (capped at 72 chars for readability).

# __box_width — usable inner width for box content
__box_width() {
    local tw=$(__term_width)
    # Use full width up to 72, then cap
    if [[ $tw -gt 78 ]]; then
        echo 76
    else
        echo $(( tw - 2 ))
    fi
}

# __hr [char] [width] — horizontal rule
__hr() {
    local char="${1:-─}"
    local width="${2:-$(__box_width)}"
    local bar
    printf -v bar '%*s' "$width" ''
    bar="${bar// /$char}"
    echo "$bar"
}

# box_start <title> [color] — open a box with title
#   ┌─ title ─────────────────────────────┐
box_start() {
    local title="$1"
    local color="${2:-$COLOR_BOX}"
    local w=$(__box_width)
    local title_len=${#title}
    local line_len=$(( w - title_len - 4 ))  # ┌─ <title> ──┐
    local left_dashes line_right
    if [[ $line_len -lt 2 ]]; then
        left_dashes=0
    else
        left_dashes=$(( line_len / 2 ))
    fi
    local right_dashes=$(( line_len - left_dashes ))

    printf -v line_left '%*s' "$left_dashes" ''
    line_left="${line_left// /─}"
    printf -v line_right '%*s' "$right_dashes" ''
    line_right="${line_right// /─}"

    echo ""
    __echo "${color}" "  ┌─${line_left} ${title} ${line_right}┐"
}

# box_line <content> [color] — a content line inside a box
#   │ <content>                        │
box_line() {
    local content="$1"
    local color="${2:-$FG_WHT}"
    local w=$(__box_width)
    local content_len
    # Strip ANSI codes for length calculation
    local plain
    plain=$(printf '%s' "$content" | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g')
    content_len=${#plain}
    local pad=$(( w - content_len - 2 ))
    [[ $pad -lt 0 ]] && pad=0
    local padding
    printf -v padding '%*s' "$pad" ''
    __echo "${color}" "  │ ${content}${padding}│"
}

# box_end [color] — close a box
#   └────────────────────────────────────┘
box_end() {
    local color="${1:-$COLOR_BOX}"
    local w=$(__box_width)
    local bar
    printf -v bar '%*s' "$w" ''
    bar="${bar// /─}"
    __echo "${color}" "  └─${bar}─┘"
    echo ""
}

# ---- Status Output ---------------------------------------------------------

# status_ok <text> — ✓ Done / Success
status_ok() {
    box_line " ${COLOR_STATUS_OK}✓${RST}  ${FG_WHT}$*${RST}" "${COLOR_BOX}"
}

# status_warn <text> — ⚠ Warning
status_warn() {
    box_line " ${COLOR_STATUS_WARN}⚠${RST}  ${FG_YLW}$*${RST}" "${COLOR_BOX}"
}

# status_err <text> — ✗ Error / Failed
status_err() {
    box_line " ${COLOR_STATUS_ERR}✗${RST}  ${FG_RED}$*${RST}" "${COLOR_BOX}"
}

# status_running <text> — ◌ Running / In Progress
status_running() {
    box_line " ${COLOR_STATUS_RUN}◌${RST}  ${FG_BCYN}$*${RST}" "${COLOR_BOX}"
}

# status_info <text> — ℹ Informational line (no icon)
status_info() {
    box_line "   ${COLOR_HINT}$*${RST}" "${COLOR_BOX}"
}

# status_detail <key> <value> — key: value pair inside box
status_detail() {
    local key="$1"
    local val="$2"
    box_line " ${FG_BBLU}${BLD}$key${RST} ${FG_BWHT}$val${RST}" "${COLOR_BOX}"
}

# ---- Progress Bar ----------------------------------------------------------

# progress_bar <current> <total> [label]
# Draws a progress bar inside a box line:
#   │  ████████░░  22/26  85%  Installing phase 2  │
progress_bar() {
    local current="$1"
    local total="$2"
    local label="${3:-}"

    local w=$(__box_width)
    local bar_width=20

    # Calculate fraction
    local pct=0
    if [[ $total -gt 0 ]]; then
        pct=$(( current * 100 / total ))
    fi
    [[ $pct -gt 100 ]] && pct=100

    local filled=$(( pct * bar_width / 100 ))
    [[ $filled -gt $bar_width ]] && filled=$bar_width
    local empty=$(( bar_width - filled ))

    # Build the bar string: filled + empty
    local bar_str=""
    local i
    for ((i=0; i<filled; i++)); do bar_str+="█"; done
    for ((i=0; i<empty; i++)); do bar_str+="░"; done

    local pct_str="${pct}%"
    local counter_str="${current}/${total}"
    local line=" ${FG_GRN}${bar_str}${RST}  ${FG_BWHT}${counter_str}${RST}  ${FG_BBLK}${pct_str}${RST}"

    if [[ -n "$label" ]]; then
        line+="  ${COLOR_HINT}${label}${RST}"
    fi

    box_line "$line" "${COLOR_BOX}"
}

# ---- Summary Dashboard -----------------------------------------------------

# summary_begin [title] — open the summary box
summary_begin() {
    local title="${1:-📊  Summary}"
    box_start "$title" "${FG_BBLU}"
}

# summary_row <icon_color> <icon> <label> <value>
summary_row() {
    local icon_color="$1"
    local icon="$2"
    local label="$3"
    local value="$4"
    box_line " ${icon_color}${icon}${RST}  ${FG_WHT}${label}:${RST} ${FG_BWHT}${BLD}${value}${RST}" "${COLOR_BOX}"
}

# summary_end — close the summary box and show execution time
summary_end() {
    local time_str="${1:-}"
    if [[ -n "$time_str" ]]; then
        box_line " ${COLOR_HINT}⏱️  Time: ${time_str}${RST}" "${COLOR_BOX}"
    fi
    box_end "${FG_BBLU}"
}

# ---- Legacy Styled Output Functions (backward compatible) ------------------

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

# header → bright magenta + bold + old box style (kept for compatibility)
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

# kv — key: value pair for summary tables
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
    __echo "${FG_RED}${BLD}"  "  ██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗ "
    __echo "${FG_RED}${BLD}"  "  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝ "
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
