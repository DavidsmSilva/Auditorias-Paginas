#!/usr/bin/env bash
# ============================================================================
# ui.sh — Terminal UI Library (dialog / whiptail / fallback)
# Part of PaginasAudit Cyber Audit Installer
# ----------------------------------------------------------------------------
# Provides:
#   - Auto-detection of best TUI backend (dialog > whiptail > read fallback)
#   - Menu rendering
#   - Progress bars with ETA estimation
#   - Spinner for long operations
#   - Checkbox lists for multi-select
#   - Yes/No prompts
#   - Gauge / progress meter
#   - Message/info boxes
#   - Password input (masked)
# ============================================================================

[[ -n "${__UI_LOADED:-}" ]] && return 0
readonly __UI_LOADED=true

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/colors.sh"

# ---- Backend Detection ----------------------------------------------------
__UI_BACKEND=""
__ui_detect_backend() {
    if command -v dialog &>/dev/null; then
        __UI_BACKEND="dialog"
    elif command -v whiptail &>/dev/null; then
        __UI_BACKEND="whiptail"
    else
        __UI_BACKEND="read"
    fi
    export __UI_BACKEND
}
__ui_detect_backend

# Common dialog options
__UI_OPTS=(
    --backtitle "PaginasAudit Cyber Audit Installer"
    --title "Auditoría Cibernética"
    --cancel-label "Cancelar"
    --exit-label "Continuar"
    --help-button
    --help-label "Ayuda"
)

__dialog_avail() { [[ "$__UI_BACKEND" == "dialog" ]]; }
__whiptail_avail() { [[ "$__UI_BACKEND" == "whiptail" ]]; }
__read_avail() { [[ "$__UI_BACKEND" == "read" ]]; }

# ---- Terminal Dimensions --------------------------------------------------
__ui_width()  { tput cols 2>/dev/null || echo 80; }
__ui_height() { tput lines 2>/dev/null || echo 24; }

# ---- Menu -----------------------------------------------------------------
# ui_menu <title> <prompt> <menu_height> <item1> <description1> [item2 desc2...]
ui_menu() {
    local title="$1"; shift
    local prompt="$1"; shift
    local menu_h="$1"; shift
    local items=("$@")

    if __dialog_avail; then
        local h
        h=$(( $(__ui_height) - 6 ))
        local w=$(( $(__ui_width) - 6 ))
        [[ $h -lt 10 ]] && h=10
        [[ $w -lt 60 ]] && w=60
        local list_h=$(( h - 6 ))
        [[ $list_h -lt 1 ]] && list_h=1

        dialog "${__UI_OPTS[@]}" \
            --menu "$prompt" \
            "$h" "$w" "$list_h" \
            "${items[@]}" \
            2>&1 >/dev/tty
        return $?
    elif __whiptail_avail; then
        local h=$(( $(__ui_height) - 8 ))
        local w=$(( $(__ui_width) - 8 ))
        [[ $h -lt 10 ]] && h=10
        [[ $w -lt 60 ]] && w=60
        whiptail --title "$title" --menu "$prompt" "$h" "$w" "$menu_h" "${items[@]}" 3>&1 1>&2 2>&3
        return $?
    else
        echo ""
        __echo "${COLOR_HEADER}" "  ╔══════════════════════════════════════╗"
        __echo "${COLOR_HEADER}" "  ║  ${title}  ║"
        __echo "${COLOR_HEADER}" "  ╚══════════════════════════════════════╝"
        echo "  ${prompt}"
        echo ""
        local i=1 n=${#items[@]}
        while [[ $i -lt $n ]]; do
            printf "  ${FG_BGRN}%2d)${RST} ${FG_BWHT}%-25s${RST} ${FG_BBLK}%s${RST}\n" "$(( (i+1)/2 ))" "${items[$((i-1))]}" "${items[$i]}"
            i=$(( i + 2 ))
        done
        echo ""
        read -r -p "  ${FG_BYLW}Seleccione opción${RST} [1-$((n/2))]: " choice
        [[ -z "$choice" ]] && return 1
        local idx=$(( choice * 2 - 1 ))
        if [[ $idx -ge 1 && $idx -le $n ]]; then
            echo "${items[$((idx-1))]}"
            return 0
        fi
        return 1
    fi
}

# ---- Multi-Select Checkbox ------------------------------------------------
# ui_checklist <title> <prompt> <list_height> <tag1> <desc1> <status1> [...]
ui_checklist() {
    local title="$1"; shift
    local prompt="$1"; shift
    local list_h="$1"; shift
    local items=("$@")

    if __dialog_avail; then
        local h=$(( $(__ui_height) - 6 ))
        local w=$(( $(__ui_width) - 6 ))
        [[ $h -lt 12 ]] && h=12
        [[ $w -lt 70 ]] && w=70

        dialog "${__UI_OPTS[@]}" \
            --checklist "$prompt" \
            "$h" "$w" "$list_h" \
            "${items[@]}" \
            2>&1 >/dev/tty
        return $?
    elif __whiptail_avail; then
        local h=$(( $(__ui_height) - 8 ))
        local w=$(( $(__ui_width) - 8 ))
        [[ $h -lt 12 ]] && h=12
        whiptail --title "$title" --checklist "$prompt" "$h" "$w" "$list_h" "${items[@]}" 3>&1 1>&2 2>&3
        return $?
    else
        # Fallback: simple numbered list with y/n
        echo ""
        __echo "${COLOR_HEADER}" "  ── ${title} ──"
        echo "  ${prompt}"
        echo "  ${FG_BBLK}(separar opciones con espacio, ej: 1 3 5)${RST}"
        echo ""
        local i=1 n=${#items[@]}
        while [[ $i -lt $n ]]; do
            local tag="${items[$((i-1))]}"
            local desc="${items[$i]}"
            local stat="${items[$((i+1))]}"
            local mark="[ ]"
            [[ "$stat" == "on" ]] && mark="[x]"
            printf "  ${FG_BGRN}%2d)${RST} ${mark} ${FG_BWHT}%-12s${RST} %s\n" "$(( (i+2)/3 ))" "$tag" "$desc"
            i=$(( i + 3 ))
        done
        echo ""
        read -r -p "  ${FG_BYLW}Seleccione números${RST}: " choices
        local result=""
        for c in $choices; do
            local idx=$(( (c - 1) * 3 ))
            [[ $idx -ge 0 && $idx -lt $n ]] && result="${result} ${items[$idx]}"
        done
        echo "${result## }"
        return 0
    fi
}

# ---- Progress Bar (gauge) -------------------------------------------------
# ui_gauge <title> <percent>
ui_gauge() {
    local title="$1"
    local percent="$2"

    if __dialog_avail; then
        echo "$percent" | dialog "${__UI_OPTS[@]}" \
            --gauge "$title" \
            8 60 0
        return $?
    fi
}

# ---- Spinner for long operations ------------------------------------------
# ui_spinner <pid> <message>
ui_spinner() {
    local pid=$1
    local msg="${2:-Trabajando...}"
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0

    printf "  ${FG_CYN}${msg}${RST} "
    while kill -0 "$pid" 2>/dev/null; do
        printf "\b${FG_BGRN}%s${RST}" "${spinstr:$i:1}"
        i=$(( (i + 1) % ${#spinstr} ))
        sleep 0.1
    done
    printf "\b${FG_GRN}✓${RST}\n"
    wait "$pid" 2>/dev/null
    return $?
}

# ---- Yes/No Prompt --------------------------------------------------------
# ui_confirm <title> <prompt> [default: y|n]
ui_confirm() {
    local title="$1"
    local prompt="$2"
    local default="${3:-n}"

    if __dialog_avail; then
        dialog "${__UI_OPTS[@]}" \
            --defaultno \
            --yesno "$prompt" \
            8 60
        return $?
    elif __whiptail_avail; then
        whiptail --title "$title" --yesno "$prompt" 8 60
        return $?
    else
        confirm "$prompt" "$default"
        return $?
    fi
}

# ---- Info Box -------------------------------------------------------------
# ui_msg <title> <message>
ui_msg() {
    local title="$1"
    local msg="$2"

    if __dialog_avail; then
        dialog "${__UI_OPTS[@]}" \
            --msgbox "$msg" \
            12 60
        return $?
    elif __whiptail_avail; then
        whiptail --title "$title" --msgbox "$msg" 12 60
        return $?
    else
        echo ""
        __echo "${COLOR_HEADER}" "  ── ${title} ──"
        echo "${msg}"
        echo ""
        read -r -p "  Presione Enter para continuar... "
        return 0
    fi
}

# ---- Input Box ------------------------------------------------------------
# ui_input <title> <prompt> [default]
ui_input() {
    local title="$1"
    local prompt="$2"
    local default="${3:-}"

    if __dialog_avail; then
        dialog "${__UI_OPTS[@]}" \
            --inputbox "$prompt" \
            8 60 "$default" \
            2>&1 >/dev/tty
        return $?
    elif __whiptail_avail; then
        whiptail --title "$title" --inputbox "$prompt" 8 60 "$default" 3>&1 1>&2 2>&3
        return $?
    else
        echo ""
        __echo "${COLOR_HEADER}" "  ── ${title} ──"
        printf "  ${FG_BYLW}%s${RST} " "$prompt"
        read -r input
        echo "${input:-$default}"
        return 0
    fi
}

# ---- Password Box (masked) ------------------------------------------------
# ui_password <title> <prompt>
ui_password() {
    local title="$1"
    local prompt="$2"

    if __dialog_avail; then
        dialog "${__UI_OPTS[@]}" \
            --insecure \
            --passwordbox "$prompt" \
            8 60 \
            2>&1 >/dev/tty
        return $?
    elif __whiptail_avail; then
        whiptail --title "$title" --passwordbox "$prompt" 8 60 3>&1 1>&2 2>&3
        return $?
    else
        echo ""
        __echo "${COLOR_HEADER}" "  ── ${title} ──"
        printf "  ${FG_BYLW}%s${RST} " "$prompt"
        read -r -s input
        echo ""
        echo "$input"
        return 0
    fi
}

# ---- Progress: Multi-step with tracking -----------------------------------
# ui_progress <steps...>
# Example: ui_progress "Instalando nmap" "Instalando nikto" "Instalando zaproxy"
ui_progress() {
    local steps=("$@")
    local total=${#steps[@]}
    local current=0

    for step in "${steps[@]}"; do
        current=$(( current + 1 ))
        local pct=$(( current * 100 / total ))
        if __dialog_avail; then
            echo "$pct" | dialog "${__UI_OPTS[@]}" \
                --gauge "Paso ${current}/${total}: ${step}" \
                8 60 0
        else
            printf "\r  ${FG_CYN}[%3d%%]${RST} ${FG_BWHT}%s${RST}" "$pct" "$step"
        fi
        sleep 0.5
    done
    if ! __dialog_avail; then
        echo ""
    fi
}

# ---- Text Box (scrollable help/documentation) -----------------------------
# ui_text <title> <file_path>
ui_text() {
    local title="$1"
    local file="$2"

    if __dialog_avail; then
        local h=$(( $(__ui_height) - 4 ))
        local w=$(( $(__ui_width) - 6 ))
        [[ $h -lt 10 ]] && h=10
        dialog "${__UI_OPTS[@]}" \
            --textbox "$file" \
            "$h" "$w"
        return $?
    elif __whiptail_avail; then
        whiptail --title "$title" --textbox "$file" 20 70
        return $?
    else
        cat "$file"
        echo ""
        read -r -p "  Presione Enter para continuar... "
        return 0
    fi
}

# ---- Tool Description Formatter -------------------------------------------
# Shows a table of tools in a message box
ui_tool_table() {
    local title="$1"
    local phase_name="$2"
    shift 2
    local tools=("$@")

    local msg="\n  ${BLD}Fase:${RST} ${phase_name}\n"
    msg+="  ${BLD}Herramientas incluidas:${RST}\n\n"

    local i=0
    while [[ $i -lt ${#tools[@]} ]]; do
        local name="${tools[$i]}"
        local desc="${tools[$((i+1))]}"
        local status="${tools[$((i+2))]}"
        local status_char
        if [[ "$status" == "installed" ]]; then
            status_char="${FG_GRN}✓${RST}"
        elif [[ "$status" == "missing" ]]; then
            status_char="${FG_RED}✗${RST}"
        else
            status_char="${FG_YLW}?${RST}"
        fi
        msg+="  ${status_char} ${FG_BWHT}${name}${RST}\n"
        msg+="     ${FG_BBLK}${desc}${RST}\n"
        i=$((i+3))
    done

    if __dialog_avail; then
        dialog "${__UI_OPTS[@]}" \
            --msgbox "$msg" \
            20 70
    else
        echo -e "$msg"
        read -r -p "  Presione Enter para continuar... "
    fi
}
