#!/usr/bin/env bash
# ============================================================================
# logging.sh — Centralized Logging System
# Part of PaginasAudit Cyber Audit Installer
# ----------------------------------------------------------------------------
# Features:
#   - Dual-logging: stdout (modern boxed style) + file (plain text + timestamps)
#   - Log levels: DEBUG, INFO, OK, WARN, ERROR, FATAL
#   - Automatic log rotation (keeps last 5)
#   - JSON log mode for machine parsing
#   - Section boxes with box-drawing characters
#   - Progress bar integration
#   - Execution ID per session for tracing
# ============================================================================

[[ -n "${__LOGGING_LOADED:-}" ]] && return 0
readonly __LOGGING_LOADED=true

# ---- Dependencies ---------------------------------------------------------
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/colors.sh"

# ---- Global State ---------------------------------------------------------
declare LOG_FILE=""
declare LOG_LEVEL="INFO"
declare LOG_JSON=false
declare LOG_EXEC_ID=""
declare -A LOG_LEVEL_MAP=(
    [DEBUG]=0
    [INFO]=1
    [OK]=2
    [WARN]=3
    [ERROR]=4
    [FATAL]=5
)
readonly LOG_LEVEL_ORDER=("DEBUG" "INFO" "OK" "WARN" "ERROR" "FATAL")

# Track open boxes for nesting
declare -a LOG_BOX_STACK=()

# ---- Initialization -------------------------------------------------------

# log_init [log_dir] [log_level] [json_mode]
log_init() {
    local log_dir="${1:-./logs}"
    local level="${2:-INFO}"
    local json="${3:-false}"

    LOG_LEVEL="$level"
    LOG_JSON="$json"

    # Generate execution ID (timestamp + random)
    LOG_EXEC_ID="$(date '+%Y%m%d-%H%M%S')-${RANDOM}"

    # Ensure log directory exists
    mkdir -p "$log_dir" 2>/dev/null || true

    LOG_FILE="${log_dir}/audit-${LOG_EXEC_ID}.log"

    # Rotate old logs (keep last 5)
    _log_rotate "$log_dir"

    _log_write "SYSTEM" "Logging initialized | level=${LOG_LEVEL} file=${LOG_FILE} exec_id=${LOG_EXEC_ID}"
}

# ---- Internal Helpers -----------------------------------------------------

_log_level_num() {
    local lvl="${1:-INFO}"
    echo "${LOG_LEVEL_MAP[$lvl]:-1}"
}

_log_timestamp() {
    date '+%Y-%m-%d %H:%M:%S.%3N %z'
}

_log_rotate() {
    local log_dir="$1"
    local pattern="${log_dir}/audit-*.log"
    local files=()
    while IFS= read -r -d '' f; do
        files+=("$f")
    done < <(find "$log_dir" -maxdepth 1 -name 'audit-*.log' -printf '%T@ %p\0' 2>/dev/null | sort -z -t' ' -k1 -n | cut -z -d' ' -f2-)
    while [[ ${#files[@]} -gt 5 ]]; do
        rm -f "${files[0]}"
        files=("${files[@]:1}")
    done
}

_log_write() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp="$(_log_timestamp)"

    # Always write to file
    if [[ -n "$LOG_FILE" ]]; then
        if $LOG_JSON; then
            printf '{"ts":"%s","lvl":"%s","exec":"%s","msg":"%s"}\n' \
                "$timestamp" "$level" "$LOG_EXEC_ID" "$(printf '%s' "$message" | sed 's/"/\\"/g')" \
                >> "$LOG_FILE" 2>/dev/null || true
        else
            printf '[%s] [%-5s] [%s] %s\n' \
                "$timestamp" "$level" "$LOG_EXEC_ID" "$message" \
                >> "$LOG_FILE" 2>/dev/null || true
        fi
    fi
}

# ---- Section Box Management -----------------------------------------------

# log_section_start <title> — open a box section
log_section_start() {
    local title="$1"
    _log_write "INFO" "══════ ${title} ══════"
    if ! $LOG_JSON; then
        box_start "$title"
        LOG_BOX_STACK+=("$title")
    fi
}

# log_section_end — close the current box section
log_section_end() {
    if ! $LOG_JSON; then
        if [[ ${#LOG_BOX_STACK[@]} -gt 0 ]]; then
            box_end
            LOG_BOX_STACK=("${LOG_BOX_STACK[@]:0:${#LOG_BOX_STACK[@]}-1}")
        fi
    fi
}

# ---- Public API -----------------------------------------------------------

log_debug() {
    [[ $(_log_level_num DEBUG) -ge $(_log_level_num "$LOG_LEVEL") ]] || return 0
    _log_write "DEBUG" "$*"
    if ! $LOG_JSON; then
        box_line "  ${FG_BBLK}$*${RST}" "${COLOR_BOX}"
    fi
}

log_info() {
    [[ $(_log_level_num INFO) -ge $(_log_level_num "$LOG_LEVEL") ]] || return 0
    _log_write "INFO" "$*"
    if ! $LOG_JSON; then
        if [[ ${#LOG_BOX_STACK[@]} -gt 0 ]]; then
            status_info "$*"
        else
            __echo "${COLOR_INFO}" "  ℹ️  $*"
        fi
    fi
}

log_ok() {
    [[ $(_log_level_num OK) -ge $(_log_level_num "$LOG_LEVEL") ]] || return 0
    _log_write "OK" "$*"
    if ! $LOG_JSON; then
        if [[ ${#LOG_BOX_STACK[@]} -gt 0 ]]; then
            status_ok "$*"
        else
            __echo "${COLOR_OK}" "  ✔️  $*"
        fi
    fi
}

log_warn() {
    [[ $(_log_level_num WARN) -ge $(_log_level_num "$LOG_LEVEL") ]] || return 0
    _log_write "WARN" "$*"
    if ! $LOG_JSON; then
        if [[ ${#LOG_BOX_STACK[@]} -gt 0 ]]; then
            status_warn "$*"
        else
            __echo "${COLOR_WARN}" "  ⚠️  $*"
        fi
    fi
}

log_error() {
    [[ $(_log_level_num ERROR) -ge $(_log_level_num "$LOG_LEVEL") ]] || return 0
    _log_write "ERROR" "$*"
    if ! $LOG_JSON; then
        if [[ ${#LOG_BOX_STACK[@]} -gt 0 ]]; then
            status_err "$*"
        else
            __echo "${COLOR_ERROR}" "  ✖️  $*"
        fi
    fi
}

log_fatal() {
    _log_write "FATAL" "$*"
    if ! $LOG_JSON; then
        status_err "FATAL: $*"
    fi
    exit 1
}

# log_section <title> — legacy: open + close a quick section
log_section() {
    local title="$1"
    _log_write "INFO" "══════════ ${title} ══════════"
    if ! $LOG_JSON; then
        box_start "$title"
        box_end
    fi
}

# log_cmd <command> <exit_code> — log a command execution
log_cmd() {
    local cmd="$1"
    local exit_code="$2"
    _log_write "CMD" "exit=${exit_code} cmd=${cmd}"
    if ! $LOG_JSON; then
        if [[ ${#LOG_BOX_STACK[@]} -gt 0 ]]; then
            if [[ "$exit_code" -eq 0 ]]; then
                box_line " ${COLOR_OK}${BLD}\$${RST}  ${FG_WHT}${cmd}${RST}" "${COLOR_BOX}"
            else
                box_line " ${COLOR_ERROR}${BLD}\$${RST}  ${FG_RED}${cmd}${RST}  → exit ${exit_code}" "${COLOR_BOX}"
            fi
        else
            if [[ "$exit_code" -eq 0 ]]; then
                __echo "${COLOR_OK}" "  $ ${cmd}"
            else
                __echo "${COLOR_ERROR}" "  $ ${cmd}  → exit ${exit_code}"
            fi
        fi
    fi
}

# log_progress <current> <total> [label] — show a progress bar
log_progress() {
    local current="$1"
    local total="$2"
    local label="${3:-}"
    _log_write "PROGRESS" "${current}/${total} ${label}"
    if ! $LOG_JSON; then
        progress_bar "$current" "$total" "$label"
    fi
}

# log_summary — start a summary dashboard block
log_summary() {
    local title="${1:-📊  Results}"
    _log_write "INFO" "══════ Summary ══════"
    if ! $LOG_JSON; then
        summary_begin "$title"
    fi
}

# log_summary_row <icon_color> <icon> <label> <value>
log_summary_row() {
    local icon_color="$1"
    local icon="$2"
    local label="$3"
    local value="$4"
    _log_write "INFO" "${label}: ${value}"
    if ! $LOG_JSON; then
        summary_row "$icon_color" "$icon" "$label" "$value"
    fi
}

# log_summary_end [time_str] — close the summary dashboard
log_summary_end() {
    local time_str="${1:-}"
    _log_write "INFO" "══════ End Summary ══════"
    if ! $LOG_JSON; then
        summary_end "$time_str"
    fi
}

# Get the log file path for reporting
log_get_file() {
    echo "$LOG_FILE"
}

# Get execution ID
log_get_exec_id() {
    echo "$LOG_EXEC_ID"
}

# Export for subprocesses
export -f log_debug log_info log_ok log_warn log_error log_fatal log_section log_cmd 2>/dev/null || true
