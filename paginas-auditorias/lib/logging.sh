#!/usr/bin/env bash
# ============================================================================
# logging.sh — Centralized Logging System
# Part of PaginasAudit Cyber Audit Installer
# ----------------------------------------------------------------------------
# Features:
#   - Dual-logging: stdout (colored) + file (plain text + timestamps)
#   - Log levels: DEBUG, INFO, OK, WARN, ERROR, FATAL
#   - Automatic log rotation (keeps last 5)
#   - JSON log mode for machine parsing
#   - Syslog-compatible output format
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

# ---- Public API -----------------------------------------------------------

log_debug() {
    [[ $(_log_level_num DEBUG) -ge $(_log_level_num "$LOG_LEVEL") ]] || return 0
    _log_write "DEBUG" "$*"
    if ! $LOG_JSON; then
        __echo "${FG_BBLK}" "  [DEBUG] $*"
    fi
}

log_info() {
    [[ $(_log_level_num INFO) -ge $(_log_level_num "$LOG_LEVEL") ]] || return 0
    _log_write "INFO" "$*"
    if ! $LOG_JSON; then
        __echo "${FG_CYN}" "  [INFO] $*"
    fi
}

log_ok() {
    [[ $(_log_level_num OK) -ge $(_log_level_num "$LOG_LEVEL") ]] || return 0
    _log_write "OK" "$*"
    if ! $LOG_JSON; then
        __echo "${FG_GRN}" "  [ OK ] $*"
    fi
}

log_warn() {
    [[ $(_log_level_num WARN) -ge $(_log_level_num "$LOG_LEVEL") ]] || return 0
    _log_write "WARN" "$*"
    if ! $LOG_JSON; then
        __echo "${FG_YLW}" "  [WARN] $*"
    fi
}

log_error() {
    [[ $(_log_level_num ERROR) -ge $(_log_level_num "$LOG_LEVEL") ]] || return 0
    _log_write "ERROR" "$*"
    if ! $LOG_JSON; then
        __echo "${FG_RED}" "  [ERR ] $*"
    fi
}

log_fatal() {
    _log_write "FATAL" "$*"
    if ! $LOG_JSON; then
        __echo "${FG_BRED}${BLD}" "  [FATAL] $*"
    fi
    exit 1
}

log_section() {
    local title="$1"
    _log_write "INFO" "══════════ ${title} ══════════"
    if ! $LOG_JSON; then
        __echo "${FG_BMAG}" "  ── ${title} ──"
    fi
}

log_cmd() {
    local cmd="$1"
    local exit_code="$2"
    _log_write "CMD" "exit=${exit_code} cmd=${cmd}"
    if ! $LOG_JSON; then
        if [[ "$exit_code" -eq 0 ]]; then
            __echo "${FG_BGRN}" "  $ ${cmd}"
        else
            __echo "${FG_BRED}" "  $ ${cmd}  → exit ${exit_code}"
        fi
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
