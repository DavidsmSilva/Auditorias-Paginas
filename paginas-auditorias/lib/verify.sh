#!/usr/bin/env bash
# ============================================================================
# verify.sh — Installation Verification & Report Generation
# Part of PaginasAudit Cyber Audit Installer
# ----------------------------------------------------------------------------
# Features:
#   - Verify each tool: binary exists + version check + basic smoke test
#   - Generate detailed report (TXT + JSON)
#   - Summarize pass/fail per phase
#   - Export for CI/CD pipelines
#   - Audit-ready documentation output
# ============================================================================

[[ -n "${__VERIFY_LOADED:-}" ]] && return 0
readonly __VERIFY_LOADED=true

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/colors.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logging.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/utils.sh"

# ---- State ----------------------------------------------------------------
declare -A VERIFY_RESULTS=()       # tool -> status (pass|fail|skip)
declare -A VERIFY_VERSIONS=()      # tool -> version string
declare -A VERIFY_MESSAGES=()      # tool -> message
declare -A VERIFY_PHASES=()        # tool -> phase name
declare VERIFY_TOTAL=0
declare VERIFY_PASS=0
declare VERIFY_FAIL=0
declare VERIFY_SKIP=0

# ---- Smoke Test Registry --------------------------------------------------
# For each tool, define a "smoke test" command that proves it works

__smoke_test() {
    local tool="$1"
    case "$tool" in
        nmap)       nmap -V &>/dev/null ;;
        nikto)      nikto -Version &>/dev/null ;;
        sqlmap)     sqlmap --version &>/dev/null ;;
        whatweb)    whatweb --version &>/dev/null ;;
        wpscan)     wpscan --version &>/dev/null ;;
        dirb)       dirb 2>&1 | head -5 &>/dev/null ;;
        gobuster)   gobuster --help &>/dev/null ;;
        zaproxy)    zap-cli --help &>/dev/null ;;
        burpsuite)  java -jar /opt/burpsuite/burpsuite_*.jar --version &>/dev/null ;;
        dnsrecon)   dnsrecon --help &>/dev/null ;;
        theharvester) theharvester --help &>/dev/null ;;
        dnstwist)   dnstwist --help &>/dev/null ;;
        wireshark)  wireshark --version &>/dev/null ;;
        tcpdump)    tcpdump --version &>/dev/null ;;
        volatility) vol --help &>/dev/null ;;
        autopsy)    autopsy --version &>/dev/null;;
        binwalk)    binwalk --help &>/dev/null ;;
        lynis)      lynis --version &>/dev/null ;;
        chkrootkit) chkrootkit -V &>/dev/null ;;
        rkhunter)   rkhunter --version &>/dev/null ;;
        clamav)     clamscan --version &>/dev/null ;;
        aide)       aide --version &>/dev/null ;;
        snyk)       snyk --version &>/dev/null ;;
        npm)        npm --version &>/dev/null ;;
        python3)    python3 --version &>/dev/null ;;
        python-docx) python3 -c "import docx; print(docx.__version__)" &>/dev/null ;;
        weasyprint) python3 -c "import weasyprint; print(weasyprint.__version__)" &>/dev/null ;;
        docker)     docker --version &>/dev/null ;;
        curl)       curl --version &>/dev/null ;;
        wget)       wget --version &>/dev/null ;;
        git)        git --version &>/dev/null ;;
        jq)         jq --version &>/dev/null ;;
        yq)         yq --version &>/dev/null ;;
        nuclei)     nuclei -version &>/dev/null ;;
        httpx)      httpx -version &>/dev/null ;;
        subfinder)  subfinder --help &>/dev/null ;;
        amass)      amass --help &>/dev/null ;;
        hydra)      hydra --help &>/dev/null ;;
        john)       john --help &>/dev/null ;;
        hashcat)    hashcat --version &>/dev/null ;;
        sqlite3)    sqlite3 --version &>/dev/null ;;
        testssl)    testssl.sh --help &>/dev/null ;;
        tripwire)   tripwire --version &>/dev/null ;;
        duplicity)  duplicity --version &>/dev/null ;;
        borg)       borg --version &>/dev/null ;;
        dcfldd)     dcfldd --version &>/dev/null ;;
        semgrep)    semgrep --version &>/dev/null ;;
        trufflehog) trufflehog --help &>/dev/null ;;
        gitleaks)   gitleaks version &>/dev/null ;;
        bandit)     bandit --version &>/dev/null ;;
        ruff)       ruff --version &>/dev/null ;;
        naabu)      naabu --version &>/dev/null ;;
        katana)     katana --version &>/dev/null ;;
        ffuf)       ffuf --version &>/dev/null ;;
        trivy)      trivy --version &>/dev/null ;;
        syft)       syft --version &>/dev/null ;;
        grype)      grype --version &>/dev/null ;;
        osv-scanner) osv-scanner --version &>/dev/null ;;
        dependency-check) dependency-check --version &>/dev/null ;;
        *)
            # Generic: just check binary exists
            command -v "$tool" &>/dev/null
            return $?
            ;;
    esac
}

# ---- Core Verification ----------------------------------------------------

# verify_tool <tool_name> <phase_name> [expected_command]
verify_tool() {
    local tool="$1"
    local phase="$2"
    local cmd="${3:-$tool}"

    VERIFY_RESULTS["$tool"]="skip"
    VERIFY_PHASES["$tool"]="$phase"
    VERIFY_TOTAL=$(( VERIFY_TOTAL + 1 ))

    # Check binary exists
    if ! command -v "$cmd" &>/dev/null; then
        VERIFY_RESULTS["$tool"]="fail"
        VERIFY_VERSIONS["$tool"]="N/A"
        VERIFY_MESSAGES["$tool"]="Binario '${cmd}' no encontrado en PATH"
        VERIFY_FAIL=$(( VERIFY_FAIL + 1 ))
        log_warn "✗ ${tool} → NO INSTALADO (binario: ${cmd})"
        return 1
    fi

    # Get version
    local ver
    ver="$(tool_version "$tool" 2>/dev/null || echo "unknown")"
    VERIFY_VERSIONS["$tool"]="$ver"

    # Smoke test
    if __smoke_test "$tool"; then
        VERIFY_RESULTS["$tool"]="pass"
        VERIFY_MESSAGES["$tool"]="Funcionando correctamente"
        VERIFY_PASS=$(( VERIFY_PASS + 1 ))
        log_ok "✓ ${tool} v${ver} → OK"
        return 0
    else
        VERIFY_RESULTS["$tool"]="fail"
        VERIFY_MESSAGES["$tool"]="Binario encontrado pero smoke test falló"
        VERIFY_FAIL=$(( VERIFY_FAIL + 1 ))
        log_warn "⚠ ${tool} v${ver} → binario presente, smoke test falló"
        return 1
    fi
}

# verify_skip_tool <tool_name> <phase> <reason>
verify_skip_tool() {
    local tool="$1"
    local phase="$2"
    local reason="$3"
    VERIFY_RESULTS["$tool"]="skip"
    VERIFY_PHASES["$tool"]="$phase"
    VERIFY_VERSIONS["$tool"]="N/A"
    VERIFY_MESSAGES["$tool"]="Saltado: ${reason}"
    VERIFY_TOTAL=$(( VERIFY_TOTAL + 1 ))
    VERIFY_SKIP=$(( VERIFY_SKIP + 1 ))
    log_info "- ${tool} → saltado (${reason})"
}

# verify_phase_complete <phase_name> — check all tools in a phase
verify_phase_complete() {
    local phase="$1"
    local pass=0 fail=0 skip=0 total=0
    for tool in "${!VERIFY_RESULTS[@]}"; do
        [[ "${VERIFY_PHASES[$tool]}" != "$phase" ]] && continue
        total=$(( total + 1 ))
        case "${VERIFY_RESULTS[$tool]}" in
            pass) pass=$(( pass + 1 )) ;;
            fail) fail=$(( fail + 1 )) ;;
            skip) skip=$(( skip + 1 )) ;;
        esac
    done
    echo "$pass $fail $skip $total"
}

# ---- Report Generation ----------------------------------------------------

# generate_report_txt <output_path>
generate_report_txt() {
    local output="${1:-reports/verification-report.txt}"
    mkdir -p "$(dirname "$output")"

    {
        echo "═══════════════════════════════════════════════════════════════"
        echo "  PaginasAudit Cyber Audit — Reporte de Verificación"
        echo "  Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Ejecución: ${LOG_EXEC_ID:-N/A}"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        # Summary
        local total=$VERIFY_TOTAL
        local pass=$VERIFY_PASS
        local fail=$VERIFY_FAIL
        local skip=$VERIFY_SKIP
        echo "  RESUMEN GENERAL"
        echo "  ───────────────"
        printf "  %-25s: %d\n" "Total herramientas" "$total"
        printf "  %-25s: %d\n" "Instaladas correctamente" "$pass"
        printf "  %-25s: %d\n" "Fallidas" "$fail"
        printf "  %-25s: %d\n" "Saltadas" "$skip"
        echo ""

        # Phases
        local phases=("Assessment" "Malware Analysis" "Brand Protection" "Incident Response" "SAST" "SCA + SBOM")
        for phase in "${phases[@]}"; do
            # 🛡️ read con defaults: verify_phase_complete puede retornar vacío
            #    si la fase no tiene tools registradas → sin defaults, printf %d
            #    recibe string vacío y explota ("número inválido")
            read -r p f s t <<< "$(verify_phase_complete "$phase")" 2>/dev/null || true
            : "${p:=0}" "${f:=0}" "${s:=0}" "${t:=0}"
            echo "  FASE: ${phase}"
            echo "  ──────────────────────────────────"
            printf "    %-25s: %d/%d\n" "Herramientas instaladas" "$p" "$t"
            [[ $f -gt 0 ]] && printf "    ${FG_RED}%-25s: %d${RST}\n" "Fallidas" "$f"
            [[ $s -gt 0 ]] && printf "    %-25s: %d\n" "Saltadas" "$s"
            echo ""

            # Tool details for this phase
            local tool_count=0
            for tool in "${!VERIFY_RESULTS[@]}"; do
                [[ "${VERIFY_PHASES[$tool]}" != "$phase" ]] && continue
                tool_count=$(( tool_count + 1 ))
                local status="[${VERIFY_RESULTS[$tool]}]"
                local ver="${VERIFY_VERSIONS[$tool]}"
                local msg="${VERIFY_MESSAGES[$tool]}"
                printf "    ${tool_count}. %-18s %-7s v%-12s %s\n" "$tool" "$status" "$ver" "$msg"
            done
            echo ""
        done

        echo "═══════════════════════════════════════════════════════════════"
        echo "  Fin del reporte"
        echo "═══════════════════════════════════════════════════════════════"
    } > "$output"

    log_ok "Reporte TXT generado: ${output}"
    echo "$output"
}

# generate_report_json <output_path>
generate_report_json() {
    local output="${1:-reports/verification-report.json}"
    mkdir -p "$(dirname "$output")"

    # Build JSON structure
    local json="{"
    json+="\"meta\":{"
    json+="\"date\":\"$(date -Iseconds)\","
    json+="\"exec_id\":\"${LOG_EXEC_ID:-N/A}\","
    json+="\"version\":\"${VERSION:-1.0.0}\""
    json+="},"
    json+="\"summary\":{"
    json+="\"total\":${VERIFY_TOTAL},"
    json+="\"pass\":${VERIFY_PASS},"
    json+="\"fail\":${VERIFY_FAIL},"
    json+="\"skip\":${VERIFY_SKIP}"
    json+="},"

    # Group by phase
    json+="\"phases\":{"
    local first_phase=true
    local phases=("Assessment" "Malware Analysis" "Brand Protection" "Incident Response" "SAST" "SCA + SBOM")
    for phase in "${phases[@]}"; do
        $first_phase || json+=","
        first_phase=false
        json+="\"${phase}\":["
        local first_tool=true
        for tool in "${!VERIFY_RESULTS[@]}"; do
            [[ "${VERIFY_PHASES[$tool]}" != "$phase" ]] && continue
            $first_tool || json+=","
            first_tool=false
            json+="{"
            json+="\"tool\":\"${tool}\","
            json+="\"status\":\"${VERIFY_RESULTS[$tool]}\","
            json+="\"version\":\"${VERIFY_VERSIONS[$tool]}\","
            json+="\"message\":\"${VERIFY_MESSAGES[$tool]}\""
            json+="}"
        done
        json+="]"
    done
    json+="}}"

    printf '%s\n' "$json" > "$output"
    log_ok "Reporte JSON generado: ${output}"
    echo "$output"
}

# generate_report <output_path_prefix> — generate both reports
generate_report() {
    local prefix="${1:-reports/verification}"
    local txt_file="${prefix}.txt"
    local json_file="${prefix}.json"

    log_section "GENERANDO REPORTE DE VERIFICACIÓN"

    generate_report_txt "$txt_file"
    generate_report_json "$json_file"

    # Print summary to console
    echo ""
    summary
    echo ""

    kv "Reporte TXT" "$txt_file"
    kv "Reporte JSON" "$json_file"
    kv "Log completo" "$LOG_FILE"
    echo ""
}

# ---- Summary Display ------------------------------------------------------

# summary — print a beautiful summary table
summary() {
    __echo "${COLOR_HEADER}" "  ┌────────────────────────────────────────────────┐"
    __echo "${COLOR_HEADER}" "  │        RESUMEN DE INSTALACIÓN                 │"
    __echo "${COLOR_HEADER}" "  ├──────────────┬──────┬──────┬──────┬──────────┤"
    __echo "${COLOR_HEADER}" "  │ Fase         │ Total│ ✓ OK │ ✗ Fail│ - Skip   │"
    __echo "${COLOR_HEADER}" "  ├──────────────┼──────┼──────┼──────┼──────────┤"

    local phases=("Assessment" "Malware Analysis" "Brand Protection" "Incident Response" "SAST" "SCA + SBOM")
    local g_total=0 g_pass=0 g_fail=0 g_skip=0
    for phase in "${phases[@]}"; do
        read -r p f s t <<< "$(verify_phase_complete "$phase")" 2>/dev/null || true
        : "${p:=0}" "${f:=0}" "${s:=0}" "${t:=0}"
        g_total=$(( g_total + t ))
        g_pass=$(( g_pass + p ))
        g_fail=$(( g_fail + f ))
        g_skip=$(( g_skip + s ))

        local phase_short
        case "$phase" in
            "Assessment") phase_short="Assessment" ;;
            "Malware Analysis") phase_short="Malware An." ;;
            "Brand Protection") phase_short="Brand Prot." ;;
            "Incident Response") phase_short="Incident Resp." ;;
            "SAST") phase_short="SAST" ;;
            "SCA + SBOM") phase_short="SCA+SBOM" ;;
        esac
        __echo "${COLOR_ACCENT2}" "  │ $(printf '%-12s' "$phase_short")│  $(printf '%3d' "$t")  │  $(printf '%3d' "$p")  │   $(printf '%3d' "$f")  │    $(printf '%3d' "$s")  │"
    done

    __echo "${COLOR_HEADER}" "  ├──────────────┼──────┼──────┼──────┼──────────┤"
    __echo "${COLOR_HEADER}" "  │ $(printf '%-12s' 'TOTAL')│  $(printf '%3d' "$g_total")  │  $(printf '%3d' "$g_pass")  │   $(printf '%3d' "$g_fail")  │    $(printf '%3d' "$g_skip")  │"
    __echo "${COLOR_HEADER}" "  └──────────────┴──────┴──────┴──────┴──────────┘"
}

# ---- CI/CD Export ---------------------------------------------------------

# export_github_actions — set GITHUB_OUTPUT variables
export_github_actions() {
    if [[ -z "${GITHUB_OUTPUT:-}" ]]; then
        return 0
    fi
    {
        echo "verify_total=${VERIFY_TOTAL}"
        echo "verify_pass=${VERIFY_PASS}"
        echo "verify_fail=${VERIFY_FAIL}"
        echo "verify_skip=${VERIFY_SKIP}"
        echo "verify_success=$([[ $VERIFY_FAIL -eq 0 ]] && echo true || echo false)"
    } >> "$GITHUB_OUTPUT"
    log_debug "Exportado a GITHUB_OUTPUT"
}

# ---- Reset ----------------------------------------------------------------

verify_reset() {
    VERIFY_RESULTS=()
    VERIFY_VERSIONS=()
    VERIFY_MESSAGES=()
    VERIFY_PHASES=()
    VERIFY_TOTAL=0
    VERIFY_PASS=0
    VERIFY_FAIL=0
    VERIFY_SKIP=0
}
