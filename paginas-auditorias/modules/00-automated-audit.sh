#!/usr/bin/env bash
# ============================================================================
# 00-automated-audit.sh — Pipeline de Auditoría Automática
# ============================================================================
# Toma una URL y ejecuta las 6 fases de auditoría automáticamente:
#   Fase 1: Assessment (Nmap, Nikto, WhatWeb, Nuclei, SSL, DNS, fuzzing)
#   Fase 2: Malware Analysis (YARA, exiftool, análisis de recursos)
#   Fase 3: Brand Protection (dnstwist, theHarvester, sublist3r)
#   Fase 4: IR Readiness Checklist
#   Fase 5: SAST (Semgrep, TruffleHog, Gitleaks, Bandit)
#   Fase 6: SCA + SBOM (Trivy, Dep-Check, Syft, Grype, OSV-Scanner)
#
# Genera reporte consolidado en TXT + JSON + HTML interactivo.
# ============================================================================

[[ -n "${__MODULE_AUDIT_LOADED:-}" ]] && return 0
readonly __MODULE_AUDIT_LOADED=true

MODULE_AUDIT_NAME="Automated Audit"
MODULE_AUDIT_DESC="Auditoría automática completa contra URL objetivo"

# ---- State ---------------------------------------------------------------
declare -g -a AUDIT_FINDINGS=()        # SEVERITY|SOURCE|TITLE|DETAIL|RECOMMENDATION|EVIDENCE
declare -g -A AUDIT_TARGET=(
    [url]=""
    [domain]=""
    [ip]=""
    [hostname]=""
    [scheme]=""
    [base]=""
    [waf]="unknown"
    [technologies]=""
    [status]="pending"
)
declare -g -A AUDIT_TIMING=()          # phase -> seconds
declare -g -a AUDIT_LOG=()            # All tool outputs (captured)
declare -g AUDIT_DIR=""                # Working directory for this audit
declare -g AUDIT_START_TIME=""
declare -g AUDIT_END_TIME=""

# ---- Constants -----------------------------------------------------------
AUDIT_TIMEOUT_DEFAULT=120           # seconds per tool
AUDIT_WORDLIST_DIR="/usr/share/wordlists"
AUDIT_NSE_SCRIPTS=(
    "http-headers"
    "http-title"
    "http-server-header"
    "http-methods"
    "http-enum"
    "http-webdav-scan"
    "ssl-enum-ciphers"
    "ssl-cert"
    "dns-service-discovery"
    "http-cors"
    "http-robots.txt"
    "http-sitemap-generator"
)

# ---- Color severity mapping ----------------------------------------------
SEV_COLOR_CRIT="${FG_RED}${BLD}"
SEV_COLOR_HIGH="${FG_RED}"
SEV_COLOR_MED="${FG_YLW}"
SEV_COLOR_LOW="${FG_BBLU}"
SEV_COLOR_INFO="${FG_CYN}"
SEV_COLOR_UNK="${FG_BBLK}"

sev_color() {
    case "${1:-UNKNOWN}" in
        CRITICAL) echo "${FG_RED}${BLD}" ;;
        HIGH)     echo "${FG_RED}" ;;
        MEDIUM)   echo "${FG_YLW}" ;;
        LOW)      echo "${FG_BBLU}" ;;
        INFO)     echo "${FG_CYN}" ;;
        *)        echo "${FG_BBLK}" ;;
    esac
}

sev_emoji() {
    case "${1:-UNKNOWN}" in
        CRITICAL) echo "🛑" ;;
        HIGH)     echo "⚠️" ;;
        MEDIUM)   echo "⚡" ;;
        LOW)      echo "ℹ️" ;;
        INFO)     echo "📌" ;;
        *)        echo "❓" ;;
    esac
}

# ---- Finding Engine ------------------------------------------------------
# add_finding SEVERITY SOURCE TITLE DETAIL RECOMMENDATION [EVIDENCE]
add_finding() {
    local severity="${1:-INFO}"
    local source="${2:-general}"
    local title="${3:-Unknown finding}"
    local detail="${4:-}"
    local recommendation="${5:-}"
    local evidence="${6:-}"

    AUDIT_FINDINGS+=("${severity}|${source}|${title}|${detail}|${recommendation}|${evidence}")
    log_debug "[${severity}] [${source}] ${title}"
}

# findings_by_severity <severity> — returns matching finding indices
findings_by_severity() {
    local sev="$1"
    local i=0
    for finding in "${AUDIT_FINDINGS[@]}"; do
        IFS='|' read -r fsev _ _ _ _ _ <<< "$finding"
        if [[ "$fsev" == "$sev" ]]; then
            echo "$i"
        fi
        i=$((i + 1))
    done
}

# findings_count <severity>
findings_count() {
    local sev="$1"
    local count=0
    for finding in "${AUDIT_FINDINGS[@]}"; do
        IFS='|' read -r fsev _ _ _ _ _ <<< "$finding"
        [[ "$fsev" == "$sev" ]] && ((count++))
    done
    echo "$count"
}

findings_total() {
    echo "${#AUDIT_FINDINGS[@]}"
}

# ---- Target Normalization ------------------------------------------------
audit_normalize_url() {
    local url="$1"

    # Defensive: ensure we have a URL (set -u guard)
    if [[ -z "${url:-}" ]]; then
        log_error "audit_normalize_url: URL vacía"
        return 1
    fi

    # Add scheme if missing
    if [[ "$url" != http://* && "$url" != https://* ]]; then
        url="https://${url}"
        log_info "Scheme añadido: ${url}"
    fi

    # ⚠️  Paréntesis temporal para evitar que set -u + :// causen errores
    #     en bash 5.2+ con patrones de expansión de parámetros
    set +u
    AUDIT_TARGET[url]="$url"
    AUDIT_TARGET[scheme]="${url%%://*}"
    AUDIT_TARGET[base]="${url#*://}"
    AUDIT_TARGET[base]="${AUDIT_TARGET[base]%%/*}"
    AUDIT_TARGET[domain]="${AUDIT_TARGET[base]}"
    set -u

    # Extract hostname (remove port if present)
    local host="${AUDIT_TARGET[base]}"
    host="${host%:*}"
    AUDIT_TARGET[hostname]="$host"

    log_info "Target normalizado: ${AUDIT_TARGET[url]}"
    log_info "  Domain: ${AUDIT_TARGET[domain]}"
    log_info "  Host:   ${AUDIT_TARGET[hostname]}"
    log_info "  Scheme: ${AUDIT_TARGET[scheme]}"
}

# ---- Pre-flight: DNS & Reachability --------------------------------------
audit_pre_flight() {
    log_section "PRE-FLIGHT — VERIFICACIÓN DEL TARGET"
    local domain="${AUDIT_TARGET[domain]}"

    info "Resolviendo DNS para ${domain}..."

    # 🛡️ DNS resolution — MUST return a real IPv4 address, NOT a CNAME
    #    Previous bug: dig +short returned CNAME (cdn1.wixdns.net) instead of IP,
    #    which caused Nmap and all IP-based tools to fail.
    local ip=""
    # Method 1: dig A record + grep for valid IPv4 (filters out CNAMEs)
    ip=$(dig +short A "$domain" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    # Method 2: host command, parse "has address"
    [[ -z "$ip" ]] && ip=$(host "$domain" 2>/dev/null | grep -oP 'has address \K[\d.]+' | head -1)
    # Method 3: nslookup
    [[ -z "$ip" ]] && ip=$(nslookup "$domain" 2>/dev/null | grep -oP 'Address: \K[\d.]+' | grep -v ':' | head -1)
    # Method 4: ping fallback
    [[ -z "$ip" ]] && ip=$(ping -c1 -W2 "$domain" 2>/dev/null | grep -oP '[\d.]+(?= \()' | head -1)

    if [[ -n "$ip" ]]; then
        AUDIT_TARGET[ip]="$ip"
        log_ok "DNS resuelto: ${domain} → ${ip}"

        # Reverse DNS
        local rdns
        rdns=$(host "$ip" 2>/dev/null | head -1 | grep -oP 'pointer \K.+')
        [[ -n "$rdns" ]] && log_info "  PTR: ${rdns}"

        # HTTP reachability
        if curl -sI --max-time 10 "${AUDIT_TARGET[url]}" &>/dev/null; then
            log_ok "Target reachable via HTTP"
            AUDIT_TARGET[status]="reachable"

            # Detect WAF
            local waf
            waf=$(curl -sI --max-time 10 "${AUDIT_TARGET[url]}" 2>/dev/null | grep -i "server\|x-powered-by\|cf-ray\|x-sucuri\|x-akamai" | head -3 | tr '\n' ' ')
            [[ -n "$waf" ]] && AUDIT_TARGET[waf]="$waf" || AUDIT_TARGET[waf]="none detected"

            # Get HTTP headers for analysis
            curl -sI --max-time 10 "${AUDIT_TARGET[url]}" > "${AUDIT_DIR}/http-headers.txt" 2>/dev/null || true
        else
            log_warn "Target no reachable via HTTP"
            AUDIT_TARGET[status]="unreachable"
            add_finding "HIGH" "Pre-flight" "Target no responde en HTTP" \
                "La URL ${AUDIT_TARGET[url]} no respondió a peticiones HTTP. Verifique disponibilidad." \
                "Asegurar que el servicio esté activo y accesible."
            return 1
        fi
    else
        log_warn "No se pudo resolver DNS para ${domain}"
        AUDIT_TARGET[status]="dns_failed"
        add_finding "CRITICAL" "Pre-flight" "Fallo de resolución DNS" \
            "No se pudo resolver el dominio ${domain}" \
            "Verifique que el dominio exista y sea accesible desde esta red."
        return 1
    fi

    # Create working directory structure
    mkdir -p "${AUDIT_DIR}/scans/nmap"
    mkdir -p "${AUDIT_DIR}/scans/web"
    mkdir -p "${AUDIT_DIR}/scans/ssl"
    mkdir -p "${AUDIT_DIR}/scans/dns"
    mkdir -p "${AUDIT_DIR}/osint"
    mkdir -p "${AUDIT_DIR}/malware"
    mkdir -p "${AUDIT_DIR}/scans/sast"
    mkdir -p "${AUDIT_DIR}/scans/sca"
    mkdir -p "${AUDIT_DIR}/sbom"
    mkdir -p "${AUDIT_DIR}/resources"
    mkdir -p "${AUDIT_DIR}/reports"

    return 0
}

# ---- Phase 1: Assessment -------------------------------------------------
audit_assessment() {
    log_section "FASE 1: ASSESSMENT — ESCANEO ACTIVO"
    local start_time
    start_time=$(date +%s)

    local domain="${AUDIT_TARGET[domain]}"
    local ip="${AUDIT_TARGET[ip]}"
    local url="${AUDIT_TARGET[url]}"

    # ----- 1.1 WhatWeb — Technology fingerprinting -----
    info "[1/8] WhatWeb — Identificando tecnologías..."
    if cmd_exists whatweb; then
        timed_run 120 whatweb --aggression 1 --color=never "$url" 2>/dev/null \
            > "${AUDIT_DIR}/scans/web/whatweb.txt" || true
        if [[ -s "${AUDIT_DIR}/scans/web/whatweb.txt" ]]; then
            AUDIT_TARGET[technologies]=$(head -1 "${AUDIT_DIR}/scans/web/whatweb.txt")
            log_ok "Tecnologías detectadas: $(wc -l < "${AUDIT_DIR}/scans/web/whatweb.txt") lineas"
            # Extract key findings
            if grep -qi "wordpress" "${AUDIT_DIR}/scans/web/whatweb.txt"; then
                add_finding "INFO" "WhatWeb" "CMS detectado: WordPress" \
                    "Se detectó WordPress como CMS. Se ejecutará WPScan más adelante." \
                    "Asegurar que WordPress, plugins y temas estén actualizados."
            fi
            if grep -qi "jquery\|angular\|react\|vue" "${AUDIT_DIR}/scans/web/whatweb.txt"; then
                add_finding "INFO" "WhatWeb" "Framework JS detectado" \
                    "Se detectó un framework JavaScript frontend." \
                    "Verificar versiones y actualizar dependencias."
            fi
        fi
    else
        warn "WhatWeb no instalado — saltando"
    fi

    # ----- 1.2 Nmap — Port scan + NSE scripts -----
    info "[2/8] Nmap — Escaneo de puertos y servicios..."
    if cmd_exists nmap; then
        # Quick port scan first
        timed_run 180 nmap -T4 --open -sV --reason \
            -oN "${AUDIT_DIR}/scans/nmap/quick-scan.txt" \
            -oX "${AUDIT_DIR}/scans/nmap/quick-scan.xml" \
            "$ip" 2>/dev/null || true

        if [[ -s "${AUDIT_DIR}/scans/nmap/quick-scan.txt" ]]; then
            local open_ports
            open_ports=$(grep -c "^[0-9]\+/tcp" "${AUDIT_DIR}/scans/nmap/quick-scan.txt" 2>/dev/null || echo 0)
            log_ok "Puertos abiertos encontrados: ${open_ports}"

            # Analyze critical ports
            if grep -q "3306.*mysql\|5432.*postgresql\|6379.*redis\|27017.*mongodb" \
                "${AUDIT_DIR}/scans/nmap/quick-scan.txt" 2>/dev/null; then
                add_finding "CRITICAL" "Nmap" "Base de datos expuesta en puerto público" \
                    "Se detectó un servicio de base de datos accesible desde internet." \
                    "Restringir acceso por firewall. Usar VPN/túnel SSH para acceso remoto." \
                    "$(grep "3306\|5432\|6379\|27017" "${AUDIT_DIR}/scans/nmap/quick-scan.txt")"
            fi

            if grep -q "22/tcp.*open" "${AUDIT_DIR}/scans/nmap/quick-scan.txt" 2>/dev/null; then
                add_finding "MEDIUM" "Nmap" "SSH (puerto 22) expuesto" \
                    "SSH accesible desde internet. Riesgo de fuerza bruta." \
                    "Usar autenticación por llave, deshabilitar root login, cambiar puerto o usar VPN."
            fi

            if grep -q "21/tcp.*open" "${AUDIT_DIR}/scans/nmap/quick-scan.txt" 2>/dev/null; then
                add_finding "HIGH" "Nmap" "FTP (puerto 21) expuesto" \
                    "FTP sin cifrar detectado. Credenciales viajan en texto plano." \
                    "Migrar a SFTP o FTPS. Deshabilitar si no es necesario."
            fi

            # NSE vulnerability scripts
            info "Ejecutando scripts NSE de vulnerabilidad..."
            local nse_scripts=$(IFS=,; echo "${AUDIT_NSE_SCRIPTS[*]}")
            timed_run 300 nmap -T4 --script "${nse_scripts}" \
                -oN "${AUDIT_DIR}/scans/nmap/nse-vuln.txt" \
                "$ip" 2>/dev/null || true

            # Check for interesting NSE findings
            if [[ -f "${AUDIT_DIR}/scans/nmap/nse-vuln.txt" ]]; then
                if grep -qi "vulnerable\|CVE-\|misconfigured\|VULNERABLE" \
                    "${AUDIT_DIR}/scans/nmap/nse-vuln.txt" 2>/dev/null; then
                    add_finding "HIGH" "Nmap NSE" "Vulnerabilidad detectada por NSE" \
                        "Los scripts NSE encontraron posibles vulnerabilidades." \
                        "Revisar el archivo de escaneo NSE para detalles específicos." \
                        "$(grep -i "vulnerable\|CVE-" "${AUDIT_DIR}/scans/nmap/nse-vuln.txt" | head -5)"
                fi
            fi
        else
            warn "Nmap no produjo resultados — posible bloqueo de red/firewall"
            add_finding "MEDIUM" "Nmap" "Sin respuesta de Nmap — firewall detectado" \
                "El escaneo de puertos no obtuvo respuesta. Firewall o WAF bloqueando." \
                "Intentar escaneo con -Pn o desde otra red."
        fi
    else
        warn "Nmap no instalado — saltando escaneo de puertos"
    fi

    # ----- 1.3 Nikto — Web vulnerability scanner -----
    info "[3/8] Nikto — Escaneo de vulnerabilidades web..."
    if cmd_exists nikto; then
        # 🛡️ WAF/CDN detection: si el target usa Wix/Cloudflare/ Akamai,
        #    Nikto es significativamente más lento. Timeout aumentado a 600s.
        if [[ "${AUDIT_TARGET[waf]}" != "none detected" ]]; then
            log_info "WAF detectado (${AUDIT_TARGET[waf]}) — usando timeout extendido para Nikto"
        fi
        timed_run 600 nikto -h "$url" -Format txt \
            -output "${AUDIT_DIR}/scans/web/nikto.txt" 2>/dev/null || true

        if [[ -f "${AUDIT_DIR}/scans/web/nikto.txt" ]]; then
            local vuln_count
            vuln_count=$(grep -c "^+ " "${AUDIT_DIR}/scans/web/nikto.txt" 2>/dev/null || echo 0)
            log_ok "Nikto completado: ${vuln_count} hallazgos"

            if [[ "$vuln_count" -gt 0 ]]; then
                # Extract critical findings
                while IFS= read -r line; do
                    if [[ "$line" == "+ "* ]]; then
                        local finding_info="${line#+ }"
                        local sev="MEDIUM"
                        if echo "$finding_info" | grep -qi "xss\|sqli\|remote.*exec\|directory traversal"; then
                            sev="CRITICAL"
                        elif echo "$finding_info" | grep -qi "info\|cookie.*missing\|server.*header"; then
                            sev="LOW"
                        fi
                        add_finding "$sev" "Nikto" "${finding_info:0:80}" \
                            "Nikto identificó este hallazgo durante el escaneo web." \
                            "Revisar y remediar según la severidad indicada." \
                            "$finding_info"
                    fi
                done < "${AUDIT_DIR}/scans/web/nikto.txt"
            fi
        fi
    else
        warn "Nikto no instalado — saltando"
    fi

    # ----- 1.4 SSL/TLS Scan -----
    info "[4/8] SSL/TLS — Evaluación de seguridad..."
    if [[ "${AUDIT_TARGET[scheme]}" == "https" ]]; then
        # sslscan
        if cmd_exists sslscan; then
            timed_run 120 sslscan --no-colour "$domain" \
                > "${AUDIT_DIR}/scans/ssl/sslscan.txt" 2>/dev/null || true

            if [[ -f "${AUDIT_DIR}/scans/ssl/sslscan.txt" ]]; then
                if grep -qi "SSLv2\|SSLv3\|TLSv1\.0\|TLSv1\.1\|weak\|RC4\|MD5\|DES\|3DES" \
                    "${AUDIT_DIR}/scans/ssl/sslscan.txt" 2>/dev/null; then
                    add_finding "HIGH" "SSLScan" "Protocolos SSL/TLS débiles habilitados" \
                        "Se detectaron versiones obsoletas o inseguras de SSL/TLS." \
                        "Deshabilitar SSLv2, SSLv3, TLSv1.0, TLSv1.1. Solo permitir TLSv1.2+."
                fi
                if grep -qi "self-signed\|self signed" "${AUDIT_DIR}/scans/ssl/sslscan.txt" 2>/dev/null; then
                    add_finding "MEDIUM" "SSLScan" "Certificado SSL auto-firmado" \
                        "El certificado SSL es auto-firmado. Los navegadores mostrarán advertencia." \
                        "Usar Let's Encrypt o un CA comercial."
                fi
            fi
        fi

        # testssl.sh
        if cmd_exists testssl.sh; then
            timed_run 180 testssl.sh --quiet --color=0 \
                --csvfile "${AUDIT_DIR}/scans/ssl/testssl.csv" \
                "$domain" > "${AUDIT_DIR}/scans/ssl/testssl.txt" 2>/dev/null || true
            log_ok "testssl.sh completado"
        fi
    else
        info "HTTP (no HTTPS) — saltando análisis SSL/TLS"
        add_finding "HIGH" "SSL" "Sitio en HTTP sin HTTPS" \
            "El sitio no usa HTTPS. Todo el tráfico viaja sin cifrar." \
            "Implementar HTTPS con Let's Encrypt. Redirigir HTTP→HTTPS."
    fi

    # ----- 1.5 DNS Enumeration -----
    info "[5/8] DNS — Enumeración de registros..."
    if cmd_exists dnsrecon; then
        timed_run 120 dnsrecon -d "$domain" \
            > "${AUDIT_DIR}/scans/dns/dnsrecon.txt" 2>/dev/null || true

        if [[ -f "${AUDIT_DIR}/scans/dns/dnsrecon.txt" ]]; then
            if grep -qi "zone transfer\|AXFR" "${AUDIT_DIR}/scans/dns/dnsrecon.txt" 2>/dev/null; then
                add_finding "CRITICAL" "DNS" "Zone Transfer (AXFR) permitido" \
                    "El servidor DNS permite transferencia de zona. Atacantes pueden obtener todos los registros." \
                    "Restringir AXFR solo a servidores DNS secundarios autorizados."
            fi
            # Extract interesting records
            local subdomains
            subdomains=$(grep -oP '\[A\] \K\S+' "${AUDIT_DIR}/scans/dns/dnsrecon.txt" 2>/dev/null | head -10 || true)
            if [[ -n "$subdomains" ]]; then
                add_finding "INFO" "DNS" "Subdominios descubiertos via DNS" \
                    "Registros A adicionales encontrados: $(echo "$subdomains" | tr '\n' ' ')" \
                    "Revisar que todos los subdominios estén controlados y actualizados."
            fi
        fi
    fi

    # ----- 1.6 Nuclei — Template-based scanning -----
    info "[6/8] Nuclei — Escaneo basado en templates..."
    if cmd_exists nuclei; then
        timed_run 300 nuclei -u "$url" -severity low,medium,high,critical \
            -o "${AUDIT_DIR}/scans/web/nuclei.txt" \
            -silent 2>/dev/null || true

        if [[ -f "${AUDIT_DIR}/scans/web/nuclei.txt" && -s "${AUDIT_DIR}/scans/web/nuclei.txt" ]]; then
            local nuclei_count
            nuclei_count=$(wc -l < "${AUDIT_DIR}/scans/web/nuclei.txt")
            log_ok "Nuclei: ${nuclei_count} hallazgos"

            while IFS= read -r line; do
                if [[ -n "$line" ]]; then
                    # Parse nuclei output: [severity] [name] url
                    local nsev="MEDIUM"
                    if echo "$line" | grep -qi "\[critical\]\|\[high\]"; then
                        echo "$line" | grep -qi "\[critical\]" && nsev="CRITICAL" || nsev="HIGH"
                    elif echo "$line" | grep -qi "\[info\]\|\[unknown\]"; then
                        nsev="INFO"
                    fi
                    add_finding "$nsev" "Nuclei" "${line:0:100}" \
                        "Template de Nuclei detectó potencial vulnerabilidad." \
                        "Revisar el output completo de Nuclei para contexto." \
                        "$line"
                fi
            done < "${AUDIT_DIR}/scans/web/nuclei.txt"
        else
            log_ok "Nuclei: sin hallazgos"
        fi
    else
        warn "Nuclei no instalado — saltando"
    fi

    # ----- 1.7 WPScan (conditional) -----
    info "[7/8] WPScan — Escaneo WordPress (si aplica)..."
    if cmd_exists wpscan && grep -qi "wordpress" "${AUDIT_DIR}/scans/web/whatweb.txt" 2>/dev/null; then
        timed_run 300 wpscan --url "$url" --no-update \
            --output "${AUDIT_DIR}/scans/web/wpscan.txt" 2>/dev/null || true

        if [[ -f "${AUDIT_DIR}/scans/web/wpscan.txt" ]]; then
            if grep -qi "vulnerability\|vuln\|CVE-" "${AUDIT_DIR}/scans/web/wpscan.txt" 2>/dev/null; then
                add_finding "HIGH" "WPScan" "Vulnerabilidades en WordPress detectadas" \
                    "WPScan encontró vulnerabilidades conocidas en WordPress/plugins/temas." \
                    "Actualizar WordPress, plugins y temas a sus últimas versiones."
            fi
        fi
    else
        info "  WordPress no detectado — saltando WPScan"
    fi

    # ----- 1.8 Gobuster — Directory fuzzing (lite) -----
    info "[8/8] Gobuster — Fuzzing de directorios..."
    if cmd_exists gobuster; then
        local wordlist=""
        # Find a suitable wordlist
        for wl in "${AUDIT_WORDLIST_DIR}/dirb/common.txt" \
                  "${AUDIT_WORDLIST_DIR}/dirbuster/directory-list-2.3-medium.txt" \
                  "/usr/share/dirb/wordlists/common.txt" \
                  "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt"; do
            if [[ -f "$wl" ]]; then
                wordlist="$wl"
                break
            fi
        done

        if [[ -n "$wordlist" ]]; then
            timed_run 180 gobuster dir -u "$url" -w "$wordlist" \
                -t 30 -q \
                -o "${AUDIT_DIR}/scans/web/gobuster.txt" 2>/dev/null || true

            if [[ -f "${AUDIT_DIR}/scans/web/gobuster.txt" && -s "${AUDIT_DIR}/scans/web/gobuster.txt" ]]; then
                local dir_count
                dir_count=$(wc -l < "${AUDIT_DIR}/scans/web/gobuster.txt")
                add_finding "INFO" "Gobuster" "${dir_count} directorios/archivos descubiertos" \
                    "Gobuster encontró ${dir_count} rutas en el servidor web." \
                    "Revisar que ninguna ruta descubierta exponga información sensible."
            fi
        else
            warn "No se encontró wordlist para Gobuster"
            add_finding "MEDIUM" "Gobuster" "Wordlist no encontrada" \
                "No se encontró wordlist para fuzzing de directorios." \
                "Instalar: sudo apt install dirb (incluye wordlists)"
        fi
    fi

    local end_time
    end_time=$(date +%s)
    AUDIT_TIMING[assessment]=$(( end_time - start_time ))
    log_ok "Assessment completado en $(( AUDIT_TIMING[assessment] / 60 ))m $(( AUDIT_TIMING[assessment] % 60 ))s"
}

# ---- Phase 2: Malware Analysis -------------------------------------------
audit_malware() {
    log_section "FASE 2: ANÁLISIS DE MALWARE"
    local start_time
    start_time=$(date +%s)

    local url="${AUDIT_TARGET[url]}"
    local domain="${AUDIT_TARGET[domain]}"

    # ----- 2.1 Resource Download & Analysis -----
    info "[1/4] Descargando recursos de la página principal..."
    # Download homepage and extract resources
    curl -sL --max-time 30 "$url" > "${AUDIT_DIR}/resources/homepage.html" 2>/dev/null || true

    if [[ -f "${AUDIT_DIR}/resources/homepage.html" && -s "${AUDIT_DIR}/resources/homepage.html" ]]; then
        # Extract JS files
        grep -oP 'src=["'\'']\K[^"'\'']+\.js[^"'\'']*' "${AUDIT_DIR}/resources/homepage.html" \
            > "${AUDIT_DIR}/resources/js-urls.txt" 2>/dev/null || true
        # Extract CSS files
        grep -oP 'href=["'\'']\K[^"'\'']+\.css[^"'\'']*' "${AUDIT_DIR}/resources/homepage.html" \
            > "${AUDIT_DIR}/resources/css-urls.txt" 2>/dev/null || true
        # Extract images
        grep -oP 'src=["'\'']\K[^"'\'']+\.(png|jpg|jpeg|gif|svg|ico)[^"'\'']*' "${AUDIT_DIR}/resources/homepage.html" \
            > "${AUDIT_DIR}/resources/img-urls.txt" 2>/dev/null || true

        local js_count=0 css_count=0 img_count=0
        [[ -f "${AUDIT_DIR}/resources/js-urls.txt" ]] && js_count=$(wc -l < "${AUDIT_DIR}/resources/js-urls.txt")
        [[ -f "${AUDIT_DIR}/resources/css-urls.txt" ]] && css_count=$(wc -l < "${AUDIT_DIR}/resources/css-urls.txt")
        [[ -f "${AUDIT_DIR}/resources/img-urls.txt" ]] && img_count=$(wc -l < "${AUDIT_DIR}/resources/img-urls.txt")
        log_ok "Recursos encontrados: ${js_count} JS, ${css_count} CSS, ${img_count} imágenes"
    fi

    # ----- 2.2 ExifTool — Metadata analysis -----
    info "[2/4] ExifTool — Analizando metadatos de imágenes..."
    if cmd_exists exiftool; then
        if [[ -f "${AUDIT_DIR}/resources/img-urls.txt" ]]; then
            local img_dir="${AUDIT_DIR}/resources/images"
            mkdir -p "$img_dir"

            # Download a sample of images for metadata analysis
            local count=0
            while IFS= read -r img_url && [[ $count -lt 5 ]]; do
                # Resolve relative URLs
                if [[ "$img_url" == http* ]]; then
                    local full_url="$img_url"
                elif [[ "$img_url" == /* ]]; then
                    local full_url="${AUDIT_TARGET[scheme]}://${AUDIT_TARGET[domain]}${img_url}"
                else
                    local full_url="${AUDIT_TARGET[url]}/${img_url}"
                fi

                local fname
                fname=$(basename "${img_url%%\?*}")
                curl -sL --max-time 10 "$full_url" -o "${img_dir}/${fname}" 2>/dev/null || true
                count=$((count + 1))
            done < "${AUDIT_DIR}/resources/img-urls.txt"

            # Run exiftool on downloaded images
            if [[ -d "$img_dir" ]]; then
                exiftool -r -j "$img_dir" > "${AUDIT_DIR}/malware/exiftool.json" 2>/dev/null || true
                if [[ -f "${AUDIT_DIR}/malware/exiftool.json" && -s "${AUDIT_DIR}/malware/exiftool.json" ]]; then
                    if grep -qi "gps\|latitude\|longitude\|author\|creator\|software" \
                        "${AUDIT_DIR}/malware/exiftool.json" 2>/dev/null; then
                        add_finding "MEDIUM" "ExifTool" "Metadatos sensibles en imágenes" \
                            "Se encontraron metadatos (GPS, autor, software) en imágenes descargadas." \
                            "Limpiar metadatos EXIF antes de publicar imágenes en producción."
                    fi
                fi
            fi
        fi
    fi

    # ----- 2.3 YARA — Pattern scanning on resources -----
    info "[3/4] YARA — Escaneo de patrones en recursos..."
    if cmd_exists yara; then
        # Check for YARA rules
        local yara_rules=""
        for rules in "/opt/yara-rules/rules" "/usr/share/yara" "/usr/local/share/yara"; do
            if [[ -d "$rules" ]]; then
                yara_rules="$rules"
                break
            fi
        done

        if [[ -n "$yara_rules" ]]; then
            local yara_output="${AUDIT_DIR}/malware/yara-results.txt"
            > "$yara_output"

            # Scan downloaded resources
            find "${AUDIT_DIR}/resources" -type f -size -10M 2>/dev/null | while IFS= read -r resource; do
                yara -s "$yara_rules" "$resource" >> "$yara_output" 2>/dev/null || true
            done

            if [[ -s "$yara_output" ]]; then
                add_finding "HIGH" "YARA" "Patrón de malware detectado en recursos" \
                    "YARA detectó coincidencias con reglas de malware en los recursos descargados." \
                    "Revisar el reporte YARA e investigar los archivos señalados." \
                    "$(head -20 "$yara_output")"
            else
                log_ok "YARA: sin coincidencias"
            fi
        else
            warn "No se encontraron reglas YARA"
        fi
    fi

    # ----- 2.4 Security Headers Analysis -----
    info "[4/4] Análisis de cabeceras de seguridad HTTP..."
    if [[ -f "${AUDIT_DIR}/http-headers.txt" ]]; then
        local headers
        headers=$(cat "${AUDIT_DIR}/http-headers.txt")

        # Check missing security headers
        if ! echo "$headers" | grep -qi "Strict-Transport-Security"; then
            add_finding "MEDIUM" "Security Headers" "Falta HSTS (HTTP Strict Transport Security)" \
                "No se encontró cabecera Strict-Transport-Security." \
                "Agregar: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        fi

        if ! echo "$headers" | grep -qi "Content-Security-Policy"; then
            add_finding "MEDIUM" "Security Headers" "Falta CSP (Content Security Policy)" \
                "No se encontró cabecera Content-Security-Policy." \
                "Implementar CSP para mitigar XSS y data injection."
        fi

        if ! echo "$headers" | grep -qi "X-Frame-Options\|frame-ancestors"; then
            add_finding "MEDIUM" "Security Headers" "Falta protección contra Clickjacking" \
                "No se detectó X-Frame-Options o CSP frame-ancestors." \
                "Agregar: X-Frame-Options: DENY o SAMEORIGIN"
        fi

        if ! echo "$headers" | grep -qi "X-Content-Type-Options"; then
            add_finding "LOW" "Security Headers" "Falta X-Content-Type-Options" \
                "No se encontró cabecera X-Content-Type-Options." \
                "Agregar: X-Content-Type-Options: nosniff"
        fi

        if echo "$headers" | grep -qi "Server:.*Apache/2\|Server:.*nginx/1\."; then
            add_finding "LOW" "Security Headers" "Versión del servidor expuesta en cabecera Server" \
                "La cabecera Server revela la versión exacta del software." \
                "Configurar ServerTokens minimal en Apache o server_tokens off en nginx."
        fi

        if echo "$headers" | grep -qi "X-Powered-By"; then
            add_finding "LOW" "Security Headers" "Versión de tecnología expuesta (X-Powered-By)" \
                "La cabecera X-Powered-By revela información de tecnologías backend." \
                "Eliminar o deshabilitar la cabecera X-Powered-By."
        fi
    fi

    local end_time
    end_time=$(date +%s)
    AUDIT_TIMING[malware]=$(( end_time - start_time ))
    log_ok "Malware Analysis completado en $(( AUDIT_TIMING[malware] / 60 ))m $(( AUDIT_TIMING[malware] % 60 ))s"
}

# ---- Phase 3: Brand Protection -------------------------------------------
audit_brand() {
    log_section "FASE 3: PROTECCIÓN DE MARCA"
    local start_time
    start_time=$(date +%s)

    local domain="${AUDIT_TARGET[domain]}"
    local url="${AUDIT_TARGET[url]}"

    # ----- 3.1 dnstwist — Typosquatting -----
    info "[1/4] dnstwist — Detectando typosquatting..."
    if cmd_exists dnstwist; then
        timed_run 180 dnstwist --registered "$domain" \
            > "${AUDIT_DIR}/osint/dnstwist.txt" 2>/dev/null || true

        if [[ -f "${AUDIT_DIR}/osint/dnstwist.txt" && -s "${AUDIT_DIR}/osint/dnstwist.txt" ]]; then
            local phishing_domains
            phishing_domains=$(grep -cv "^Domain\|^$" "${AUDIT_DIR}/osint/dnstwist.txt" 2>/dev/null || echo 0)
            if [[ "$phishing_domains" -gt 0 ]]; then
                add_finding "HIGH" "dnstwist" "${phishing_domains} dominios similares registrados" \
                    "Se encontraron dominios typosquatting registrados que podrían usarse para phishing." \
                    "Monitorear estos dominios. Considerar registrar variaciones críticas." \
                    "$(head -10 "${AUDIT_DIR}/osint/dnstwist.txt")"
            else
                log_ok "dnstwist: sin dominios typosquatting registrados"
            fi
        fi
    else
        warn "dnstwist no instalado — saltando"
    fi

    # ----- 3.2 theHarvester — OSINT -----
    info "[2/4] theHarvester — Recolección OSINT..."
    if cmd_exists theharvester; then
        timed_run 180 theharvester -d "$domain" -b all \
            -f "${AUDIT_DIR}/osint/theharvester.html" 2>/dev/null || true

        # Also save text version
        if [[ -f "${AUDIT_DIR}/osint/theharvester.html" ]]; then
            # Extract emails
            grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
                "${AUDIT_DIR}/osint/theharvester.html" 2>/dev/null \
                > "${AUDIT_DIR}/osint/theharvester-emails.txt" || true

            local email_count=0
            [[ -f "${AUDIT_DIR}/osint/theharvester-emails.txt" ]] && \
                email_count=$(wc -l < "${AUDIT_DIR}/osint/theharvester-emails.txt")

            if [[ "$email_count" -gt 0 ]]; then
                add_finding "MEDIUM" "theHarvester" "${email_count} correos electrónicos descubiertos públicamente" \
                    "Se encontraron direcciones de email asociadas al dominio en fuentes públicas." \
                    "Revisar qué información está expuesta. Usar aliases de correo para roles."
            fi
        fi
    else
        warn "theHarvester no instalado — saltando"
    fi

    # ----- 3.3 Sublist3r — Subdomain enumeration -----
    info "[3/4] Sublist3r — Enumeración de subdominios..."
    if cmd_exists sublist3r; then
        timed_run 180 sublist3r -d "$domain" \
            -o "${AUDIT_DIR}/osint/sublist3r.txt" 2>/dev/null || true

        if [[ -f "${AUDIT_DIR}/osint/sublist3r.txt" && -s "${AUDIT_DIR}/osint/sublist3r.txt" ]]; then
            local subdomain_count
            subdomain_count=$(wc -l < "${AUDIT_DIR}/osint/sublist3r.txt")
            add_finding "INFO" "Sublist3r" "${subdomain_count} subdominios descubiertos" \
                "Se descubrieron ${subdomain_count} subdominios asociados al dominio principal." \
                "Auditar cada subdominio. Ocultar o deshabilitar los no utilizados."

            # Check for interesting subdomains
            if grep -qi "dev\|test\|staging\|admin\|mail\|vpn\|remote\|gitlab\|jenkins\|jira\|confluence" \
                "${AUDIT_DIR}/osint/sublist3r.txt" 2>/dev/null; then
                add_finding "MEDIUM" "Sublist3r" "Subdominios de administración/internal expuestos" \
                    "Se encontraron subdominios con nombres de administración, desarrollo o internos." \
                    "Restringir acceso por IP o VPN. No exponer paneles de admin en internet."
            fi
        fi
    else
        warn "Sublist3r no instalado — saltando"
    fi

    # ----- 3.4 Credential leak check (via HIBP) -----
    info "[4/4] Have I Been Pwned — Verificación de fugas..."
    if cmd_exists hibp-check || cmd_exists hibp || cmd_exists pyhibp; then
        if [[ -f "${AUDIT_DIR}/osint/theharvester-emails.txt" ]]; then
            local check_tool
            check_tool=$(cmd_exists hibp && echo "hibp" || cmd_exists hibp-check && echo "hibp-check" || echo "")
            if [[ -n "$check_tool" ]]; then
                while IFS= read -r email; do
                    timed_run 30 "$check_tool" "$email" >> "${AUDIT_DIR}/osint/hibp-results.txt" 2>/dev/null || true
                done < "${AUDIT_DIR}/osint/theharvester-emails.txt"

                if [[ -f "${AUDIT_DIR}/osint/hibp-results.txt" && -s "${AUDIT_DIR}/osint/hibp-results.txt" ]]; then
                    if grep -qi "breach\|pwned\|compromised" "${AUDIT_DIR}/osint/hibp-results.txt" 2>/dev/null; then
                        add_finding "CRITICAL" "HIBP" "Correos corporativos filtrados en brechas de datos" \
                            "Se encontraron correos del dominio en brechas de seguridad conocidas." \
                            "Forzar cambio de contraseñas. Implementar 2FA. Revisar активности de cuentas." \
                            "$(head -10 "${AUDIT_DIR}/osint/hibp-results.txt")"
                    fi
                fi
            fi
        fi
    else
        info "  HIBP CLI no disponible — saltando verificación de fugas"
        info "  Instalar con: pip install hibp-cli"
    fi

    local end_time
    end_time=$(date +%s)
    AUDIT_TIMING[brand]=$(( end_time - start_time ))
    log_ok "Brand Protection completado en $(( AUDIT_TIMING[brand] / 60 ))m $(( AUDIT_TIMING[brand] % 60 ))s"
}

# ---- Phase 4: Incident Response Readiness ---------------------------------
audit_incident() {
    log_section "FASE 4: INCIDENT RESPONSE — EVALUACIÓN DE PREPARACIÓN"
    local start_time
    start_time=$(date +%s)

    local checks_passed=0
    local checks_failed=0
    local checks_total=0

    echo ""
    evaluate_check() {
        local id="$1"
        local title="$2"
        local status="$3"
        local recommendation="$4"
        checks_total=$(( checks_total + 1 ))

        if [[ "$status" == "pass" ]]; then
            echo -e "  ${FG_GRN}✓${RST} ${title}"
            checks_passed=$(( checks_passed + 1 ))
        else
            echo -e "  ${FG_RED}✗${RST} ${title}"
            checks_failed=$(( checks_failed + 1 ))
            if [[ "$status" == "fail" ]]; then
                add_finding "$5" "IR Readiness" "${title} — ${recommendation}" \
                    "Checklist de preparación: Falló la verificación de '${title}'." \
                    "$recommendation"
            fi
        fi
    }

    # 4.1 Wireshark/tcpdump availability
    if cmd_exists tcpdump; then
        evaluate_check "4.1" "Captura de paquetes (tcpdump)" "pass" ""
    else
        evaluate_check "4.1" "Captura de paquetes (tcpdump)" "fail" \
            "Instalar: sudo apt install tcpdump" "MEDIUM"
    fi

    # 4.2 Logging capabilities
    if cmd_exists rsyslogd || cmd_exists systemd-journald; then
        evaluate_check "4.2" "Logging del sistema (rsyslog/journald)" "pass" ""
    else
        evaluate_check "4.2" "Logging del sistema (rsyslog/journald)" "fail" \
            "Asegurar que rsyslog o systemd-journald estén en ejecución." "MEDIUM"
    fi

    # 4.3 Backup tools
    if cmd_exists rsync || cmd_exists duplicity || cmd_exists borg; then
        evaluate_check "4.3" "Herramientas de backup (rsync/borg)" "pass" ""
    else
        evaluate_check "4.3" "Herramientas de backup" "fail" \
            "Instalar: sudo apt install rsync borgbackup" "MEDIUM"
    fi

    # 4.4 Disk forensics
    if cmd_exists dd || cmd_exists dcfldd; then
        evaluate_check "4.4" "Adquisición forense (dd/dcfldd)" "pass" ""
    else
        evaluate_check "4.4" "Adquisición forense" "fail" \
            "Instalar: sudo apt install dcfldd" "LOW"
    fi

    # 4.5 Memory forensics
    if cmd_exists vol || cmd_exists volatility; then
        evaluate_check "4.5" "Análisis forense de memoria (Volatility)" "pass" ""
    else
        evaluate_check "4.5" "Análisis forense de memoria" "warn" \
            "Instalar: pip install volatility3" "LOW"
    fi

    # 4.6 File integrity monitoring
    if cmd_exists aide || cmd_exists tripwire; then
        evaluate_check "4.6" "Monitoreo de integridad (AIDE/Tripwire)" "pass" ""
    else
        evaluate_check "4.6" "Monitoreo de integridad" "warn" \
            "Instalar: sudo apt install aide" "MEDIUM"
    fi

    # 4.7 Centralized logging check
    if systemctl is-active rsyslog &>/dev/null || journalctl -n1 &>/dev/null 2>&1; then
        evaluate_check "4.7" "Logs centralizados operativos" "pass" ""
    else
        evaluate_check "4.7" "Logs centralizados" "warn" \
            "Configurar rsyslog para envío a servidor central de logs." "MEDIUM"
    fi

    echo ""
    log_ok "IR Readiness: ${checks_passed}/${checks_total} checks pasados"

    if [[ "$checks_failed" -gt 0 ]]; then
        add_finding "INFO" "IR Readiness" "${checks_failed} áreas de mejora en respuesta a incidentes" \
            "La evaluación de preparación encontró ${checks_failed} puntos a mejorar." \
            "Revisar cada recomendación y priorizar según el perfil de riesgo."
    fi

    local end_time
    end_time=$(date +%s)
    AUDIT_TIMING[incident]=$(( end_time - start_time ))
    log_ok "IR Readiness completado en $(( AUDIT_TIMING[incident] / 60 ))m $(( AUDIT_TIMING[incident] % 60 ))s"
}

# ---- Phase 5: SAST ----------------------------------------------------------

audit_sast() {
    log_section "FASE 5: SAST — STATIC APPLICATION SECURITY TESTING"
    local start_time
    start_time=$(date +%s)

    local domain="${AUDIT_TARGET[domain]}"
    local url="${AUDIT_TARGET[url]}"

    # ----- 5.1 Semgrep — Multi-language SAST scanning -----
    info "[1/4] Semgrep — Escaneo SAST multi-lenguaje..."
    if cmd_exists semgrep; then
        # Try to scan downloaded resources first, fallback to URL
        local semgrep_target="${AUDIT_DIR}/resources"
        if [[ -d "$semgrep_target" ]] && [[ "$(find "$semgrep_target" -type f 2>/dev/null | wc -l)" -gt 0 ]]; then
            timed_run 300 semgrep --quiet --metrics=off --config=auto \
                "$semgrep_target" 2>/dev/null \
                > "${AUDIT_DIR}/scans/sast/semgrep-results.txt" || true
        else
            # Scan from URL: download page source and scan
            timed_run 60 curl -sL --max-time 30 "$url" 2>/dev/null \
                > "${AUDIT_DIR}/scans/sast/page-source.html" || true
            if [[ -s "${AUDIT_DIR}/scans/sast/page-source.html" ]]; then
                timed_run 300 semgrep --quiet --metrics=off --config=auto \
                    "${AUDIT_DIR}/scans/sast/page-source.html" 2>/dev/null \
                    > "${AUDIT_DIR}/scans/sast/semgrep-results.txt" || true
            fi
        fi
        if [[ -s "${AUDIT_DIR}/scans/sast/semgrep-results.txt" ]]; then
            local findings_count
            findings_count=$(grep -c "finding:" "${AUDIT_DIR}/scans/sast/semgrep-results.txt" 2>/dev/null || echo "0")
            if [[ "$findings_count" -gt 0 ]]; then
                add_finding "MEDIUM" "Semgrep" "Semgrep detectó ${findings_count} hallazgos SAST" \
                    "Semgrep (configuración automática) encontró ${findings_count} posibles vulnerabilidades en los recursos escaneados." \
                    "Revise ${AUDIT_DIR}/scans/sast/semgrep-results.txt y corrija los hallazgos según prioridad." \
                    "Resultados en: scans/sast/semgrep-results.txt"
            else
                add_finding "INFO" "Semgrep" "Semgrep completado: sin hallazgos críticos" \
                    "El escaneo SAST con Semgrep no detectó vulnerabilidades significativas." \
                    "Monitoreo continuo recomendado."
            fi
        else
            add_finding "INFO" "Semgrep" "Semgrep ejecutado sin resultados" \
                "El escaneo SAST con Semgrep no produjo resultados (puede no haber código fuente disponible)." \
                "Para un análisis completo, ejecute Semgrep directamente sobre el repositorio."
        fi
    else
        add_finding "INFO" "Semgrep" "Semgrep no instalado — escaneo SAST omitido" \
            "Semgrep no está disponible en este sistema." \
            "Instale Semgrep: pip install semgrep"
    fi
    echo ""

    # ----- 5.2 TruffleHog — Secret scanning -----
    info "[2/4] TruffleHog — Buscando secretos..."
    if cmd_exists trufflehog; then
        # TruffleHog filesystem scan on downloaded resources
        if [[ -d "${AUDIT_DIR}/resources" ]] && [[ "$(find "${AUDIT_DIR}/resources" -type f 2>/dev/null | wc -l)" -gt 0 ]]; then
            timed_run 180 trufflehog filesystem --no-verification \
                "${AUDIT_DIR}/resources" 2>/dev/null \
                > "${AUDIT_DIR}/scans/sast/trufflehog-results.txt" || true
            if [[ -s "${AUDIT_DIR}/scans/sast/trufflehog-results.txt" ]]; then
                local secret_count
                secret_count=$(wc -l < "${AUDIT_DIR}/scans/sast/trufflehog-results.txt")
                add_finding "HIGH" "TruffleHog" "Posibles secretos detectados en recursos (${secret_count} hallazgos)" \
                    "TruffleHog encontró ${secret_count} posibles secretos/credenciales en los recursos descargados." \
                    "Revise cada hallazgo en ${AUDIT_DIR}/scans/sast/trufflehog-results.txt y rote credenciales reales." \
                    "Resultados en: scans/sast/trufflehog-results.txt"
            else
                add_finding "INFO" "TruffleHog" "TruffleHog completado: sin secretos detectados" \
                    "No se encontraron secretos hardcodeados en los recursos analizados." \
                    "Continúe monitoreando con escaneos periódicos."
            fi
        else
            add_finding "INFO" "TruffleHog" "TruffleHog: sin recursos para escanear" \
                "No hay recursos descargados para escanear en busca de secretos." \
                "Ejecute TruffleHog directamente sobre el repositorio para un análisis completo."
        fi
    else
        add_finding "INFO" "TruffleHog" "TruffleHog no instalado — escaneo de secretos omitido" \
            "TruffleHog no está disponible en este sistema." \
            "Instale TruffleHog: pip install trufflehog"
    fi
    echo ""

    # ----- 5.3 Gitleaks — Git secret scanning -----
    info "[3/4] Gitleaks — Buscando secretos en repositorios Git..."
    if cmd_exists gitleaks; then
        # Check if there's a git repo in resources
        if [[ -d "${AUDIT_DIR}/resources/.git" ]]; then
            timed_run 180 gitleaks detect --source="${AUDIT_DIR}/resources" \
                --no-git --verbose 2>/dev/null \
                > "${AUDIT_DIR}/scans/sast/gitleaks-results.txt" || true
            if [[ -s "${AUDIT_DIR}/scans/sast/gitleaks-results.txt" ]]; then
                local leak_count
                leak_count=$(grep -c "Leak:" "${AUDIT_DIR}/scans/sast/gitleaks-results.txt" 2>/dev/null || echo "0")
                add_finding "HIGH" "Gitleaks" "Posibles fugas de credenciales en repositorio Git" \
                    "Gitleaks detectó posibles credenciales hardcodeadas en el repositorio Git." \
                    "Revise ${AUDIT_DIR}/scans/sast/gitleaks-results.txt y elimine secretos del historial Git."
            else
                add_finding "INFO" "Gitleaks" "Gitleaks completado: sin fugas detectadas" \
                    "No se encontraron secretos en el historial Git analizado." \
                    "Mantenga Gitleaks en su pipeline CI/CD."
            fi
        else
            add_finding "INFO" "Gitleaks" "Gitleaks: sin repositorio Git para escanear" \
                "No se detectó un repositorio Git en los recursos descargados." \
                "Ejecute Gitleaks directamente sobre el repositorio."
        fi
    else
        add_finding "INFO" "Gitleaks" "Gitleaks no instalado — escaneo Git omitido" \
            "Gitleaks no está disponible en este sistema." \
            "Instale Gitleaks: go install github.com/gitleaks/gitleaks/v8@latest"
    fi
    echo ""

    # ----- 5.4 Bandit — Python SAST -----
    info "[4/4] Bandit — Analizando código Python..."
    if cmd_exists bandit; then
        local py_files
        py_files=$(find "${AUDIT_DIR}/resources" -name "*.py" -type f 2>/dev/null | head -20)
        if [[ -n "$py_files" ]]; then
            timed_run 120 bandit -r -q -f json \
                "${AUDIT_DIR}/resources" 2>/dev/null \
                > "${AUDIT_DIR}/scans/sast/bandit-results.json" || true
            if [[ -s "${AUDIT_DIR}/scans/sast/bandit-results.json" ]]; then
                local bandit_count
                bandit_count=$(python3 -c "import json; d=json.load(open('${AUDIT_DIR}/scans/sast/bandit-results.json')); print(len(d.get('results',[])))" 2>/dev/null || echo "0")
                if [[ "$bandit_count" -gt 0 ]]; then
                    add_finding "MEDIUM" "Bandit" "Bandit detectó ${bandit_count} problemas de seguridad en código Python" \
                        "Bandit encontró ${bandit_count} posibles vulnerabilidades en archivos Python." \
                        "Revise ${AUDIT_DIR}/scans/sast/bandit-results.json y corrija según severidad." \
                        "Resultados en: scans/sast/bandit-results.json"
                else
                    add_finding "INFO" "Bandit" "Bandit completado: código Python sin problemas" \
                        "El análisis SAST de código Python no encontró vulnerabilidades." \
                        "Mantenga Bandit en su pipeline CI/CD."
                fi
            fi
        else
            add_finding "INFO" "Bandit" "Bandit: sin archivos Python para analizar" \
                "No se encontraron archivos .py en los recursos descargados." \
                "Ejecute Bandit directamente sobre el repositorio si contiene código Python."
        fi
    else
        add_finding "INFO" "Bandit" "Bandit no instalado — análisis Python omitido" \
            "Bandit no está disponible en este sistema." \
            "Instale Bandit: pip install bandit"
    fi
    echo ""

    local end_time
    end_time=$(date +%s)
    AUDIT_TIMING[sast]=$(( end_time - start_time ))
    log_ok "SAST completado en $(( AUDIT_TIMING[sast] / 60 ))m $(( AUDIT_TIMING[sast] % 60 ))s"
}

# ---- Phase 6: SCA + SBOM ----------------------------------------------------

audit_sca() {
    log_section "FASE 6: SCA + SBOM — DEPENDENCY & SUPPLY CHAIN SECURITY"
    local start_time
    start_time=$(date +%s)

    local domain="${AUDIT_TARGET[domain]}"
    local url="${AUDIT_TARGET[url]}"

    # ----- 6.1 Trivy — Filesystem vulnerability scan -----
    info "[1/5] Trivy — Escaneo de vulnerabilidades..."
    if cmd_exists trivy; then
        local trivy_target="${AUDIT_DIR}/resources"
        if [[ -d "$trivy_target" ]] && [[ "$(find "$trivy_target" -type f 2>/dev/null | wc -l)" -gt 0 ]]; then
            timed_run 300 trivy fs --quiet --sca=true \
                --severity CRITICAL,HIGH,MEDIUM \
                "$trivy_target" 2>/dev/null \
                > "${AUDIT_DIR}/scans/sca/trivy-fs-results.txt" || true
            if [[ -s "${AUDIT_DIR}/scans/sca/trivy-fs-results.txt" ]]; then
                local trivy_count
                trivy_count=$(grep -c "Total:" "${AUDIT_DIR}/scans/sca/trivy-fs-results.txt" 2>/dev/null || echo "0")
                add_finding "MEDIUM" "Trivy" "Trivy detectó vulnerabilidades en el sistema de archivos" \
                    "Trivy escaneó los recursos descargados y encontró vulnerabilidades en dependencias." \
                    "Revise ${AUDIT_DIR}/scans/sca/trivy-fs-results.txt y actualice las dependencias afectadas." \
                    "Resultados en: scans/sca/trivy-fs-results.txt"
            else
                add_finding "INFO" "Trivy" "Trivy completado: sin vulnerabilidades detectadas" \
                    "No se encontraron vulnerabilidades conocidas en los recursos analizados." \
                    "Mantenga escaneos periódicos con la base de datos actualizada."
            fi
        else
            add_finding "INFO" "Trivy" "Trivy: sin recursos para escanear" \
                "No hay recursos descargados para análisis SCA." \
                "Ejecute Trivy directamente sobre el proyecto con: trivy fs /ruta/al/proyecto"
        fi
    else
        add_finding "INFO" "Trivy" "Trivy no instalado — escaneo SCA omitido" \
            "Trivy no está disponible en este sistema." \
            "Instale Trivy siguiendo la guía oficial."
    fi
    echo ""

    # ----- 6.2 OWASP Dependency-Check -----
    info "[2/5] OWASP Dependency-Check — Análisis de dependencias..."
    if cmd_exists dependency-check && cmd_exists java; then
        if [[ -d "${AUDIT_DIR}/resources" ]]; then
            timed_run 300 dependency-check --scan "${AUDIT_DIR}/resources" \
                --format JSON --out "${AUDIT_DIR}/scans/sca/" \
                2>/dev/null || true
            local depcheck_file="${AUDIT_DIR}/scans/sca/dependency-check-report.json"
            if [[ -s "$depcheck_file" ]]; then
                local dep_count
                dep_count=$(python3 -c "
import json
try:
    with open('${depcheck_file}') as f:
        d = json.load(f)
    print(len(d.get('dependencies', [])))
except:
    print('0')
" 2>/dev/null || echo "0")
                add_finding "MEDIUM" "Dependency-Check" "OWASP Dependency-Check analizó ${dep_count} dependencias" \
                    "Se identificaron dependencias con posibles vulnerabilidades conocidas." \
                    "Revise el reporte en ${AUDIT_DIR}/scans/sca/ y actualice las librerías vulnerables." \
                    "Reporte en: scans/sca/dependency-check-report.json"
            fi
        fi
    else
        add_finding "INFO" "Dependency-Check" "Dependency-Check no disponible — requiere Java" \
            "OWASP Dependency-Check no está instalado o Java no está disponible." \
            "Instale: pip install dependency-check && sudo apt install default-jre"
    fi
    echo ""

    # ----- 6.3 Syft — SBOM Generation -----
    info "[3/5] Syft — Generando SBOM (CycloneDX + SPDX)..."
    if cmd_exists syft; then
        if [[ -d "${AUDIT_DIR}/resources" ]] && [[ "$(find "${AUDIT_DIR}/resources" -type f 2>/dev/null | wc -l)" -gt 0 ]]; then
            # CycloneDX format
            timed_run 120 syft "${AUDIT_DIR}/resources" -o cyclonedx-json \
                > "${AUDIT_DIR}/sbom/sbom-cyclonedx.json" 2>/dev/null || true
            # SPDX format
            timed_run 120 syft "${AUDIT_DIR}/resources" -o spdx-json \
                > "${AUDIT_DIR}/sbom/sbom-spdx.json" 2>/dev/null || true

            if [[ -s "${AUDIT_DIR}/sbom/sbom-cyclonedx.json" ]]; then
                local pkg_count
                pkg_count=$(python3 -c "
import json
try:
    with open('${AUDIT_DIR}/sbom/sbom-cyclonedx.json') as f:
        d = json.load(f)
    print(len(d.get('components', [])))
except:
    print('0')
" 2>/dev/null || echo "0")
                add_finding "INFO" "Syft" "SBOM generado (CycloneDX + SPDX) — ${pkg_count} componentes" \
                    "Se generó el SBOM en formatos CycloneDX y SPDX con ${pkg_count} componentes identificados." \
                    "Use estos SBOM para tracking de dependencias y escaneo con Grype." \
                    "SBOMs en: sbom/sbom-cyclonedx.json, sbom/sbom-spdx.json"
            fi
        else
            add_finding "INFO" "Syft" "Syft: sin recursos para generar SBOM" \
                "No hay recursos descargados para generar el SBOM." \
                "Ejecute Syft directamente sobre el proyecto."
        fi
    else
        add_finding "INFO" "Syft" "Syft no instalado — generación de SBOM omitida" \
            "Syft no está disponible en este sistema." \
            "Instale Syft: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
    fi
    echo ""

    # ----- 6.4 Grype — Vulnerability scan on SBOM -----
    info "[4/5] Grype — Escaneo de vulnerabilidades sobre SBOM..."
    if cmd_exists grype; then
        if [[ -s "${AUDIT_DIR}/sbom/sbom-cyclonedx.json" ]]; then
            timed_run 180 grype "${AUDIT_DIR}/sbom/sbom-cyclonedx.json" \
                -o json 2>/dev/null \
                > "${AUDIT_DIR}/scans/sca/grype-results.json" || true
            if [[ -s "${AUDIT_DIR}/scans/sca/grype-results.json" ]]; then
                local grype_count
                grype_count=$(python3 -c "
import json
try:
    with open('${AUDIT_DIR}/scans/sca/grype-results.json') as f:
        d = json.load(f)
    print(len(d.get('matches', [])))
except:
    print('0')
" 2>/dev/null || echo "0")
                if [[ "$grype_count" -gt 0 ]]; then
                    add_finding "HIGH" "Grype" "Grype detectó ${grype_count} vulnerabilidades en dependencias (desde SBOM)" \
                        "Escaneo sobre SBOM encontró ${grype_count} vulnerabilidades en las dependencias identificadas." \
                        "Revise ${AUDIT_DIR}/scans/sca/grype-results.json y remédielas según severidad." \
                        "Resultados en: scans/sca/grype-results.json"
                else
                    add_finding "INFO" "Grype" "Grype completado: sin vulnerabilidades en SBOM" \
                        "No se encontraron vulnerabilidades conocidas en las dependencias del SBOM." \
                        "Mantenga escaneos periódicos."
                fi
            fi
        else
            add_finding "INFO" "Grype" "Grype: sin SBOM para escanear" \
                "No hay SBOM disponible. Ejecute Syft primero para generar el SBOM." \
                "Pipeline recomendado: syft → grype"
        fi
    else
        add_finding "INFO" "Grype" "Grype no instalado — escaneo SBOM omitido" \
            "Grype no está disponible en este sistema." \
            "Instale Grype: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
    fi
    echo ""

    # ----- 6.5 OSV-Scanner -----
    info "[5/5] OSV-Scanner — Escaneo adicional con base OSV.dev..."
    if cmd_exists osv-scanner; then
        if [[ -s "${AUDIT_DIR}/sbom/sbom-cyclonedx.json" ]]; then
            timed_run 120 osv-scanner --sbom="${AUDIT_DIR}/sbom/sbom-cyclonedx.json" \
                --format json 2>/dev/null \
                > "${AUDIT_DIR}/scans/sca/osv-scanner-results.json" || true
            if [[ -s "${AUDIT_DIR}/scans/sca/osv-scanner-results.json" ]]; then
                local osv_count
                osv_count=$(python3 -c "
import json
try:
    with open('${AUDIT_DIR}/scans/sca/osv-scanner-results.json') as f:
        d = json.load(f)
    print(len(d.get('results', [])))
except:
    print('0')
" 2>/dev/null || echo "0")
                add_finding "MEDIUM" "OSV-Scanner" "OSV-Scanner reportó resultados de vulnerabilidades" \
                    "Escaneo adicional con la base OSV.dev encontró resultados para las dependencias." \
                    "Revise ${AUDIT_DIR}/scans/sca/osv-scanner-results.json para más detalles." \
                    "Resultados en: scans/sca/osv-scanner-results.json"
            fi
        else
            # Try recursive directory scan
            if [[ -d "${AUDIT_DIR}/resources" ]]; then
                timed_run 120 osv-scanner -r "${AUDIT_DIR}/resources" \
                    --format json 2>/dev/null \
                    > "${AUDIT_DIR}/scans/sca/osv-scanner-results.json" || true
            fi
        fi
    else
        add_finding "INFO" "OSV-Scanner" "OSV-Scanner no instalado — escaneo omitido" \
            "OSV-Scanner no está disponible en este sistema." \
            "Instale: go install github.com/google/osv-scanner/cmd/osv-scanner@latest"
    fi
    echo ""

    local end_time
    end_time=$(date +%s)
    AUDIT_TIMING[sca]=$(( end_time - start_time ))
    log_ok "SCA + SBOM completado en $(( AUDIT_TIMING[sca] / 60 ))m $(( AUDIT_TIMING[sca] % 60 ))s"
}

# ---- Report Generator ----------------------------------------------------

audit_generate_report_txt() {
    local file="${AUDIT_DIR}/reports/audit-report.txt"

    {
        echo "═══════════════════════════════════════════════════════════════"
        echo "  PaginasAudit Cyber Audit — Reporte de Auditoría Automatizada"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "  Fecha:       $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Target:      ${AUDIT_TARGET[url]}"
        echo "  Dominio:     ${AUDIT_TARGET[domain]}"
        echo "  IP:          ${AUDIT_TARGET[ip]}"
        echo "  Estado:      ${AUDIT_TARGET[status]}"
        echo "  WAF:         ${AUDIT_TARGET[waf]}"
        echo "  Tecnologías: ${AUDIT_TARGET[technologies]}"
        echo "  Duración:    $(( ( $(date +%s) - AUDIT_START_TIME ) / 60 ))m"
        echo ""

        # Executive Summary
        echo "═══════════════════════════════════════════════════════════════"
        echo "  1. RESUMEN EJECUTIVO"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        local total=$(findings_total)
        local crit=$(findings_count "CRITICAL")
        local high=$(findings_count "HIGH")
        local med=$(findings_count "MEDIUM")
        local low=$(findings_count "LOW")
        local info=$(findings_count "INFO")
        echo "  Total hallazgos: ${total}"
        echo "  🛑  CRÍTICOS:  ${crit}"
        echo "  ⚠️   ALTOS:     ${high}"
        echo "  ⚡  MEDIOS:    ${med}"
        echo "  ℹ️   BAJOS:     ${low}"
        echo "  📌  INFO:      ${info}"
        echo ""

        # Risk score
        local risk_score=$(( crit * 10 + high * 5 + med * 2 + low * 1 ))
        local risk_label="BAJO"
        [[ $risk_score -gt 10 ]] && risk_label="MEDIO"
        [[ $risk_score -gt 25 ]] && risk_label="ALTO"
        [[ $risk_score -gt 50 ]] && risk_label="CRÍTICO"
        echo "  Risk Score: ${risk_score} — ${risk_label}"
        echo ""

        # Findings by severity
        echo "═══════════════════════════════════════════════════════════════"
        echo "  2. HALLAZGOS"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        local sev_order=("CRITICAL" "HIGH" "MEDIUM" "LOW" "INFO")
        for sev in "${sev_order[@]}"; do
            local count=$(findings_count "$sev")
            [[ "$count" -eq 0 ]] && continue
            echo "  ── [${sev}] ──"
            echo ""
            for finding in "${AUDIT_FINDINGS[@]}"; do
                IFS='|' read -r fsev fsrc ftitle fdetail frec fevidence <<< "$finding"
                [[ "$fsev" != "$sev" ]] && continue
                echo "    • ${ftitle}"
                echo "      Fuente: ${fsrc}"
                echo "      Detalle: ${fdetail}"
                echo "      Recomendación: ${frec}"
                [[ -n "$fevidence" ]] && echo "      Evidencia: ${fevidence:0:200}"
                echo ""
            done
        done

        # Technologies detected
        echo "═══════════════════════════════════════════════════════════════"
        echo "  3. TECNOLOGÍAS DETECTADAS"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        if [[ -f "${AUDIT_DIR}/scans/web/whatweb.txt" ]]; then
            cat "${AUDIT_DIR}/scans/web/whatweb.txt"
        else
            echo "  No disponible"
        fi
        echo ""

        # Open ports
        echo "═══════════════════════════════════════════════════════════════"
        echo "  4. PUERTOS Y SERVICIOS"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        if [[ -f "${AUDIT_DIR}/scans/nmap/quick-scan.txt" ]]; then
            grep "^[0-9]" "${AUDIT_DIR}/scans/nmap/quick-scan.txt" 2>/dev/null || echo "  Sin puertos abiertos detectados"
        else
            echo "  No disponible"
        fi
        echo ""

        # Timing
        echo "═══════════════════════════════════════════════════════════════"
        echo "  5. TIEMPOS DE EJECUCIÓN"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        for phase in assessment malware brand incident sast sca; do
            local secs=${AUDIT_TIMING[$phase]:-0}
            printf "  %-20s %2dm %2ds\n" "${phase}:" $(( secs / 60 )) $(( secs % 60 ))
        done
        echo ""

        echo "═══════════════════════════════════════════════════════════════"
        echo "  Fin del reporte — Generado por PaginasAudit Cyber Audit"
        echo "═══════════════════════════════════════════════════════════════"
    } > "$file"

    log_ok "Reporte TXT: ${file}"
    echo "$file"
}

audit_generate_report_json() {
    local file="${AUDIT_DIR}/reports/audit-report.json"

    local json="{"
    json+="\"meta\":{"
    json+="\"date\":\"$(date -Iseconds)\","
    json+="\"version\":\"${VERSION:-1.0.0}\""
    json+="},"
    json+="\"target\":{"
    json+="\"url\":\"${AUDIT_TARGET[url]}\","
    json+="\"domain\":\"${AUDIT_TARGET[domain]}\","
    json+="\"ip\":\"${AUDIT_TARGET[ip]}\","
    json+="\"status\":\"${AUDIT_TARGET[status]}\","
    local waf_val="${AUDIT_TARGET[waf]:-N/A}"
    json+="\"waf\":\"${waf_val//\"/\\\"}\","
    json+="\"technologies\":\"${AUDIT_TARGET[technologies]//\"/\\\"}\""
    json+="},"

    local all_findings=$(findings_total)
    json+="\"summary\":{"
    json+="\"total\":${all_findings},"
    json+="\"critical\":$(findings_count "CRITICAL"),"
    json+="\"high\":$(findings_count "HIGH"),"
    json+="\"medium\":$(findings_count "MEDIUM"),"
    json+="\"low\":$(findings_count "LOW"),"
    json+="\"info\":$(findings_count "INFO")"
    json+="},"

    json+="\"findings\":["
    local first=true
    for finding in "${AUDIT_FINDINGS[@]}"; do
        $first || json+=","
        first=false
        IFS='|' read -r sev src title detail rec evid <<< "$finding"
        json+="{"
        json+="\"severity\":\"${sev}\","
        json+="\"source\":\"${src//\"/\\\"}\","
        json+="\"title\":\"${title//\"/\\\"}\","
        json+="\"detail\":\"${detail//\"/\\\"}\","
        json+="\"recommendation\":\"${rec//\"/\\\"}\""
        json+="}"
    done
    json+="],"

    json+="\"timing\":{"
    local first_phase=true
    for phase in assessment malware brand incident sast sca; do
        $first_phase || json+=","
        first_phase=false
        json+="\"${phase}\":${AUDIT_TIMING[$phase]:-0}"
    done
    json+="}"
    json+="}"

    printf '%s\n' "$json" > "$file"
    log_ok "Reporte JSON: ${file}"
    echo "$file"
}

audit_generate_report_html() {
    local file="${AUDIT_DIR}/reports/audit-report.html"

    local total=$(findings_total)
    local crit=$(findings_count "CRITICAL")
    local high=$(findings_count "HIGH")
    local med=$(findings_count "MEDIUM")
    local low=$(findings_count "LOW")
    local info=$(findings_count "INFO")
    local risk_score=$(( crit * 10 + high * 5 + med * 2 + low * 1 ))
    local risk_label="BAJO"
    [[ $risk_score -gt 10 ]] && risk_label="MEDIO"
    [[ $risk_score -gt 25 ]] && risk_label="ALTO"
    [[ $risk_score -gt 50 ]] && risk_label="CRÍTICO"

    # Build findings HTML
    local findings_html=""
    local sev_order=("CRITICAL" "HIGH" "MEDIUM" "LOW" "INFO")
    local sev_colors=("#dc3545" "#fd7e14" "#ffc107" "#0dcaf0" "#6c757d")
    local sev_i=0
    for sev in "${sev_order[@]}"; do
        local count=$(findings_count "$sev")
        [[ "$count" -eq 0 ]] && continue
        local color="${sev_colors[$sev_i]}"
        findings_html+="<h3 style='color:${color};'>${sev} (${count})</h3>"
        findings_html+="<div class='findings-group'>"
        for finding in "${AUDIT_FINDINGS[@]}"; do
            IFS='|' read -r fsev fsrc ftitle fdetail frec fevidence <<< "$finding"
            [[ "$fsev" != "$sev" ]] && continue
            findings_html+="<div class='finding'>"
            findings_html+="  <div class='finding-title'><strong>${ftitle}</strong> <span class='tag'>${fsrc}</span></div>"
            findings_html+="  <div class='finding-detail'>${fdetail}</div>"
            findings_html+="  <div class='finding-rec'><em>Recomendación:</em> ${frec}</div>"
            [[ -n "$fevidence" ]] && findings_html+="  <pre class='finding-evidence'>${fevidence}</pre>"
            findings_html+="</div>"
        done
        findings_html+="</div>"
        sev_i=$(( sev_i + 1 ))
    done

    # Ports HTML
    local ports_html=""
    if [[ -f "${AUDIT_DIR}/scans/nmap/quick-scan.txt" ]]; then
        ports_html=$(grep "^[0-9]" "${AUDIT_DIR}/scans/nmap/quick-scan.txt" 2>/dev/null | head -30 | sed 's/$/<br>/') || true
    fi

    # Technologies HTML
    local tech_html=""
    if [[ -f "${AUDIT_DIR}/scans/web/whatweb.txt" ]]; then
        tech_html=$(cat "${AUDIT_DIR}/scans/web/whatweb.txt" | sed 's/$/<br>/') || true
    fi

    # JavaScript for interactivity
    local js='
    <script>
    function filterSeverity(sev) {
        document.querySelectorAll(".findings-group").forEach(function(g) {
            g.style.display = sev === "all" ? "block" : "none";
        });
        if (sev !== "all") {
            document.querySelectorAll("h3").forEach(function(h) {
                if (h.textContent.includes(sev)) {
                    h.nextElementSibling.style.display = "block";
                }
            });
        }
    }
    function toggleSection(id) {
        var el = document.getElementById(id);
        el.style.display = el.style.display === "none" ? "block" : "none";
    }
    </script>'

    # ⚠️  Heredoc con delimiter sin comillas para que bash expanda ${AUDIT_TARGET[url]}, etc.
    #     Los ${} de JavaScript (risk_score, risk_label) se escapan con \$ para que NO se expandan
    cat > "$file" << HTMLEOF
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PaginasAudit Audit Report — ${AUDIT_TARGET[domain]}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }
  .container { max-width: 1100px; margin: 0 auto; }
  h1 { color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; margin-bottom: 20px; }
  h2 { color: #8b949e; margin: 20px 0 10px; cursor: pointer; user-select: none; }
  h3 { margin: 15px 0 10px; }
  .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin: 15px 0; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px; text-align: center; }
  .card .num { font-size: 28px; font-weight: bold; }
  .card .label { font-size: 12px; color: #8b949e; text-transform: uppercase; }
  .risk-meter { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin: 15px 0; text-align: center; }
  .risk-meter .score { font-size: 48px; font-weight: bold; }
  .risk-meter .label { font-size: 14px; color: #8b949e; }
  .meta-grid { display: grid; grid-template-columns: auto 1fr; gap: 5px 15px; margin: 10px 0; }
  .meta-key { color: #8b949e; }
  .finding { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; margin: 8px 0; }
  .finding-title { margin-bottom: 5px; }
  .tag { display: inline-block; background: #21262d; color: #8b949e; border-radius: 3px; padding: 1px 6px; font-size: 11px; margin-left: 8px; }
  .finding-detail { color: #8b949e; font-size: 13px; margin: 5px 0; }
  .finding-rec { color: #58a6ff; font-size: 13px; margin: 5px 0; }
  pre { background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 10px; font-size: 12px; overflow-x: auto; margin: 5px 0; color: #7ee787; }
  .section-content { display: none; margin: 10px 0; }
  .section-content.active { display: block; }
  .footer { text-align: center; color: #30363d; font-size: 12px; margin-top: 40px; padding-top: 20px; border-top: 1px solid #30363d; }
  @media print { body { background: white; color: black; } .card, .finding, .risk-meter { background: #f6f8fa; border-color: #d0d7de; } }
</style>
${js}
</head>
<body>
<div class="container">
  <h1>🛡️ PaginasAudit Cyber Audit Report</h1>

  <div class="meta-grid">
    <span class="meta-key">Target:</span><span>${AUDIT_TARGET[url]}</span>
    <span class="meta-key">Domain:</span><span>${AUDIT_TARGET[domain]}</span>
    <span class="meta-key">IP:</span><span>${AUDIT_TARGET[ip]}</span>
    <span class="meta-key">Date:</span><span>$(date '+%Y-%m-%d %H:%M:%S')</span>
    <span class="meta-key">Status:</span><span>${AUDIT_TARGET[status]}</span>
    <span class="meta-key">WAF:</span><span>${AUDIT_TARGET[waf]}</span>
  </div>

  <h2>📊 Executive Summary</h2>
  <div class="summary-cards">
    <div class="card"><div class="num" style="color:#dc3545;">${crit}</div><div class="label">Critical</div></div>
    <div class="card"><div class="num" style="color:#fd7e14;">${high}</div><div class="label">High</div></div>
    <div class="card"><div class="num" style="color:#ffc107;">${med}</div><div class="label">Medium</div></div>
    <div class="card"><div class="num" style="color:#0dcaf0;">${low}</div><div class="label">Low</div></div>
    <div class="card"><div class="num" style="color:#6c757d;">${info}</div><div class="label">Info</div></div>
    <div class="card"><div class="num" style="color:#58a6ff;">${total}</div><div class="label">Total</div></div>
  </div>

  <div class="risk-meter">
    <div class="score" style="color: \${risk_score > 50 ? '#dc3545' : risk_score > 25 ? '#fd7e14' : risk_score > 10 ? '#ffc107' : '#0dcaf0'}">\${risk_score}</div>
    <div class="label">Risk Score — \${risk_label}</div>
  </div>

  <h2 onclick="toggleSection('findings-section')">🔍 Findings ▾</h2>
  <div id="findings-section" class="section-content active">
    <div style="margin:10px 0;">
      <button onclick="filterSeverity('all')" style="background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:4px;padding:4px 10px;margin:2px;cursor:pointer;">All</button>
      <button onclick="filterSeverity('CRITICAL')" style="background:#dc3545;color:white;border:none;border-radius:4px;padding:4px 10px;margin:2px;cursor:pointer;">Critical</button>
      <button onclick="filterSeverity('HIGH')" style="background:#fd7e14;color:white;border:none;border-radius:4px;padding:4px 10px;margin:2px;cursor:pointer;">High</button>
      <button onclick="filterSeverity('MEDIUM')" style="background:#ffc107;color:black;border:none;border-radius:4px;padding:4px 10px;margin:2px;cursor:pointer;">Medium</button>
      <button onclick="filterSeverity('LOW')" style="background:#0dcaf0;color:black;border:none;border-radius:4px;padding:4px 10px;margin:2px;cursor:pointer;">Low</button>
      <button onclick="filterSeverity('INFO')" style="background:#6c757d;color:white;border:none;border-radius:4px;padding:4px 10px;margin:2px;cursor:pointer;">Info</button>
    </div>
    ${findings_html}
  </div>

  <h2 onclick="toggleSection('tech-section')">⚙️ Technologies ▾</h2>
  <div id="tech-section" class="section-content">
    <pre>${tech_html}</pre>
  </div>

  <h2 onclick="toggleSection('ports-section')">🔌 Open Ports ▾</h2>
  <div id="ports-section" class="section-content">
    <pre>${ports_html:-<p style="color:#8b949e;">No port scan data available</p>}</pre>
  </div>

  <h2 onclick="toggleSection('timing-section')">⏱️ Execution Timing ▾</h2>
  <div id="timing-section" class="section-content">
    <div class="meta-grid">
      <span class="meta-key">Assessment:</span><span>$(( ${AUDIT_TIMING[assessment]:-0} / 60 ))m $(( ${AUDIT_TIMING[assessment]:-0} % 60 ))s</span>
      <span class="meta-key">Malware Analysis:</span><span>$(( ${AUDIT_TIMING[malware]:-0} / 60 ))m $(( ${AUDIT_TIMING[malware]:-0} % 60 ))s</span>
      <span class="meta-key">Brand Protection:</span><span>$(( ${AUDIT_TIMING[brand]:-0} / 60 ))m $(( ${AUDIT_TIMING[brand]:-0} % 60 ))s</span>
      <span class="meta-key">Incident Response:</span><span>$(( ${AUDIT_TIMING[incident]:-0} / 60 ))m $(( ${AUDIT_TIMING[incident]:-0} % 60 ))s</span>
      <span class="meta-key">SAST:</span><span>$(( ${AUDIT_TIMING[sast]:-0} / 60 ))m $(( ${AUDIT_TIMING[sast]:-0} % 60 ))s</span>
      <span class="meta-key">SCA+SBOM:</span><span>$(( ${AUDIT_TIMING[sca]:-0} / 60 ))m $(( ${AUDIT_TIMING[sca]:-0} % 60 ))s</span>
      <span class="meta-key">Total:</span><span>$(( ( $(date +%s) - AUDIT_START_TIME ) / 60 ))m</span>
    </div>
  </div>

  <div class="footer">
    Generated by PaginasAudit Cyber Audit Installer v${VERSION:-1.0.0} | $(date '+%Y-%m-%d %H:%M:%S')
  </div>
</div>
</body>
</html>
HTMLEOF

    log_ok "Reporte HTML: ${file}"
    echo "$file"
}

# ---- DOCX Report Generator ------------------------------------------------

audit_generate_report_docx() {
    local json_file="${AUDIT_DIR}/reports/audit-report.json"
    local docx_file="${AUDIT_DIR}/reports/audit-report.docx"

    log_info "Generando reporte DOCX profesional..."

    # Check prerequisites
    if ! command -v python3 &>/dev/null; then
        log_warn "python3 no disponible — saltando generación DOCX"
        return 1
    fi

    # Check if json report exists
    if [[ ! -f "$json_file" ]]; then
        log_warn "Reporte JSON no encontrado en ${json_file}"
        return 1
    fi

    # Find the docx report generator script
    local docx_script="${SCRIPT_DIR}/lib/docx_report.py"
    if [[ ! -f "$docx_script" ]]; then
        log_warn "Script generador DOCX no encontrado: ${docx_script}"
        return 1
    fi

    # Check python-docx availability (should be installed by install_core_deps)
    if ! python3 -c "import docx" 2>/dev/null; then
        log_warn "python-docx no instalado (ejecute '--install-all' o 'pip3 install python-docx')"
        return 1
    fi

    # Generate DOCX
    log_info "Ejecutando generador DOCX..."
    # 🛡️ Capturar stderr real de Python — antes PIPESTATUS[0] apuntaba al while loop,
    #    no al comando python3. Ahora usamos un archivo temporal para stderr.
    local docx_err
    docx_err=$(mktemp /tmp/docx_err.XXXXXX 2>/dev/null || echo "/tmp/docx_err.tmp")
    python3 "$docx_script" "$json_file" "$docx_file" 2>"$docx_err"
    local rc=$?

    # Log the stderr output
    if [[ -f "$docx_err" && -s "$docx_err" ]]; then
        while IFS= read -r line; do
            log_debug "[docx] ${line}"
        done < "$docx_err"
    fi
    rm -f "$docx_err" 2>/dev/null || true

    if [[ $rc -eq 0 && -f "$docx_file" ]]; then
        log_ok "Reporte DOCX generado: ${docx_file}"
        echo "$docx_file"
        return 0
    else
        log_error "Falló generación de reporte DOCX (exit: ${rc})"
        log_error "Revise el log para detalles del error de Python (docx_report.py)"
        return 1
    fi
}

# ---- PDF Report Generator (HTML → PDF con WeasyPrint) ---------------------

audit_generate_report_pdf() {
    local html_file="${AUDIT_DIR}/reports/audit-report.html"
    local pdf_file="${AUDIT_DIR}/reports/audit-report.pdf"

    log_info "Generando reporte PDF profesional..."

    # Check prerequisites
    if ! python3 -c "import weasyprint" 2>/dev/null; then
        log_warn "weasyprint no instalado — reporte PDF no generado (ejecute '--install-all' o 'pip3 install weasyprint')"
        return 1
    fi

    if [[ ! -f "$html_file" ]]; then
        log_warn "Reporte HTML no encontrado en ${html_file}"
        return 1
    fi

    # Generate PDF from HTML
    log_info "Convirtiendo HTML a PDF con WeasyPrint..."
    python3 -c "
import weasyprint, sys
try:
    weasyprint.HTML(filename='${html_file}').write_pdf('${pdf_file}')
    print('OK')
except Exception as e:
    print(f'ERROR: {e}')
    sys.exit(1)
" 2>&1 | while IFS= read -r line; do
        log_debug "[pdf] ${line}"
    done

    local rc=${PIPESTATUS[0]}

    if [[ $rc -eq 0 && -f "$pdf_file" ]]; then
        log_ok "Reporte PDF generado: ${pdf_file}"
        echo "$pdf_file"
        return 0
    else
        log_warn "Falló generación de reporte PDF (exit: ${rc})"
        return 1
    fi
}

# ---- Main Orchestrator ----------------------------------------------------

# audit_url <url> [output_dir]
audit_url() {
    local url="$1"
    local output_dir="${2:-${SCRIPT_DIR}/audits}"

    AUDIT_START_TIME=$(date +%s)

    # Create output directory
    local domain_slug
    domain_slug=$(echo "$url" | sed 's|https\?://||' | sed 's|/.*||' | tr '.' '_')
    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')
    AUDIT_DIR="${output_dir}/${domain_slug}_${timestamp}"
    mkdir -p "$AUDIT_DIR"

    echo ""
    __echo "${FG_RED}${BLD}"  "  ╔══════════════════════════════════════════════════════════════╗"
    __echo "${FG_RED}${BLD}"  "  ║        PaginasAudit — AUDITORÍA AUTOMÁTICA INICIADA               ║"
    __echo "${FG_RED}${BLD}"  "  ╚══════════════════════════════════════════════════════════════╝"
    echo ""
    kv "Target" "$url"
    kv "Directorio" "${AUDIT_DIR}"
    echo ""

    # 1. Normalize target
    audit_normalize_url "$url"

    # 2. Pre-flight
    if ! audit_pre_flight; then
        error "Pre-flight falló — abortando auditoría"
        add_finding "CRITICAL" "System" "Pre-flight falló — target no accesible" \
            "No se pudo verificar el target. La auditoría no pudo completarse." \
            "Verificar que la URL sea correcta y el target esté accesible."
        AUDIT_END_TIME=$(date +%s)
        audit_generate_report_txt || true
        audit_generate_report_json || true
        return 1
    fi

    # 3. Run phases
    local phases=("assessment" "malware" "brand" "incident" "sast" "sca")
    local phase_names=("Assessment: Escaneo activo (Nmap, Nikto, Nuclei...)" 
                       "Malware: Análisis de dependencias e integridad"
                       "Brand Protection: OSINT y typosquatting"
                       "IR Readiness: Preparación ante incidentes"
                       "SAST: Análisis estático de código (Semgrep, TruffleHog...)"
                       "SCA + SBOM: Composición y dependencias (Trivy, Syft, Grype...)")

    # Use dialog gauge if available
    local phase_count=${#phases[@]}
    local current=0
    for phase in "${phases[@]}"; do
        current=$(( current + 1 ))
        if __dialog_avail; then
            local pct=$(( current * 100 / phase_count ))
            echo "$pct" | dialog "${__UI_OPTS[@]}" \
                --gauge "Ejecutando: ${phase_names[$((current-1))]}\n\nFase ${current}/${phase_count}" \
                8 70 0 2>/dev/null || true
        else
            info "=========================================="
            info "FASE ${current}/${phase_count}: ${phase_names[$((current-1))]}"
            info "=========================================="
        fi
        case "$phase" in
            assessment) audit_assessment ;;
            malware)    audit_malware ;;
            brand)      audit_brand ;;
            incident)   audit_incident ;;
            sast)       audit_sast ;;
            sca)        audit_sca ;;
        esac
    done

    AUDIT_END_TIME=$(date +%s)

    # 4. Generate consolidated report
    echo ""
    log_section "GENERANDO REPORTES"
    info "Consolidando hallazgos de las 6 fases..."

    audit_generate_report_txt || log_warn "Reporte TXT no generado"
    audit_generate_report_json || log_warn "Reporte JSON no generado"
    audit_generate_report_html || log_warn "Reporte HTML no generado"
    audit_generate_report_docx || log_warn "Reporte DOCX no generado (python-docx?)"
    audit_generate_report_pdf || log_warn "Reporte PDF no generado (weasyprint?)"

    # 5. Print summary
    echo ""
    __echo "${COLOR_HEADER}" "  ╔══════════════════════════════════════════════════════════════╗"
    __echo "${COLOR_HEADER}" "  ║           AUDITORÍA COMPLETADA — RESUMEN                     ║"
    __echo "${COLOR_HEADER}" "  ╚══════════════════════════════════════════════════════════════╝"
    echo ""

    local total=$(findings_total)
    local crit=$(findings_count "CRITICAL")
    local high=$(findings_count "HIGH")
    local med=$(findings_count "MEDIUM")
    local low=$(findings_count "LOW")
    local duration=$(( AUDIT_END_TIME - AUDIT_START_TIME ))

    printf "  ${FG_BWHT}%-25s${RST} %s\n" "Target:" "${AUDIT_TARGET[url]}"
    printf "  ${FG_BWHT}%-25s${RST} %s\n" "Dominio:" "${AUDIT_TARGET[domain]}"
    printf "  ${FG_BWHT}%-25s${RST} %s\n" "IP:" "${AUDIT_TARGET[ip]}"
    printf "  ${FG_BWHT}%-25s${RST} %d\n" "Total hallazgos:" "$total"
    [[ $crit -gt 0 ]] && printf "  ${FG_RED}%-25s${RST} %d\n" "🛑 CRÍTICOS:" "$crit"
    [[ $high -gt 0 ]] && printf "  ${FG_RED}%-25s${RST} %d\n" "⚠️  ALTOS:" "$high"
    [[ $med  -gt 0 ]] && printf "  ${FG_YLW}%-25s${RST} %d\n" "⚡ MEDIOS:" "$med"
    [[ $low  -gt 0 ]] && printf "  ${FG_BBLU}%-25s${RST} %d\n" "ℹ️  BAJOS:" "$low"
    printf "  ${FG_BWHT}%-25s${RST} %02d:%02d\n" "Duración:" "$((duration/60))" "$((duration%60))"
    echo ""

    kv "Reporte TXT"  "${AUDIT_DIR}/reports/audit-report.txt"
    kv "Reporte JSON" "${AUDIT_DIR}/reports/audit-report.json"
    kv "Reporte HTML" "${AUDIT_DIR}/reports/audit-report.html"
    kv "Reporte DOCX" "${AUDIT_DIR}/reports/audit-report.docx"
    kv "Reporte PDF"  "${AUDIT_DIR}/reports/audit-report.pdf"
    echo ""

    if __dialog_avail; then
        local msg="Auditoría completada contra: ${AUDIT_TARGET[url]}\n\n"
        msg+="Hallazgos: ${total} total (${crit} críticos, ${high} altos, ${med} medios, ${low} bajos)\n\n"
        msg+="Reportes:\n"
        msg+="  TXT:  ${AUDIT_DIR}/reports/audit-report.txt\n"
        msg+="  JSON: ${AUDIT_DIR}/reports/audit-report.json\n"
        msg+="  HTML: ${AUDIT_DIR}/reports/audit-report.html\n"
        msg+="  DOCX: ${AUDIT_DIR}/reports/audit-report.docx\n"
        msg+="  PDF:  ${AUDIT_DIR}/reports/audit-report.pdf"
        dialog "${__UI_OPTS[@]}" \
            --msgbox "$msg" 16 70 2>/dev/null || true
    fi

    return 0
}

# ---- TUI Menu Entry Point -------------------------------------------------

audit_menu() {
    echo ""
    __echo "${FG_RED}${BLD}"  "  ╔══════════════════════════════════════════════════════════════╗"
    __echo "${FG_RED}${BLD}"  "  ║         AUDITORÍA AUTOMÁTICA COMPLETA                       ║"
    __echo "${FG_RED}${BLD}"  "  ╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  ${FG_BBLK}Esta opción ejecutará las 6 fases de auditoría automáticamente"
    echo "  contra la URL que proporcione:"
    echo ""
    echo "    1. Assessment       → Nmap, Nikto, WhatWeb, Nuclei, SSL, DNS, fuzzing"
    echo "    2. Malware Analysis → YARA, exiftool, cabeceras de seguridad"
    echo "    3. Brand Protection → dnstwist, theHarvester, sublist3r, HIBP"
    echo "    4. IR Readiness     → Evaluación de preparación ante incidentes"
    echo "    5. SAST             → Semgrep, TruffleHog, Gitleaks, Bandit"
    echo "    6. SCA + SBOM       → Trivy, Dep-Check, Syft, Grype, OSV-Scanner"
    echo ""
    echo "  Tiempo estimado: 15-40 minutos dependiendo del target"
    echo "  Se generarán reportes en TXT + JSON + HTML + DOCX + PDF${RST}"
    echo ""

    # Check if tools are installed
    local missing_tools=()
    for tool in nmap whatweb nikto dnsrecon; do
        if ! cmd_exists "$tool"; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        warn "Herramientas no instaladas: ${missing_tools[*]}"
        warn "La auditoría saltará las herramientas faltantes."
        warn "Use el menú principal para instalar las fases primero."
        echo ""
        if ! ui_confirm "Auditoría" "¿Continuar de todas formas?"; then
            return 0
        fi
    fi

    # Get URL
    local url
    url=$(ui_input "PaginasAudit Audit" "Ingrese la URL del target a auditar:" "https://")

    if [[ -z "$url" ]]; then
        log_info "Auditoría cancelada — sin URL"
        return 0
    fi

    if ! ui_confirm "Auditoría" "¿Iniciar auditoría automática contra:\n${url}?"; then
        return 0
    fi

    audit_url "$url"

    return 0
}

# ---- Auto-Execute ---------------------------------------------------------
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -ge 1 ]]; then
        audit_url "$1" "${2:-./audits}"
    else
        audit_menu
    fi
fi
