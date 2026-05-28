#!/usr/bin/env bash
# ============================================================================
# 03-brand-protection.sh — Fase 3: Protección de Marca
# ----------------------------------------------------------------------------
# Detección de typosquatting (dnstwist), búsqueda de fugas de credenciales,
# revisión de reputación en listas negras, OSINT de superficie pública.
# ============================================================================

[[ -n "${__MODULE_BRAND_LOADED:-}" ]] && return 0
readonly __MODULE_BRAND_LOADED=true

MODULE_BRAND_NAME="Brand Protection"
MODULE_BRAND_DESC="Protección de marca, typosquatting y OSINT"

# ---- Phase Banner ---------------------------------------------------------

brand_banner() {
    clear 2>/dev/null || true
    echo ""
    __echo "${FG_GRN}${BLD}"  "  ╔══════════════════════════════════════════════════════════════╗"
    __echo "${FG_GRN}${BLD}"  "  ║            FASE 3: PROTECCIÓN DE MARCA                        ║"
    __echo "${FG_GRN}${BLD}"  "  ╠══════════════════════════════════════════════════════════════╣"
    __echo "${FG_GRN}"        "  ║  Typosquatting · Fugas · Reputación · OSINT                    ║"
    __echo "${FG_GRN}${BLD}"  "  ╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  ${FG_BBLK}dnstwist → Encontrar dominios similares registrados (phishing)"
    echo ""
    echo "  theHarvester → Recolección de emails, subdominios, IPs"
    echo "  Sublist3r → Enumeración rápida de subdominios"
    echo "  Holehe → Verificar si un email está registrado en servicios"
    echo "  SpiderFoot → Automatización de OSINT${RST}"
    echo ""
}

# ---- Tool Install Functions -----------------------------------------------

brand_install_dnstwist() {
    log_section "Instalando dnstwist"
    info "Detección de typosquatting en dominios — encuentra variaciones del dominio"

    if cmd_exists dnstwist; then
        log_ok "dnstwist ya está instalado"
        verify_tool "dnstwist" "Brand Protection" "dnstwist"
        return 0
    fi

    # Try apt first, fallback to pip
    pkg_install dnstwist 2>/dev/null || {
        log_info "dnstwist no disponible en repositorios, instalando con pip..."
        pip_install "dnstwist"
    }

    verify_tool "dnstwist" "Brand Protection" "dnstwist"
}

brand_install_theharvester() {
    log_section "Instalando theHarvester"
    info "Recolección de emails, subdominios, IPs y URLs"

    if cmd_exists theharvester; then
        log_ok "theHarvester ya está instalado"
        verify_tool "theharvester" "Brand Protection" "theharvester"
        return 0
    fi

    pkg_install theharvester 2>/dev/null || {
        log_info "theHarvester no disponible en repositorios, instalando con pip..."
        pip_install "theHarvester"
    }

    verify_tool "theharvester" "Brand Protection" "theharvester"
}

brand_install_sublist3r() {
    log_section "Instalando Sublist3r"
    info "Enumeración rápida de subdominios"

    if cmd_exists sublist3r; then
        verify_tool "sublist3r" "Brand Protection" "sublist3r"
        return 0
    fi

    pip_install "sublist3r"
    verify_tool "sublist3r" "Brand Protection" "sublist3r"
}

brand_install_holehe() {
    log_section "Instalando Holehe"
    info "Verifica si un correo electrónico está registrado en múltiples servicios"

    if cmd_exists holehe; then
        verify_tool "holehe" "Brand Protection" "holehe"
        return 0
    fi

    pip_install "holehe"
    verify_tool "holehe" "Brand Protection" "holehe"
}

brand_install_emailfinder() {
    log_section "Instalando EmailFinder"
    info "Búsqueda de emails asociados a un dominio"

    if cmd_exists emailfinder; then
        verify_tool "emailfinder" "Brand Protection" "emailfinder"
        return 0
    fi

    pip_install "emailfinder"
    verify_tool "emailfinder" "Brand Protection" "emailfinder"
}

brand_install_ghunt() {
    log_section "Instalando GHunt"
    info "OSINT sobre cuentas de Google"

    if cmd_exists ghunt; then
        verify_tool "ghunt" "Brand Protection" "ghunt"
        return 0
    fi

    pip_install "ghunt"
    verify_tool "ghunt" "Brand Protection" "ghunt"
}

brand_install_social_analyzer() {
    log_section "Instalando Social Analyzer"
    info "Análisis de perfiles en redes sociales"

    if cmd_exists social-analyzer; then
        verify_tool "social-analyzer" "Brand Protection" "social-analyzer"
        return 0
    fi

    # Requires npm
    if ! cmd_exists npm; then
        log_info "npm requerido. Instalando Node.js..."
        pkg_install nodejs || log_warn "nodejs no se pudo instalar"
        pkg_install npm || log_warn "npm no se pudo instalar"
    fi

    npm_global "social-analyzer"
    verify_tool "social-analyzer" "Brand Protection" "social-analyzer"
}

brand_install_whatsmyname() {
    log_section "Instalando WhatsMyName"
    info "Enumeración de nombres de usuario en múltiples plataformas"

    if cmd_exists whatsmyname; then
        verify_tool "whatsmyname" "Brand Protection" "whatsmyname"
        return 0
    fi

    # Clone the Maigret alternative or use the original tool
    pip_install "whatsmyname" 2>/dev/null || {
        log_info "Instalando desde GitHub..."
        local tmp_dir
        tmp_dir=$(make_temp_dir "whatsmyname")
        cd "$tmp_dir" || return 1
        git clone --depth 1 https://github.com/WebBreacher/WhatsMyName.git 2>&1 | log_debug
        cd WhatsMyName || return 1
        sudo_exec python3 setup.py install 2>&1 | log_debug || true
        cleanup_temp "$tmp_dir"
    }

    verify_tool "whatsmyname" "Brand Protection" "whatsmyname"
}

brand_install_haveibeenpwned() {
    log_section "Instalando HIBP CLI"
    info "Consulta de fugas de credenciales contra Have I Been Pwned"

    if cmd_exists hibp; then
        verify_tool "haveibeenpwned" "Brand Protection" "hibp"
        return 0
    fi

    pip_install "hibp-cli" 2>/dev/null || {
        log_info "Instalando PyHIBP..."
        pip_install "pyhibp"
    }

    # Fallback: create a wrapper
    if ! cmd_exists hibp && ! cmd_exists pyhibp; then
        log_info "Creando script wrapper para consultas HIBP..."
        cat > /tmp/hibp-check.py << 'PYEOF'
#!/usr/bin/env python3
"""Simple Have I Been Pwned query tool"""
import sys
try:
    import requests
    email = sys.argv[1] if len(sys.argv) > 1 else input("Email: ")
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    r = requests.get(url, headers={"hibp-api-key": ""}, timeout=10)
    if r.status_code == 200:
        for b in r.json():
            print(f"  Breach: {b['Name']} - {b['BreachDate']}")
    elif r.status_code == 404:
        print("  No breaches found")
    else:
        print(f"  Error: {r.status_code}")
except Exception as e:
    print(f"  Error: {e}")
PYEOF
        sudo_exec mv /tmp/hibp-check.py /usr/local/bin/hibp-check
        sudo_exec chmod +x /usr/local/bin/hibp-check
        log_ok "Script hibp-check creado en /usr/local/bin/hibp-check"
    fi

    verify_tool "haveibeenpwned" "Brand Protection" "$(cmd_exists hibp && echo hibp || echo hibp-check)"
}

brand_install_spiderfoot() {
    log_section "Instalando SpiderFoot"
    info "Automatización de OSINT y footprinting"

    if cmd_exists spiderfoot; then
        verify_tool "spiderfoot" "Brand Protection" "spiderfoot"
        return 0
    fi

    pip_install "spiderfoot" 2>/dev/null || {
        log_info "SpiderFoot no disponible en pip, descargando desde GitHub..."
        local tmp_dir
        tmp_dir=$(make_temp_dir "spiderfoot")
        cd "$tmp_dir" || return 1
        git clone --depth 1 https://github.com/smicallef/spiderfoot.git 2>&1 | log_debug
        cd spiderfoot || return 1
        pip3 install -r requirements.txt 2>&1 | log_debug
        sudo_exec ln -sf "$(pwd)/sf.py" /usr/local/bin/spiderfoot 2>/dev/null || true
        cleanup_temp "$tmp_dir"
    }

    verify_tool "spiderfoot" "Brand Protection" "spiderfoot"
}

brand_install_yq() {
    log_section "Instalando yq"
    info "Procesador YAML para línea de comandos"

    if cmd_exists yq; then
        verify_tool "yq" "Brand Protection" "yq"
        return 0
    fi

    snap_install "yq" "classic"
    verify_tool "yq" "Brand Protection" "yq"
}

# ---- Generic Install Dispatcher -------------------------------------------

brand_install_tool() {
    local tool="$1"
    case "$tool" in
        dnstwist)        brand_install_dnstwist ;;
        theharvester)    brand_install_theharvester ;;
        sublist3r)       brand_install_sublist3r ;;
        holehe)          brand_install_holehe ;;
        emailfinder)     brand_install_emailfinder ;;
        ghunt)           brand_install_ghunt ;;
        social-analyzer) brand_install_social_analyzer ;;
        whatsmyname)     brand_install_whatsmyname ;;
        haveibeenpwned)  brand_install_haveibeenpwned ;;
        spiderfoot)      brand_install_spiderfoot ;;
        yq)              brand_install_yq ;;
        *)               log_warn "Fase Brand Protection: herramienta desconocida '${tool}'"; return 1 ;;
    esac
}

# ---- Phase Installation ---------------------------------------------------

brand_install_all() {
    brand_banner

    log_section "FASE 3: PROTECCIÓN DE MARCA"
    log_info "Iniciando instalación de herramientas de Brand Protection..."

    local tools=()
    mapfile -t tools < <(tools_by_phase "Brand Protection")

    local total=${#tools[@]}
    local current=0

    for tool in "${tools[@]}"; do
        current=$(( current + 1 ))

        if $SKIP_INSTALLED && tool_installed "$tool"; then
            local ver
            ver=$(tool_version "$(tool_bin "$tool")")
            log_ok "✓ ${tool} v${ver} — ya instalado, saltando"
            verify_tool "$tool" "Brand Protection" "$(tool_bin "$tool")"
            continue
        fi

        log_info "[${current}/${total}] Instalando ${tool}..."

        local dep="${TOOL_DEPS[$tool]:-}"
        if [[ -n "$dep" ]] && $AUTO_INSTALL_DEPS; then
            if ! tool_installed "$dep"; then
                log_info "Dependencia requerida: ${dep}. Instalando primero..."
                case "$dep" in
                    npm) malware_install_npm ;;
                    python3) malware_install_python3 ;;
                    *) log_warn "Dependencia '${dep}' no manejada" ;;
                esac
            fi
        fi

        brand_install_tool "$tool" || {
            log_error "Falló instalación de ${tool}"
        }
    done

    log_ok "Fase Brand Protection completada"
}

# ---- Interactive Selection -------------------------------------------------

brand_menu() {
    while true; do
        brand_banner

        local tools=()
        mapfile -t tools < <(tools_by_phase "Brand Protection")
        local menu_items=()

        menu_items+=("all" "Instalar TODAS las herramientas de Brand Protection")
        for tool in "${tools[@]}"; do
            local status
            if tool_installed "$tool"; then
                status="✓ INSTALADO"
            else
                status="✗ PENDIENTE"
            fi
            menu_items+=("$tool" "${TOOL_DESC[$tool]} [${status}]")
        done
        menu_items+=("back" "Volver al menú principal")

        local choice
        choice=$(ui_menu "Fase 3: Brand Protection" "Seleccione una opción:" 20 "${menu_items[@]}")

        case "$choice" in
            "")
                return 0
                ;;
            "all")
                if ui_confirm "Brand Protection" "¿Instalar TODAS las herramientas de Brand Protection?"; then
                    brand_install_all
                    ui_msg "Brand Protection" "Instalación de Fase Brand Protection completada."
                fi
                ;;
            "back")
                return 0
                ;;
            *)
                if ui_confirm "Brand Protection" "¿Instalar ${choice}?"; then
                    brand_install_tool "$choice"
                fi
                ;;
        esac
    done
}

# ---- Auto-Execute ---------------------------------------------------------
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    brand_menu
fi
