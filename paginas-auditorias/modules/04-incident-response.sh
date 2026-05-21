#!/usr/bin/env bash
# ============================================================================
# 04-incident-response.sh — Fase 4: Atención a Incidentes Cibernéticos
# ----------------------------------------------------------------------------
# Auditoría de logs, análisis de tráfico (Wireshark/tcpdump), forense de
# memoria (Volatility), recuperación de backups y restauración.
# ============================================================================

[[ -n "${__MODULE_INCIDENT_LOADED:-}" ]] && return 0
readonly __MODULE_INCIDENT_LOADED=true

MODULE_INCIDENT_NAME="Incident Response"
MODULE_INCIDENT_DESC="Respuesta a incidentes, forense y recuperación"

# ---- Phase Banner ---------------------------------------------------------

incident_banner() {
    clear 2>/dev/null || true
    echo ""
    __echo "${FG_BLU}${BLD}"  "  ╔══════════════════════════════════════════════════════════════╗"
    __echo "${FG_BLU}${BLD}"  "  ║      FASE 4: ATENCIÓN A INCIDENTES CIBERNÉTICOS               ║"
    __echo "${FG_BLU}${BLD}"  "  ╠══════════════════════════════════════════════════════════════╣"
    __echo "${FG_BLU}"        "  ║  Forense · Tráfico · Logs · Backups · Recuperación             ║"
    __echo "${FG_BLU}${BLD}"  "  ╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  ${FG_BBLK}Wireshark / tcpdump → Analizar tráfico de red en busca de anomalías"
    echo ""
    echo "  Volatility → Análisis forense de memoria RAM"
    echo "  Sleuth Kit + Autopsy → Forense de sistema de archivos"
    echo "  Foremost + Scalpel → Recuperación de archivos (carving)"
    echo "  TestDisk + PhotoRec → Recuperación de particiones"
    echo "  rsync → Backup y sincronización${RST}"
    echo ""
}

# ---- Tool Install Functions -----------------------------------------------

incident_install_wireshark() {
    log_section "Instalando Wireshark"
    info "Analizador de protocolos de red (GUI)"

    pkg_install wireshark

    # Add user to wireshark group for non-root capture
    if groups "$USER" 2>/dev/null | grep -qv 'wireshark'; then
        log_info "Agregando ${USER} al grupo wireshark para captura sin root..."
        sudo_exec usermod -aG wireshark "$USER" 2>/dev/null || true
        warn "Es necesario cerrar sesión y volver a entrar para capturar sin root."
    fi

    verify_tool "wireshark" "Incident Response" "wireshark"
}

incident_install_tcpdump() {
    log_section "Instalando tcpdump"
    info "Captura de paquetes en línea de comandos"

    pkg_install tcpdump
    verify_tool "tcpdump" "Incident Response" "tcpdump"
}

incident_install_tshark() {
    log_section "Instalando tshark"
    info "Wireshark en modo CLI — análisis de paquetes sin GUI"

    pkg_install tshark

    # Add to wireshark group for non-root capture
    if groups "$USER" 2>/dev/null | grep -qv 'wireshark'; then
        sudo_exec usermod -aG wireshark "$USER" 2>/dev/null || true
    fi

    verify_tool "tshark" "Incident Response" "tshark"
}

incident_install_volatility() {
    log_section "Instalando Volatility"
    info "Análisis forense de memoria RAM (Volatility 3)"

    if cmd_exists vol; then
        log_ok "Volatility 3 ya está instalado"
        verify_tool "volatility" "Incident Response" "vol"
        return 0
    fi

    # Volatility 3 via pip
    pip_install "volatility3" 2>/dev/null || pip_install "volatility"

    # Create symlink if needed
    if ! cmd_exists vol && cmd_exists vol.py; then
        sudo_exec ln -sf "$(which vol.py)" /usr/local/bin/vol 2>/dev/null || true
    fi

    # Download symbol tables reference
    log_info "Descargando tablas de símbolos de referencia..."
    local sym_dir="/opt/volatility/symbols"
    sudo_exec mkdir -p "$sym_dir"
    cat > /tmp/vol-symbols.sh << 'SHEOF'
#!/bin/bash
echo "Symbol tables for Volatility can be downloaded from:"
echo "  https://github.com/volatilityfoundation/volatility3/releases"
echo ""
echo "Place them in: /opt/volatility/symbols/"
echo "Then run: vol --symbol-dir /opt/volatility/symbols/ -f memory.dmp windows.info"
SHEOF
    sudo_exec mv /tmp/vol-symbols.sh /opt/volatility/download-symbols.sh
    sudo_exec chmod +x /opt/volatility/download-symbols.sh

    verify_tool "volatility" "Incident Response" "$(cmd_exists vol && echo vol || echo vol.py)"
}

incident_install_bulk_extractor() {
    log_section "Instalando bulk_extractor"
    info "Extracción forense de datos de discos y archivos"

    pkg_install bulk-extractor 2>/dev/null || {
        log_info "Instalando desde pip..."
        pip_install "bulk_extractor" 2>/dev/null || {
            # Build from source
            log_info "Compilando bulk_extractor desde fuente..."
            local tmp_dir
            tmp_dir=$(make_temp_dir "bulk_extractor")
            cd "$tmp_dir" || return 1
            git clone --depth 1 https://github.com/simsong/bulk_extractor.git 2>&1 | log_debug
            cd bulk_extractor || return 1
            ./configure 2>&1 | log_debug
            make -j"$(nproc)" 2>&1 | log_debug
            sudo_exec make install 2>&1 | log_debug
            cleanup_temp "$tmp_dir"
        }
    }

    verify_tool "bulk_extractor" "Incident Response" "bulk_extractor"
}

incident_install_guymager() {
    log_section "Instalando Guymager"
    info "Adquisición forense de imágenes de disco"

    pkg_install guymager 2>/dev/null || {
        log_warn "Guymager no disponible en repositorios. Instalar manualmente."
        verify_skip_tool "guymager" "Incident Response" "No disponible en repositorios"
        return 1
    }

    verify_tool "guymager" "Incident Response" "guymager"
}

incident_install_ddrescue() {
    log_section "Instalando ddrescue"
    info "Recuperación de datos de discos dañados"

    pkg_install ddrescue
    verify_tool "ddrescue" "Incident Response" "ddrescue"
}

incident_install_sleuthkit() {
    log_section "Instalando Sleuth Kit"
    info "Suite de análisis forense de sistema de archivos"

    pkg_install sleuthkit
    verify_tool "sleuthkit" "Incident Response" "fls"
}

incident_install_autopsy() {
    log_section "Instalando Autopsy"
    info "Interfaz gráfica de Sleuth Kit para análisis forense"

    if cmd_exists autopsy; then
        verify_tool "autopsy" "Incident Response" "autopsy"
        return 0
    fi

    pkg_install autopsy 2>/dev/null || {
        log_info "Instalando Autopsy desde pip..."
        pip_install "autopsy" 2>/dev/null || {
            log_warn "Autopsy no disponible. Se usará Sleuth Kit (CLI)."
            verify_skip_tool "autopsy" "Incident Response" "Requiere instalación manual"
            return 1
        }
    }

    verify_tool "autopsy" "Incident Response" "autopsy"
}

incident_install_foremost() {
    log_section "Instalando Foremost"
    info "Recuperación de archivos por firmas (file carving)"

    pkg_install foremost
    verify_tool "foremost" "Incident Response" "foremost"
}

incident_install_scalpel() {
    log_section "Instalando Scalpel"
    info "File carving basado en base de datos de firmas"

    pkg_install scalpel
    verify_tool "scalpel" "Incident Response" "scalpel"
}

incident_install_magicrescue() {
    log_section "Instalando Magic Rescue"
    info "Recuperación de archivos por magic bytes"

    pkg_install magicrescue 2>/dev/null || {
        log_info "Compilando Magic Rescue desde fuente..."
        local tmp_dir
        tmp_dir=$(make_temp_dir "magicrescue")
        cd "$tmp_dir" || return 1
        git clone --depth 1 https://github.com/jbj/magicrescue.git 2>&1 | log_debug
        cd magicrescue || return 1
        make 2>&1 | log_debug
        sudo_exec make install 2>&1 | log_debug
        cleanup_temp "$tmp_dir"
    }

    verify_tool "magicrescue" "Incident Response" "magicrescue"
}

incident_install_testdisk() {
    log_section "Instalando TestDisk"
    info "Recuperación de particiones perdidas"

    pkg_install testdisk
    verify_tool "testdisk" "Incident Response" "testdisk"
}

incident_install_photorec() {
    log_section "Instalando PhotoRec"
    info "Recuperación de fotos y archivos borrados (incluido en testdisk)"

    pkg_install testdisk  # photorec viene con testdisk
    if cmd_exists photorec; then
        verify_tool "photorec" "Incident Response" "photorec"
    else
        verify_skip_tool "photorec" "Incident Response" "Incluido en testdisk"
    fi
}

incident_install_rsync() {
    log_section "Instalando rsync"
    info "Sincronización y backup de archivos"

    pkg_install rsync
    verify_tool "rsync" "Incident Response" "rsync"
}

# ---- Generic Install Dispatcher -------------------------------------------

incident_install_tool() {
    local tool="$1"
    case "$tool" in
        wireshark)     incident_install_wireshark ;;
        tcpdump)       incident_install_tcpdump ;;
        tshark)        incident_install_tshark ;;
        volatility)    incident_install_volatility ;;
        bulk_extractor) incident_install_bulk_extractor ;;
        guymager)      incident_install_guymager ;;
        ddrescue)      incident_install_ddrescue ;;
        sleuthkit)     incident_install_sleuthkit ;;
        autopsy)       incident_install_autopsy ;;
        foremost)      incident_install_foremost ;;
        scalpel)       incident_install_scalpel ;;
        magicrescue)   incident_install_magicrescue ;;
        testdisk)      incident_install_testdisk ;;
        photorec)      incident_install_photorec ;;
        rsync)         incident_install_rsync ;;
        *)             log_warn "Fase Incident Response: herramienta desconocida '${tool}'"; return 1 ;;
    esac
}

# ---- Phase Installation ---------------------------------------------------

incident_install_all() {
    incident_banner

    log_section "FASE 4: ATENCIÓN A INCIDENTES CIBERNÉTICOS"
    log_info "Iniciando instalación de herramientas de Incident Response..."

    local tools
    tools=($(tools_by_phase "Incident Response"))

    local total=${#tools[@]}
    local current=0

    for tool in "${tools[@]}"; do
        current=$(( current + 1 ))

        if $SKIP_INSTALLED && tool_installed "$tool"; then
            local ver
            ver=$(tool_version "$(tool_bin "$tool")")
            log_ok "✓ ${tool} v${ver} — ya instalado, saltando"
            verify_tool "$tool" "Incident Response" "$(tool_bin "$tool")"
            continue
        fi

        log_info "[${current}/${total}] Instalando ${tool}..."

        local dep="${TOOL_DEPS[$tool]:-}"
        if [[ -n "$dep" ]] && $AUTO_INSTALL_DEPS; then
            if ! tool_installed "$dep"; then
                log_info "Dependencia requerida: ${dep}. Instalando primero..."
                case "$dep" in
                    python3) malware_install_python3 ;;
                    *) log_warn "Dependencia '${dep}' no manejada" ;;
                esac
            fi
        fi

        incident_install_tool "$tool" || {
            log_error "Falló instalación de ${tool}"
        }
    done

    log_ok "Fase Incident Response completada"
}

# ---- Interactive Selection -------------------------------------------------

incident_menu() {
    while true; do
        incident_banner

        local tools
        tools=($(tools_by_phase "Incident Response"))
        local menu_items=()

        menu_items+=("all" "Instalar TODAS las herramientas de Incident Response")
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
        choice=$(ui_menu "Fase 4: Incident Response" "Seleccione una opción:" 20 "${menu_items[@]}")

        case "$choice" in
            "")
                return 0
                ;;
            "all")
                if ui_confirm "Incident Response" "¿Instalar TODAS las herramientas de Incident Response?"; then
                    incident_install_all
                    ui_msg "Incident Response" "Instalación de Fase Incident Response completada."
                fi
                ;;
            "back")
                return 0
                ;;
            *)
                if ui_confirm "Incident Response" "¿Instalar ${choice}?"; then
                    incident_install_tool "$choice"
                fi
                ;;
        esac
    done
}

# ---- Auto-Execute ---------------------------------------------------------
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    incident_menu
fi
