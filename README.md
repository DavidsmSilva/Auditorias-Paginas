# PaginasAudit — Cyber Audit Toolkit

> Auditoría automatizada de ciberseguridad para sitios web. **82 herramientas** en **6 fases**, instalador inteligente, reportes TXT + JSON + HTML + DOCX + PDF.

```bash
curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash
```

---

## Instalación

### 🚀 One-command (recomendado)

Un solo comando, clona el repo + menú interactivo:

```bash
curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash
```

> El repo se instala en `~/tools/Auditorias-Paginas/`. Al finalizar se abre el menú interactivo automáticamente.

### 📦 Con instalación completa de herramientas

Instala el repo + **todas** las herramientas de las 6 fases:

```bash
curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash -s -- --install-all
```

> ⏱ Aprox. 20-40 minutos dependiendo de tu conexión y sistema.

### 📂 Clonar y ejecutar local

Si preferís clonar manualmente:

```bash
git clone https://github.com/DavidsmSilva/Auditorias-Paginas.git
cd Auditorias-Paginas
bash installer.sh
```

O directamente sin el instalador:

```bash
git clone https://github.com/DavidsmSilva/Auditorias-Paginas.git
cd Auditorias-Paginas
bash paginas-auditorias/audit.sh
```

### 🎯 Instalar una fase o herramienta específica

```bash
# Una fase específica (1-6)
bash paginas-auditorias/audit.sh --install-phase 1
bash paginas-auditorias/audit.sh --install-phase 5

# Solo una herramienta
bash paginas-auditorias/audit.sh --install-tool naabu
bash paginas-auditorias/audit.sh --install-tool ruff
```

### 📁 Directorio personalizado

```bash
INSTALL_DIR=/opt/audit-tools curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash
```

---

## Uso

### 🔍 Auditoría automática a un sitio

Ejecuta las **6 fases** completas contra un target y genera reportes:

```bash
cd ~/tools/Auditorias-Paginas
bash paginas-auditorias/audit.sh --audit https://ejemplo.com
```

Esto ejecuta:

| # | Fase | Qué hace |
|---|------|----------|
| 1 | **Assessment** | Escaneo de puertos (Naabu + Nmap), fingerprinting (WhatWeb), vulnerabilidades web (Nikto, Nuclei), SSL/TLS, DNS, WPScan, crawleo (Katana), fuzzing (FFUF, Gobuster) |
| 2 | **Malware Analysis** | YARA, ExifTool, análisis de cabeceras de seguridad, detección de webshells |
| 3 | **Brand Protection** | dnstwist, theHarvester, Sublist3r, HIBP, búsqueda de fugas de datos |
| 4 | **Incident Response** | Evaluación de preparación ante incidentes (backups, logging, forense) |
| 5 | **SAST** | Semgrep, TruffleHog, Gitleaks, Bandit, Ruff — análisis estático de código |
| 6 | **SCA + SBOM** | Trivy, Dependency-Check, Syft, Grype, OSV-Scanner — composición de dependencias |

### 📁 Auditoría con carpeta de salida personalizada

```bash
bash paginas-auditorias/audit.sh --audit https://ejemplo.com ./reportes-cliente
```

### 🐞 Modo Bug Bounty

Activa guías de explotación en los reportes HTML:

```bash
bash paginas-auditorias/audit.sh --mode bounty --audit https://ejemplo.com
```

### 🛡️ Modo OPSEC

Activa chequeo de anonimato pre-vuelo antes de la auditoría:

```bash
bash paginas-auditorias/audit.sh --mode opsec --audit https://ejemplo.com
```

### 🖥️ Menú interactivo (TUI)

```bash
cd ~/tools/Auditorias-Paginas
bash paginas-auditorias/audit.sh
```

Te muestra un menú con `dialog` para elegir fases, instalar tools, ejecutar auditorías, etc.

### 🔧 Instalar herramientas

```bash
# Todas las herramientas (6 fases)
bash paginas-auditorias/audit.sh --install-all

# Una fase específica
bash paginas-auditorias/audit.sh --install-phase 1   # Assessment (26 tools)
bash paginas-auditorias/audit.sh --install-phase 2   # Malware Analysis (16)
bash paginas-auditorias/audit.sh --install-phase 3   # Brand Protection (11)
bash paginas-auditorias/audit.sh --install-phase 4   # Incident Response (19)
bash paginas-auditorias/audit.sh --install-phase 5   # SAST (5)
bash paginas-auditorias/audit.sh --install-phase 6   # SCA + SBOM (5)

# Una herramienta específica
bash paginas-auditorias/audit.sh --install-tool naabu
bash paginas-auditorias/audit.sh --install-tool nuclei
```

### ✅ Verificar instalación

```bash
# Qué tools están instaladas
bash paginas-auditorias/audit.sh --verify

# Generar reporte de verificación (TXT + JSON)
bash paginas-auditorias/audit.sh --report
```

### 📋 Información

```bash
bash paginas-auditorias/audit.sh --help          # Ayuda completa
bash paginas-auditorias/audit.sh --version       # Versión instalada
bash paginas-auditorias/audit.sh --list-tools    # Listar tools por fase
```

### 📊 Reportes

```bash
# Los reportes se generan automáticamente en cada auditoría:
#   audit-report.txt   — Terminal
#   audit-report.json  — Datos estructurados
#   audit-report.html  — Interactivo con filtros y guías de explotación
#   audit-report.docx  — Documento Word profesional (portada, TOC, gráficos)
```

---

## Las 6 Fases

| # | Fase | Tools | Destacadas |
|---|------|-------|------------|
| 1 | **Assessment** | 26 | Nmap, Naabu, Nikto, WhatWeb, Nuclei, Katana, FFUF, Gobuster, WPScan, SQLmap, ZAP, Hydra, Amass, Subfinder, SSLScan, testssl.sh, dnsrecon, John, Hashcat... |
| 2 | **Malware Analysis** | 16 | Lynis, ClamAV, YARA, ExifTool, Radare2, Chkrootkit, Rkhunter, AIDE, Binwalk, Strings, FLOSS... |
| 3 | **Brand Protection** | 11 | DNSTwist, theHarvester, Sublist3r, Holehe, HIBP, SpiderFoot, GHunt, Sherlock... |
| 4 | **Incident Response** | 19 | Wireshark, TShark, Volatility, Sleuth Kit, Bulk Extractor, Guymager, Tripwire, Borg, Rsync, Dcfldd... |
| 5 | **SAST** | 5 | Semgrep, TruffleHog, Gitleaks, Bandit, Ruff |
| 6 | **SCA + SBOM** | 5 | Trivy, Dependency-Check, Syft, Grype, OSV-Scanner |

**Total: 82 herramientas** — todas instalables individualmente o por fase.

---

## Herramientas 2026 (agregadas recientemente)

| Tool | Fase | Método | Descripción |
|------|------|--------|-------------|
| **Naabu** | Assessment | `go install` | Escáner de puertos rápido (ProjectDiscovery) — SYN scan masivo |
| **Katana** | Assessment | `go install` | Crawler web que descubre endpoints, rutas ocultas y parámetros |
| **FFUF** | Assessment | `go install` | Fuzzing ultra-rápido de contenido web (directorios, subdominios, parámetros) |
| **Ruff** | SAST | `pip install` | Linter Python en Rust (10-100x más rápido que Flake8) — 800+ reglas incluyendo seguridad |

---

## Modos Especiales

### 🐞 Modo Bounty (`--mode bounty`)

Agrega guías de explotación detalladas al reporte HTML para cada hallazgo. Incluye payloads, vectores de ataque, y referencias. Diseñado para **bug bounty hunters** que necesitan contexto ofensivo.

### 🛡️ Modo OPSEC (`--mode opsec`)

Ejecuta un checklist de anonimato pre-vuelo antes de la auditoría: verifica VPN, DNS leaks, WebRTC, User-Agent, y otras fugas de identidad. Indispensable si operás desde entornos controlados.

Si ejecutás `--audit` sin `--mode opsec`, **el tool te pregunta automáticamente** si querés ejecutar el chequeo antes de arrancar.

### 📄 Consent log

Antes de cada auditoría, el tool pide **confirmación de autorización por escrito** del propietario del sitio. Sin eso, no arranca. Guarda un registro firmado con timestamp, operador, target y referencia en `logs/consent.log` (permisos 600).

### 🔒 Findings vault

Al finalizar la auditoría, todos los archivos con hallazgos sensibles (resultados, secretos, credenciales) se protegen con permisos **600** (solo el operador puede leerlos). El directorio completo se cierra a otros usuarios.

### 🧹 Cleanup (`--clean`)

```bash
bash paginas-auditorias/audit.sh --clean
```

Elimina toda la evidencia de auditorías anteriores (directorio `audits/` + logs). Te pide confirmación antes de borrar.

---

## Reportes

Cada auditoría genera **5 formatos** con la misma información:

| Formato | Archivo | Para qué |
|---------|---------|----------|
| **TXT** | `audit-report.txt` | Lectura rápida en terminal / compartir por texto |
| **JSON** | `audit-report.json` | Procesamiento automatizado, integraciones |
| **HTML** | `audit-report.html` | Informe interactivo con filtros por severidad, secciones colapsables y guías de explotación (modo bounty) |
| **DOCX** | `audit-report.docx` | Documento Word profesional con portada, tabla de contenido, hallazgos y gráficos |
| **PDF** | `audit-report.pdf` | Exportación del DOCX a PDF (si python-docx está instalado) |

---

## Troubleshooting

| Problema | Causa | Solución |
|----------|-------|----------|
| `bash: línea 1: 404:: orden no encontrada` | URL incorrecta | Usar exactamente: `curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh \| bash` |
| `curl: (6) Could not resolve host` | Sin internet | Verificar conectividad |
| `git: command not found` | Kali minimal | `sudo apt update && sudo apt install git -y` |
| `Permission denied` | Scripts sin ejecución | `chmod +x paginas-auditorias/*.sh` |
| `python-docx` no instalado | Reporte DOCX | `pip install python-docx` o ejecutar `--install-all` |
| Las tools no se instalan | Faltan dependencias base | `./audit.sh --install-all` resuelve todo automáticamente |
| Naabu/Katana/FFUF no detectados | Go no instalado | El instalador instala Go automáticamente como dependencia |

---

## Requisitos

- **Sistema**: Kali Linux (recomendado), Debian 11+, Ubuntu 22.04+, Arch, Fedora
- **Base**: `bash`, `git`, `curl`, `python3`, `pip3`, `dialog`
- **GO** (se instala automáticamente para herramientas de ProjectDiscovery)

---

## Arquitectura

```
├── installer.sh              # One-command installer (curl | bash)
├── build.sh                  # Script de build/bundle (opcional)
├── README.md
└── paginas-auditorias/
    ├── audit.sh               # Entry point CLI + TUI (6 fases)
    ├── config/
    │   ├── tools.db           # Registro de 82 herramientas (TOOL_PHASE, TOOL_PKG, etc.)
    │   └── settings.cfg       # Configuración
    ├── lib/
    │   ├── colors.sh           # Códigos de color ANSI
    │   ├── logging.sh          # Sistema de logging
    │   ├── ui.sh               # Interfaz TUI (dialog)
    │   ├── utils.sh            # Utilidades: pkg_install, pip_install, go_install, timed_run
    │   ├── verify.sh           # Verificación de instalación
    │   └── docx_report.py      # Generación de reportes DOCX (Python)
    └── modules/
        ├── 00-automated-audit.sh   # Pipeline automatizado completo (6 fases + reportes)
        ├── 01-assessment.sh        # Fase 1: Assessment (26 tools)
        ├── 02-malware.sh           # Fase 2: Malware Analysis (16 tools)
        ├── 03-brand-protection.sh  # Fase 3: Brand Protection (11 tools)
        ├── 04-incident-response.sh # Fase 4: Incident Response (19 tools)
        ├── 05-sast.sh              # Fase 5: SAST (5 tools)
        ├── 06-sca-sbom.sh          # Fase 6: SCA + SBOM (5 tools)
        └── 07-exploit-guides.sh    # Guías de explotación (modo bounty)
```

**Pipeline de auditoría automática:**

```
URL → Pre-flight (DNS + WAF + OPSEC)
    → Assessment (Naabu → Nmap → Nikto → SSL → DNS → Nuclei → WPScan → Katana → FFUF → Gobuster)
    → Malware Analysis (YARA → ExifTool → Security Headers → Dependencies)
    → Brand Protection (dnstwist → theHarvester → Sublist3r → HIBP)
    → IR Readiness (Checklist: forense, backups, logging, integridad)
    → SAST (Semgrep → TruffleHog → Gitleaks → Bandit → Ruff)
    → SCA + SBOM (Trivy → Dependency-Check → Syft → Grype → OSV-Scanner)
    → Reportes (TXT + JSON + HTML + DOCX + PDF)
```

---

## Licencia

[MIT](LICENSE) © DavidsmSilva
