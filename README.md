# PaginasAudit — Cyber Audit Toolkit

Auditoría automatizada de ciberseguridad para sitios web. 69 herramientas organizadas en 4 fases, instalador inteligente y reportes profesionales en **TXT + JSON + HTML + DOCX**.

```bash
curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash
```

---

## Características

- **Auditoría automática** con un solo comando contra cualquier URL
- **4 fases** de análisis: Assessment, Malware, Brand Protection, IR Readiness
- **69 herramientas** registradas con instalación inteligente (apt/pip/npm/gem/go/cargo/snap)
- **Reportes profesionales** en TXT, JSON, HTML interactivo y DOCX (Word)
- **Instalador One-Command** — clona, instala dependencias y ejecuta
- **TUI interactivo** con `dialog` + menús y barras de progreso
- **Multi-plataforma**: Kali Linux, Debian, Ubuntu, Arch, Fedora

---

## Instalación

### One-command (recomendado)

```bash
curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash
```

### Con instalación completa de herramientas

```bash
curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash -s -- --install-all
```

### Directorio personalizado

```bash
INSTALL_DIR=/opt/audit-tools curl -sL URL | bash
```

### Rama específica

```bash
REPO_BRANCH=develop curl -sL URL | bash
```

---

## Uso

### Auditoría automática (recomendado)

```bash
./audit.sh --audit https://ejemplo.com
./audit.sh --audit https://ejemplo.com ./resultados
```

### Menú interactivo

```bash
./audit.sh
```

### Instalación de herramientas

```bash
./audit.sh --install-all              # Las 4 fases completas
./audit.sh --install-phase 1          # Fase específica (1-4)
./audit.sh --install-tool nmap        # Herramienta específica
```

### Verificación

```bash
./audit.sh --verify                   # Verificar instalación
./audit.sh --report                   # Generar reporte de verificación
```

### Información

```bash
./audit.sh --help                     # Ayuda completa
./audit.sh --version                  # Versión
./audit.sh --list-tools               # Listar herramientas por fase
```

---

## Las 4 Fases

### Fase 1: Assessment (23 herramientas)

| Herramienta | Descripción |
|-------------|-------------|
| Nmap | Escaneo de puertos y servicios con NSE |
| Nikto | Escáner de vulnerabilidades web |
| WhatWeb | Identificación de tecnologías web |
| Nuclei | Escáner basado en templates YAML |
| WPScan | Vulnerabilidades WordPress |
| SSLScan / TestSSL | Evaluación SSL/TLS |
| DNSRecon / DNSEnum | Enumeración DNS |
| Gobuster / Dirb | Fuzzing de directorios |
| SQLMap | Detección de SQL Injection |
| ZAP / Burp Suite | Proxy de interceptación (DAST) |
| + 11 más | Hydra, Amass, Subfinder, etc. |

### Fase 2: Malware Analysis (16 herramientas)

| Herramienta | Descripción |
|-------------|-------------|
| Lynis | Auditoría de seguridad del sistema |
| ClamAV | Antivirus open-source |
| YARA | Clasificación de malware por patrones |
| ExifTool | Análisis de metadatos |
| Chkrootkit / Rkhunter | Detección de rootkits |
| AIDE | Monitor de integridad |
| Binwalk | Análisis de firmware |
| Radare2 | Reverse engineering |
| **python-docx** | Generación de reportes DOCX profesionales |
| + 7 más | Snyk, Peepdf, JQ, Strings, etc. |

### Fase 3: Brand Protection (11 herramientas)

| Herramienta | Descripción |
|-------------|-------------|
| DNSTwist | Detección de typosquatting |
| theHarvester | OSINT de emails y subdominios |
| Sublist3r | Enumeración rápida de subdominios |
| Holehe | Verificación de cuentas por email |
| HIBP | Consulta de fugas de credenciales |
| SpiderFoot | Automatización de OSINT |
| + 5 más | GHunt, Social-Analyzer, WhatsMyName, etc. |

### Fase 4: Incident Response (19 herramientas)

| Herramienta | Descripción |
|-------------|-------------|
| Wireshark / TShark | Análisis de tráfico de red |
| Tcpdump | Captura de paquetes |
| Volatility | Forense de memoria RAM |
| Sleuth Kit / Autopsy | Forense de sistema de archivos |
| Bulk Extractor | Extracción forense de datos |
| Guymager / DD Rescue | Adquisición forense de discos |
| Foremost / Scalpel | File carving |
| **Tripwire** | Monitor de integridad de archivos |
| **Duplicity** | Backups cifrados incrementales |
| **Borg** | Backup deduplicante |
| **dcfldd** | DD forense con hashing |
| + 8 más | TestDisk, PhotoRec, MagicRescue, etc. |

---

## Reportes

Cada auditoría genera 4 formatos de reporte:

| Formato | Archivo | Descripción |
|---------|---------|-------------|
| **TXT** | `audit-report.txt` | Reporte texto plano, lista de hallazgos |
| **JSON** | `audit-report.json` | Estructura de datos para procesamiento |
| **HTML** | `audit-report.html` | Interactivo con filtros por severidad, secciones colapsables |
| **DOCX** | `audit-report.docx` | Documento Word profesional con portada, tabla de contenidos, hallazgos por severidad, fases detalladas, recomendaciones y apéndice |

### Estructura del reporte DOCX

```
1. Portada corporativa
2. Índice / Tabla de Contenidos
3. Resumen Ejecutivo (hallazgos por severidad)
4. Información del Target (URL, IP, WAF, tecnologías)
5. Hallazgos Detallados (tabla por severidad con colores)
6. Detalle por Fase (Assessment, Malware, Brand, IR)
7. Recomendaciones priorizadas
8. Apéndice (metadatos, tiempos de ejecución)
```

---

## Arquitectura

```
paginas-auditorias/
├── audit.sh                  # Entry point CLI + TUI
├── installer.sh              # One-command GitHub installer
├── config/
│   ├── tools.db              # Registro central de 69 herramientas
│   └── settings.cfg          # Configuración del instalador
├── lib/
│   ├── colors.sh             # Estilos ANSI
│   ├── logging.sh            # Sistema de logging
│   ├── ui.sh                 # Abstracción TUI (dialog/whiptail)
│   ├── utils.sh              # OS detection, package abstraction
│   ├── verify.sh             # Verificación + generación de reportes
│   └── docx_report.py        # Generador de reportes DOCX (python-docx)
└── modules/
    ├── 00-automated-audit.sh # Pipeline automatizado completo
    ├── 01-assessment.sh      # Fase 1: Assessment
    ├── 02-malware.sh         # Fase 2: Malware Analysis
    ├── 03-brand-protection.sh# Fase 3: Brand Protection
    └── 04-incident-response.sh# Fase 4: Incident Response
```

### Pipeline de auditoría

```
URL → Pre-flight (DNS + WAF) → Assessment (8 pasos)
                              → Malware Analysis (4 pasos)
                              → Brand Protection (4 pasos)
                              → IR Readiness Checklist
                              → Reportes (TXT + JSON + HTML + DOCX)
```

---

## Requisitos

- **Sistema**: Kali Linux (recomendado), Debian 11+, Ubuntu 22.04+, Arch, Fedora
- **Dependencias base**: `bash`, `git`, `curl`, `python3`, `pip3`, `dialog`
- **Reportes DOCX**: `python-docx` (se instala automáticamente con `--install-all`)

---

## Hoja de Ruta

- [x] Instalador modular con registro de 69 herramientas
- [x] Pipeline de auditoría automática (4 fases)
- [x] Reportes TXT + JSON + HTML interactivo
- [x] Reportes DOCX profesionales (python-docx)
- [x] Instalador One-Command desde GitHub
- [x] 4 herramientas adicionales registradas (Tripwire, Duplicity, Borg, dcfldd)
- [ ] Soporte para proxies y autenticación
- [ ] Escaneo programado (cron)
- [ ] Integración con Slack/Teams para notificaciones
- [ ] Dashboard web embebido

---

## Licencia

MIT © DavidsmSilva
