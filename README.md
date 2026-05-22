# PaginasAudit — Cyber Audit Toolkit

> Auditoría automatizada de ciberseguridad para sitios web. 69 herramientas en 4 fases, instalador inteligente, reportes TXT + JSON + HTML + DOCX.

```bash
curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash
```

---

## Quick Start — 3 pasos

```bash
# 1. Instalar (clona el repo + menú interactivo)
curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash

# 2. Navegar al directorio
cd ~/tools/Auditorias-Paginas

# 3. Auditar un sitio
bash paginas-auditorias/audit.sh --audit https://ejemplo.com
```

> 💡 **Tip**: si querés instalar TODAS las herramientas primero (nmap, sqlmap, wireshark, etc.):
> ```bash
> curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash -s -- --install-all
> ```

---

## Comandos

| Comando | Qué hace |
|---------|----------|
| `./audit.sh` | Menú interactivo (TUI) |
| `./audit.sh --audit https://ejemplo.com` | Auditoría completa a un sitio |
| `./audit.sh --audit https://ejemplo.com ./resultados` | Auditoría + carpeta de salida |
| `./audit.sh --install-all` | Instalar TODAS las herramientas |
| `./audit.sh --install-phase 1` | Instalar herramientas de una fase |
| `./audit.sh --install-tool nmap` | Instalar una herramienta específica |
| `./audit.sh --verify` | Verificar qué tools están instaladas |
| `./audit.sh --report` | Generar reporte de verificación |
| `./audit.sh --list-tools` | Listar todas las herramientas |
| `./audit.sh --help` | Ayuda completa |
| `./audit.sh --version` | Versión instalada |

---

## Las 4 Fases

| # | Fase | Tools | Algunas herramientas |
|---|------|-------|---------------------|
| 1 | **Assessment** | 23 | Nmap, Nikto, WhatWeb, Nuclei, WPScan, SQLmap, ZAP, Gobuster... |
| 2 | **Malware Analysis** | 13 | Lynis, ClamAV, YARA, ExifTool, Radare2, Chkrootkit, AIDE... |
| 3 | **Brand Protection** | 11 | DNSTwist, theHarvester, Sublist3r, Holehe, SpiderFoot, GHunt... |
| 4 | **Incident Response** | 19 | Wireshark, Volatility, Sleuth Kit, Tripwire, Borg, Bulk Extractor... |

---

## Reportes

Cada auditoría genera **4 formatos**:

| Formato | Archivo | Para qué |
|---------|---------|----------|
| TXT | `audit-report.txt` | Lectura rápida en terminal |
| JSON | `audit-report.json` | Procesamiento automatizado |
| HTML | `audit-report.html` | Informe interactivo con filtros |
| DOCX | `audit-report.docx` | Documento Word profesional con portada, TOC y hallazgos |

---

## Troubleshooting

| Problema | Causa | Solución |
|----------|-------|----------|
| `curl: (6) Could not resolve host` | Sin internet | Verificar conectividad |
| `bash: línea 1: 404:: orden no encontrada` | URL incorrecta | Usar exactamente: `curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh \| bash` |
| `git not found` | Kali minimal | `sudo apt install git` |
| `Permission denied` | Sin ejecución | `chmod +x paginas-auditorias/*.sh` |
| `python-docx` no instalado | Reporte DOCX | Correr `pip install python-docx` o `--install-all` |
| Las tools no se instalan | Faltan dependencias | `./audit.sh --install-all` instala todo automáticamente |

---

## Arquitectura

```
├── installer.sh              # One-command installer (raíz del repo)
├── README.md
└── paginas-auditorias/
    ├── audit.sh               # Entry point CLI + TUI
    ├── config/
    │   ├── tools.db           # Registro de 69 herramientas
    │   └── settings.cfg       # Configuración
    ├── lib/                   # Librerías (colors, logging, ui, utils, verify)
    └── modules/               # Fases 1-4 + pipeline automatizado
```

**Pipeline de auditoría:**
```
URL → Pre-flight (DNS + WAF) → Assessment → Malware Analysis
                              → Brand Protection → IR Readiness
                              → Reportes (TXT + JSON + HTML + DOCX)
```

---

## Requisitos

- **Sistema**: Kali Linux (recomendado), Debian 11+, Ubuntu 22.04+, Arch, Fedora
- **Base**: `bash`, `git`, `curl`, `python3`, `pip3`, `dialog`

---

## Licencia

MIT © DavidsmSilva
