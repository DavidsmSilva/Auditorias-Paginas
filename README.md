# PaginasAudit — Cyber Audit Toolkit

> Auditoría automatizada de ciberseguridad para sitios web. **69 herramientas** en 4 fases, instalador inteligente, reportes TXT + JSON + HTML + DOCX.

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

Instala el repo + **todas** las herramientas (nmap, sqlmap, wireshark, volatility, etc.):

```bash
curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash -s -- --install-all
```

> ⏱ Aprox. 15-30 minutos dependiendo de tu conexión y sistema.

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
# Solo fase 1 (Assessment): Nmap, ZAP, SQLmap, etc.
bash paginas-auditorias/audit.sh --install-phase 1

# Solo una herramienta
bash paginas-auditorias/audit.sh --install-tool nmap
```

### 📁 Directorio personalizado

```bash
INSTALL_DIR=/opt/audit-tools curl -sL https://raw.githubusercontent.com/DavidsmSilva/Auditorias-Paginas/main/installer.sh | bash
```

---

## Uso

### 🔍 Auditoría rápida a un sitio

```bash
cd ~/tools/Auditorias-Paginas
bash paginas-auditorias/audit.sh --audit https://ejemplo.com
```

Esto ejecuta las 4 fases y genera reportes en `./resultados/` (o la carpeta que indiques).

### 📁 Auditoría con carpeta de salida personalizada

```bash
bash paginas-auditorias/audit.sh --audit https://ejemplo.com ./reportes-cliente
```

### 🖥️ Menú interactivo (TUI)

```bash
cd ~/tools/Auditorias-Paginas
bash paginas-auditorias/audit.sh
```

Te muestra un menú con `dialog` para elegir fases, instalar tools, ejecutar auditorías, etc.

### 🔧 Instalar herramientas

```bash
# Todas las herramientas (4 fases)
bash paginas-auditorias/audit.sh --install-all

# Una fase específica
bash paginas-auditorias/audit.sh --install-phase 1   # Assessment
bash paginas-auditorias/audit.sh --install-phase 2   # Malware
bash paginas-auditorias/audit.sh --install-phase 3   # Brand Protection
bash paginas-auditorias/audit.sh --install-phase 4   # Incident Response

# Una herramienta específica
bash paginas-auditorias/audit.sh --install-tool nmap
bash paginas-auditorias/audit.sh --install-tool wireshark
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
#   audit-report.html  — Interactivo con filtros
#   audit-report.docx  — Documento Word profesional
```

---

## Las 4 Fases

| # | Fase | Tools | Destacadas |
|---|------|-------|------------|
| 1 | **Assessment** | 23 | Nmap, Nikto, WhatWeb, Nuclei, WPScan, SQLmap, ZAP, Gobuster, Dirb, Hydra, Amass... |
| 2 | **Malware Analysis** | 13 | Lynis, ClamAV, YARA, ExifTool, Radare2, Chkrootkit, Rkhunter, AIDE, Binwalk... |
| 3 | **Brand Protection** | 11 | DNSTwist, theHarvester, Sublist3r, Holehe, HIBP, SpiderFoot, GHunt... |
| 4 | **Incident Response** | 19 | Wireshark, TShark, Volatility, Sleuth Kit, Bulk Extractor, Guymager, Tripwire, Borg... |

---

## Reportes

Cada auditoría genera **4 formatos** con la misma información:

| Formato | Archivo | Para qué |
|---------|---------|----------|
| **TXT** | `audit-report.txt` | Lectura rápida en terminal / compartir por texto |
| **JSON** | `audit-report.json` | Procesamiento automatizado, integraciones |
| **HTML** | `audit-report.html` | Informe interactivo: filtros por severidad, secciones colapsables |
| **DOCX** | `audit-report.docx` | Documento Word profesional con portada, TOC, hallazgos y recomendaciones |

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

---

## Requisitos

- **Sistema**: Kali Linux (recomendado), Debian 11+, Ubuntu 22.04+, Arch, Fedora
- **Base**: `bash`, `git`, `curl`, `python3`, `pip3`, `dialog`

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

## Licencia

[MIT](LICENSE) © DavidsmSilva
