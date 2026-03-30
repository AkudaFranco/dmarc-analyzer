# DMARC Analyzer

## Qué es este proyecto

Herramienta de análisis, enriquecimiento y visualización de informes DMARC (RFC 7489) para Akuda Security, un MSSP de 3 personas. Procesa los XMLs de reportes DMARC, enriquece cada IP detectada con inteligencia de amenazas de múltiples fuentes, y genera un dashboard HTML interactivo autocontenido + base de datos Excel.

**Usuarios:** Equipo SOC interno de Akuda Security. Potencialmente para presentar informes a clientes.
**Dominios monitorizados:** akuda.es (principal) + 2 dominios de clientes.
**Fuentes de informes:** Google, Microsoft, Mimecast, Cisco/iphmx.

## Arquitectura

El proyecto tiene tres capas que se ejecutan en secuencia:

```
XMLs de DMARC → [dmarc_visualizer.py] → Parseo + Stats + HTML base + Excel
                                              ↓
                  [ip_enrichment.py]    → Enriquecimiento IPs (4 APIs + cache)
                                              ↓
                  [dmarc_run.py]        → Orquestación + Inyección panel IP en HTML
                                              ↓
                  Outputs: dmarc_dashboard.html + dmarc_database.xlsx
```

### Componentes principales

**`dmarc_visualizer.py`** (~900 líneas) — Motor principal
- Carga XMLs/ZIPs/GZs de una carpeta
- Parsea XML con `xml.etree.ElementTree`
- Calcula estadísticas: pass rate, alineación DKIM/SPF, disposiciones, timeline, top IPs
- Genera Excel multi-hoja con `openpyxl`
- Genera HTML autocontenido (~3000 líneas) con Chart.js, tabs, filtros, tabla ordenable
- Funciones clave: `parse_dmarc_xml()`, `load_folder()`, `compute_stats()`, `generate_html()`

**`ip_enrichment.py`** (~550 líneas) — Módulo de inteligencia
- Consulta 4 fuentes: Reverse DNS, IPinfo.io, AbuseIPDB, VirusTotal
- Calcula score de riesgo compuesto (0-100) con nivel y razones
- Cache en disco (JSON) con TTL configurable
- Rate limiting automático por API
- Clase principal: `IPEnricher` con métodos `enrich_all()`, `get()`, `get_serializable()`

**`dmarc_run.py`** (~300 líneas) — Orquestador
- Conecta visualizer + enrichment
- Genera e inyecta panel lateral de IP en el HTML (antes de `</body>`)
- Flags: `--no-enrich` (sin APIs), `--no-open` (sin navegador)

**`dmarc_extract.ps1`** — Utilidad independiente (PowerShell)
- Extrae XMLs desde archivos .eml exportados de Outlook
- Soporta formatos de Google, Microsoft, Mimecast, Cisco
- Paso previo manual, no forma parte del pipeline Python

**`config.json`** — Configuración y API keys
- Contiene tokens de AbuseIPDB, IPinfo, VirusTotal
- Parámetros de cache, TTL, delays entre peticiones
- ⚠️ NUNCA commitear con API keys reales

## Estructura del repositorio

```
dmarc-analyzer/
├── CLAUDE.md                    # Este archivo
├── README.md                    # Documentación pública
├── .gitignore                   # Excluir outputs, cache, keys
├── dmarc_visualizer.py          # Motor: parseo XML + stats + HTML + Excel
├── ip_enrichment.py             # Enriquecimiento de IPs (4 APIs + cache)
├── dmarc_run.py                 # Orquestador del pipeline completo
├── config.json.example          # Template de config SIN API keys
├── dmarc_extract.ps1            # Utilidad PowerShell para extraer XMLs de .eml
├── requirements.txt             # Dependencias Python
├── dmarc_reports/               # XMLs de entrada (no commitear datos reales)
│   └── .gitkeep
├── tests/                       # Tests automatizados
│   ├── test_parser.py           # Tests del parser DMARC
│   ├── test_enrichment.py       # Tests del enriquecimiento (con mocks)
│   ├── test_stats.py            # Tests de cálculo de estadísticas
│   └── fixtures/                # XMLs de ejemplo para tests
│       ├── google_report.xml
│       ├── microsoft_report.xml
│       ├── mimecast_report.xml
│       └── malformed_report.xml
└── .github/
    └── workflows/
        └── ci.yml               # GitHub Actions: lint + test en cada PR
```

### Archivos generados (en .gitignore, NO commitear)
```
dmarc_dashboard.html             # Dashboard HTML generado
dmarc_database.xlsx              # Base de datos Excel generada
ip_enrichment_cache.json         # Cache de consultas API
config.json                      # Config con API keys reales
```

## Estructura de datos clave

### Report parseado (salida de `parse_dmarc_xml()`)
```python
{
    "filename": "google.com!akuda.es!...xml",
    "org_name": "google.com",
    "domain": "akuda.es",
    "report_id": "1234567890",
    "date_begin": "2026-03-17 00:00 UTC",
    "date_end": "2026-03-18 00:00 UTC",
    "date_label": "2026-03-17",
    "policy_p": "quarantine",
    "policy_sp": "quarantine",
    "policy_adkim": "r",
    "policy_aspf": "r",
    "_hash": "abc123...",
    "records": [
        {
            "source_ip": "194.104.111.120",
            "count": 3,
            "disposition": "none",       # none | quarantine | reject
            "dkim_result": "fail",       # pass | fail
            "spf_result": "pass",        # pass | fail
            "dmarc_result": "pass",      # pass si DKIM o SPF pasan
            "alignment": "spf_only",     # full_pass | dkim_only | spf_only | fail
            "header_from": "akuda.es",
            "envelope_from": "akuda.es",
            "auth_dkim_domain": "",
            "auth_spf_domain": "akuda.es",
            "reasons": [{"type": "forwarded", "comment": "..."}]
        }
    ],
    "summary": {
        "total_messages": 10,
        "dmarc_pass": 9,
        "dmarc_fail": 1,
        "dmarc_pass_rate": 90.0,
        "full_pass": 0,
        "dkim_only": 0,
        "spf_only": 9,
        "align_fail": 1,
        "quarantined": 0,
        "rejected": 0,
        "unique_ips": 3,
        "record_count": 4
    }
}
```

### IP enriquecida (salida de `IPEnricher.get()`)
```python
{
    "ip": "194.104.111.120",
    "rdns": {"hostname": "smtp.mimecast.com", "error": ""},
    "ipinfo": {
        "city": "London", "region": "England", "country": "GB",
        "org": "AS55095 Mimecast", "asn": "AS55095", "as_name": "Mimecast",
        "is_vpn": null, "is_tor": null, "is_proxy": null, "error": ""
    },
    "abuseipdb": {
        "abuse_score": 0, "total_reports": 0, "isp": "Mimecast",
        "country_code": "GB", "categories": [], "error": ""
    },
    "virustotal": {
        "malicious": 0, "suspicious": 0, "harmless": 72, "undetected": 12,
        "as_owner": "Mimecast", "tags": [], "error": ""
    },
    "risk": {
        "level": "low",       # low | medium | high | critical
        "score": 0,           # 0-100
        "reasons": ["Sin indicadores de riesgo detectados"]
    }
}
```

## APIs integradas

| Fuente | Endpoint | Auth | Límite free | Delay config |
|--------|----------|------|-------------|--------------|
| Reverse DNS | `socket.gethostbyaddr()` | Ninguna | Sin límite | — |
| IPinfo.io | `GET https://ipinfo.io/{ip}` | Query param `token` | Ilimitado (Lite) | 0.1s |
| AbuseIPDB | `GET /api/v2/check` | Header `Key` | 1.000/día | 0.2s |
| VirusTotal | `GET /api/v3/ip_addresses/{ip}` | Header `x-apikey` | 4 req/min | 16s |

**Shodan** está pendiente de integrar como fuente adicional.

## Comandos esenciales

```bash
# Ejecución
python dmarc_run.py                    # Pipeline completo
python dmarc_run.py --no-enrich        # Solo parseo + dashboard (sin APIs)
python dmarc_run.py --no-open          # Sin abrir navegador

# Testing
pytest tests/ -v                       # Ejecutar todos los tests
pytest tests/test_parser.py -v         # Solo tests del parser
pytest tests/ -v --tb=short            # Tests con traceback corto

# Linting
ruff check .                           # Linter
ruff format .                          # Formateo automático

# Dependencias
pip install -r requirements.txt        # Instalar dependencias
```

## Convenciones de código

### General
- Idioma del código (variables, funciones, comentarios): **inglés**
- Idioma de la UI (textos del dashboard, labels, mensajes): **español**
- Commits en **español**, Conventional Commits: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`
- Python 3.8+ compatible (sin walrus operator ni match/case)

### Python
- Docstrings en funciones públicas (formato Google-style)
- Type hints donde aporten claridad, no obligatorios en todo
- Funciones puras cuando sea posible: entrada → salida, sin efectos secundarios
- La generación de HTML con f-strings es el patrón actual; mantenerlo consistente
- Imports: stdlib → third-party → locales, con línea en blanco entre grupos

### Testing
- `parse_dmarc_xml()` es la función más crítica — cobertura exhaustiva obligatoria
- Tests del parser: cubrir XMLs de Google, Microsoft, Mimecast, Cisco, y XML malformado
- Tests del enrichment: usar mocks para APIs, NUNCA hacer peticiones reales en CI
- Tests de `compute_stats()`: verificar cálculos de pass rate, alineación, disposiciones
- Ejecutar `pytest` ANTES de hacer commit. Si fallan, NO commitear

### Seguridad
- **NUNCA commitear API keys** — `config.json` real va en `.gitignore`
- Mantener `config.json.example` con keys vacías como template
- El parseo XML debe ser seguro contra XXE
- Validar IPs como públicas antes de enviarlas a APIs externas
- Rate limiting obligatorio en todas las consultas a APIs

## Workflow de desarrollo con Git

### Ramas
- `main` — protegida, solo via PR
- `feat/nombre-descriptivo` — nuevas funcionalidades
- `fix/nombre-descriptivo` — correcciones
- `refactor/nombre-descriptivo` — mejoras internas
- `test/nombre-descriptivo` — tests nuevos o mejorados

### Proceso para cada cambio
1. Crear rama desde `main`: `git checkout -b feat/nombre`
2. Desarrollar con commits atómicos (un commit = un cambio lógico)
3. Ejecutar `pytest tests/ -v` y `ruff check .` — todo debe pasar
4. Push: `git push origin feat/nombre`
5. Abrir PR en GitHub con descripción de qué y por qué
6. Esperar CI (GitHub Actions) y CodeRabbit
7. Merge a `main` cuando todo esté verde

### Mensajes de commit (ejemplos)
```
feat: añadir integración con Shodan para puertos abiertos
fix: corregir parseo de reportes Microsoft sin campo sp en policy_published
test: añadir cobertura para XML de Cisco/iphmx
refactor: extraer generación de panel IP a función independiente
docs: documentar estructura de datos de IP enriquecida
chore: actualizar dependencias en requirements.txt
```

## Contexto del desarrollador

El desarrollador principal (Cristian) es analista de ciberseguridad en Akuda Security, no desarrollador profesional. Tiene 5 años de experiencia en sistemas y ciberseguridad, certificaciones CEH/CHFI/Pentest+, CPTS en curso, y experiencia con Python para scripting. Está aprendiendo desarrollo profesional con IA (Claude Code).

Esto significa:
- **Explicar decisiones:** Ante cambios arquitectónicos, explicar brevemente el porqué
- **Preferir claridad sobre elegancia:** Código legible y comentado > conciso pero críptico
- **No asumir patrones avanzados:** Si se usa un patrón no obvio, comentar qué hace y por qué
- **Proponer, no imponer:** Ante decisiones de diseño, presentar opciones con pros/contras

## Decisiones de diseño vigentes

1. **HTML autocontenido:** Un solo .html con CSS/JS embebidos para compartir fácilmente
2. **Cache en disco:** JSON con TTL 24h para no gastar cuota de APIs
3. **Degradación elegante:** Si falta una API key, esa fuente se omite sin errores
4. **Inyección no invasiva:** `dmarc_run.py` inyecta el panel IP sin modificar `dmarc_visualizer.py`
5. **Score de riesgo compuesto:** AbuseIPDB (50%) + VirusTotal + flags IPinfo
6. **VirusTotal opcional:** Rate limit de 4/min; desactivable en config

## Límites actuales

- No tiene servidor web persistente — genera HTML estático
- No almacena en base de datos — usa Excel + cache JSON
- No se conecta a buzones de correo — carga de XMLs manual
- No es multi-tenant — herramienta interna
- No tiene autenticación

## Mejoras futuras identificadas

- Integrar Shodan como quinta fuente de inteligencia
- Refactorizar generación HTML (separar del monolito de f-strings)
- Evolucionar a app web con Flask/FastAPI + base de datos
- Ingesta automática de .eml desde buzón
- Informes PDF ejecutivos por dominio para clientes
- Soporte multi-dominio/multi-tenant