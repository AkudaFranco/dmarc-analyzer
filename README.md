# DMARC Dashboard con Enriquecimiento de IPs

## Estructura de archivos

```
proyecto/
├── dmarc_visualizer.py      # Motor principal (parseo XML, stats, HTML base)
├── ip_enrichment.py          # Módulo de enriquecimiento (APIs externas)
├── dmarc_run.py              # Orquestador (conecta todo + inyecta panel IP)
├── config.json               # API keys y configuración
├── dmarc_reports/            # ← Pon aquí los XMLs extraídos
│   ├── google.com!akuda.es!1774396800!1774483199.xml
│   ├── enterprise.protection.outlook.com!akuda.es!...xml
│   └── ...
├── dmarc_dashboard.html      # (generado automáticamente)
├── dmarc_database.xlsx       # (generado automáticamente)
└── ip_enrichment_cache.json  # (generado automáticamente)
```

## Instalación

```bash
pip install requests openpyxl
```

## Configuración de API keys

Edita `config.json` con tus claves:

```json
{
    "abuseipdb_key":      "TU_KEY_AQUI",
    "ipinfo_token":       "TU_TOKEN_AQUI",
    "virustotal_key":     "TU_KEY_AQUI",
    "virustotal_enabled": true
}
```

### Dónde obtener las keys (todas gratuitas):

| Servicio   | URL                                      | Límite free           |
|------------|------------------------------------------|-----------------------|
| AbuseIPDB  | https://www.abuseipdb.com/account/api    | 1.000 checks/día      |
| IPinfo     | https://ipinfo.io/signup                 | Ilimitado (tier Lite) |
| VirusTotal | https://www.virustotal.com/gui/join-us   | 4 requests/minuto     |

> **Nota:** Cada key es opcional. Sin keys, el dashboard funciona
> igualmente pero sin datos de enriquecimiento.

## Uso

### Opción A — Con enriquecimiento (recomendado)

```bash
python dmarc_run.py ./dmarc_reports
```

Esto:
1. Parsea los XMLs DMARC
2. Consulta AbuseIPDB + IPinfo + VirusTotal + rDNS para cada IP
3. Genera el dashboard HTML con panel interactivo de detalle de IP
4. Abre el navegador automáticamente

### Opción B — Sin enriquecimiento (rápido)

```bash
python dmarc_run.py ./dmarc_reports --no-enrich
```

Dashboard completo pero sin datos de reputación/geolocalización.

### Opción C — Solo probar el enriquecimiento

```bash
python ip_enrichment.py 194.104.111.120 52.212.19.177
```

### Opción D — Solo el visualizador original

```bash
python dmarc_visualizer.py ./dmarc_reports
```

## Qué ves en el dashboard

### Tabla principal (mejorada)
- 🟢🟡🟠🔴 Dot de riesgo junto a cada IP
- 🇪🇸🇺🇸🇩🇪 Bandera de país
- Click en cualquier IP → abre panel lateral

### Panel lateral de IP (nuevo)
- **Evaluación de riesgo**: Score 0-100 con razones explicadas
- **Geolocalización**: País, ciudad, ASN/ISP, flags VPN/Tor/Proxy
- **Reputación AbuseIPDB**: Gauge visual, nº reportes, categorías de abuso
- **Detecciones VirusTotal**: Barra de vendors (malicioso/sospechoso/inofensivo)
- **DNS reverso**: Hostname PTR

## Cache

Los resultados de las APIs se cachean en `ip_enrichment_cache.json`
con un TTL de 24 horas. Para forzar reconsulta:

```bash
# Borrar cache
rm ip_enrichment_cache.json

# O cambiar TTL en config.json
"cache_ttl": 3600   # 1 hora en vez de 24
```

## Notas sobre VirusTotal

VT free tiene un límite muy estricto (4 req/min). El script espera
~16 segundos entre cada petición. Con 10 IPs únicas:
- Sin VT: ~30 segundos
- Con VT: ~3 minutos

Si no necesitas VT, desactívalo:
```json
"virustotal_enabled": false
```