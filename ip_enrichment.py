"""
ip_enrichment.py — Módulo de enriquecimiento de IPs para DMARC Dashboard
═════════════════════════════════════════════════════════════════════════

Consulta múltiples fuentes de inteligencia para cada IP encontrada
en los informes DMARC y devuelve un perfil completo de cada una.

Fuentes soportadas:
  1. AbuseIPDB   → Reputación, score de abuso, nº reportes, categorías
  2. IPinfo.io   → Geolocalización, ASN/ISP, hostname, flags (hosting/VPN/Tor)
  3. VirusTotal  → Detecciones maliciosas por vendors, reputación comunidad
  4. Reverse DNS → Hostname PTR (sin API externa, usa socket de Python)

Uso standalone (test):
    python ip_enrichment.py 194.104.111.120 52.212.19.177 82.223.190.18

Uso como módulo (desde dmarc_visualizer.py):
    from ip_enrichment import IPEnricher
    enricher = IPEnricher("config.json")
    enricher.enrich_all(list_of_ips)
    data = enricher.get("194.104.111.120")

Configuración:
    Crear un archivo config.json junto al script (ver ejemplo al final).
    Las API keys son opcionales: si no se proporcionan, esa fuente se omite.

Dependencias:
    pip install requests
    (requests es la única dependencia externa)
"""

import json
import socket
import time
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from collections import OrderedDict

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False
    print("  ⚠  requests no encontrado. Instala: pip install requests")


# ═════════════════════════════════════════════════════════════════
#  CONFIGURACIÓN
# ═════════════════════════════════════════════════════════════════

# Estructura por defecto. Se sobreescribe con config.json si existe.
DEFAULT_CONFIG = {
    # ── API Keys ──────────────────────────────────────────────
    # Déjalas vacías ("") para desactivar esa fuente
    "abuseipdb_key":   "",
    "ipinfo_token":    "",
    "virustotal_key":  "",

    # ── Opciones de consulta ──────────────────────────────────
    "abuseipdb_max_age_days": 90,     # Ventana de reportes en AbuseIPDB
    "virustotal_enabled":     True,   # VT tiene 4 req/min gratis, cuidado
    "rdns_enabled":           True,   # Reverse DNS (sin API, gratis)

    # ── Cache ─────────────────────────────────────────────────
    # Los resultados se cachean en disco para no repetir consultas.
    # TTL en segundos (86400 = 24h). 0 = sin caché.
    "cache_enabled": True,
    "cache_file":    "ip_enrichment_cache.json",
    "cache_ttl":     86400,

    # ── Rate limiting ─────────────────────────────────────────
    # Pausa entre peticiones a cada API (en segundos).
    # AbuseIPDB free = 1000/día, IPinfo Lite = ilimitado,
    # VirusTotal free = 4/min (15s entre peticiones para ir seguro)
    "delay_abuseipdb":   0.2,
    "delay_ipinfo":      0.1,
    "delay_virustotal":  16,  # 4 req/min → ~15s entre cada una
}


def load_config(config_path="config.json"):
    """
    Carga la configuración desde un archivo JSON.
    Si no existe, devuelve la configuración por defecto.
    También soporta que el path sea un dict ya cargado.
    """
    if isinstance(config_path, dict):
        cfg = {**DEFAULT_CONFIG, **config_path}
        return cfg

    path = Path(config_path)
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
            # Merge: user overrides defaults
            cfg = {**DEFAULT_CONFIG, **user_cfg}
            print(f"  ⚙  Config cargada: {path.name}")
            return cfg
        except Exception as e:
            print(f"  ⚠  Error leyendo {path.name}: {e} — usando defaults")

    return dict(DEFAULT_CONFIG)


# ═════════════════════════════════════════════════════════════════
#  CACHE EN DISCO
# ═════════════════════════════════════════════════════════════════

class DiskCache:
    """
    Cache simple en archivo JSON.
    Cada entrada tiene un timestamp; se invalida tras cache_ttl segundos.
    Estructura: { "ip": { "_ts": 1234567890, "abuseipdb": {...}, ... } }
    """

    def __init__(self, filepath, ttl=86400, enabled=True):
        self.path = Path(filepath)
        self.ttl = ttl
        self.enabled = enabled
        self.data = {}
        if enabled and self.path.exists():
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
            except Exception:
                self.data = {}

    def get(self, ip):
        """Devuelve datos cacheados para la IP, o None si expiró/no existe."""
        if not self.enabled:
            return None
        entry = self.data.get(ip)
        if not entry:
            return None
        ts = entry.get("_ts", 0)
        if time.time() - ts > self.ttl:
            return None  # Expirado
        return entry

    def set(self, ip, data):
        """Guarda datos enriquecidos para la IP con timestamp actual."""
        if not self.enabled:
            return
        data["_ts"] = time.time()
        self.data[ip] = data

    def save(self):
        """Persiste la cache a disco."""
        if not self.enabled:
            return
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"  ⚠  Error guardando cache: {e}")


# ═════════════════════════════════════════════════════════════════
#  PROVEEDORES DE DATOS
# ═════════════════════════════════════════════════════════════════

def query_rdns(ip):
    """
    Reverse DNS lookup usando socket.
    No requiere API ni dependencias externas.

    Devuelve:
    {
        "hostname": "mail.example.com" | "",
        "error": "" | "mensaje de error"
    }
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return {"hostname": hostname, "error": ""}
    except (socket.herror, socket.gaierror):
        return {"hostname": "", "error": "No PTR record"}
    except Exception as e:
        return {"hostname": "", "error": str(e)}


def query_abuseipdb(ip, api_key, max_age_days=90):
    """
    Consulta el endpoint CHECK de AbuseIPDB API v2.

    Endpoint: GET https://api.abuseipdb.com/api/v2/check
    Params:   ipAddress, maxAgeInDays, verbose
    Headers:  Key: <api_key>, Accept: application/json

    Devuelve dict con los campos más relevantes:
    {
        "abuse_score":     0-100 (abuseConfidenceScore),
        "total_reports":   int,
        "is_public":       bool,
        "is_whitelisted":  bool,
        "isp":             str,
        "domain":          str,
        "country_code":    str (ISO),
        "usage_type":      str,
        "last_reported":   str (fecha ISO),
        "categories":      [int, ...] (códigos de categoría de abuso),
        "error":           str (vacío si ok)
    }
    """
    if not api_key or not REQUESTS_OK:
        return {"error": "no_key" if not api_key else "no_requests"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": api_key,
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": str(max_age_days),
        "verbose": "",  # Incluir últimos reportes
    }

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=15)
        if resp.status_code == 429:
            return {"error": "rate_limited"}
        if resp.status_code != 200:
            return {"error": f"http_{resp.status_code}"}

        body = resp.json()
        d = body.get("data", {})

        # Extraer categorías únicas de los últimos reportes
        categories = set()
        for report in d.get("reports", []):
            for cat in report.get("categories", []):
                categories.add(cat)

        return {
            "abuse_score":    d.get("abuseConfidenceScore", 0),
            "total_reports":  d.get("totalReports", 0),
            "is_public":      d.get("isPublic", True),
            "is_whitelisted": d.get("isWhitelisted", False),
            "isp":            d.get("isp", ""),
            "domain":         d.get("domain", ""),
            "country_code":   d.get("countryCode", ""),
            "usage_type":     d.get("usageType", ""),
            "last_reported":  d.get("lastReportedAt", ""),
            "categories":     sorted(categories),
            "error":          "",
        }

    except requests.exceptions.Timeout:
        return {"error": "timeout"}
    except requests.exceptions.ConnectionError:
        return {"error": "connection_error"}
    except Exception as e:
        return {"error": str(e)}


def query_ipinfo(ip, token=""):
    """
    Consulta IPinfo.io para geolocalización y datos ASN.

    Endpoint: GET https://ipinfo.io/{ip}?token={token}
    (Si no hay token, usa el tier gratuito con datos limitados)

    Devuelve:
    {
        "city":           str,
        "region":         str,
        "country":        str (código ISO),
        "loc":            str ("lat,lon"),
        "org":            str ("AS12345 Nombre ISP"),
        "asn":            str ("AS12345"),
        "as_name":        str ("Nombre ISP"),
        "hostname":       str,
        "timezone":       str,
        "postal":         str,
        "is_hosting":     bool | None,
        "is_vpn":         bool | None,
        "is_proxy":       bool | None,
        "is_tor":         bool | None,
        "is_relay":       bool | None,
        "error":          str
    }
    """
    if not REQUESTS_OK:
        return {"error": "no_requests"}

    url = f"https://ipinfo.io/{ip}"
    params = {}
    if token:
        params["token"] = token

    try:
        resp = requests.get(url, params=params, timeout=10)
        if resp.status_code == 429:
            return {"error": "rate_limited"}
        if resp.status_code != 200:
            return {"error": f"http_{resp.status_code}"}

        d = resp.json()

        # El campo "org" viene como "AS12345 Nombre ISP", lo separamos
        org_raw = d.get("org", "")
        asn = ""
        as_name = org_raw
        if org_raw.startswith("AS"):
            parts = org_raw.split(" ", 1)
            asn = parts[0]
            as_name = parts[1] if len(parts) > 1 else ""

        # Campos de privacy (solo disponibles con token Core+)
        privacy = d.get("privacy", {})

        return {
            "city":       d.get("city", ""),
            "region":     d.get("region", ""),
            "country":    d.get("country", ""),
            "loc":        d.get("loc", ""),
            "org":        org_raw,
            "asn":        asn,
            "as_name":    as_name,
            "hostname":   d.get("hostname", ""),
            "timezone":   d.get("timezone", ""),
            "postal":     d.get("postal", ""),
            "is_hosting": privacy.get("hosting"),
            "is_vpn":     privacy.get("vpn"),
            "is_proxy":   privacy.get("proxy"),
            "is_tor":     privacy.get("tor"),
            "is_relay":   privacy.get("relay"),
            "error":      "",
        }

    except requests.exceptions.Timeout:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def query_virustotal(ip, api_key):
    """
    Consulta VirusTotal API v3 para reputación de IP.

    Endpoint: GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
    Headers:  x-apikey: <api_key>

    La respuesta incluye last_analysis_stats con conteos de
    harmless / malicious / suspicious / undetected por vendors.

    Devuelve:
    {
        "malicious":    int (nº vendors que lo marcan malicioso),
        "suspicious":   int,
        "harmless":     int,
        "undetected":   int,
        "reputation":   int (score de votos de la comunidad),
        "as_owner":     str,
        "asn":          int,
        "country":      str,
        "network":      str (rango CIDR),
        "tags":         [str, ...],
        "error":        str
    }
    """
    if not api_key or not REQUESTS_OK:
        return {"error": "no_key" if not api_key else "no_requests"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 429:
            return {"error": "rate_limited"}
        if resp.status_code != 200:
            return {"error": f"http_{resp.status_code}"}

        body = resp.json()
        attrs = body.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        return {
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "as_owner":   attrs.get("as_owner", ""),
            "asn":        attrs.get("asn", 0),
            "country":    attrs.get("country", ""),
            "network":    attrs.get("network", ""),
            "tags":       attrs.get("tags", []),
            "error":      "",
        }

    except requests.exceptions.Timeout:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


# ═════════════════════════════════════════════════════════════════
#  CLASIFICACIÓN DE RIESGO
# ═════════════════════════════════════════════════════════════════

# Mapa de categorías de AbuseIPDB a nombres legibles
ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


def classify_risk(enriched_data):
    """
    Calcula un nivel de riesgo agregado (low/medium/high/critical)
    combinando los datos de todas las fuentes.

    Criterios:
    - AbuseIPDB score > 80 → critical, > 40 → high, > 10 → medium
    - VirusTotal malicious > 5 → +high, > 1 → +medium
    - Flags de VPN/Tor/Proxy → +medium
    - Hosting sin reports → low (probablemente legítimo)

    Devuelve: {
        "level":   "low" | "medium" | "high" | "critical",
        "score":   0-100 (score numérico compuesto),
        "reasons": [str, ...] (explicaciones de por qué)
    }
    """
    score = 0
    reasons = []

    # ── AbuseIPDB ─────────────────────────────────────────────
    abuse = enriched_data.get("abuseipdb", {})
    if abuse and not abuse.get("error"):
        abuse_score = abuse.get("abuse_score", 0)
        if abuse_score > 0:
            # Peso principal: score de AbuseIPDB (ya es 0-100)
            score += abuse_score * 0.5
            reasons.append(f"AbuseIPDB score: {abuse_score}/100")

        total_reports = abuse.get("total_reports", 0)
        if total_reports > 50:
            score += 15
            reasons.append(f"{total_reports} reportes de abuso")
        elif total_reports > 10:
            score += 8
            reasons.append(f"{total_reports} reportes de abuso")

        cats = abuse.get("categories", [])
        dangerous_cats = {7, 11, 17}  # Phishing, Email Spam, Spoofing
        if dangerous_cats & set(cats):
            score += 15
            cat_names = [ABUSE_CATEGORIES.get(c, f"Cat-{c}")
                         for c in cats if c in dangerous_cats]
            reasons.append(f"Categorías relevantes: {', '.join(cat_names)}")

    # ── VirusTotal ────────────────────────────────────────────
    vt = enriched_data.get("virustotal", {})
    if vt and not vt.get("error"):
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        if mal > 5:
            score += 20
            reasons.append(f"VirusTotal: {mal} vendors lo marcan malicioso")
        elif mal > 1:
            score += 10
            reasons.append(f"VirusTotal: {mal} vendors lo marcan malicioso")
        if sus > 3:
            score += 5
            reasons.append(f"VirusTotal: {sus} vendors sospechoso")

    # ── IPinfo flags ──────────────────────────────────────────
    ipinfo = enriched_data.get("ipinfo", {})
    if ipinfo and not ipinfo.get("error"):
        if ipinfo.get("is_vpn"):
            score += 8
            reasons.append("IP identificada como VPN")
        if ipinfo.get("is_tor"):
            score += 12
            reasons.append("IP identificada como nodo Tor")
        if ipinfo.get("is_proxy"):
            score += 10
            reasons.append("IP identificada como proxy")

    # ── Clasificación final ───────────────────────────────────
    score = min(100, max(0, round(score)))

    if score >= 70:
        level = "critical"
    elif score >= 40:
        level = "high"
    elif score >= 15:
        level = "medium"
    else:
        level = "low"

    if not reasons:
        reasons.append("Sin indicadores de riesgo detectados")

    return {"level": level, "score": score, "reasons": reasons}


# ═════════════════════════════════════════════════════════════════
#  CLASE PRINCIPAL: IPEnricher
# ═════════════════════════════════════════════════════════════════

class IPEnricher:
    """
    Orquesta las consultas a todas las fuentes, gestiona cache
    y rate-limiting, y expone los resultados en un formato unificado.

    Uso:
        enricher = IPEnricher("config.json")
        enricher.enrich_all(["194.104.111.120", "52.212.19.177"])
        data = enricher.get("194.104.111.120")
        all_data = enricher.get_all()
        enricher.save_cache()
    """

    def __init__(self, config_path="config.json"):
        self.cfg = load_config(config_path)
        self.cache = DiskCache(
            filepath=self.cfg.get("cache_file", "ip_enrichment_cache.json"),
            ttl=self.cfg.get("cache_ttl", 86400),
            enabled=self.cfg.get("cache_enabled", True),
        )
        # Resultados en memoria: { "ip": { "abuseipdb":{...}, ... } }
        self.results = OrderedDict()
        # Contadores de peticiones (para info del usuario)
        self.api_calls = {"abuseipdb": 0, "ipinfo": 0, "virustotal": 0, "rdns": 0}

    def _has_key(self, key_name):
        """Comprueba si hay API key configurada para un servicio."""
        return bool(self.cfg.get(key_name, "").strip())

    def enrich_ip(self, ip, skip_virustotal=False):
        """
        Enriquece una única IP consultando todas las fuentes activas.
        Usa cache si hay datos válidos. Respeta rate limits.

        Args:
            ip: Dirección IP a enriquecer.
            skip_virustotal: Si True, no consulta VirusTotal (se hará bajo demanda).

        Devuelve el dict completo de la IP.
        """
        # Intentar cache primero
        cached = self.cache.get(ip)
        if cached:
            # Verificar si la cache tiene fuentes sin key que ahora sí están disponibles
            needs_refresh = False
            if (cached.get("abuseipdb", {}).get("error") == "no_key"
                    and self._has_key("abuseipdb_key")):
                needs_refresh = True
            if (cached.get("ipinfo", {}).get("error") == "no_key"
                    and self._has_key("ipinfo_token")):
                needs_refresh = True

            if not needs_refresh:
                if skip_virustotal:
                    # Forzar que VT se muestre como "no consultado" para
                    # que el dashboard ofrezca el botón de consulta on-demand
                    cached["virustotal"] = {"error": "not_queried"}
                    cached["risk"] = classify_risk(cached)
                self.results[ip] = cached
                return cached
            # Si needs_refresh, caer al flujo normal y re-consultar todas las fuentes

        result = {"ip": ip, "_enriched_at": datetime.now(timezone.utc).isoformat()}

        # ── 1. Reverse DNS ────────────────────────────────────
        if self.cfg.get("rdns_enabled", True):
            result["rdns"] = query_rdns(ip)
            self.api_calls["rdns"] += 1

        # ── 2. IPinfo ─────────────────────────────────────────
        # IPinfo funciona sin token (tier gratuito), así que
        # siempre lo consultamos. Con token da más datos.
        ipinfo_data = query_ipinfo(ip, self.cfg.get("ipinfo_token", ""))
        result["ipinfo"] = ipinfo_data
        self.api_calls["ipinfo"] += 1
        if ipinfo_data.get("error") != "rate_limited":
            time.sleep(self.cfg.get("delay_ipinfo", 0.1))
        else:
            print(f"    ⚠  IPinfo rate limited en {ip}")
            time.sleep(2)

        # ── 3. AbuseIPDB ──────────────────────────────────────
        if self._has_key("abuseipdb_key"):
            abuse_data = query_abuseipdb(
                ip,
                self.cfg["abuseipdb_key"],
                self.cfg.get("abuseipdb_max_age_days", 90),
            )
            result["abuseipdb"] = abuse_data
            self.api_calls["abuseipdb"] += 1
            if abuse_data.get("error") == "rate_limited":
                print(f"    ⚠  AbuseIPDB rate limited en {ip}")
                time.sleep(5)
            else:
                time.sleep(self.cfg.get("delay_abuseipdb", 0.2))
        else:
            result["abuseipdb"] = {"error": "no_key"}

        # ── 4. VirusTotal ─────────────────────────────────────
        if skip_virustotal:
            result["virustotal"] = {"error": "not_queried"}
        elif self._has_key("virustotal_key") and self.cfg.get("virustotal_enabled", True):
            vt_data = query_virustotal(ip, self.cfg["virustotal_key"])
            result["virustotal"] = vt_data
            self.api_calls["virustotal"] += 1
            if vt_data.get("error") == "rate_limited":
                print(f"    ⚠  VirusTotal rate limited en {ip}, esperando 60s...")
                time.sleep(60)
            else:
                time.sleep(self.cfg.get("delay_virustotal", 16))
        else:
            result["virustotal"] = {"error": "disabled" if not self.cfg.get("virustotal_enabled") else "no_key"}

        # ── 5. Clasificación de riesgo ────────────────────────
        result["risk"] = classify_risk(result)

        # Guardar en cache y memoria
        self.cache.set(ip, result)
        self.results[ip] = result
        return result

    def enrich_all(self, ips):
        """
        Enriquece una lista de IPs. Muestra progreso por consola.
        Omite IPs privadas (RFC1918) y localhost.
        """
        # Deduplicar y filtrar IPs privadas
        unique_ips = list(OrderedDict.fromkeys(ips))
        public_ips = [ip for ip in unique_ips if not _is_private(ip)]

        total = len(public_ips)
        if total == 0:
            print("  ℹ  No hay IPs públicas para enriquecer")
            return

        # Contar cuántas ya están en cache
        cached_count = sum(1 for ip in public_ips if self.cache.get(ip))
        to_fetch = total - cached_count

        print(f"\n  🔍 Enriqueciendo {total} IPs ({cached_count} en cache, {to_fetch} a consultar)")

        # Mostrar qué APIs están activas
        apis = []
        apis.append("rDNS" if self.cfg.get("rdns_enabled") else "rDNS ✗")
        apis.append("IPinfo" + (" (token)" if self._has_key("ipinfo_token") else " (free)"))
        apis.append("AbuseIPDB ✓" if self._has_key("abuseipdb_key") else "AbuseIPDB ✗")
        vt_available = self._has_key("virustotal_key") and self.cfg.get("virustotal_enabled")
        apis.append("VirusTotal → bajo demanda" if vt_available else "VirusTotal ✗")
        print(f"  ⚡ APIs activas: {' · '.join(apis)}")
        print()

        for i, ip in enumerate(public_ips, 1):
            cached = self.cache.get(ip)
            tag = "CACHE" if cached else "API"
            print(f"  [{i}/{total}] {ip:<20} [{tag}] ", end="", flush=True)

            data = self.enrich_ip(ip, skip_virustotal=True)

            # Mostrar resumen rápido
            risk = data.get("risk", {})
            level = risk.get("level", "?")
            score = risk.get("score", 0)
            country = (data.get("ipinfo", {}).get("country", "") or
                       data.get("abuseipdb", {}).get("country_code", ""))
            abuse_s = data.get("abuseipdb", {}).get("abuse_score", "—")
            hostname = (data.get("rdns", {}).get("hostname", "") or
                        data.get("ipinfo", {}).get("hostname", ""))

            level_icon = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(level, "⚪")
            print(f"{level_icon} {level.upper():8} score:{score:3} "
                  f"abuse:{abuse_s:>3} country:{country:>2} "
                  f"host:{hostname[:40] if hostname else '—'}")

        # Persistir cache
        self.save_cache()

        print(f"\n  ✅ Enriquecimiento completado")
        print(f"     Llamadas API: {dict(self.api_calls)}")

    def get(self, ip):
        """Devuelve los datos enriquecidos de una IP, o None."""
        return self.results.get(ip) or self.cache.get(ip)

    def get_all(self):
        """Devuelve un dict con todas las IPs enriquecidas."""
        return dict(self.results)

    def get_serializable(self):
        """
        Devuelve los datos listos para inyectar en JSON/HTML.
        Limpia campos internos como _ts.
        """
        out = {}
        for ip, data in self.results.items():
            clean = {k: v for k, v in data.items() if not k.startswith("_")}
            out[ip] = clean
        return out

    def enrich_ip_virustotal(self, ip):
        """
        Consulta solo VirusTotal para una IP específica (bajo demanda).
        Actualiza los datos existentes, recalcula el riesgo y persiste en cache.

        Devuelve el dict completo actualizado de la IP, o un dict con error.
        """
        if not self._has_key("virustotal_key"):
            return {"error": "no_key"}
        if not self.cfg.get("virustotal_enabled", True):
            return {"error": "disabled"}

        # Cargar datos existentes de results o cache
        existing = self.results.get(ip) or self.cache.get(ip)
        if not existing:
            existing = {"ip": ip}

        # Consultar VirusTotal
        vt_data = query_virustotal(ip, self.cfg["virustotal_key"])
        self.api_calls["virustotal"] += 1

        # Actualizar solo el campo virustotal
        existing["virustotal"] = vt_data

        # Recalcular riesgo con los nuevos datos VT
        existing["risk"] = classify_risk(existing)

        # Persistir en cache y memoria
        self.cache.set(ip, existing)
        self.cache.save()
        self.results[ip] = existing

        # Devolver datos limpios (sin campos internos)
        return {k: v for k, v in existing.items() if not k.startswith("_")}

    def save_cache(self):
        """Persiste la cache a disco."""
        self.cache.save()

    def print_summary(self):
        """Imprime un resumen de las IPs enriquecidas."""
        if not self.results:
            print("  Sin datos de enriquecimiento")
            return

        print(f"\n  {'═' * 68}")
        print(f"  {'IP':<20} {'Riesgo':<10} {'Score':>5} {'Abuse':>5} {'VT':>4} {'País':>4} {'Hostname'}")
        print(f"  {'─' * 68}")

        for ip, data in self.results.items():
            risk = data.get("risk", {})
            abuse = data.get("abuseipdb", {})
            vt = data.get("virustotal", {})
            ipinfo = data.get("ipinfo", {})
            rdns = data.get("rdns", {})

            level = risk.get("level", "?")
            score = risk.get("score", 0)
            abuse_s = abuse.get("abuse_score", "—") if not abuse.get("error") else "—"
            vt_mal = vt.get("malicious", "—") if not vt.get("error") else "—"
            country = ipinfo.get("country", "") or abuse.get("country_code", "")
            hostname = rdns.get("hostname", "") or ipinfo.get("hostname", "")

            icon = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(level, "⚪")
            print(f"  {ip:<20} {icon} {level:<8} {score:>5} {str(abuse_s):>5} {str(vt_mal):>4} {country:>4} {hostname[:35]}")

        print(f"  {'═' * 68}")


# ═════════════════════════════════════════════════════════════════
#  UTILIDADES
# ═════════════════════════════════════════════════════════════════

def _is_private(ip):
    """Detecta si una IP es privada (RFC1918), loopback o link-local."""
    try:
        # IPv6 simplificado
        if ":" in ip:
            return ip.startswith("fe80") or ip.startswith("::1") or ip.startswith("fc") or ip.startswith("fd")
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        if a == 10: return True                        # 10.0.0.0/8
        if a == 172 and 16 <= b <= 31: return True     # 172.16.0.0/12
        if a == 192 and b == 168: return True          # 192.168.0.0/16
        if a == 127: return True                        # 127.0.0.0/8
        if a == 169 and b == 254: return True           # 169.254.0.0/16
        return False
    except Exception:
        return False


def extract_ips_from_reports(reports):
    """
    Extrae todas las IPs únicas de una lista de reportes DMARC
    (en el formato que produce parse_dmarc_xml del visualizer).
    """
    ips = set()
    for rpt in reports:
        for rec in rpt.get("records", []):
            ip = rec.get("source_ip", "").strip()
            if ip:
                ips.add(ip)
    return sorted(ips)


# ═════════════════════════════════════════════════════════════════
#  EJECUCIÓN STANDALONE (para testing)
# ═════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    print()
    print("━" * 62)
    print("   DMARC IP ENRICHMENT — Test Mode")
    print("━" * 62)

    # IPs de los argumentos, o usar las de los XMLs de ejemplo
    ips = sys.argv[1:] if len(sys.argv) > 1 else [
        "194.104.111.120",  # Mimecast (legítima)
        "194.104.109.120",  # Mimecast (legítima)
        "52.212.19.177",    # AWS — DMARC fail en los reportes
        "82.223.190.18",    # Posible forwarding
    ]

    enricher = IPEnricher("config.json")
    enricher.enrich_all(ips)
    enricher.print_summary()

    # Mostrar detalle de riesgo para cada IP
    for ip in ips:
        data = enricher.get(ip)
        if data:
            risk = data.get("risk", {})
            print(f"\n  📋 {ip} — Razones de riesgo:")
            for r in risk.get("reasons", []):
                print(f"     • {r}")

    print()


# ═════════════════════════════════════════════════════════════════
#  EJEMPLO DE config.json
# ═════════════════════════════════════════════════════════════════
#
#  Crear este archivo junto al script con tus API keys:
#
#  {
#      "abuseipdb_key":        "tu_key_de_abuseipdb",
#      "ipinfo_token":         "tu_token_de_ipinfo",
#      "virustotal_key":       "tu_key_de_virustotal",
#      "virustotal_enabled":   true,
#      "rdns_enabled":         true,
#      "cache_enabled":        true,
#      "cache_ttl":            86400,
#      "abuseipdb_max_age_days": 90,
#      "delay_abuseipdb":      0.2,
#      "delay_ipinfo":         0.1,
#      "delay_virustotal":     16
#  }
#
# ═════════════════════════════════════════════════════════════════