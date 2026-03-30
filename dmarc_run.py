#!/usr/bin/env python3
"""
dmarc_run.py — Orquestador del DMARC Dashboard con enriquecimiento de IPs
══════════════════════════════════════════════════════════════════════════

Este script conecta los tres componentes:
  1. dmarc_visualizer.py  → Parseo de XMLs, stats, generación HTML base
  2. ip_enrichment.py     → Consultas a AbuseIPDB, IPinfo, VirusTotal, rDNS
  3. IP Detail Panel       → Componente HTML/JS inyectado en el dashboard

Uso:
    python dmarc_run.py                          # carpeta: ./dmarc_reports
    python dmarc_run.py /ruta/reportes
    python dmarc_run.py /ruta/reportes --no-enrich   # sin enriquecimiento
    python dmarc_run.py /ruta/reportes --no-open

Requisitos:
    pip install requests openpyxl
"""

import sys, json, http.server, threading, webbrowser, time
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs

# ── Importar los módulos hermanos ─────────────────────────────────
# Asegurar que el directorio del script está en el path
script_dir = Path(__file__).parent.resolve()
if str(script_dir) not in sys.path:
    sys.path.insert(0, str(script_dir))

from dmarc_visualizer import (
    load_folder, compute_stats, generate_html,
    init_excel, update_excel, find_port, VERSION
)
from ip_enrichment import IPEnricher, extract_ips_from_reports


# ══════════════════════════════════════════════════════════════════
#  INYECCIÓN DEL PANEL DE DETALLE DE IP EN EL HTML
# ══════════════════════════════════════════════════════════════════

def build_ip_panel_html(ip_enrichment_data):
    """
    Genera el bloque HTML/CSS/JS del panel lateral de detalle de IP.
    Se inyecta justo antes del </body> del dashboard generado.

    ip_enrichment_data: dict { "ip": { "ipinfo":{...}, "abuseipdb":{...}, ... } }
    """
    data_json = json.dumps(ip_enrichment_data, ensure_ascii=False, default=str)

    return f"""
<!-- ═══════════════════════════════════════════════════════════ -->
<!--  IP DETAIL PANEL — Inyectado por dmarc_run.py              -->
<!-- ═══════════════════════════════════════════════════════════ -->
<style>
/* ── Overlay + Panel lateral ── */
.ip-overlay{{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:900;opacity:0;
  pointer-events:none;transition:opacity .25s;backdrop-filter:blur(4px)}}
.ip-overlay.open{{opacity:1;pointer-events:auto}}
.ip-panel{{position:fixed;top:0;right:-520px;width:500px;max-width:92vw;height:100vh;
  background:var(--s1);border-left:1px solid var(--bd);z-index:910;
  transition:right .3s cubic-bezier(.4,0,.2,1);overflow-y:auto;
  scrollbar-width:thin;scrollbar-color:var(--bd) transparent}}
.ip-panel.open{{right:0}}
.ip-panel-close{{position:absolute;top:12px;right:14px;background:none;border:none;
  color:var(--mt);font-size:22px;cursor:pointer;z-index:2;transition:color .15s}}
.ip-panel-close:hover{{color:var(--tx)}}

/* ── Header del panel ── */
.ipp-hdr{{padding:20px 22px 16px;border-bottom:1px solid var(--bd);
  background:linear-gradient(135deg,rgba(34,211,238,.04),transparent)}}
.ipp-ip{{font-family:var(--mono);font-size:22px;font-weight:700;color:var(--cy)}}
.ipp-host{{font-family:var(--mono);font-size:11px;color:var(--mt);margin-top:3px;
  word-break:break-all}}
.ipp-risk-bar{{display:flex;align-items:center;gap:10px;margin-top:10px}}
.ipp-risk-badge{{font-family:var(--mono);font-size:10px;font-weight:700;
  padding:3px 10px;border-radius:20px;text-transform:uppercase;letter-spacing:.08em}}
.ipp-risk-low{{background:rgba(74,222,128,.12);color:var(--gr);border:1px solid rgba(74,222,128,.25)}}
.ipp-risk-medium{{background:rgba(251,191,36,.12);color:var(--yw);border:1px solid rgba(251,191,36,.25)}}
.ipp-risk-high{{background:rgba(251,146,60,.12);color:var(--or);border:1px solid rgba(251,146,60,.25)}}
.ipp-risk-critical{{background:rgba(248,113,113,.15);color:var(--rd);border:1px solid rgba(248,113,113,.3)}}
.ipp-score-gauge{{width:100px;height:6px;background:var(--s3);border-radius:3px;overflow:hidden}}
.ipp-score-fill{{height:100%;border-radius:3px;transition:width .4s}}

/* ── Secciones del panel ── */
.ipp-section{{padding:16px 22px;border-bottom:1px solid rgba(31,45,71,.5)}}
.ipp-section:last-child{{border-bottom:none}}
.ipp-sec-title{{font-family:var(--mono);font-size:9.5px;text-transform:uppercase;
  letter-spacing:.12em;color:var(--mt);margin-bottom:10px;display:flex;align-items:center;gap:6px}}
.ipp-sec-title .ipp-src{{font-size:8px;padding:1px 6px;border-radius:10px;
  background:rgba(34,211,238,.08);color:var(--cy);border:1px solid rgba(34,211,238,.15);margin-left:auto}}

/* ── Grid de datos ── */
.ipp-grid{{display:grid;grid-template-columns:1fr 1fr;gap:8px}}
.ipp-item{{display:flex;flex-direction:column;gap:2px}}
.ipp-label{{font-family:var(--mono);font-size:8.5px;text-transform:uppercase;
  letter-spacing:.08em;color:var(--mt)}}
.ipp-value{{font-family:var(--mono);font-size:12px;color:var(--tx);word-break:break-all}}
.ipp-value.mono-sm{{font-size:10.5px}}

/* ── AbuseIPDB gauge ── */
.abuse-gauge{{display:flex;align-items:center;gap:10px}}
.abuse-gauge-ring{{width:56px;height:56px;border-radius:50%;position:relative;
  display:flex;align-items:center;justify-content:center}}
.abuse-gauge-val{{font-family:var(--mono);font-size:18px;font-weight:700}}
.abuse-gauge-lbl{{font-family:var(--mono);font-size:9px;color:var(--mt)}}

/* ── Tags/categorías ── */
.ipp-tags{{display:flex;flex-wrap:wrap;gap:4px;margin-top:6px}}
.ipp-tag{{font-family:var(--mono);font-size:9px;padding:2px 7px;border-radius:12px;
  background:rgba(248,113,113,.08);color:var(--rd);border:1px solid rgba(248,113,113,.15)}}
.ipp-tag.safe{{background:rgba(74,222,128,.08);color:var(--gr);border-color:rgba(74,222,128,.15)}}
.ipp-tag.info{{background:rgba(34,211,238,.08);color:var(--cy);border-color:rgba(34,211,238,.15)}}
.ipp-tag.warn{{background:rgba(251,191,36,.08);color:var(--yw);border-color:rgba(251,191,36,.15)}}

/* ── VT mini bar ── */
.vt-bar{{display:flex;height:14px;border-radius:4px;overflow:hidden;margin-top:6px;gap:1px}}
.vt-bar div{{height:100%;min-width:2px}}

/* ── Razones de riesgo ── */
.ipp-reasons{{list-style:none;padding:0;margin:6px 0 0}}
.ipp-reasons li{{font-family:var(--mono);font-size:10.5px;color:var(--dm);
  padding:4px 0;border-bottom:1px solid rgba(31,45,71,.3);display:flex;align-items:flex-start;gap:6px}}
.ipp-reasons li::before{{content:'›';color:var(--cy);font-weight:700;flex-shrink:0}}

/* ── Indicador en la tabla principal ── */
.ip-risk-dot{{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;
  vertical-align:middle;flex-shrink:0}}
.ip-risk-dot.low{{background:var(--gr);box-shadow:0 0 4px rgba(74,222,128,.4)}}
.ip-risk-dot.medium{{background:var(--yw);box-shadow:0 0 4px rgba(251,191,36,.4)}}
.ip-risk-dot.high{{background:var(--or);box-shadow:0 0 4px rgba(251,146,60,.4)}}
.ip-risk-dot.critical{{background:var(--rd);box-shadow:0 0 5px rgba(248,113,113,.5)}}

/* ── Country flag (emoji) ── */
.cflag{{margin-right:3px}}

/* ── Botón VT bajo demanda ── */
.vt-demand-btn{{background:rgba(34,211,238,.08);border:1px solid rgba(34,211,238,.2);
  color:var(--cy);font-family:var(--mono);font-size:11px;padding:10px 16px;
  border-radius:8px;cursor:pointer;width:100%;transition:all .2s}}
.vt-demand-btn:hover{{background:rgba(34,211,238,.15);border-color:rgba(34,211,238,.4);
  box-shadow:0 0 12px rgba(34,211,238,.1)}}
.vt-demand-btn:disabled{{cursor:wait;opacity:.6}}
</style>

<!-- Panel overlay -->
<div class="ip-overlay" id="ip-overlay" onclick="closeIPPanel()"></div>
<div class="ip-panel" id="ip-panel">
  <button class="ip-panel-close" onclick="closeIPPanel()">✕</button>
  <div id="ip-panel-content"></div>
</div>

<script>
// ── Datos de enriquecimiento inyectados ──
const IP_DATA = {data_json};

// ── Mapa de categorías AbuseIPDB ──
const ABUSE_CATS = {{
  1:"DNS Compromise",2:"DNS Poisoning",3:"Fraud Orders",4:"DDoS",5:"FTP Brute-Force",
  6:"Ping of Death",7:"Phishing",8:"Fraud VoIP",9:"Open Proxy",10:"Web Spam",
  11:"Email Spam",12:"Blog Spam",13:"VPN IP",14:"Port Scan",15:"Hacking",
  16:"SQL Injection",17:"Spoofing",18:"Brute-Force",19:"Bad Web Bot",20:"Exploited Host",
  21:"Web App Attack",22:"SSH",23:"IoT Targeted"
}};

// ── Código de país → emoji bandera ──
function countryFlag(code) {{
  if(!code||code.length!==2) return '';
  const c=code.toUpperCase();
  return String.fromCodePoint(...[...c].map(ch=>0x1F1E6-65+ch.charCodeAt(0)));
}}

// ── Abrir panel de detalle ──
function openIPPanel(ip) {{
  const d=IP_DATA[ip];
  const panel=$('ip-panel-content');
  if(!d) {{
    panel.innerHTML=`<div class="ipp-hdr"><div class="ipp-ip">${{ip}}</div>
      <div style="color:var(--mt);margin-top:12px;font-family:var(--mono);font-size:11px">
        ℹ Sin datos de enriquecimiento para esta IP.<br>
        Ejecuta el script con API keys configuradas para obtener detalles.
      </div></div>`;
    $('ip-overlay').classList.add('open');
    $('ip-panel').classList.add('open');
    return;
  }}

  const risk=d.risk||{{}};
  const ipinfo=d.ipinfo||{{}};
  const abuse=d.abuseipdb||{{}};
  const vt=d.virustotal||{{}};
  const rdns=d.rdns||{{}};

  const level=risk.level||'low';
  const score=risk.score||0;
  const hostname=rdns.hostname||ipinfo.hostname||'';
  const country=ipinfo.country||abuse.country_code||'';
  const flag=countryFlag(country);

  // Color según riesgo
  const riskCol={{low:'var(--gr)',medium:'var(--yw)',high:'var(--or)',critical:'var(--rd)'}}[level]||'var(--mt)';

  let html='';

  // ── Header ──
  html+=`<div class="ipp-hdr">
    <div class="ipp-ip">${{flag}} ${{ip}}</div>
    ${{hostname?`<div class="ipp-host">${{hostname}}</div>`:''}}
    <div class="ipp-risk-bar">
      <span class="ipp-risk-badge ipp-risk-${{level}}">${{level}}</span>
      <div class="ipp-score-gauge"><div class="ipp-score-fill" style="width:${{score}}%;background:${{riskCol}}"></div></div>
      <span style="font-family:var(--mono);font-size:11px;color:${{riskCol}};font-weight:600">${{score}}/100</span>
    </div>
  </div>`;

  // ── Razones de riesgo ──
  if(risk.reasons&&risk.reasons.length) {{
    html+=`<div class="ipp-section">
      <div class="ipp-sec-title">⚡ Evaluación de riesgo</div>
      <ul class="ipp-reasons">${{risk.reasons.map(r=>`<li>${{r}}</li>`).join('')}}</ul>
    </div>`;
  }}

  // ── Geolocalización (IPinfo) ──
  if(!ipinfo.error) {{
    html+=`<div class="ipp-section">
      <div class="ipp-sec-title">📍 Geolocalización <span class="ipp-src">IPinfo</span></div>
      <div class="ipp-grid">
        ${{_item('País',flag+' '+(ipinfo.country||'—'))}}
        ${{_item('Ciudad',ipinfo.city||'—')}}
        ${{_item('Región',ipinfo.region||'—')}}
        ${{_item('Timezone',ipinfo.timezone||'—')}}
        ${{_item('ASN',ipinfo.asn||'—')}}
        ${{_item('ISP / Org',ipinfo.as_name||'—')}}
        ${{_item('Coordenadas',ipinfo.loc||'—')}}
        ${{_item('Código postal',ipinfo.postal||'—')}}
      </div>`;
    // Flags de privacidad (si disponibles)
    const flags=[];
    if(ipinfo.is_hosting===true) flags.push(['info','Hosting']);
    if(ipinfo.is_vpn===true) flags.push(['warn','VPN']);
    if(ipinfo.is_tor===true) flags.push(['','Tor Exit']);
    if(ipinfo.is_proxy===true) flags.push(['warn','Proxy']);
    if(ipinfo.is_relay===true) flags.push(['info','Relay']);
    if(flags.length) {{
      html+=`<div class="ipp-tags" style="margin-top:10px">${{flags.map(([c,l])=>
        `<span class="ipp-tag ${{c}}">${{l}}</span>`).join('')}}</div>`;
    }}
    html+=`</div>`;
  }}

  // ── AbuseIPDB ──
  if(!abuse.error) {{
    const as=abuse.abuse_score||0;
    const ac=as>=70?'var(--rd)':as>=30?'var(--yw)':'var(--gr)';
    const ringBg=`conic-gradient(${{ac}} ${{as*3.6}}deg, rgba(22,32,50,.8) 0)`;
    html+=`<div class="ipp-section">
      <div class="ipp-sec-title">🛡 Reputación <span class="ipp-src">AbuseIPDB</span></div>
      <div class="abuse-gauge">
        <div class="abuse-gauge-ring" style="background:${{ringBg}}">
          <div style="width:42px;height:42px;border-radius:50%;background:var(--s1);
            display:flex;align-items:center;justify-content:center">
            <span class="abuse-gauge-val" style="color:${{ac}}">${{as}}</span>
          </div>
        </div>
        <div>
          <div style="font-family:var(--mono);font-size:11px;color:var(--tx)">
            Abuse Confidence Score
          </div>
          <div style="font-family:var(--mono);font-size:10px;color:var(--mt)">
            ${{abuse.total_reports||0}} reportes en ${{abuse.last_reported?'últimos 90 días':'—'}}
          </div>
        </div>
      </div>
      <div class="ipp-grid" style="margin-top:10px">
        ${{_item('ISP',abuse.isp||'—')}}
        ${{_item('Dominio',abuse.domain||'—')}}
        ${{_item('Uso',abuse.usage_type||'—')}}
        ${{_item('Último reporte',(abuse.last_reported||'—').slice(0,10))}}
      </div>`;
    // Categorías de abuso
    const cats=(abuse.categories||[]).map(c=>ABUSE_CATS[c]||'Cat-'+c);
    if(cats.length) {{
      html+=`<div style="margin-top:8px">
        <div class="ipp-label">Categorías reportadas</div>
        <div class="ipp-tags">${{cats.map(c=>`<span class="ipp-tag">${{c}}</span>`).join('')}}</div>
      </div>`;
    }}
    html+=`</div>`;
  }}

  // ── VirusTotal ──
  if(!vt.error) {{
    const mal=vt.malicious||0,sus=vt.suspicious||0,har=vt.harmless||0,und=vt.undetected||0;
    const tot=mal+sus+har+und||1;
    html+=`<div class="ipp-section">
      <div class="ipp-sec-title">🔬 Detecciones <span class="ipp-src">VirusTotal</span></div>
      <div class="ipp-grid">
        ${{_item('Malicioso',`<span style="color:${{mal>0?'var(--rd)':'var(--gr)'}};font-weight:600">${{mal}}</span> vendors`)}}
        ${{_item('Sospechoso',`<span style="color:${{sus>0?'var(--yw)':'var(--mt)'}}">${{sus}}</span> vendors`)}}
        ${{_item('Inofensivo',har+' vendors')}}
        ${{_item('Sin detectar',und+' vendors')}}
        ${{_item('Reputación',vt.reputation||0)}}
        ${{_item('Red',vt.network||'—')}}
      </div>
      <div class="vt-bar">
        <div style="width:${{mal/tot*100}}%;background:var(--rd)" title="Malicioso: ${{mal}}"></div>
        <div style="width:${{sus/tot*100}}%;background:var(--yw)" title="Sospechoso: ${{sus}}"></div>
        <div style="width:${{har/tot*100}}%;background:var(--gr)" title="Inofensivo: ${{har}}"></div>
        <div style="width:${{und/tot*100}}%;background:var(--mt)" title="Sin detectar: ${{und}}"></div>
      </div>
      <div style="display:flex;gap:12px;margin-top:6px;font-family:var(--mono);font-size:9px;color:var(--mt)">
        <span style="color:var(--rd)">■ Malicioso</span>
        <span style="color:var(--yw)">■ Sospechoso</span>
        <span style="color:var(--gr)">■ Inofensivo</span>
        <span>■ Sin detectar</span>
      </div>`;
    if(vt.tags&&vt.tags.length) {{
      html+=`<div class="ipp-tags" style="margin-top:8px">${{vt.tags.map(t=>
        `<span class="ipp-tag info">${{t}}</span>`).join('')}}</div>`;
    }}
    html+=`</div>`;
  }} else if(vt.error==='not_queried' || vt.error==='disabled') {{
    const btnId='vt-btn-'+ip.replace(/\\./g,'-');
    html+=`<div class="ipp-section">
      <div class="ipp-sec-title">🔬 Detecciones <span class="ipp-src">VirusTotal</span></div>
      <div id="vt-status-${{btnId}}" style="text-align:center">
        <button id="${{btnId}}" class="vt-demand-btn" onclick="queryVirusTotal('${{ip}}')">
          🔬 Consultar VirusTotal
        </button>
        <div style="font-family:var(--mono);font-size:9px;color:var(--mt);margin-top:6px">
          Consulta bajo demanda (4 req/min)
        </div>
      </div>
    </div>`;
  }} else if(vt.error==='no_key') {{
    html+=`<div class="ipp-section">
      <div class="ipp-sec-title">🔬 Detecciones <span class="ipp-src">VirusTotal</span></div>
      <div style="font-family:var(--mono);font-size:10px;color:var(--mt);text-align:center;padding:8px">
        Sin API key de VirusTotal configurada
      </div>
    </div>`;
  }}

  // ── Reverse DNS ──
  if(rdns.hostname) {{
    html+=`<div class="ipp-section">
      <div class="ipp-sec-title">🔗 DNS Reverso <span class="ipp-src">PTR</span></div>
      <div class="ipp-value mono-sm">${{rdns.hostname}}</div>
    </div>`;
  }}

  panel.innerHTML=html;
  $('ip-overlay').classList.add('open');
  $('ip-panel').classList.add('open');
}}

function closeIPPanel() {{
  $('ip-overlay').classList.remove('open');
  $('ip-panel').classList.remove('open');
}}

// ── Consulta VirusTotal bajo demanda ──
function queryVirusTotal(ip) {{
  const btnId='vt-btn-'+ip.replace(/\\./g,'-');
  const btn=document.getElementById(btnId);
  if(btn) {{
    btn.disabled=true;
    btn.textContent='Consultando...';
    btn.style.opacity='0.6';
  }}
  fetch('/api/vt-lookup?ip='+encodeURIComponent(ip))
    .then(r => {{
      if(!r.ok) throw new Error('HTTP '+r.status);
      return r.json();
    }})
    .then(data => {{
      if(data.error) {{
        const statusEl=document.getElementById('vt-status-'+btnId);
        let msg='Error al consultar VirusTotal';
        if(data.error==='rate_limited') msg='Rate limited — espera 1 minuto e inténtalo de nuevo';
        else if(data.error==='no_key') msg='Sin API key de VirusTotal configurada';
        else if(data.error==='disabled') msg='VirusTotal desactivado en la configuración';
        if(statusEl) statusEl.innerHTML=`<div style="color:var(--yw);font-family:var(--mono);font-size:10px;padding:8px">${{msg}}</div>`;
        return;
      }}
      // Actualizar IP_DATA con los nuevos datos (incluye risk recalculado)
      IP_DATA[ip]=data;
      // Re-renderizar el panel para mostrar los datos VT
      openIPPanel(ip);
    }})
    .catch(err => {{
      if(btn) {{
        btn.disabled=false;
        btn.textContent='Error — Reintentar';
        btn.style.opacity='1';
      }}
      const statusEl=document.getElementById('vt-status-'+btnId);
      if(statusEl) {{
        const hint=location.protocol==='file:'?'Ejecuta sin --no-open para consultas bajo demanda':'Servidor no disponible';
        statusEl.innerHTML+=`<div style="color:var(--rd);font-family:var(--mono);font-size:9px;margin-top:4px">${{hint}}</div>`;
      }}
    }});
}}

// Helper para items del grid
function _item(label, value) {{
  return `<div class="ipp-item"><div class="ipp-label">${{label}}</div><div class="ipp-value">${{value}}</div></div>`;
}}

// ── Cerrar con Escape ──
document.addEventListener('keydown', e => {{
  if(e.key==='Escape') closeIPPanel();
}});

// ══════════════════════════════════════════════════════════════
//  MODIFICAR LA TABLA PRINCIPAL PARA HACERLA INTERACTIVA
// ══════════════════════════════════════════════════════════════
// Sobrescribimos renderRecs para añadir:
//   - Dot de riesgo junto a la IP
//   - Bandera de país
//   - Click para abrir panel
//   - Tooltip con info rápida

const _origRenderRecs = renderRecs;

renderRecs = function(rows) {{
  const hideIgnored=$('fhide').checked;
  $('rc').textContent=n(rows.length)+' registros';
  const tb=$('tb');
  const visible=rows.filter(r=>!(hideIgnored && ignoredIPs.has(r.source_ip)));
  if(!visible.length){{
    tb.innerHTML='<tr><td colspan="16" class="emp">Sin resultados</td></tr>';return;
  }}
  tb.innerHTML=visible.map(r=>{{
    const ignored=ignoredIPs.has(r.source_ip);
    const lbl=ipLabels[r.source_ip]||'';
    const rs=(r.reasons||[]).map(x=>x.type+(x.comment?':'+x.comment:'')).filter(Boolean).join('; ');

    // Datos de enriquecimiento para esta IP
    const ipd=IP_DATA[r.source_ip];
    const risk=ipd?.risk||{{}};
    const riskLevel=risk.level||'';
    const country=ipd?.ipinfo?.country||ipd?.abuseipdb?.country_code||'';
    const flag=countryFlag(country);
    const dotHtml=riskLevel?`<span class="ip-risk-dot ${{riskLevel}}"></span>`:'';

    return`<tr class="${{ignored?'ign':''}}">
      <td class="mn" style="cursor:pointer" onclick="openIPPanel('${{r.source_ip}}')">
        ${{dotHtml}}${{flag?`<span class="cflag">${{flag}}</span>`:''}}${{r.source_ip||'—'}}${{lbl?` <span style="color:var(--yw);font-size:9px">[${{lbl}}]</span>`:''}}
      </td>
      <td class="mn" style="color:var(--cy);font-weight:600">${{r.count||0}}</td>
      <td class="msm" style="color:var(--cy)">${{r._domain||'—'}}</td>
      <td class="msm">${{r.header_from||'—'}}</td>
      <td>${{pill(r.dmarc_result)}}</td>
      <td>${{pill(r.dkim_result)}}</td>
      <td>${{pill(r.spf_result)}}</td>
      <td>${{pill(r.disposition)}}</td>
      <td>${{apill(r.alignment)}}</td>
      <td class="msm" style="color:var(--mt)">${{r.auth_dkim_domain||'—'}}</td>
      <td class="msm" style="color:var(--mt);font-size:9px">${{r.auth_dkim_selector||'—'}}</td>
      <td class="msm" style="color:var(--mt)">${{r.auth_spf_domain||'—'}}</td>
      <td class="msm" style="font-size:9px;color:var(--mt);max-width:120px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${{rs}}">${{rs||'—'}}</td>
      <td class="msm" style="color:var(--mt);font-size:9px">${{r._org}}</td>
      <td class="msm" style="color:var(--mt);font-size:9px;max-width:100px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${{r._file}}</td>
      <td>
        <button style="background:${{ignored?'rgba(100,116,139,.1)':'rgba(248,113,113,.08)'}};
          border:1px solid ${{ignored?'rgba(100,116,139,.2)':'rgba(248,113,113,.2)'}};
          color:${{ignored?'var(--mt)':'var(--rd)'}};font-family:var(--mono);font-size:9px;
          padding:2px 7px;border-radius:6px;cursor:pointer"
          onclick="toggleIgnore('${{r.source_ip.replace(/'/g,'')}}',this)">
          ${{ignored?'↩':'⊘'}}
        </button>
      </td>
    </tr>`;
  }}).join('');
}};

// Re-renderizar con los nuevos datos
filterTable();
</script>
"""


# ══════════════════════════════════════════════════════════════════
#  FUNCIÓN DE INYECCIÓN
# ══════════════════════════════════════════════════════════════════

def inject_ip_panel(html_content, ip_enrichment_data):
    """
    Toma el HTML generado por dmarc_visualizer.generate_html()
    e inyecta el panel de detalle de IP justo antes de </body>.
    """
    panel_html = build_ip_panel_html(ip_enrichment_data)
    # Insertar antes de </body>
    return html_content.replace("</body>", panel_html + "\n</body>")


# ══════════════════════════════════════════════════════════════════
#  SERVIDOR LOCAL CON API VT ON-DEMAND
# ══════════════════════════════════════════════════════════════════

_vt_lock = threading.Lock()


def serve_and_open_with_api(html_path, enricher):
    """
    Servidor HTTP local que sirve el dashboard y expone un endpoint
    /api/vt-lookup?ip=X.X.X.X para consultas VirusTotal bajo demanda.
    """
    html_path = Path(html_path).resolve()
    port = find_port()
    if not port:
        print(f"  ⚠  Sin puerto libre. Abre: file://{html_path}")
        return

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(html_path.parent), **kw)

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/api/vt-lookup":
                self._handle_vt_lookup(parse_qs(parsed.query))
            else:
                super().do_GET()

        def _handle_vt_lookup(self, params):
            ip = params.get("ip", [""])[0].strip()
            if not ip:
                self._json_response(400, {"error": "missing_ip"})
                return

            with _vt_lock:
                result = enricher.enrich_ip_virustotal(ip)

            self._json_response(200, result)

        def _json_response(self, code, data):
            body = json.dumps(
                data, ensure_ascii=False, default=str
            ).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}/{html_path.name}"
    print(f"\n  🌐 Servidor : {url}")
    print(f"  🔬 API VT   : {url.rsplit('/', 1)[0]}/api/vt-lookup?ip=<IP>")
    print(f"  🔥 Abriendo navegador...\n")
    time.sleep(0.3)
    webbrowser.open(url)
    print("  ✅ Dashboard activo. Presiona Ctrl+C para salir.\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  Cerrando...")
        srv.shutdown()


# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════

def main():
    args    = sys.argv[1:]
    folder  = "./dmarc_reports"
    output  = "./dmarc_dashboard.html"
    no_open   = False
    no_enrich = False

    for a in args:
        if a == "--no-open":   no_open = True
        elif a == "--no-enrich": no_enrich = True
        elif a.endswith(".html"): output = a
        else: folder = a

    print()
    print("━" * 62)
    print(f"   DMARC DASHBOARD + IP ENRICHMENT  v{VERSION}")
    print("━" * 62)

    # ── 1. Excel init ────────────────────────────────────────
    wb, ignored_ips, ip_labels, seen_hashes = init_excel(folder)

    # ── 2. Cargar reportes DMARC ─────────────────────────────
    all_reports, new_reports = load_folder(folder, seen_hashes)

    if not all_reports:
        print("  ⚠  No hay reportes que mostrar.")
        print(f"     Coloca archivos .xml/.zip/.gz en: {Path(folder).resolve()}")
        sys.exit(0)

    # Marcar nuevos
    new_hashes = {r["_hash"] for r in new_reports}
    for r in all_reports:
        r["_is_new"] = r["_hash"] in new_hashes

    # ── 3. Stats ─────────────────────────────────────────────
    stats = compute_stats(all_reports, ignored_ips, ip_labels)

    print(f"\n  📊 Estadísticas globales:")
    print(f"     Mensajes: {stats['total_messages']}  |  DMARC pass: {stats['dmarc_pass_rate']}%")
    print(f"     Dominios: {', '.join(stats['domains'].keys())}")

    # ── 4. Enriquecimiento de IPs ────────────────────────────
    # Crear enricher siempre (necesario para VT on-demand desde el servidor)
    config_path = Path(folder) / "config.json"
    if not config_path.exists():
        config_path = Path(script_dir) / "config.json"
    enricher = IPEnricher(str(config_path))

    ip_enrichment_data = {}
    if not no_enrich:
        ips = extract_ips_from_reports(all_reports)
        enricher.enrich_all(ips)
        ip_enrichment_data = enricher.get_serializable()
        enricher.print_summary()
    else:
        print("\n  ⏩ Enriquecimiento desactivado (--no-enrich)")

    # ── 5. Actualizar Excel ──────────────────────────────────
    update_excel(wb, all_reports, stats, folder, new_reports)

    # ── 6. Generar HTML ──────────────────────────────────────
    html = generate_html(all_reports, stats, ignored_ips, ip_labels)

    # Inyectar panel de detalle de IP
    if ip_enrichment_data:
        html = inject_ip_panel(html, ip_enrichment_data)
        print(f"\n  🔍 Panel de IP inyectado ({len(ip_enrichment_data)} IPs enriquecidas)")

    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")

    print(f"\n  💾 Dashboard : {out.resolve()}")
    print(f"  📊 Excel     : {(Path(folder) / 'dmarc_database.xlsx').resolve()}")
    print("━" * 62)

    if no_open:
        print(f"\n  Abre manualmente: file://{out.resolve()}")
        print(f"  ⚠  VT bajo demanda no disponible sin servidor (--no-open)")
    else:
        serve_and_open_with_api(out, enricher)


if __name__ == "__main__":
    main()