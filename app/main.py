import json
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

from utils.config_manager import ConfigManager
from database.logger_db import DatabaseLogger
from app.decision_engine import DecisionEngine
from app.phishing_detector import PhishingDetector

# ---------------------------------------------------------------------------
# Instancias globales
# ---------------------------------------------------------------------------

config = ConfigManager()
db     = DatabaseLogger()
decision_engine = DecisionEngine(config)

_DOMAINS_PATH = Path(__file__).parent.parent / "config" / "legitimate_domains.json"
try:
    with open(_DOMAINS_PATH, encoding="utf-8") as _f:
        _domains_cfg  = json.load(_f)
    _legit_domains = _domains_cfg.get("legitimate_domains", [])
    _legit_emails  = _domains_cfg.get("legitimate_emails",  [])
except Exception:
    _legit_domains, _legit_emails = [], []

phishing_detector = PhishingDetector(
    legitimate_domains=_legit_domains,
    legitimate_emails=_legit_emails,
)

app = Flask(__name__)
CORS(app)

# ---------------------------------------------------------------------------
# Generador de resumen amigable para el usuario
# ---------------------------------------------------------------------------

def _build_user_summary(result: dict) -> dict:
    risk     = result["risk_score"]
    risk_pct = round(risk * 100)

    layers = result.get("layers_analyzed", {})
    l1 = layers.get("layer1_whitelist",  {})
    l2 = layers.get("layer2_similarity", {})
    l3 = layers.get("layer3_spelling",   {})

    if risk > 0.80:
        verdict       = "PHISHING_PROBABLE"
        verdict_label = "🚫 PHISHING PROBABLE - ALTO RIESGO"
    elif risk >= 0.60:
        verdict       = "SUSPICIOUS"
        verdict_label = "⚠️ SOSPECHOSO - RIESGO MEDIO"
    elif risk >= 0.40:
        verdict       = "REVIEW_MANUALLY"
        verdict_label = "⚡ REVISAR MANUALMENTE - RIESGO BAJO"
    else:
        verdict       = "LIKELY_LEGITIMATE"
        verdict_label = "✅ PROBABLEMENTE LEGÍTIMO"

    main_reasons: list[str] = []

    if l1.get("passed"):
        if l1.get("matched_email"):
            main_reasons.append("Correo en lista blanca de contactos aprobados")
        elif l1.get("matched_domain"):
            main_reasons.append("Dominio en lista blanca de dominios aprobados")
    else:
        sim  = l2.get("similarity_score", 0)
        best = l2.get("best_match", "")
        if sim >= 0.80 and best:
            main_reasons.append(f"Dominio {round(sim * 100)}% similar a {best}")
        conf = l2.get("confusables", {})
        if conf.get("found") and conf.get("chars"):
            chars_str = ", ".join(str(c) for c in conf["chars"])
            main_reasons.append(f"Caracteres confusables detectados: {chars_str}")
        if l3.get("analyzed"):
            er = l3.get("error_ratio",   0)
            ur = l3.get("upper_ratio",   0)
            sr = l3.get("special_ratio", 0)
            if er > 0.05:
                main_reasons.append(f"Errores ortográficos en el {round(er * 100)}% de las palabras")
            if ur > 0.30:
                main_reasons.append(f"Exceso de mayúsculas: {round(ur * 100)}%")
            if sr > 0.08:
                main_reasons.append(f"Densidad de caracteres especiales: {round(sr * 100)}%")

    spelling_assessment = None
    if l3.get("analyzed"):
        er = l3.get("error_ratio",   0)
        ur = l3.get("upper_ratio",   0)
        sr = l3.get("special_ratio", 0)
        ep = round(er * 100)
        up = round(ur * 100)
        sp = round(sr * 100)
        if er <= 0.05 and not l3.get("suspicious"):
            spell_level  = "NORMAL"
            spell_interp = "Ortografía NORMAL — sin indicadores de phishing"
        elif er <= 0.20 or l3.get("suspicious"):
            spell_level  = "SUSPICIOUS"
            spell_interp = f"Ortografía SOSPECHOSA — {ep}% de errores"
        else:
            spell_level  = "VERY_SUSPICIOUS"
            spell_interp = f"Ortografía MUY SOSPECHOSA — {ep}% de errores"
        spelling_assessment = {
            "error_ratio":              er,
            "error_percentage":         ep,
            "uppercase_percentage":     up,
            "special_chars_percentage": sp,
            "spelling_risk_level":      spell_level,
            "spelling_interpretation":  spell_interp,
        }

    if verdict == "LIKELY_LEGITIMATE":
        if l1.get("passed"):
            rec = "Este correo es de un contacto aprobado y no muestra signos de phishing. Puedes confiar en él."
        else:
            rec = "No se detectaron indicadores de phishing. Aún así, mantén precaución con enlaces y archivos adjuntos desconocidos."
    elif verdict == "REVIEW_MANUALLY":
        rec = "Este mensaje tiene algunas características inusuales. Verifica la identidad del remitente antes de hacer clic en enlaces o proporcionar datos personales."
    elif verdict == "SUSPICIOUS":
        rec = "Este mensaje presenta signos sospechosos típicos de phishing. No hagas clic en enlaces ni proporciones datos sin verificar la fuente directamente."
    else:
        rec = ("Este mensaje muestra múltiples signos de intento de phishing. "
               "NO hagas clic en enlaces, NO proporciones contraseñas ni datos personales. "
               "Contacta a tu equipo de TI de inmediato.")

    return {
        "verdict":            verdict,
        "verdict_label":      verdict_label,
        "risk_percentage":    risk_pct,
        "main_reasons":       main_reasons,
        "spelling_assessment": spelling_assessment,
        "recommendation":     rec,
    }


# ---------------------------------------------------------------------------
# Panel HTML
# ---------------------------------------------------------------------------

PANEL_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Detector de Phishing</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      padding: 24px 16px;
      min-height: 100vh;
    }

    .container { max-width: 900px; margin: 0 auto; }

    /* ── header ── */
    .header { margin-bottom: 28px; }
    .header h1 { font-size: 1.8rem; color: #38bdf8; }
    .header .subtitle { color: #64748b; font-size: 0.9rem; margin-top: 4px; }

    /* ── generic card ── */
    .card {
      background: #1e293b;
      border-radius: 10px;
      padding: 20px;
      margin-bottom: 20px;
    }
    .card h2 {
      color: #94a3b8;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 14px;
    }

    /* ── form ── */
    label { display: block; font-size: 0.82rem; color: #94a3b8; margin: 10px 0 4px; }
    input[type=text], textarea {
      width: 100%; padding: 10px 14px;
      background: #0f172a; border: 1px solid #334155;
      border-radius: 6px; color: #e2e8f0; font-size: 0.95rem;
      font-family: inherit; transition: border-color .2s;
    }
    input[type=text]:focus, textarea:focus {
      outline: none; border-color: #0ea5e9;
    }
    textarea { min-height: 110px; resize: vertical; }

    .form-actions { display: flex; gap: 10px; margin-top: 14px; flex-wrap: wrap; }
    .btn { padding: 10px 24px; border: none; border-radius: 6px; font-size: 0.95rem; cursor: pointer; transition: background .2s, opacity .2s; }
    .btn-primary { background: #0ea5e9; color: #fff; }
    .btn-primary:hover:not(:disabled) { background: #38bdf8; }
    .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-secondary { background: #334155; color: #94a3b8; }
    .btn-secondary:hover { background: #475569; color: #e2e8f0; }

    /* ── loader ── */
    .loader-container {
      display: none;
      align-items: center;
      gap: 12px;
      margin-top: 16px;
      padding: 12px 16px;
      background: #0f172a;
      border-radius: 8px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .spinner {
      width: 24px; height: 24px; flex-shrink: 0;
      border: 3px solid #334155;
      border-top-color: #0ea5e9;
      border-radius: 50%;
      animation: spin 0.75s linear infinite;
    }
    .loader-text { color: #94a3b8; font-size: 0.9rem; }

    /* ── results section ── */
    @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
    .results-section { animation: fadeIn .35s ease; }

    /* ── verdict card ── */
    .verdict-card {
      border-radius: 10px;
      padding: 20px 24px;
      margin-bottom: 20px;
      border-left: 5px solid #64748b;
      background: #1e293b;
    }
    .verdict-likely-legitimate  { border-left-color: #22c55e; background: #052e16cc; }
    .verdict-review-manually    { border-left-color: #a3a3a3; background: #1c191799; }
    .verdict-suspicious         { border-left-color: #f59e0b; background: #431407cc; }
    .verdict-phishing-probable  { border-left-color: #ef4444; background: #450a0acc; }

    .verdict-label {
      font-size: 1.4rem;
      font-weight: 700;
      margin-bottom: 14px;
      line-height: 1.3;
    }
    .verdict-likely-legitimate  .verdict-label { color: #86efac; }
    .verdict-review-manually    .verdict-label { color: #d4d4d4; }
    .verdict-suspicious         .verdict-label { color: #fcd34d; }
    .verdict-phishing-probable  .verdict-label { color: #fca5a5; }

    .risk-meta { display: flex; justify-content: space-between; font-size: 0.82rem; color: #94a3b8; margin-bottom: 6px; }
    .risk-bar-track { height: 10px; background: #0f172a; border-radius: 99px; overflow: hidden; }
    .risk-bar-fill  { height: 100%; border-radius: 99px; transition: width .6s ease; background: #22c55e; }
    .verdict-review-manually   .risk-bar-fill { background: #a3a3a3; }
    .verdict-suspicious        .risk-bar-fill { background: #f59e0b; }
    .verdict-phishing-probable .risk-bar-fill { background: #ef4444; }

    /* ── section title ── */
    .section-title {
      color: #94a3b8; font-size: 0.8rem; text-transform: uppercase;
      letter-spacing: 1px; margin: 4px 0 12px;
    }

    /* ── layer grid ── */
    .layers-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 14px;
      margin-bottom: 16px;
    }
    .layer-card {
      background: #1e293b;
      border-radius: 10px;
      padding: 16px;
      border-top: 3px solid #334155;
    }
    .layer-safe    { border-top-color: #22c55e; }
    .layer-neutral { border-top-color: #64748b; }
    .layer-warning { border-top-color: #f59e0b; }
    .layer-danger  { border-top-color: #ef4444; }

    .layer-header { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
    .layer-icon   { font-size: 1.2rem; }
    .layer-title  { font-size: 0.82rem; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: .5px; }

    .layer-body   { font-size: 0.85rem; line-height: 1.6; }
    .layer-row    { margin-bottom: 6px; }
    .layer-row b  { color: #cbd5e1; }
    .muted        { color: #64748b; font-style: italic; }
    .warning-text { color: #fcd34d; margin-top: 8px; }

    /* sim bar */
    .sim-bar-wrapper { margin: 8px 0; }
    .sim-bar-label   { display: flex; justify-content: space-between; font-size: 0.78rem; color: #94a3b8; margin-bottom: 4px; }
    .sim-bar-track   { height: 8px; background: #0f172a; border-radius: 99px; overflow: hidden; }
    .sim-bar-fill    { height: 100%; border-radius: 99px; background: #f59e0b; transition: width .5s ease; }
    .sim-safe   .sim-bar-fill { background: #22c55e; }
    .sim-danger .sim-bar-fill { background: #ef4444; }

    /* badges */
    .tag { display: inline-block; padding: 1px 8px; border-radius: 99px; font-size: 0.72rem; font-weight: 600; margin-right: 4px; }
    .tag-safe    { background: #14532d; color: #86efac; }
    .tag-warning { background: #78350f; color: #fcd34d; }
    .tag-danger  { background: #7f1d1d; color: #fca5a5; }
    .tag-neutral { background: #1e3a5f; color: #7dd3fc; }
    .ok-badge      { display: inline-block; font-size: 0.72rem; color: #86efac; margin-left: 4px; }
    .warning-badge { display: inline-block; font-size: 0.72rem; color: #fcd34d; margin-left: 4px; }
    .danger-badge  { display: inline-block; font-size: 0.72rem; color: #fca5a5; margin-left: 4px; }

    .spell-interp {
      margin-top: 10px; padding: 8px 10px;
      border-radius: 6px; font-size: 0.82rem; font-weight: 600;
    }
    .interp-safe    { background: #052e16; color: #86efac; }
    .interp-warning { background: #431407; color: #fcd34d; }
    .interp-danger  { background: #450a0a; color: #fca5a5; }

    /* ── reasons card ── */
    .reasons-card {
      background: #1e293b;
      border-radius: 10px;
      padding: 16px 20px;
      margin-bottom: 16px;
    }
    .reasons-card h4 { font-size: 0.82rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; }
    .reasons-card ul { padding-left: 18px; }
    .reasons-card li { font-size: 0.88rem; margin-bottom: 5px; color: #cbd5e1; line-height: 1.5; }

    /* ── recommendation ── */
    .recommendation-card {
      border-radius: 10px;
      padding: 16px 20px;
      margin-bottom: 20px;
      background: #1e293b;
      border-left: 4px solid #64748b;
    }
    .rec-likely-legitimate  { border-left-color: #22c55e; background: #052e1699; }
    .rec-review-manually    { border-left-color: #a3a3a3; }
    .rec-suspicious         { border-left-color: #f59e0b; background: #43140799; }
    .rec-phishing-probable  { border-left-color: #ef4444; background: #450a0a99; }

    .recommendation-card h4 { font-size: 0.82rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
    .recommendation-card p  { font-size: 0.92rem; line-height: 1.65; }
    .rec-likely-legitimate  p { color: #86efac; }
    .rec-review-manually    p { color: #d4d4d4; }
    .rec-suspicious         p { color: #fcd34d; }
    .rec-phishing-probable  p { color: #fca5a5; }

    /* ── network error ── */
    .error-banner {
      background: #450a0a; color: #fca5a5;
      border-radius: 8px; padding: 12px 16px;
      margin-top: 12px; font-size: 0.88rem; display: none;
    }

    /* ── stats ── */
    .stats-row { display: flex; gap: 12px; flex-wrap: wrap; }
    .stat { background: #0f172a; border-radius: 8px; padding: 14px 20px; flex: 1; min-width: 100px; }
    .stat .val { font-size: 1.9rem; font-weight: 700; color: #38bdf8; }
    .stat .lbl { font-size: 0.72rem; color: #64748b; margin-top: 2px; }

    /* ── logs table ── */
    .table-wrapper { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 0.83rem; }
    th { text-align: left; color: #64748b; padding: 6px 10px; border-bottom: 1px solid #334155; white-space: nowrap; }
    td { padding: 6px 10px; border-bottom: 1px solid #1e293b; word-break: break-all; }
    .badge { padding: 2px 8px; border-radius: 99px; font-size: 0.72rem; font-weight: 600; white-space: nowrap; }
    .badge-phishing   { background: #7f1d1d; color: #fca5a5; }
    .badge-suspicious { background: #7c2d12; color: #fdba74; }
    .badge-safe       { background: #14532d; color: #86efac; }

    @media (max-width: 600px) {
      .header h1 { font-size: 1.4rem; }
      .verdict-label { font-size: 1.1rem; }
      .layers-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
<div class="container">

  <!-- header -->
  <div class="header">
    <h1>🛡️ Detector de Phishing</h1>
    <p class="subtitle">Análisis inteligente en 3 capas de seguridad</p>
  </div>

  <!-- formulario -->
  <div class="card">
    <h2>Verificar correo o URL sospechosa</h2>
    <label for="targetInput">Correo electrónico o URL</label>
    <input type="text" id="targetInput"
           placeholder="ej: ceo@empreza.com  o  http://emp1resa.com/login">
    <label for="messageInput">Contenido del mensaje (mejora la detección)</label>
    <textarea id="messageInput"
              placeholder="Pega aquí el texto del correo o mensaje sospechoso..."></textarea>
    <div class="form-actions">
      <button id="analyzeBtn" class="btn btn-primary" onclick="checkPhishing()">🔍 Analizar</button>
      <button class="btn btn-secondary" onclick="clearForm()">✖ Limpiar</button>
    </div>
    <div id="loader" class="loader-container">
      <div class="spinner"></div>
      <span class="loader-text">Evaluando en 3 capas de seguridad…</span>
    </div>
    <div id="errorBanner" class="error-banner"></div>
  </div>

  <!-- resultados (ocultos hasta que haya datos) -->
  <div id="resultsSection" class="results-section" style="display:none">

    <!-- veredicto -->
    <div id="verdictCard" class="verdict-card">
      <div id="verdictLabel" class="verdict-label"></div>
      <div class="risk-meta">
        <span>Nivel de riesgo</span>
        <span id="riskPct">0%</span>
      </div>
      <div class="risk-bar-track">
        <div id="riskBarFill" class="risk-bar-fill" style="width:0%"></div>
      </div>
    </div>

    <!-- análisis por capas -->
    <p class="section-title">Análisis detallado por capa</p>
    <div class="layers-grid">

      <!-- capa 1 -->
      <div class="layer-card layer-neutral" id="layer1Card">
        <div class="layer-header">
          <span class="layer-icon" id="layer1Icon">—</span>
          <span class="layer-title">Capa 1 · Whitelist</span>
        </div>
        <div class="layer-body" id="layer1Body"></div>
      </div>

      <!-- capa 2 -->
      <div class="layer-card layer-neutral" id="layer2Card">
        <div class="layer-header">
          <span class="layer-icon" id="layer2Icon">—</span>
          <span class="layer-title">Capa 2 · Similitud de dominio</span>
        </div>
        <div class="layer-body" id="layer2Body"></div>
      </div>

      <!-- capa 3 -->
      <div class="layer-card layer-neutral" id="layer3Card">
        <div class="layer-header">
          <span class="layer-icon" id="layer3Icon">—</span>
          <span class="layer-title">Capa 3 · Ortografía del mensaje</span>
        </div>
        <div class="layer-body" id="layer3Body"></div>
      </div>

    </div><!-- /layers-grid -->

    <!-- indicadores detectados -->
    <div class="reasons-card" id="reasonsCard" style="display:none">
      <h4>Indicadores detectados</h4>
      <ul id="reasonsList"></ul>
    </div>

    <!-- recomendación -->
    <div id="recommendationCard" class="recommendation-card">
      <h4>⚠️ Recomendación</h4>
      <p id="recommendationText"></p>
    </div>

  </div><!-- /resultsSection -->

  <!-- estadísticas -->
  <div class="card">
    <h2>Estadísticas (última hora)</h2>
    <div class="stats-row">
      <div class="stat"><div class="val" id="sTotal">—</div><div class="lbl">Total</div></div>
      <div class="stat"><div class="val" id="sPhishing">—</div><div class="lbl">Phishing</div></div>
      <div class="stat"><div class="val" id="sLegit">—</div><div class="lbl">Legítimos</div></div>
      <div class="stat"><div class="val" id="sRate">—</div><div class="lbl">% Phishing</div></div>
    </div>
  </div>

  <!-- logs -->
  <div class="card">
    <h2>Análisis recientes</h2>
    <div class="table-wrapper">
      <table>
        <thead>
          <tr><th>Resultado</th><th>Objetivo</th><th>Razón</th><th>Score</th></tr>
        </thead>
        <tbody id="logsBody"></tbody>
      </table>
    </div>
  </div>

</div><!-- /container -->

<script>
  /* ─── utilidades ─── */
  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function setLoading(active) {
    document.getElementById('analyzeBtn').disabled = active;
    document.getElementById('loader').style.display = active ? 'flex' : 'none';
    if (active) document.getElementById('errorBanner').style.display = 'none';
  }

  function showError(msg) {
    var el = document.getElementById('errorBanner');
    el.textContent = '⚠️ ' + msg;
    el.style.display = 'block';
  }

  function clearForm() {
    document.getElementById('targetInput').value  = '';
    document.getElementById('messageInput').value = '';
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('errorBanner').style.display    = 'none';
  }

  /* ─── análisis principal ─── */
  async function checkPhishing() {
    var target  = document.getElementById('targetInput').value.trim();
    var message = document.getElementById('messageInput').value.trim();
    if (!target) { showError('Ingresa un correo electrónico o URL para analizar.'); return; }

    setLoading(true);
    document.getElementById('resultsSection').style.display = 'none';

    try {
      var res = await fetch('/api/check-phishing', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ email_or_url: target, message: message })
      });
      if (!res.ok) throw new Error('Error del servidor (' + res.status + ')');
      var data = await res.json();
      renderResults(data);
      loadStats();
      loadLogs();
    } catch (err) {
      showError('No se pudo conectar con el servidor: ' + err.message);
    } finally {
      setLoading(false);
    }
  }

  /* ─── render resultados ─── */
  function renderResults(data) {
    var summary = data.user_summary  || {};
    var layers  = data.layers_analyzed || {};

    var verdict  = summary.verdict || 'LIKELY_LEGITIMATE';
    var riskPct  = summary.risk_percentage != null ? summary.risk_percentage : 0;
    var cssClass = verdict.toLowerCase().replace(/_/g, '-');

    // veredicto + barra
    var vCard = document.getElementById('verdictCard');
    vCard.className = 'verdict-card verdict-' + cssClass;
    document.getElementById('verdictLabel').textContent    = summary.verdict_label || '';
    document.getElementById('riskPct').textContent         = riskPct + '%';
    document.getElementById('riskBarFill').style.width     = riskPct + '%';

    // capas
    renderLayer1(layers.layer1_whitelist  || {});
    renderLayer2(layers.layer2_similarity || {});
    renderLayer3(layers.layer3_spelling   || {}, summary.spelling_assessment || null);

    // razones
    var reasons = summary.main_reasons || [];
    if (reasons.length) {
      document.getElementById('reasonsCard').style.display = 'block';
      document.getElementById('reasonsList').innerHTML =
        reasons.map(function(r) { return '<li>' + esc(r) + '</li>'; }).join('');
    } else {
      document.getElementById('reasonsCard').style.display = 'none';
    }

    // recomendación
    var recCard = document.getElementById('recommendationCard');
    recCard.className = 'recommendation-card rec-' + cssClass;
    document.getElementById('recommendationText').textContent = summary.recommendation || '';

    // mostrar sección con animación
    var section = document.getElementById('resultsSection');
    section.style.display = 'block';
    section.style.animation = 'none';
    section.offsetHeight;  // reflow para reiniciar animación
    section.style.animation = '';
  }

  /* ─── capa 1: whitelist ─── */
  function renderLayer1(l1) {
    var passed = l1.passed;
    document.getElementById('layer1Icon').textContent = passed ? '✅' : '—';
    document.getElementById('layer1Card').className   = 'layer-card ' + (passed ? 'layer-safe' : 'layer-neutral');

    var html = '';
    if (passed) {
      if (l1.matched_email) {
        html = '<div class="layer-row"><span class="tag tag-safe">En lista blanca</span> Correo verificado y aprobado</div>';
      } else if (l1.matched_domain) {
        html = '<div class="layer-row"><span class="tag tag-safe">En lista blanca</span> Dominio verificado y aprobado</div>';
      } else {
        html = '<div class="layer-row"><span class="tag tag-safe">En lista blanca</span> Contacto aprobado</div>';
      }
    } else {
      html = '<div class="layer-row"><span class="tag tag-neutral">No registrado</span> No está en la lista de contactos aprobados</div>';
    }
    document.getElementById('layer1Body').innerHTML = html;
  }

  /* ─── capa 2: similitud ─── */
  function renderLayer2(l2) {
    var suspicious = l2.suspicious || false;
    var sim        = l2.similarity_score || 0;
    var simPct     = Math.round(sim * 100);
    var best       = l2.best_match  || '';
    var conf       = l2.confusables || {};

    var icon = '✅';
    if (conf.found)      icon = '🚫';
    else if (simPct >= 92) icon = '🚫';
    else if (simPct >= 80) icon = '⚠️';

    document.getElementById('layer2Icon').textContent = icon;

    var cardCls = 'layer-safe';
    if (conf.found || simPct >= 92) cardCls = 'layer-danger';
    else if (simPct >= 80) cardCls = 'layer-warning';
    document.getElementById('layer2Card').className = 'layer-card ' + cardCls;

    var html = '';
    if (best) {
      html += '<div class="layer-row"><b>Dominio más similar:</b> ' + esc(best) + '</div>';
      var barCls = simPct >= 92 ? 'sim-danger' : (simPct < 60 ? 'sim-safe' : '');
      html += '<div class="sim-bar-wrapper ' + barCls + '">';
      html += '<div class="sim-bar-label"><span>Similitud</span><span>' + simPct + '%</span></div>';
      html += '<div class="sim-bar-track"><div class="sim-bar-fill" style="width:' + simPct + '%"></div></div>';
      html += '</div>';
    } else {
      html += '<div class="layer-row muted">Sin dominios de referencia cargados</div>';
    }

    if (conf.found && conf.chars && conf.chars.length) {
      html += '<div class="layer-row warning-text">⚠️ Caracteres confusables: <b>' + esc(conf.chars.join(', ')) + '</b>';
      if (conf.normalized) html += ' → <b>' + esc(conf.normalized) + '</b>';
      html += '</div>';
    } else if (!suspicious && simPct < 80) {
      html += '<div class="layer-row"><span class="ok-badge">✓ Sin caracteres confusables</span></div>';
    }

    document.getElementById('layer2Body').innerHTML = html;
  }

  /* ─── capa 3: ortografía ─── */
  function renderLayer3(l3, sa) {
    if (!l3.analyzed) {
      document.getElementById('layer3Icon').textContent = '—';
      document.getElementById('layer3Card').className   = 'layer-card layer-neutral';
      document.getElementById('layer3Body').innerHTML   = '<div class="layer-row muted">Sin mensaje para analizar</div>';
      return;
    }

    var suspicious = l3.suspicious || false;
    var er = l3.error_ratio   || 0;
    var ur = l3.upper_ratio   || 0;
    var sr = l3.special_ratio || 0;

    var ep = sa ? sa.error_percentage         : Math.round(er * 100);
    var up = sa ? sa.uppercase_percentage     : Math.round(ur * 100);
    var sp = sa ? sa.special_chars_percentage : Math.round(sr * 100);

    var icon = suspicious ? (er > 0.20 ? '🚫' : '⚠️') : '✅';
    document.getElementById('layer3Icon').textContent = icon;

    var cardCls = suspicious ? (er > 0.20 ? 'layer-danger' : 'layer-warning') : 'layer-safe';
    document.getElementById('layer3Card').className = 'layer-card ' + cardCls;

    var upBadge = up > 30 ? '<span class="warning-badge">⚠ Alto</span>' : '<span class="ok-badge">✓ Normal</span>';
    var spBadge = sp > 8  ? '<span class="warning-badge">⚠ Alto</span>' : '<span class="ok-badge">✓ Normal</span>';
    var epBadge = ep > 5  ? '<span class="warning-badge">⚠ Detectados</span>' : '<span class="ok-badge">✓ Sin errores</span>';

    var html = '';
    html += '<div class="layer-row"><b>Errores ortográficos:</b> ' + ep + '% de palabras ' + epBadge + '</div>';
    html += '<div class="layer-row"><b>Mayúsculas:</b> ' + up + '% ' + upBadge + '</div>';
    html += '<div class="layer-row"><b>Caracteres especiales:</b> ' + sp + '% ' + spBadge + '</div>';

    if (sa && sa.spelling_interpretation) {
      var interpCls = 'interp-warning';
      if (sa.spelling_risk_level === 'NORMAL')          interpCls = 'interp-safe';
      if (sa.spelling_risk_level === 'VERY_SUSPICIOUS') interpCls = 'interp-danger';
      html += '<div class="spell-interp ' + interpCls + '">' + esc(sa.spelling_interpretation) + '</div>';
    }

    document.getElementById('layer3Body').innerHTML = html;
  }

  /* ─── estadísticas ─── */
  async function loadStats() {
    try {
      var data = await fetch('/api/phishing-stats?hours=1').then(function(r) { return r.json(); });
      document.getElementById('sTotal').textContent    = data.total    != null ? data.total    : '—';
      document.getElementById('sPhishing').textContent = data.phishing != null ? data.phishing : '—';
      document.getElementById('sLegit').textContent    = data.legit    != null ? data.legit    : '—';
      document.getElementById('sRate').textContent     = (data.phishing_rate != null ? data.phishing_rate : 0) + '%';
    } catch(e) {}
  }

  /* ─── logs ─── */
  async function loadLogs() {
    try {
      var rows = await fetch('/api/phishing-logs?limit=20').then(function(r) { return r.json(); });
      document.getElementById('logsBody').innerHTML = rows.map(function(r) {
        var cls = r.is_phishing ? 'badge-phishing' : (r.risk_score >= 0.35 ? 'badge-suspicious' : 'badge-safe');
        var lbl = r.is_phishing ? 'PHISHING'       : (r.risk_score >= 0.35 ? 'SOSPECHOSO'       : 'LEGÍTIMO');
        return '<tr>'
          + '<td><span class="badge ' + cls + '">' + lbl + '</span></td>'
          + '<td>' + esc(r.email_or_url || '') + '</td>'
          + '<td>' + esc(r.reason || '') + '</td>'
          + '<td>' + (r.risk_score != null ? Number(r.risk_score).toFixed(3) : '—') + '</td>'
          + '</tr>';
      }).join('');
    } catch(e) {}
  }

  /* ─── inicio ─── */
  loadStats();
  loadLogs();
  setInterval(function() { loadStats(); loadLogs(); }, 10000);

  // Enter para analizar desde el input
  document.getElementById('targetInput').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') checkPhishing();
  });
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Endpoints — Phishing
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    return render_template_string(PANEL_HTML)


@app.route("/api/check-phishing", methods=["POST"])
def api_check_phishing():
    body         = request.get_json(silent=True) or {}
    email_or_url = body.get("email_or_url", "").strip()
    message      = body.get("message", "").strip()

    if not email_or_url:
        return jsonify({"error": "Campo 'email_or_url' requerido"}), 400

    result  = phishing_detector.analyze(email_or_url, message)
    preview = message[:200] if message else ""
    db.log_phishing_check(
        email_or_url    = email_or_url,
        is_phishing     = result["is_phishing"],
        risk_score      = result["risk_score"],
        reason          = result["reason"],
        message_preview = preview,
        layers          = result["layers_analyzed"],
    )

    result["user_summary"] = _build_user_summary(result)
    return jsonify(result)


@app.route("/api/phishing-stats")
def api_phishing_stats():
    hours = request.args.get("hours", 1, type=int)
    return jsonify(db.get_phishing_statistics(hours))


@app.route("/api/phishing-logs")
def api_phishing_logs():
    limit = request.args.get("limit", 50, type=int)
    return jsonify(db.get_recent_phishing_logs(limit))


# ---------------------------------------------------------------------------
# Endpoints — URLs (backward compatibility)
# ---------------------------------------------------------------------------


@app.route("/api/stats")
def api_stats():
    hours = request.args.get("hours", 1, type=int)
    return jsonify(db.get_statistics(hours))


@app.route("/api/logs")
def api_logs():
    limit = request.args.get("limit", 50, type=int)
    return jsonify(db.get_recent_logs(limit))


@app.route("/api/check-url", methods=["POST"])
def api_check_url():
    body = request.get_json(silent=True) or {}
    url  = body.get("url", "").strip()
    if not url:
        return jsonify({"error": "Campo 'url' requerido"}), 400

    decision, reason, score = decision_engine.evaluate(url)
    ts        = datetime.now(timezone.utc).isoformat()
    client_ip = request.remote_addr or ""
    db.log_request(url, decision, reason, score, ts, client_ip)

    return jsonify({
        "url":              url,
        "decision":         decision,
        "reason":           reason,
        "similarity_score": round(score, 4),
        "timestamp":        ts,
    })


@app.route("/api/blocked-hosts")
def api_blocked_hosts():
    limit = request.args.get("limit", 10, type=int)
    return jsonify(db.get_top_blocked_hosts(limit))


@app.route("/api/blacklist")
def api_blacklist():
    return jsonify(decision_engine.get_blacklist())


@app.route("/api/blacklist/add", methods=["POST"])
def api_blacklist_add():
    body      = request.get_json(silent=True) or {}
    item_type = body.get("type",  "")
    value     = body.get("value", "")
    if not item_type or not value:
        return jsonify({"error": "Campos 'type' y 'value' requeridos"}), 400
    result = decision_engine.add_to_blacklist(item_type, value)
    return jsonify(result), (200 if result["ok"] else 400)


@app.route("/api/blacklist/remove", methods=["POST"])
def api_blacklist_remove():
    body      = request.get_json(silent=True) or {}
    item_type = body.get("type",  "")
    value     = body.get("value", "")
    if not item_type or not value:
        return jsonify({"error": "Campos 'type' y 'value' requeridos"}), 400
    result = decision_engine.remove_from_blacklist(item_type, value)
    return jsonify(result), (200 if result["ok"] else 400)


@app.route("/api/config")
def api_config():
    return jsonify(config.to_dict())


@app.route("/api/config/threshold", methods=["POST"])
def api_config_threshold():
    body      = request.get_json(silent=True) or {}
    threshold = body.get("threshold")
    if threshold is None:
        return jsonify({"error": "Campo 'threshold' requerido"}), 400
    try:
        threshold = float(threshold)
    except (TypeError, ValueError):
        return jsonify({"error": "'threshold' debe ser un numero"}), 400
    if not (0 <= threshold <= 1):
        return jsonify({"error": "'threshold' debe estar entre 0 y 1"}), 400
    decision_engine.update_threshold(threshold)
    return jsonify({"ok": True, "threshold": threshold})


@app.route("/api/health")
def api_health():
    return jsonify({
        "status":    "online",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version":   "2.0",
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import socket
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "127.0.0.1"

    print("=" * 55)
    print("  Detector de Phishing — v2.0")
    print(f"  Panel:  http://{local_ip}:{config.port}")
    print(f"  API:    http://{local_ip}:{config.port}/api/check-phishing")
    print(f"  Health: http://{local_ip}:{config.port}/api/health")
    print("=" * 55)

    app.run(host="0.0.0.0", port=config.port, debug=False, threaded=True)
