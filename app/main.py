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

# Cargar whitelist de dominios legitimos para el detector de phishing
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
# Panel HTML (inline)
# ---------------------------------------------------------------------------

PANEL_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Detector de Phishing</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; padding: 24px; }
    h1 { color: #38bdf8; margin-bottom: 20px; }
    h2 { color: #94a3b8; font-size: 1rem; margin: 16px 0 8px; text-transform: uppercase; letter-spacing: 1px; }
    label { display: block; font-size: 0.85rem; color: #94a3b8; margin: 10px 0 4px; }
    .card { background: #1e293b; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
    .row { display: flex; gap: 12px; flex-wrap: wrap; }
    .stat { background: #0f172a; border-radius: 6px; padding: 12px 20px; flex: 1; min-width: 120px; }
    .stat .val { font-size: 2rem; font-weight: 700; }
    .stat .lbl { font-size: 0.75rem; color: #94a3b8; margin-top: 2px; }
    input[type=text], textarea {
      width: 100%; padding: 10px 14px; background: #0f172a; border: 1px solid #334155;
      border-radius: 6px; color: #e2e8f0; font-size: 1rem; font-family: inherit;
    }
    textarea { min-height: 100px; resize: vertical; }
    button { padding: 10px 24px; background: #0ea5e9; border: none; border-radius: 6px;
             color: #fff; font-size: 1rem; cursor: pointer; margin-top: 12px; }
    button:hover { background: #38bdf8; }
    #result { margin-top: 12px; padding: 12px; border-radius: 6px; font-weight: 600; display: none; }
    .phishing   { background: #450a0a; color: #fca5a5; }
    .suspicious { background: #431407; color: #fdba74; }
    .safe       { background: #052e16; color: #86efac; }
    .layers { margin-top: 8px; font-size: 0.8rem; font-weight: 400; opacity: 0.85; line-height: 1.6; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th { text-align: left; color: #64748b; padding: 6px 10px; border-bottom: 1px solid #334155; }
    td { padding: 6px 10px; border-bottom: 1px solid #1e293b; word-break: break-all; }
    .badge-phishing   { background: #7f1d1d; color: #fca5a5; padding: 2px 8px; border-radius: 99px; font-size: 0.75rem; }
    .badge-suspicious { background: #7c2d12; color: #fdba74; padding: 2px 8px; border-radius: 99px; font-size: 0.75rem; }
    .badge-safe       { background: #14532d; color: #86efac; padding: 2px 8px; border-radius: 99px; font-size: 0.75rem; }
  </style>
</head>
<body>
  <h1>Detector de Phishing</h1>

  <div class="card">
    <h2>Verificar correo o URL sospechosa</h2>
    <label>Correo electronico o URL</label>
    <input type="text" id="targetInput"
           placeholder="ej: ceo@empreza.com  o  http://emp1resa.com/login">
    <label>Contenido del mensaje (opcional pero mejora la deteccion)</label>
    <textarea id="messageInput"
              placeholder="Pega aqui el texto del correo o mensaje sospechoso..."></textarea>
    <button onclick="checkPhishing()">Analizar</button>
    <div id="result"></div>
  </div>

  <div class="card">
    <h2>Estadisticas (ultima hora)</h2>
    <div class="row" id="statsRow">
      <div class="stat"><div class="val" id="sTotal">—</div><div class="lbl">Total</div></div>
      <div class="stat"><div class="val" id="sPhishing">—</div><div class="lbl">Phishing</div></div>
      <div class="stat"><div class="val" id="sLegit">—</div><div class="lbl">Legitimos</div></div>
      <div class="stat"><div class="val" id="sRate">—</div><div class="lbl">% Phishing</div></div>
    </div>
  </div>

  <div class="card">
    <h2>Analisis recientes</h2>
    <table>
      <thead><tr><th>Resultado</th><th>Objetivo</th><th>Razon</th><th>Score</th></tr></thead>
      <tbody id="logsBody"></tbody>
    </table>
  </div>

  <script>
    async function checkPhishing() {
      const target  = document.getElementById('targetInput').value.trim();
      const message = document.getElementById('messageInput').value.trim();
      if (!target) return;

      const res  = await fetch('/api/check-phishing', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ email_or_url: target, message })
      });
      const data = await res.json();
      const el   = document.getElementById('result');
      el.style.display = 'block';

      let cls, label;
      if (data.is_phishing) {
        cls = 'phishing'; label = '🚫 Phishing detectado';
      } else if (data.risk_score >= 0.35) {
        cls = 'suspicious'; label = '⚠️ Sospechoso';
      } else {
        cls = 'safe'; label = '✅ Legitimo';
      }

      const ly = data.layers_analyzed || {};
      const l1 = ly.layer1_whitelist  || {};
      const l2 = ly.layer2_similarity || {};
      const l3 = ly.layer3_spelling   || {};

      const layerLines = [
        'Capa 1 (whitelist): '  + (l1.passed ? '✔ En lista blanca' : '✘ No encontrado'),
        'Capa 2 (similitud): score=' + (l2.similarity_score ?? '—')
          + (l2.confusables && l2.confusables.found ? ' | confusables: ' + l2.confusables.chars.join(', ') : ''),
        l3.analyzed
          ? 'Capa 3 (ortografia): errores=' + l3.error_ratio + ' mayusc=' + l3.upper_ratio + ' especiales=' + l3.special_ratio
          : 'Capa 3: sin mensaje',
      ].join('<br>');

      el.className = cls;
      el.innerHTML = '<strong>' + label + '</strong>'
        + ' — ' + (data.reason || '')
        + ' (score: ' + Number(data.risk_score || 0).toFixed(3) + ')'
        + '<div class="layers">' + layerLines + '</div>';

      loadStats(); loadLogs();
    }

    async function loadStats() {
      const data = await fetch('/api/phishing-stats?hours=1').then(r => r.json());
      document.getElementById('sTotal').textContent    = data.total    ?? '—';
      document.getElementById('sPhishing').textContent = data.phishing ?? '—';
      document.getElementById('sLegit').textContent    = data.legit    ?? '—';
      document.getElementById('sRate').textContent     = (data.phishing_rate ?? 0) + '%';
    }

    async function loadLogs() {
      const rows = await fetch('/api/phishing-logs?limit=20').then(r => r.json());
      const tbody = document.getElementById('logsBody');
      tbody.innerHTML = rows.map(r => {
        const badgeCls = r.is_phishing
          ? 'badge-phishing'
          : (r.risk_score >= 0.35 ? 'badge-suspicious' : 'badge-safe');
        const lbl = r.is_phishing
          ? 'PHISHING'
          : (r.risk_score >= 0.35 ? 'SOSPECHOSO' : 'LEGITIMO');
        return '<tr>'
          + '<td><span class="' + badgeCls + '">' + lbl + '</span></td>'
          + '<td>' + (r.email_or_url || '') + '</td>'
          + '<td>' + (r.reason || '') + '</td>'
          + '<td>' + (r.risk_score != null ? Number(r.risk_score).toFixed(3) : '—') + '</td>'
          + '</tr>';
      }).join('');
    }

    loadStats(); loadLogs();
    setInterval(() => { loadStats(); loadLogs(); }, 10000);
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
    body        = request.get_json(silent=True) or {}
    email_or_url = body.get("email_or_url", "").strip()
    message      = body.get("message", "").strip()

    if not email_or_url:
        return jsonify({"error": "Campo 'email_or_url' requerido"}), 400

    result   = phishing_detector.analyze(email_or_url, message)
    preview  = message[:200] if message else ""
    db.log_phishing_check(
        email_or_url  = email_or_url,
        is_phishing   = result["is_phishing"],
        risk_score    = result["risk_score"],
        reason        = result["reason"],
        message_preview = preview,
        layers        = result["layers_analyzed"],
    )

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
