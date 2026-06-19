"""
Prueba de extremo a extremo sin necesidad de que el servidor Flask este corriendo.
Incluye tests del motor de URLs original y del nuevo detector de phishing.
"""

import sys
import os
import json
import traceback
from datetime import datetime, timezone
from pathlib import Path

# Forzar UTF-8 en la salida para que los emojis se impriman correctamente en Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TEST_URLS = [
    "https://facebook.com",
    "https://www.instagram.com/stories",
    "https://futbol.com/noticias",
    "https://mundial2026.com",
    "https://google.com",
    "https://wikipedia.org/wiki/Python",
]

PHISHING_CASOS = [
    {
        "nombre":  "Caso 1: Correo legitimo con mensaje normal",
        "target":  "contacto@empresa.com",
        "message": "Hola, adjunto encontrara la factura del mes de junio. Saludos.",
    },
    {
        "nombre":  "Caso 2: Correo falso similar + mensaje con errores",
        "target":  "ceo@empreza.com",
        "message": "URGENTE!! Su cuanta sera suspendida si no verifica sus datos AHORA. "
                   "Haga click aqui!!",
    },
    {
        "nombre":  "Caso 3: Dominio con confusables + mayusculas anormales",
        "target":  "http://emp1resa.com/login",
        "message": "VERIFIQUE SU IDENTIDAD INMEDIATAMENTE PARA EVITAR EL BLOQUEO DE SU CUENTA",
    },
    {
        "nombre":  "Caso 4: Dominio desconocido + mensaje con muchos errores",
        "target":  "soporte@empresa-segura-verificacion.net",
        "message": "Estimado cleinte, se ha dettectado activiidad inusuall en su cuanta. "
                   "Por favor haga clcik en el enlace para verficar su identidad.",
    },
]


def test_url_engine():
    from utils.config_manager import ConfigManager
    from app.decision_engine import DecisionEngine
    from database.logger_db import DatabaseLogger

    print("=" * 60)
    print("  TEST 1 — Motor de URLs")
    print("=" * 60)

    config = ConfigManager()
    print(f"\n[Config] threshold={config.similarity_threshold}  "
          f"use_embeddings={config.use_embeddings}\n")

    db     = DatabaseLogger()
    engine = DecisionEngine(config)

    print("-" * 60)
    print(f"{'URL':<40} {'DECISION':<10} {'SCORE':<7} RAZON")
    print("-" * 60)

    for url in TEST_URLS:
        decision, reason, score = engine.evaluate(url)
        icon      = "🚫" if decision == "BLOCKED" else "✅"
        score_str = f"{score:.3f}" if score > 0 else "  —  "
        print(f"{icon} {url:<38} {decision:<10} {score_str:<7} {reason[:50]}")

        ts = datetime.now(timezone.utc).isoformat()
        db.log_request(url, decision, reason, score, ts, "127.0.0.1")

    print("-" * 60)

    print("\n[Estadisticas — ultimas 24 h]")
    stats = db.get_statistics(hours=24)
    print(f"  Total:     {stats['total']}")
    print(f"  Bloqueadas:{stats['blocked']}")
    print(f"  Permitidas:{stats['allowed']}")
    print(f"  Tasa:      {stats['block_rate']}%")

    print("\n[Ultimos 5 logs de URL]")
    for log in db.get_recent_logs(limit=5):
        icon = "🚫" if log["decision"] == "BLOCKED" else "✅"
        print(f"  {icon} {log['url']} → {log['decision']}")


def test_phishing_detector():
    from app.phishing_detector import PhishingDetector
    from database.logger_db import DatabaseLogger

    print("\n" + "=" * 60)
    print("  TEST 2 — Detector de Phishing (3 capas)")
    print("=" * 60)

    domains_path = Path(__file__).parent / "config" / "legitimate_domains.json"
    try:
        with open(domains_path, encoding="utf-8") as f:
            cfg = json.load(f)
        legit_domains = cfg.get("legitimate_domains", [])
        legit_emails  = cfg.get("legitimate_emails",  [])
    except Exception:
        legit_domains = ["empresa.com", "mail.empresa.com"]
        legit_emails  = ["ceo@empresa.com", "contacto@empresa.com"]

    detector = PhishingDetector(
        legitimate_domains=legit_domains,
        legitimate_emails=legit_emails,
    )
    db = DatabaseLogger()

    for caso in PHISHING_CASOS:
        result = detector.analyze(caso["target"], caso["message"])
        is_p   = result["is_phishing"]
        score  = result["risk_score"]
        reason = result["reason"]
        layers = result["layers_analyzed"]

        icon = "🚫" if is_p else ("⚠️" if score >= 0.35 else "✅")

        print(f"\n{caso['nombre']}")
        print(f"  Objetivo : {caso['target']}")
        print(f"  Resultado: {icon}  {reason}  (risk_score={score})")

        l1 = layers["layer1_whitelist"]
        print(f"  Capa 1 — Whitelist  : {'EN LISTA BLANCA' if l1['passed'] else 'No encontrado'}")

        l2 = layers["layer2_similarity"]
        conf_info = ""
        if l2["confusables"]["found"]:
            conf_info = " | confusables: " + str(l2["confusables"]["chars"])
        print(f"  Capa 2 — Similitud  : {l2['similarity_score']} con '{l2['best_match']}'{conf_info}")

        l3 = layers["layer3_spelling"]
        if l3["analyzed"]:
            print(f"  Capa 3 — Ortografia : errores={l3['error_ratio']} "
                  f"mayusc={l3['upper_ratio']} especiales={l3['special_ratio']}")
        else:
            print(f"  Capa 3 — Ortografia : {l3['reason']}")

        db.log_phishing_check(
            email_or_url=caso["target"],
            is_phishing=is_p,
            risk_score=score,
            reason=reason,
            message_preview=caso["message"][:200],
            layers=layers,
        )

    print("\n[Estadisticas de phishing — ultimas 24 h]")
    stats = db.get_phishing_statistics(hours=24)
    print(f"  Total:    {stats['total']}")
    print(f"  Phishing: {stats['phishing']}")
    print(f"  Legitimos:{stats['legit']}")
    print(f"  Tasa:     {stats['phishing_rate']}%")

    print("\n✅ Test de phishing completado.")


def main():
    try:
        test_url_engine()
        test_phishing_detector()
        print("\n✅ Todos los tests completados correctamente.")
    except Exception:
        print("\n❌ Error durante el test:")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
