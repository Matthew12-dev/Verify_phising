"""
Deteccion de phishing en 3 capas:
  Capa 1 — Whitelist deterministica (UNICA capa que decide is_phishing)
  Capa 2 — Similitud de dominio (SequenceMatcher + confusables visuales)
  Capa 3 — Analisis de ortografia del mensaje (TextBlob con fallback heuristico)

DISEÑO "default deny": si el remitente/dominio no esta en la lista de
contactos aprobados, se marca como intento de phishing de forma
determinista (is_phishing=True). Las capas 2 y 3 NO pueden revertir esa
decision: su funcion es calcular la SEVERIDAD del ataque (que tan
sofisticado es el intento de suplantacion) para que el usuario sepa si
esta ante un dominio aleatorio desconocido o ante una suplantacion
deliberada y elaborada de la empresa.
"""

import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

try:
    from textblob import TextBlob
    TEXTBLOB_AVAILABLE = True
except ImportError:
    TEXTBLOB_AVAILABLE = False

# Tabla de sustitucion de caracteres confusables: digito/simbolo → letra real
_CONFUSABLES = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "rn": "m", "vv": "w",
}

_CONFUSABLE_RE = re.compile(r"rn|vv|[01345]")


class PhishingDetector:
    """
    Analiza un correo/URL mas el contenido del mensaje para determinar si es phishing.

    Capa 1 (whitelist): UNICA capa que decide is_phishing. Si el remitente
                         no esta aprobado, se marca como phishing, punto.
    Capa 2 (similitud):  no decide el veredicto. Aporta severidad: indica
                         si el dominio desconocido ademas intenta imitar
                         visualmente a uno legitimo (typosquatting, confusables).
    Capa 3 (ortografia): no decide el veredicto. Aporta severidad: indica
                         si el mensaje tiene patrones de redaccion tipicos
                         de phishing (errores, mayusculas, simbolos).
    """

    _SIM_SUSPICIOUS = 0.80   # similitud >= este valor → aporta severidad media
    _SIM_PHISHING   = 0.92   # similitud >= este valor → aporta severidad alta

    # Severidad base por no estar en whitelist (un correo desconocido,
    # SIN ninguna otra señal, ya es phishing — pero de severidad baja)
    _BASE_RISK_NOT_WHITELISTED = 0.40

    def __init__(
        self,
        legitimate_domains: list | None = None,
        legitimate_emails: list | None = None,
    ):
        self._domains = [d.lower() for d in (legitimate_domains or [])]
        self._emails  = [e.lower() for e in (legitimate_emails  or [])]

    # ------------------------------------------------------------------
    # Punto de entrada publico
    # ------------------------------------------------------------------

    def analyze(self, email_or_url: str, message_content: str = "") -> dict:
        """
        Retorna un dict con:
          is_phishing    (bool)  — determinado SOLO por la capa 1 (whitelist)
          risk_score     (float 0.0–1.0) — severidad, calculada con las 3 capas
          severity       (str) — "NINGUNA" | "BAJA" | "MEDIA" | "ALTA"
          reason         (str)
          layers_analyzed (dict con el detalle de cada capa)
        """
        target = email_or_url.strip().lower()
        host   = self._extract_host(target)

        layer1 = self._check_whitelist(target, host)
        layer2 = self._check_similarity(host)
        layer3 = self._check_message_spelling(message_content)

        risk_score = self._compute_risk(layer1, layer2, layer3)
        is_phishing = not layer1["passed"]          # <-- determinista, solo capa 1
        severity    = self._severity_label(layer1, risk_score)
        reason      = self._build_reason(layer1, layer2, layer3, risk_score)

        return {
            "is_phishing": is_phishing,
            "risk_score":  round(risk_score, 3),
            "severity":    severity,
            "reason":      reason,
            "layers_analyzed": {
                "layer1_whitelist":  layer1,
                "layer2_similarity": layer2,
                "layer3_spelling":   layer3,
            },
        }

    # ------------------------------------------------------------------
    # Capa 1 — Whitelist deterministica (DECIDE is_phishing)
    # ------------------------------------------------------------------

    def _check_whitelist(self, target: str, host: str) -> dict:
        """
        Coincidencia exacta contra dominios y correos aprobados.
        Los subdominios de dominios aprobados tambien se aceptan (ej: mail.empresa.com).

        Esta es la UNICA capa que determina is_phishing. Si "passed" es
        False, el remitente se trata como no autorizado / phishing,
        sin importar lo que digan las capas 2 y 3.
        """
        in_domains = host in self._domains or any(
            host.endswith("." + d) for d in self._domains
        )
        in_emails = target in self._emails

        return {
            "passed":         in_domains or in_emails,
            "matched_domain": in_domains,
            "matched_email":  in_emails,
        }

    # ------------------------------------------------------------------
    # Capa 2 — Similitud de dominio (solo aporta severidad, no decide)
    # ------------------------------------------------------------------

    def _check_similarity(self, host: str) -> dict:
        """
        SequenceMatcher compara el host contra cada dominio legitimo.
        Un score alto en un dominio que NO esta en la whitelist indica
        que el atacante intenta imitar visualmente a la empresa
        (typosquatting). Esto SUMA severidad, pero el veredicto ya
        quedo fijado por la capa 1.
        """
        best_match = ""
        best_score = 0.0

        for legit in self._domains:
            score = SequenceMatcher(None, host, legit).ratio()
            if score > best_score:
                best_score = score
                best_match = legit

        confusables = self._check_visual_confusables(host)
        suspicious  = (best_score >= self._SIM_SUSPICIOUS and host not in self._domains)

        return {
            "best_match":       best_match,
            "similarity_score": round(best_score, 3),
            "suspicious":       suspicious or confusables["found"],
            "confusables":      confusables,
        }

    def _check_visual_confusables(self, host: str) -> dict:
        """
        Detecta digitos usados para imitar letras (1→l, 0→o, rn→m, etc.).
        Solo marca como confusable si el host normalizado coincide con un dominio legitimo,
        lo que indica una suplantacion intencional.
        """
        found_chars = _CONFUSABLE_RE.findall(host)
        normalized  = host
        for char, replacement in _CONFUSABLES.items():
            normalized = normalized.replace(char, replacement)

        matches_after_norm = normalized in self._domains or any(
            normalized.endswith("." + d) for d in self._domains
        )

        return {
            "found":      bool(found_chars) and matches_after_norm,
            "chars":      found_chars,
            "normalized": normalized,
        }

    # ------------------------------------------------------------------
    # Capa 3 — Ortografia y estilo del mensaje (solo aporta severidad)
    # ------------------------------------------------------------------

    def _check_message_spelling(self, message: str) -> dict:
        """
        Tres señales extraidas del contenido del mensaje:
          error_ratio   — proporcion de palabras con errores (TextBlob)
          upper_ratio   — proporcion de letras en mayuscula
          special_ratio — densidad de caracteres especiales (!$%#...)

        Si TextBlob no esta instalado, solo se calculan las dos heuristicas.
        Esta capa NUNCA decide is_phishing; solo suma severidad.
        """
        if not message:
            return {"analyzed": False, "reason": "Mensaje vacio", "suspicious": False}

        upper_ratio   = self._upper_ratio(message)
        special_ratio = self._special_char_ratio(message)

        if TEXTBLOB_AVAILABLE:
            blob  = TextBlob(message)
            words = blob.words
            if words:
                corrected   = blob.correct()
                error_count = sum(
                    1 for orig, fixed in zip(words, TextBlob(str(corrected)).words)
                    if orig.lower() != fixed.lower()
                )
                error_ratio = error_count / len(words)
            else:
                error_ratio = 0.0
            method = "textblob"
        else:
            error_ratio = 0.0
            method      = "heuristic"

        suspicious = (
            error_ratio   > 0.25 or
            upper_ratio   > 0.40 or
            special_ratio > 0.10
        )

        return {
            "analyzed":     True,
            "method":       method,
            "error_ratio":  round(error_ratio,    3),
            "upper_ratio":  round(upper_ratio,    3),
            "special_ratio": round(special_ratio, 3),
            "suspicious":   suspicious,
        }

    # ------------------------------------------------------------------
    # Calculo de severidad (risk_score) — NO decide is_phishing
    # ------------------------------------------------------------------

    def _compute_risk(self, l1: dict, l2: dict, l3: dict) -> float:
        """
        Si l1 paso (whitelist), no hay riesgo: 0.0.

        Si l1 NO paso, el remitente YA es phishing por definicion. Este
        metodo calcula que tan severo/sofisticado es el intento, sumando
        señales de las capas 2 y 3 sobre una base minima por no estar
        autorizado.
        """
        if l1["passed"]:
            return 0.0

        # Base: el solo hecho de no estar en whitelist ya es sospechoso
        score = self._BASE_RISK_NOT_WHITELISTED
        sim   = l2["similarity_score"]

        if sim >= self._SIM_PHISHING:
            score += 0.35
        elif sim >= self._SIM_SUSPICIOUS:
            score += 0.20

        if l2["confusables"]["found"]:
            score += 0.15

        if l3.get("suspicious"):
            score += 0.10

        if l3.get("error_ratio", 0) > 0.25:
            score += 0.05

        return min(score, 1.0)

    def _severity_label(self, l1: dict, risk: float) -> str:
        """Traduce el risk_score a una etiqueta legible para el panel."""
        if l1["passed"]:
            return "NINGUNA"
        if risk >= 0.85:
            return "ALTA"
        if risk >= 0.60:
            return "MEDIA"
        return "BAJA"

    def _build_reason(self, l1: dict, l2: dict, l3: dict, risk: float) -> str:
        """
        Construye una razon legible. Si l1 paso, es legitimo. Si no,
        SIEMPRE es phishing (capa 1 lo decide), y aqui se describe
        CON QUE TIPO de ataque coincide segun las capas 2 y 3.
        """
        if l1["passed"]:
            return "En lista blanca: remitente aprobado por la organizacion"

        details = ["Remitente no esta en la lista de contactos aprobados"]

        sim = l2["similarity_score"]
        if l2["confusables"]["found"]:
            details.append(
                f"caracteres confusables detectados imitando '{l2['best_match']}'"
            )
        elif sim >= self._SIM_PHISHING:
            details.append(
                f"dominio {sim:.0%} similar a '{l2['best_match']}' (suplantacion probable)"
            )
        elif sim >= self._SIM_SUSPICIOUS:
            details.append(
                f"dominio con similitud sospechosa ({sim:.0%}) a '{l2['best_match']}'"
            )

        if l3.get("suspicious"):
            details.append("mensaje con indicadores de redaccion de phishing")

        return "Phishing (no autorizado): " + "; ".join(details)

    # ------------------------------------------------------------------
    # Utilidades estaticas
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_host(target: str) -> str:
        if "@" in target:
            return target.split("@")[-1].lower()
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        parsed = urlparse(target)
        return (parsed.hostname or target).lower()

    @staticmethod
    def _upper_ratio(text: str) -> float:
        letters = [c for c in text if c.isalpha()]
        if not letters:
            return 0.0
        return sum(1 for c in letters if c.isupper()) / len(letters)

    @staticmethod
    def _special_char_ratio(text: str) -> float:
        if not text:
            return 0.0
        specials = sum(1 for c in text if not c.isalnum() and not c.isspace())
        return specials / len(text)
