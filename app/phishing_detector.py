"""
Deteccion de phishing en 3 capas:
  Capa 1 — Whitelist deterministica
  Capa 2 — Similitud de dominio (SequenceMatcher + confusables visuales)
  Capa 3 — Analisis de ortografia del mensaje (TextBlob con fallback heuristico)
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

    Capa 1 (whitelist): coincidencia exacta contra dominios/correos aprobados.
    Capa 2 (similitud): SequenceMatcher + deteccion de confusables visuales.
    Capa 3 (ortografia): TextBlob para detectar errores gramaticales, exceso de
                          mayusculas y densidad de caracteres especiales.
    """

    _SIM_SUSPICIOUS = 0.80   # similitud >= este valor → sospechoso
    _SIM_PHISHING   = 0.92   # similitud >= este valor → phishing probable

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
          is_phishing    (bool)
          risk_score     (float 0.0–1.0)
          reason         (str)
          layers_analyzed (dict con el detalle de cada capa)
        """
        target = email_or_url.strip().lower()
        host   = self._extract_host(target)

        layer1 = self._check_whitelist(target, host)
        layer2 = self._check_similarity(host)
        layer3 = self._check_message_spelling(message_content)

        risk_score         = self._compute_risk(layer1, layer2, layer3)
        is_phishing, reason = self._decide(layer1, layer2, layer3, risk_score)

        return {
            "is_phishing": is_phishing,
            "risk_score":  round(risk_score, 3),
            "reason":      reason,
            "layers_analyzed": {
                "layer1_whitelist":  layer1,
                "layer2_similarity": layer2,
                "layer3_spelling":   layer3,
            },
        }

    # ------------------------------------------------------------------
    # Capa 1 — Whitelist deterministica
    # ------------------------------------------------------------------

    def _check_whitelist(self, target: str, host: str) -> dict:
        """
        Coincidencia exacta contra dominios y correos aprobados.
        Los subdominios de dominios aprobados tambien se aceptan (ej: mail.empresa.com).
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
    # Capa 2 — Similitud de dominio
    # ------------------------------------------------------------------

    def _check_similarity(self, host: str) -> dict:
        """
        SequenceMatcher compara el host contra cada dominio legitimo.
        Un score alto en un dominio que NO esta en la whitelist es sospechoso.
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
    # Capa 3 — Ortografia y estilo del mensaje
    # ------------------------------------------------------------------

    def _check_message_spelling(self, message: str) -> dict:
        """
        Tres señales extraidas del contenido del mensaje:
          error_ratio   — proporcion de palabras con errores (TextBlob)
          upper_ratio   — proporcion de letras en mayuscula
          special_ratio — densidad de caracteres especiales (!$%#...)

        Si TextBlob no esta instalado, solo se calculan las dos heuristicas.
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
    # Calculo de riesgo y decision final
    # ------------------------------------------------------------------

    def _compute_risk(self, l1: dict, l2: dict, l3: dict) -> float:
        if l1["passed"]:
            return 0.0

        score = 0.0
        sim   = l2["similarity_score"]

        if sim >= self._SIM_PHISHING:
            score += 0.55
        elif sim >= self._SIM_SUSPICIOUS:
            score += 0.35

        if l2["confusables"]["found"]:
            score += 0.25

        if l3.get("suspicious"):
            score += 0.20

        if l3.get("error_ratio", 0) > 0.25:
            score += 0.10

        return min(score, 1.0)

    def _decide(self, l1: dict, l2: dict, l3: dict, risk: float) -> tuple:
        if l1["passed"]:
            return False, "En lista blanca"

        if risk >= 0.70:
            return True,  "Phishing probable: dominio muy similar al legitimo"
        if l2["confusables"]["found"] and risk >= 0.40:
            return True,  "Phishing probable: caracteres confusables detectados"
        if risk >= 0.35:
            return False, "Sospechoso: similitud alta con dominio legitimo"
        if l3.get("suspicious") and risk >= 0.20:
            return False, "Sospechoso: contenido del mensaje con indicadores de phishing"

        return False, "Sin indicadores de phishing"

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
