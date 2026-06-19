"""
DecisionEngine: motor de dos capas para evaluar URLs.

Capa 1 — Exact match: compara el dominio contra blacklist_domains (O(1) en set).
Capa 2 — Detección contextual con IA: si sentence-transformers y sklearn están
          instalados, calcula similitud coseno entre el embedding de la URL y los
          embeddings de cada tema bloqueado. Si la similitud supera el umbral
          configurable (default 0.72), la URL queda bloqueada aunque no esté en
          la lista exacta.

El fallback gracioso garantiza que, sin las librerías opcionales, el sistema
siga funcionando solo con exact match.
"""

import json
from pathlib import Path
from typing import Tuple, Optional
from urllib.parse import urlparse

# Flags de disponibilidad de librerías opcionales
EMBEDDINGS_AVAILABLE = False
SKLEARN_AVAILABLE = False

try:
    from sentence_transformers import SentenceTransformer
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    pass

try:
    from sklearn.metrics.pairwise import cosine_similarity
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    pass


BLACKLIST_PATH = Path(__file__).parent.parent / "config" / "blacklist.json"


class DecisionEngine:
    def __init__(self, config):
        self.config = config
        self._model = None
        self._theme_embeddings = []
        self._load_blacklist()
        self._load_model()

    # ------------------------------------------------------------------
    # Inicialización
    # ------------------------------------------------------------------

    def _load_blacklist(self) -> None:
        try:
            if BLACKLIST_PATH.exists():
                with open(BLACKLIST_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                data = {"domains": [], "themes": []}
                self._save_blacklist_data(data)
            self._blacklist_domains: set = set(data.get("domains", []))
            self._blacklist_themes: list = data.get("themes", [])
        except json.JSONDecodeError:
            print("[DecisionEngine] blacklist.json malformado, iniciando vacío.")
            self._blacklist_domains = set()
            self._blacklist_themes = []
        except Exception as e:
            print(f"[DecisionEngine] Error al cargar blacklist: {e}")
            self._blacklist_domains = set()
            self._blacklist_themes = []

    def _load_model(self) -> None:
        if not (EMBEDDINGS_AVAILABLE and SKLEARN_AVAILABLE):
            print("[DecisionEngine] sentence-transformers o sklearn no disponibles. "
                  "Modo exact-match únicamente.")
            return

        if not self.config.use_embeddings:
            print("[DecisionEngine] use_embeddings=False. Modo exact-match únicamente.")
            return

        try:
            print("[DecisionEngine] Cargando modelo all-MiniLM-L6-v2 …")
            self._model = SentenceTransformer("all-MiniLM-L6-v2")
            self._compute_theme_embeddings()
            print("[DecisionEngine] Modelo cargado correctamente.")
        except Exception as e:
            print(f"[DecisionEngine] No se pudo cargar el modelo: {e}. Usando exact-match.")
            self._model = None

    def _compute_theme_embeddings(self) -> None:
        if self._model and self._blacklist_themes:
            try:
                self._theme_embeddings = self._model.encode(self._blacklist_themes)
            except Exception as e:
                print(f"[DecisionEngine] Error al generar embeddings de temas: {e}")
                self._theme_embeddings = []

    # ------------------------------------------------------------------
    # Evaluación principal
    # ------------------------------------------------------------------

    def evaluate(self, url: str) -> Tuple[str, str, float]:
        """Retorna (decision, reason, similarity_score)."""
        if not url or not url.strip():
            return ("BLOCKED", "URL vacía o inválida", 0.0)

        # Asegurar esquema para que urlparse funcione correctamente
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        host = parsed.hostname or ""
        host = host.lower().strip()

        if not host:
            return ("BLOCKED", "Host no reconocible", 0.0)

        # Capa 1: exact match (O(1))
        blocked, reason = self._check_exact_match(host)
        if blocked:
            return ("BLOCKED", reason, 1.0)

        # Capa 2: detección contextual con IA (solo si el modelo está cargado)
        if self._model is not None:
            decision, reason, score = self._check_contextual(url, host)
            if decision == "BLOCKED":
                return ("BLOCKED", reason, score)

        return ("ALLOWED", "No coincide con ninguna regla", 0.0)

    # ------------------------------------------------------------------
    # Capas auxiliares
    # ------------------------------------------------------------------

    def _check_exact_match(self, host: str) -> Tuple[bool, str]:
        # Verificar con y sin "www."
        variants = {host}
        if host.startswith("www."):
            variants.add(host[4:])
        else:
            variants.add("www." + host)

        for variant in variants:
            if variant in self._blacklist_domains:
                return (True, f"Dominio en lista negra exacta: {variant}")

        return (False, "")

    def _check_contextual(self, url: str, host: str) -> Tuple[str, str, float]:
        if not self._blacklist_themes or len(self._theme_embeddings) == 0:
            return ("ALLOWED", "", 0.0)

        try:
            text = host + " " + self._extract_keywords(url)
            url_embedding = self._model.encode([text])
            scores = cosine_similarity(url_embedding, self._theme_embeddings)[0]
            max_idx = int(scores.argmax())
            max_score = float(scores[max_idx])

            threshold = self.config.similarity_threshold
            if max_score >= threshold:
                tema = self._blacklist_themes[max_idx]
                return (
                    "BLOCKED",
                    f"Similitud contextual con tema bloqueado '{tema[:40]}…' "
                    f"(score={max_score:.3f}, umbral={threshold})",
                    max_score,
                )
        except Exception as e:
            print(f"[DecisionEngine] Error en _check_contextual: {e}")

        return ("ALLOWED", "", 0.0)

    @staticmethod
    def _extract_keywords(url: str) -> str:
        """Extrae palabras legibles del path/query de la URL para enriquecer el embedding."""
        parsed = urlparse(url)
        raw = (parsed.path or "") + " " + (parsed.query or "")
        # Reemplazar separadores comunes por espacios
        for sep in ["/", "-", "_", ".", "=", "&", "?", "%20"]:
            raw = raw.replace(sep, " ")
        return raw.strip()

    # ------------------------------------------------------------------
    # Gestión de la lista negra
    # ------------------------------------------------------------------

    def add_to_blacklist(self, item_type: str, value: str) -> dict:
        value = value.strip().lower()
        if item_type == "domain":
            if value in self._blacklist_domains:
                return {"ok": False, "message": "El dominio ya existe en la lista"}
            self._blacklist_domains.add(value)
            self._save_blacklist()
            return {"ok": True, "message": f"Dominio '{value}' agregado"}
        elif item_type == "theme":
            if value in self._blacklist_themes:
                return {"ok": False, "message": "El tema ya existe en la lista"}
            self._blacklist_themes.append(value)
            self._compute_theme_embeddings()
            self._save_blacklist()
            return {"ok": True, "message": f"Tema '{value}' agregado"}
        return {"ok": False, "message": f"Tipo inválido: '{item_type}'. Use 'domain' o 'theme'"}

    def remove_from_blacklist(self, item_type: str, value: str) -> dict:
        value = value.strip().lower()
        if item_type == "domain":
            if value not in self._blacklist_domains:
                return {"ok": False, "message": "El dominio no está en la lista"}
            self._blacklist_domains.discard(value)
            self._save_blacklist()
            return {"ok": True, "message": f"Dominio '{value}' eliminado"}
        elif item_type == "theme":
            if value not in self._blacklist_themes:
                return {"ok": False, "message": "El tema no está en la lista"}
            self._blacklist_themes.remove(value)
            self._compute_theme_embeddings()
            self._save_blacklist()
            return {"ok": True, "message": f"Tema '{value}' eliminado"}
        return {"ok": False, "message": f"Tipo inválido: '{item_type}'. Use 'domain' o 'theme'"}

    def _save_blacklist(self) -> None:
        self._save_blacklist_data({
            "domains": sorted(self._blacklist_domains),
            "themes": self._blacklist_themes,
        })

    def _save_blacklist_data(self, data: dict) -> None:
        try:
            BLACKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(BLACKLIST_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[DecisionEngine] Error al guardar blacklist: {e}")

    def get_blacklist(self) -> dict:
        return {
            "domains": sorted(self._blacklist_domains),
            "themes": list(self._blacklist_themes),
            "embeddings_active": self._model is not None,
        }

    def update_threshold(self, threshold: float) -> None:
        self.config.update(similarity_threshold=threshold)
