"""
ConfigManager: base de configuración usada por main.py y decision_engine.py.
Carga y persiste parámetros desde config/config.json, con valores default y
validación de similarity_threshold.
"""

import json
from pathlib import Path
from typing import Optional


CONFIG_PATH = Path(__file__).parent.parent / "config" / "config.json"

DEFAULTS = {
    "port": 5000,
    "host": "0.0.0.0",
    "similarity_threshold": 0.72,
    "use_embeddings": True,
    "debug": False,
}


class ConfigManager:
    def __init__(self, config_path: Optional[Path] = None):
        self._path = Path(config_path) if config_path else CONFIG_PATH
        self._data: dict = {}
        self._load_config()

    def _load_config(self) -> None:
        if not self._path.exists():
            self._data = dict(DEFAULTS)
            self._save_config()
            return

        try:
            with open(self._path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            self._data = {**DEFAULTS, **loaded}
        except json.JSONDecodeError:
            print(f"[ConfigManager] config.json malformado, usando defaults.")
            self._data = dict(DEFAULTS)
        except Exception as e:
            print(f"[ConfigManager] Error al leer config: {e}. Usando defaults.")
            self._data = dict(DEFAULTS)

        # Validar similarity_threshold
        threshold = self._data.get("similarity_threshold", 0.72)
        if not isinstance(threshold, (int, float)) or not (0 <= threshold <= 1):
            print(f"[ConfigManager] similarity_threshold inválido ({threshold}), usando 0.72.")
            self._data["similarity_threshold"] = 0.72

    def _save_config(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[ConfigManager] Error al guardar config: {e}")

    def update(self, **kwargs) -> None:
        self._data.update(kwargs)
        self._save_config()

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def to_dict(self) -> dict:
        return dict(self._data)

    # Acceso directo a los campos más usados
    @property
    def port(self) -> int:
        return int(self._data.get("port", 5000))

    @property
    def host(self) -> str:
        return str(self._data.get("host", "0.0.0.0"))

    @property
    def similarity_threshold(self) -> float:
        return float(self._data.get("similarity_threshold", 0.72))

    @property
    def use_embeddings(self) -> bool:
        return bool(self._data.get("use_embeddings", True))

    @property
    def debug(self) -> bool:
        return bool(self._data.get("debug", False))
