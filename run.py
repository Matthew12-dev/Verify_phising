import sys
import os

# Asegurar que el directorio raíz del proyecto esté en el path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.main import app, config

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=config.port, debug=False, threaded=True)
