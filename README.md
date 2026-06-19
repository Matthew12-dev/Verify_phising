# Verify_Phing 

Sistema de detección de phishing para Raspberry Pi 5 con Python e IA.  
Analiza correos electrónicos y URLs sospechosas en 3 capas de verificación para detectar intentos de suplantación de dominios oficiales.

---

## 1. Descripción del proyecto

**¿Qué es?**  
Un servicio web ligero que corre en Raspberry Pi y expone un panel + API REST para analizar si un correo o URL es un intento de phishing.

**Problema que resuelve**  
Los ataques de phishing suplantan dominios oficiales con variaciones mínimas (`empreza.com`, `emp1resa.com`) o usan mensajes mal redactados para engañar a usuarios. La detección manual es lenta y propensa a errores.

**Solución: 3 capas de verificación**

| Capa | Técnica | Descripción |
|------|---------|-------------|
| 1 — Whitelist | Determinística | ¿El correo/dominio está en la lista aprobada? Respuesta inmediata sin IA. |
| 2 — Similitud | `difflib.SequenceMatcher` + confusables | ¿Se parece sospechosamente a un dominio legítimo? Detecta `l→1`, `o→0`, `m→rn`. |
| 3 — Ortografía | TextBlob (modelo pre-entrenado) | ¿El mensaje contiene errores, mayúsculas anormales o caracteres inusuales? |

**IA usada**  
TextBlob con modelos de corrección ortográfica pre-entrenados. No requiere entrenamiento propio ni GPU.

---

## 2. Requisitos

**Hardware**
- Raspberry Pi 5 con 8 GB RAM (mínimo 4 GB)
- Tarjeta microSD de 16 GB o más (clase 10 recomendada)
- Conexión a internet solo para la primera instalación

**Software**
- Raspberry Pi OS (Bookworm 64-bit recomendado)
- Python 3.11 o superior
- pip actualizado

**Almacenamiento**  
~500 MB para modelos de IA y dependencias (TextBlob es ligero; `torch` y `sentence-transformers` son opcionales para el detector de phishing).
---

## 3. Instalación

```bash
# En la Raspberry Pi
cd proyecto-monitor

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Descargar corpus de TextBlob (solo la primera vez)
python3 -c "import textblob; textblob.download_corpora()"
```

> **Instalación mínima (sin torch/sentence-transformers):**  
> Si solo necesitas el detector de phishing, puedes omitir las dependencias pesadas.  
> El sistema arranca en modo fallback automáticamente.
>
> ```bash
> pip install Flask Flask-CORS textblob python-dotenv
> python3 -c "import textblob; textblob.download_corpora()"
> ```

---

## 4. Instrucciones para probar en Raspberry Pi

### 4.1 Probar sin servidor (recomendado para empezar)

```bash
# Activa el entorno virtual si no está activo
source venv/bin/activate

# Ejecuta los tests locales
python3 test_local.py
```

Verás dos bloques de tests:
- **TEST 1** — Motor de URLs (blacklist + similitud semántica)
- **TEST 2** — Detector de phishing (3 capas con 4 casos de prueba)

Ejemplo de salida esperada:

```
============================================================
  TEST 2 — Detector de Phishing (3 capas)
============================================================

Caso 1: Correo legitimo con mensaje normal
  Objetivo : contacto@empresa.com
  Resultado: ✅  En lista blanca  (risk_score=0.0)
  Capa 1 — Whitelist  : EN LISTA BLANCA

Caso 2: Correo falso similar + mensaje con errores
  Objetivo : ceo@empreza.com
  Resultado: 🚫  Phishing probable: dominio muy similar al legitimo  (risk_score=0.75)
  Capa 2 — Similitud  : 0.923 con 'empresa.com'
  Capa 3 — Ortografia : errores=0.4 mayusc=0.35 especiales=0.12
```

### 4.2 Arrancar el servidor web

```bash
source venv/bin/activate
python3 run.py
```

El banner mostrará la IP de la Raspberry Pi:

```
=======================================================
  Detector de Phishing — v2.0
  Panel:  http://192.168.1.XX:5000
  API:    http://192.168.1.XX:5000/api/check-phishing
  Health: http://192.168.1.XX:5000/api/health
=======================================================
```

### 4.3 Acceder al panel desde otro equipo

Abre un navegador en cualquier equipo de la misma red y ve a:

```
http://<IP-de-la-Raspberry>:5000
```

Desde la propia Raspberry:

```
http://localhost:5000
```

### 4.4 Probar la API desde la terminal

```bash
# Verificar un correo sospechoso
curl -X POST http://localhost:5000/api/check-phishing \
     -H "Content-Type: application/json" \
     -d '{"email_or_url": "ceo@empreza.com", "message": "URGENTE verifique su cuenta AHORA"}'

# Ver estadísticas de la última hora
curl http://localhost:5000/api/phishing-stats?hours=1

# Ver los últimos 10 análisis
curl http://localhost:5000/api/phishing-logs?limit=10
```

### 4.5 Personalizar la lista blanca

Edita `config/legitimate_domains.json` con los dominios y correos reales de tu empresa:

```json
{
  "company_name": "TuEmpresa",
  "legitimate_domains": [
    "tuempresa.com",
    "mail.tuempresa.com",
    "soporte.tuempresa.com"
  ],
  "legitimate_emails": [
    "ceo@tuempresa.com",
    "contacto@tuempresa.com",
    "soporte@tuempresa.com"
  ]
}
```

Reinicia el servidor para que los cambios surtan efecto.

---

## API de referencia

| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | `/api/check-phishing` | Analiza `{"email_or_url": "...", "message": "..."}` |
| GET  | `/api/phishing-stats?hours=1` | Estadísticas de phishing del período |
| GET  | `/api/phishing-logs?limit=50` | Logs recientes de análisis |
| POST | `/api/check-url` | Verificación de URL (backward compatibility) |
| GET  | `/api/stats?hours=1` | Estadísticas de URLs |
| GET  | `/api/logs?limit=50` | Logs de URLs |
| GET  | `/api/health` | Estado del servicio |
