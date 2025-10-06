# 🛡️ AI Protector

**AI Protector** es una plataforma avanzada de ciberseguridad basada en Inteligencia Artificial, diseñada para detectar amenazas mediante el análisis inteligente de logs en tiempo real.  
La aplicación identifica anomalías y comportamientos sospechosos, clasificándolos según su gravedad y proporcionando explicaciones basadas en evidencia, gracias a la integración con modelos de lenguaje (LLMs) y técnicas de *Retrieval-Augmented Generation (RAG)*.

---

## 🚀 Características Principales
- 🧠 **Análisis con IA:** Machine Learning + modelos locales (Llama3, Mistral, CodeLlama, Phi3).  
- 📊 **Dashboard visual e interactivo** con Kibana y Elasticsearch.  
- ⚡ **Alertas automáticas en tiempo real** (vía Telegram).  
- 🔐 **Autenticación JWT y roles de usuario (admin / user / server)**.  
- 📚 **Módulo RAG** que consulta una base de conocimiento local para contextualizar los logs.  
- 🧩 **Arquitectura modular**: Python + Flask + SQLite + Docker.

---

## 🧱 Arquitectura General

```
┌──────────────────────┐
│    Clientes/Agentes  │───► API Flask (Ingesta Logs)
└──────────────────────┘
             │
             ▼
      ┌──────────────┐
      │  Ollama LLM  │───► Evaluación de Riesgo (Llama3 / Mistral / etc.)
      └──────────────┘
             │
             ▼
      ┌──────────────┐
      │  Elasticsearch│──► Indexación y dashboards (Kibana)
      └──────────────┘
             │
             ▼
      ┌──────────────┐
      │ KnowledgeBase│──► Contexto RAG (ataques, CVEs, mitigación)
      └──────────────┘
```

---

## ⚙️ Instalación

### 1️⃣ Clonar el repositorio
```bash
git clone https://github.com/algonzalezj/aiprotector.git
cd aiprotector
```

### 2️⃣ Crear archivo `.env`
Crea un archivo `.env` en la raíz del proyecto con el siguiente contenido:

```dotenv
SECRET_KEY=pon_una_clave_segura_y_larga
ELASTIC_URL=http://localhost:9200/aiprotector/_doc
TELEGRAM_TOKEN=
TELEGRAM_CHAT_ID=
```

> ⚠️ Asegúrate de que `SECRET_KEY` y `ELASTIC_URL` estén configuradas correctamente antes de arrancar.

### 3️⃣ Levantar entorno base
```bash
docker compose up -d elasticsearch kibana ollama
```

### 4️⃣ Instalar modelos LLM
Recomendados y sus usos:

| Modelo              | Uso principal |
|----------------------|---------------|
| **llama3**           | Análisis general de logs. |
| **mistral**          | Rápido y liviano para detecciones simples. |
| **codellama:instruct** | Análisis de logs técnicos y servidores. |
| **phi3**             | Alternativa compacta, ideal para clasificación. |

Instalación:

```bash
docker exec -it ollama bash
ollama pull llama3
ollama pull mistral
ollama pull codellama:instruct
ollama pull phi3
exit
```

Verificar modelos:
```bash
curl http://localhost:11434/api/tags
```

### 5️⃣ (Solo devs) Crear entorno virtual
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# .\venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

### 6️⃣ Ejecutar la aplicación
```bash
python3 app.py
```

- App web: [http://localhost:5000](http://localhost:5000)  
- Kibana: [http://localhost:5601](http://localhost:5601)  
- Elasticsearch: [http://localhost:9200/_cat/indices?v](http://localhost:9200/_cat/indices?v)  
- Ollama: [http://localhost:11434](http://localhost:11434)

---

## 🧩 Endpoints Principales

### 🔐 Autenticación
| Método | Ruta | Descripción |
|--------|------|--------------|
| `POST` | `/login` | Devuelve un JWT si las credenciales son válidas. |
| `POST` | `/register` | Crea un nuevo usuario. |
| `GET` | `/logout` | Cierra sesión (borra cookie). |

Ejemplo:
```bash
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "server01", "password": "1234"}'
```

---

### 📥 Ingesta de Logs (API)
| Método | Ruta | Descripción |
|--------|------|--------------|
| `POST` | `/api/logs` | Recibe logs en JSON y evalúa con IA. |

Ejemplo:
```bash
TOKEN=$(curl -s -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"server01","password":"tu_password"}' | jq -r .token)

curl -X POST http://localhost:5000/api/logs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "203.0.113.10",
    "timestamp": "2025-09-01T15:15:45Z",
    "message": "SSH login failed for user root, attempt 567",
    "level": "warning",
    "service": "ssh"
  }'
```

Respuesta:
```json
{
  "message": "Log recibido",
  "diagnosis": "ALTO",
  "reasoning": "Actividad anómala detectada: múltiples intentos fallidos SSH.",
  "risk_level": "ALTO",
  "model": "llama3"
}
```

---

### 🧠 Módulo RAG
AI Protector incluye una **base de conocimiento interna (SQLite)** con información sobre vulnerabilidades y patrones de ataque:
- CVEs comunes (Log4j, Heartbleed, EternalBlue…)
- Firmas de detección (SQLi, DoS, XSS…)
- Medidas de mitigación.

El módulo RAG compara los mensajes de logs con esa base, añade contexto y mejora la clasificación del modelo IA, reduciendo falsos positivos.

---

## 🔔 Alertas por Telegram
1. Crea un bot en Telegram con [@BotFather](https://t.me/BotFather).
2. Obtén tu `chat_id` enviando un mensaje y visitando:
   ```
   https://api.telegram.org/bot<BOT_TOKEN>/getUpdates
   ```
3. Añade estos valores al `.env`:
   ```dotenv
   TELEGRAM_TOKEN=123456789:ABCDEF...
   TELEGRAM_CHAT_ID=123456789
   ```
4. Recibirás alertas automáticas cuando el nivel de riesgo sea **CRÍTICO**.

---

## 🧰 Tecnologías Utilizadas
- **Python** (Flask, SQLite, Requests, JWT)
- **Machine Learning:** Scikit-learn, TensorFlow
- **Elasticsearch** + **Kibana**
- **Ollama** (para modelos LLM locales)
- **Docker Compose**
- **AdminLTE** (interfaz visual)

---

## 🧠 Seguridad y Buenas Prácticas
- ✅ JWT seguros (expiran en 2h, cookies `HttpOnly` + `Secure`).
- ✅ Roles y permisos (`admin_required`, `user`).
- ✅ Cifrado de contraseñas (`werkzeug.security`).
- ✅ `Privacy by Design`: no usa datos reales ni externos.
- ⚙️ Recomendado en producción:
  - Desactivar `debug=True`
  - HTTPS + Reverse Proxy (Nginx/Caddy)
  - Rate limiting en `/login`
  - Protección CSRF en formularios

---

## 🧩 Integración con SIEM
AI Protector puede integrarse fácilmente con:
- **Wazuh**
- **Security Onion**
- **Splunk (vía Webhooks o REST)**  
para añadir una capa de inteligencia contextual y detección autónoma.

---

## 🧪 Troubleshooting
| Problema | Solución |
|-----------|-----------|
| `401 Unauthorized` | Token inválido o expirado. Renueva con `/login`. |
| Ollama no responde | Asegúrate de que el contenedor está corriendo (`docker ps`). |
| Sin datos en Kibana | Verifica `ELASTIC_URL` e índices activos. |
| Sin alertas Telegram | Comprueba `TELEGRAM_TOKEN` y `chat_id`. |
| RAG no aporta contexto | Asegúrate de que `knowledge_base` se ha inicializado correctamente. |

---

## 🤝 Contribuir
¡Las contribuciones son bienvenidas!

1. Haz un fork del repositorio.  
2. Crea una rama:  
   ```bash
   git checkout -b feature/nueva-funcionalidad
   ```  
3. Realiza cambios y haz commit:  
   ```bash
   git commit -m "Agrega nueva funcionalidad"
   ```  
4. Envía una Pull Request.

---

## 🧾 Licencia
Este proyecto está licenciado bajo **Apache 2.0**.

---

> _“La ciberseguridad no se trata solo de proteger sistemas, sino de garantizar la confianza digital.”_ — *AI Protector Team*