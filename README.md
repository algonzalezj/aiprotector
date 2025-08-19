# AI Protector 🛡️

## Descripción
AI Protector es una plataforma avanzada de ciberseguridad basada en Inteligencia Artificial diseñada para detectar amenazas mediante el análisis inteligente de logs en tiempo real. La aplicación permite identificar anomalías y comportamientos sospechosos, clasificándolos según su gravedad para facilitar una rápida respuesta y mitigación.

## Características Principales
- **Recepción y almacenamiento de logs mediante API**.
- **Análisis de logs con Machine Learning y Deep Learning**.
- **Alertas automáticas en tiempo real**.
- **Dashboard visual e interactivo** para monitorización.

## Instalación

### Clonar repositorio
```bash
git clone https://github.com/algonzalezj/aiprotector.git
cd ai_protector
```
### Arrancar el entorno
```bash
docker compose up -d elasticsearch kibana ollama sqlite
```

### Instalar LLMs
Recomendado	        Para qué usarlo
llama3              Análisis general de logs, buena comprensión de lenguaje.
mistral             Uso rápido, poco consumo, tareas livianas.
codellama:instruct	Cuando quieras analizar logs de servidores, scripts o errores técnicos.
phi3	              Alternativa compacta, buen rendimiento, especialmente para clasificación.
```bash
docker exec -it ollama ollama list
docker exec -it ollama bash

ollama pull llama3
ollama pull mistral
ollama pull codellama:instruct
ollama pull phi3
```
Para listar los modelos desde el api de ollama
```bash
curl http://localhost:11434/api/tags
```

SOLO PARA DEVS

### Crear entorno virtual
```bash
python3 -m venv venv
source venv/bin/activate  # Linux o MacOS
.\venv\Scripts\activate   # Windows
```

### Instalar dependencias
```bash
pip install -r requirements.txt
```

### Ejecutar la aplicación
```bash
python3 app.py
```

Accede al dashboard desde: `http://localhost:5000`
Accede a kibana desde : `http://localhost:5601`
Accede a los índices de elasticsearch: `http://localhost:9200/_cat/indices?`
Acceder a ollama : `http://localhost:11434` 

## Tecnologías Utilizadas
- Python
- Flask
- Elasticsearch
- Scikit-learn, TensorFlow
- AdminLTE
- Ollama

## Crear bot de telegram para avisos
1. Crear un bot con @BotFather en Telegram:

    En Telegram, busca @BotFather
    Manda /start y luego /newbot
    Ponle un nombre y un username único.
    Te dará un TOKEN, guárdalo.

2. Obtener tu chat_id personal:

Abre esta URL en tu navegador (reemplaza BOT_TOKEN):

https://api.telegram.org/bot<BOT_TOKEN>/getUpdates

Mándale un mensaje al bot, vuelve a visitar la URL, y en la respuesta JSON busca tu chat.id. Por ejemplo:

"chat": {
  "id": 123456789,
  "first_name": "usuario",
  ...
}

Ese número es tu chat_id.
3. Agrega estos datos a tu .env:

TELEGRAM_TOKEN=123456789:ABCDEF...tu_token
TELEGRAM_CHAT_ID=123456789

4. En tu app.py, carga estas variables:

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


## Contribuir
¡Las contribuciones son bienvenidas!

1. Haz un fork del repositorio.
2. Crea tu rama de función: `git checkout -b feature/nueva-funcionalidad`
3. Realiza cambios y haz commit.
4. Envía una pull request para revisión.

## Licencia
Este proyecto está licenciado bajo la licencia **Apache 2.0**.


